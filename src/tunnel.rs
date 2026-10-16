//! I2P tunnels from the creator's side: short build messages with ECIES
//! records, the layer encryption of tunnel data, and tunnel messages with
//! their fragments and delivery instructions.

use std::collections::HashMap;

use axon_addons::{
    cipher::{aes256_cbc_decrypt, aes256_decrypt_block, chacha20_xor},
    keys::{ExchangePublic, ExchangeSecret},
    noise::{CipherState, SymmetricState, hkdf},
};

use crate::{
    data::now_ms,
    i2np::{self, Message},
    identity::sha256,
};

pub const RECORD_LEN: usize = 218;
const CLEAR_RECORD_LEN: usize = 154;
const RECORDS: usize = 4;
pub const TUNNEL_DATA_LEN: usize = 1024;
const ENCRYPTED_LEN: usize = 1008;

const FLAG_GATEWAY: u8 = 0x80;
const FLAG_ENDPOINT: u8 = 0x40;

fn random_u32() -> u32 {
    loop {
        let value = i2np::random_u32();
        if value != 0 {
            return value;
        }
    }
}

/// A router chosen as a hop: its hash and its X25519 key.
#[derive(Debug, Clone, Copy)]
pub struct Peer {
    pub hash: [u8; 32],
    pub encryption_key: [u8; 32],
}

/// The keys a hop uses for tunnel data.
#[derive(Clone, Copy)]
pub struct Layer {
    layer_key: [u8; 32],
    iv_key: [u8; 32],
}

impl Layer {
    /// Undoes this hop's layer: the IV is decrypted twice around the data.
    fn decrypt(&self, data: &mut [u8; TUNNEL_DATA_LEN]) {
        let mut iv: [u8; 16] = data[..16].try_into().expect("fixed slice");
        aes256_decrypt_block(&self.iv_key, &mut iv);
        aes256_cbc_decrypt(&self.layer_key, &iv, &mut data[16..]);
        aes256_decrypt_block(&self.iv_key, &mut iv);
        data[..16].copy_from_slice(&iv);
    }
}

struct Hop {
    peer: Peer,
    tunnel: u32,
    record: usize,
    reply_key: [u8; 32],
    hash: [u8; 32],
    layer: Layer,
}

/// A tunnel being built, and once built, its layers.
pub struct Tunnel {
    hops: Vec<Hop>,
    pub inbound: bool,
    /// The id of the build reply message.
    pub reply_id: u32,
    /// For an inbound tunnel: the id its tunnel data arrives under here.
    pub receive_tunnel: u32,
    /// For an outbound tunnel: the key and tag the reply garlic comes under.
    pub reply_garlic: Option<([u8; 32], [u8; 8])>,
}

impl Tunnel {
    /// The first hop: where the build message and tunnel data are sent.
    pub fn first_hop(&self) -> &[u8; 32] {
        &self.hops[0].peer.hash
    }

    pub fn first_tunnel(&self) -> u32 {
        self.hops[0].tunnel
    }

    /// The last hop: the outbound endpoint, or the hop before us inbound.
    pub fn last_hop(&self) -> &[u8; 32] {
        &self.hops[self.hops.len() - 1].peer.hash
    }

    pub fn hops(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.hops.iter().map(|hop| &hop.peer.hash)
    }

    /// Starts an inbound tunnel through `peers`, the gateway first, ending at
    /// `us`. Returns it and the build message for the gateway.
    pub fn inbound(peers: &[Peer], us: [u8; 32]) -> (Self, Message) {
        let receive_tunnel = random_u32();
        Self::build(peers, true, us, receive_tunnel)
    }

    /// Starts an outbound tunnel through `peers` whose endpoint sends the
    /// build reply into the inbound tunnel `reply_tunnel` at `reply_gateway`.
    pub fn outbound(peers: &[Peer], reply_gateway: [u8; 32], reply_tunnel: u32) -> (Self, Message) {
        Self::build(peers, false, reply_gateway, reply_tunnel)
    }

    fn build(
        peers: &[Peer],
        inbound: bool,
        last_next: [u8; 32],
        last_next_tunnel: u32,
    ) -> (Self, Message) {
        assert!(!peers.is_empty() && peers.len() <= RECORDS, "1 to 4 hops");
        let reply_id = random_u32();
        let tunnels = peers.iter().map(|_| random_u32()).collect::<Vec<_>>();
        // Records go to random slots; unused slots are random bytes.
        let mut slots = (0..RECORDS).collect::<Vec<_>>();
        for i in (1..slots.len()).rev() {
            slots.swap(i, (random_u32() as usize) % (i + 1));
        }
        let mut records = vec![0u8; RECORDS * RECORD_LEN];
        getrandom::getrandom(&mut records).expect("system random source");
        let mut hops = Vec::new();
        let mut reply_garlic = None;
        for (index, peer) in peers.iter().enumerate() {
            let last = index + 1 == peers.len();
            let (next, next_tunnel) = if last {
                (last_next, last_next_tunnel)
            } else {
                (peers[index + 1].hash, tunnels[index + 1])
            };
            let mut flags = 0;
            if index == 0 && inbound {
                flags |= FLAG_GATEWAY;
            }
            if last && !inbound {
                flags |= FLAG_ENDPOINT;
            }
            let mut clear = [0u8; CLEAR_RECORD_LEN];
            clear[0..4].copy_from_slice(&tunnels[index].to_be_bytes());
            clear[4..8].copy_from_slice(&next_tunnel.to_be_bytes());
            clear[8..40].copy_from_slice(&next);
            clear[40] = flags;
            // 41..43 more flags, 43 layer encryption (AES): zero
            clear[44..48].copy_from_slice(&((now_ms() / 60_000) as u32).to_be_bytes());
            clear[48..52].copy_from_slice(&600u32.to_be_bytes());
            let message_id = if last { reply_id } else { random_u32() };
            clear[52..56].copy_from_slice(&message_id.to_be_bytes());
            // 56..58 an empty options mapping, the rest zero
            let slot = slots[index];
            let record = &mut records[slot * RECORD_LEN..(slot + 1) * RECORD_LEN];
            record[..16].copy_from_slice(&peer.hash[..16]);
            // Noise N to the hop's encryption key.
            let ephemeral = ExchangeSecret::generate().expect("system random source");
            let mut symmetric = SymmetricState::new(b"Noise_N_25519_ChaChaPoly_SHA256");
            symmetric.mix_hash(&[]);
            symmetric.mix_hash(&peer.encryption_key);
            symmetric.mix_hash(&ephemeral.public().0);
            symmetric
                .mix_dh(&ephemeral, &ExchangePublic(peer.encryption_key))
                .expect("valid router key");
            let sealed = symmetric.encrypt_and_hash(&clear).expect("fresh key");
            record[16..48].copy_from_slice(&ephemeral.public().0);
            record[48..].copy_from_slice(&sealed);
            // Keys for the reply and for tunnel data, chained by labels.
            let (chain, reply_key) = hkdf(symmetric.chaining_key(), &[], b"SMTunnelReplyKey");
            let (chain, layer_key) = hkdf(&chain, &[], b"SMTunnelLayerKey");
            let iv_key = if last && !inbound {
                let (chain, iv_key) = hkdf(&chain, &[], b"TunnelLayerIVKey");
                let (tag, garlic_key) = hkdf(&chain, &[], b"RGarlicKeyAndTag");
                reply_garlic = Some((garlic_key, tag[..8].try_into().expect("fixed slice")));
                iv_key
            } else {
                chain
            };
            hops.push(Hop {
                peer: *peer,
                tunnel: tunnels[index],
                record: slot,
                reply_key,
                hash: *symmetric.hash(),
                layer: Layer { layer_key, iv_key },
            });
        }
        // Each hop encrypts the records after its own with ChaCha20; undo
        // that in advance so they arrive readable, last hops first.
        for index in (0..hops.len().saturating_sub(1)).rev() {
            for later in &hops[index + 1..] {
                chacha_record(&mut records, later.record, &hops[index].reply_key);
            }
        }
        let mut payload = vec![RECORDS as u8];
        payload.extend_from_slice(&records);
        let tunnel = Self {
            hops,
            inbound,
            reply_id,
            receive_tunnel: if inbound { last_next_tunnel } else { 0 },
            reply_garlic,
        };
        let message = Message::new(i2np::SHORT_TUNNEL_BUILD, payload);
        (tunnel, message)
    }

    /// Reads the build reply records. Returns each hop's answer, zero for
    /// accepted.
    pub fn handle_reply(&self, payload: &[u8]) -> Result<Vec<u8>, String> {
        let count = usize::from(*payload.first().ok_or("empty reply")?);
        let mut records = payload
            .get(1..1 + count * RECORD_LEN)
            .ok_or("truncated reply")?
            .to_vec();
        for (index, hop) in self.hops.iter().enumerate().rev() {
            if hop.record >= count {
                return Err("reply has too few records".to_owned());
            }
            let start = hop.record * RECORD_LEN;
            let mut cipher = CipherState::new(hop.reply_key);
            // The nonce has the record index in byte 4: the counter is the index.
            cipher.set_nonce(hop.record as u64);
            let opened = cipher
                .decrypt(&hop.hash, &records[start..start + RECORD_LEN])
                .map_err(|_| format!("reply record of hop {index} does not decrypt"))?;
            records[start..start + RECORD_LEN - 16].copy_from_slice(&opened);
            for earlier in &self.hops[..index] {
                chacha_record(&mut records, earlier.record, &hop.reply_key);
            }
        }
        Ok(self
            .hops
            .iter()
            .map(|hop| records[hop.record * RECORD_LEN + 201])
            .collect())
    }

    /// Removes the layers of every hop from tunnel data, last hop first, as
    /// the endpoint of an inbound tunnel reads it and as the gateway of an
    /// outbound tunnel prepares it.
    pub fn remove_layers(&self, data: &mut [u8; TUNNEL_DATA_LEN]) {
        for hop in self.hops.iter().rev() {
            hop.layer.decrypt(data);
        }
    }
}

/// ChaCha20 over one record with the nonce the record's index gives. The
/// block counter starts at one, as I2P routers have it.
fn chacha_record(records: &mut [u8], index: usize, key: &[u8; 32]) {
    let mut nonce = [0u8; 12];
    nonce[4] = index as u8;
    chacha20_xor(
        key,
        &nonce,
        1,
        &mut records[index * RECORD_LEN..(index + 1) * RECORD_LEN],
    );
}

/// Where a message leaving a tunnel goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    Local,
    Router([u8; 32]),
    Tunnel([u8; 32], u32),
}

/// Builds tunnel messages (IV and 1008 bytes, before layers) carrying
/// `messages`, fragmenting them as needed.
pub fn tunnel_messages(messages: &[(Delivery, Vec<u8>)]) -> Vec<[u8; TUNNEL_DATA_LEN]> {
    // Lay out fragments: (instructions, data) pairs.
    let mut fragments: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for (delivery, message) in messages {
        let mut first = Vec::new();
        let mut flag = match delivery {
            Delivery::Local => 0u8,
            Delivery::Tunnel(..) => 1 << 5,
            Delivery::Router(_) => 2 << 5,
        };
        let header_len =
            1 + match delivery {
                Delivery::Local => 0,
                Delivery::Router(_) => 32,
                Delivery::Tunnel(..) => 36,
            } + 2;
        // Room in an empty tunnel message: 1008 minus checksum and zero byte.
        let room = ENCRYPTED_LEN - 4 - 1;
        let message_id = random_u32();
        let fits = header_len + message.len() <= room;
        if !fits {
            flag |= 0x08;
        }
        first.push(flag);
        match delivery {
            Delivery::Local => {}
            Delivery::Router(hash) => first.extend_from_slice(hash),
            Delivery::Tunnel(hash, tunnel) => {
                first.extend_from_slice(&tunnel.to_be_bytes());
                first.extend_from_slice(hash);
            }
        }
        if fits {
            first.extend_from_slice(&(message.len() as u16).to_be_bytes());
            fragments.push((first, message.clone()));
            continue;
        }
        first.extend_from_slice(&message_id.to_be_bytes());
        let first_size = room - first.len() - 2;
        first.extend_from_slice(&(first_size as u16).to_be_bytes());
        fragments.push((first, message[..first_size].to_vec()));
        let mut rest = &message[first_size..];
        let mut number = 1u8;
        while !rest.is_empty() {
            let size = rest.len().min(room - 7);
            let last = size == rest.len();
            let mut header = vec![0x80 | (number << 1) | u8::from(last)];
            header.extend_from_slice(&message_id.to_be_bytes());
            header.extend_from_slice(&(size as u16).to_be_bytes());
            fragments.push((header, rest[..size].to_vec()));
            rest = &rest[size..];
            number += 1;
        }
    }
    // One fragment per tunnel message keeps the layout simple.
    fragments
        .into_iter()
        .map(|(header, data)| {
            let mut body = header;
            body.extend_from_slice(&data);
            let mut message = [0u8; TUNNEL_DATA_LEN];
            getrandom::getrandom(&mut message[..16]).expect("system random source");
            let iv: [u8; 16] = message[..16].try_into().expect("fixed slice");
            let padding = ENCRYPTED_LEN - 4 - 1 - body.len();
            let start = 16 + 4 + padding + 1;
            message[start..].copy_from_slice(&body);
            let mut nonzero = vec![0u8; padding];
            getrandom::getrandom(&mut nonzero).expect("system random source");
            for (slot, byte) in message[20..20 + padding].iter_mut().zip(nonzero) {
                *slot = byte | 1;
            }
            message[20 + padding] = 0;
            let mut checked = body;
            checked.extend_from_slice(&iv);
            message[16..20].copy_from_slice(&sha256(&checked)[..4]);
            message
        })
        .collect()
}

/// Puts fragments that arrive at a tunnel's end back together.
#[derive(Default)]
pub struct Reassembler {
    partial: HashMap<u32, Partial>,
}

struct Partial {
    delivery: Delivery,
    pieces: Vec<Option<Vec<u8>>>,
    last: Option<usize>,
}

impl Reassembler {
    /// Reads a tunnel message whose layers are removed and returns the
    /// messages it completes.
    pub fn read(
        &mut self,
        data: &[u8; TUNNEL_DATA_LEN],
    ) -> Result<Vec<(Delivery, Vec<u8>)>, String> {
        let iv = &data[..16];
        let body = &data[16..];
        let zero = body[4..]
            .iter()
            .position(|&byte| byte == 0)
            .ok_or("no end of padding")?
            + 4;
        let fragments = &body[zero + 1..];
        let mut checked = fragments.to_vec();
        checked.extend_from_slice(iv);
        if sha256(&checked)[..4] != body[..4] {
            return Err("tunnel message checksum does not match".to_owned());
        }
        let mut done = Vec::new();
        let mut at = 0;
        while at < fragments.len() {
            let flag = fragments[at];
            at += 1;
            let field = |at: &mut usize, length: usize| -> Result<&[u8], String> {
                let slice = fragments
                    .get(*at..*at + length)
                    .ok_or("truncated fragment")?;
                *at += length;
                Ok(slice)
            };
            if flag & 0x80 == 0 {
                let delivery = match (flag >> 5) & 3 {
                    0 => Delivery::Local,
                    1 => {
                        let tunnel = u32::from_be_bytes(field(&mut at, 4)?.try_into().expect("4"));
                        Delivery::Tunnel(field(&mut at, 32)?.try_into().expect("32"), tunnel)
                    }
                    2 => Delivery::Router(field(&mut at, 32)?.try_into().expect("32")),
                    _ => return Err("unknown delivery type".to_owned()),
                };
                let fragmented = flag & 0x08 != 0;
                let message_id = if fragmented {
                    Some(u32::from_be_bytes(
                        field(&mut at, 4)?.try_into().expect("4"),
                    ))
                } else {
                    None
                };
                let size = usize::from(u16::from_be_bytes(
                    field(&mut at, 2)?.try_into().expect("2"),
                ));
                let data = field(&mut at, size)?.to_vec();
                match message_id {
                    None => done.push((delivery, data)),
                    Some(id) => {
                        let partial = self.partial.entry(id).or_insert(Partial {
                            delivery,
                            pieces: Vec::new(),
                            last: None,
                        });
                        partial.delivery = delivery;
                        if partial.pieces.is_empty() {
                            partial.pieces.push(None);
                        }
                        partial.pieces[0] = Some(data);
                        if let Some(message) = self.complete(id) {
                            done.push(message);
                        }
                    }
                }
            } else {
                let number = usize::from((flag >> 1) & 0x3f);
                let last = flag & 1 != 0;
                let id = u32::from_be_bytes(field(&mut at, 4)?.try_into().expect("4"));
                let size = usize::from(u16::from_be_bytes(
                    field(&mut at, 2)?.try_into().expect("2"),
                ));
                let data = field(&mut at, size)?.to_vec();
                let partial = self.partial.entry(id).or_insert(Partial {
                    delivery: Delivery::Local,
                    pieces: Vec::new(),
                    last: None,
                });
                if partial.pieces.len() <= number {
                    partial.pieces.resize(number + 1, None);
                }
                partial.pieces[number] = Some(data);
                if last {
                    partial.last = Some(number);
                }
                if let Some(message) = self.complete(id) {
                    done.push(message);
                }
            }
        }
        // Forget assemblies that never finish.
        if self.partial.len() > 64 {
            self.partial.clear();
        }
        Ok(done)
    }

    fn complete(&mut self, id: u32) -> Option<(Delivery, Vec<u8>)> {
        let partial = self.partial.get(&id)?;
        let last = partial.last?;
        if partial.pieces.len() < last + 1 || partial.pieces[..=last].iter().any(Option::is_none) {
            return None;
        }
        let partial = self.partial.remove(&id)?;
        let data = partial.pieces.into_iter().flatten().flatten().collect();
        Some((partial.delivery, data))
    }
}

/// A message for a router's tunnel gateway: the tunnel id and the message.
pub fn tunnel_gateway(tunnel: u32, message: &[u8]) -> Message {
    let mut payload = tunnel.to_be_bytes().to_vec();
    payload.extend_from_slice(&(message.len() as u16).to_be_bytes());
    payload.extend_from_slice(message);
    Message::new(i2np::TUNNEL_GATEWAY, payload)
}

/// A TunnelData message: the tunnel id and the 1024 bytes.
pub fn tunnel_data(tunnel: u32, data: &[u8; TUNNEL_DATA_LEN]) -> Message {
    let mut payload = tunnel.to_be_bytes().to_vec();
    payload.extend_from_slice(data);
    Message::new(i2np::TUNNEL_DATA, payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_and_large_messages_survive_the_tunnel_format() {
        let small = vec![1u8; 100];
        let large: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
        let router = [9u8; 32];
        let messages = tunnel_messages(&[
            (Delivery::Local, small.clone()),
            (Delivery::Tunnel(router, 77), large.clone()),
        ]);
        assert!(messages.len() >= 4);
        let mut reassembler = Reassembler::default();
        let mut out = Vec::new();
        // Fragments may arrive out of order.
        for message in messages.iter().rev() {
            out.extend(reassembler.read(message).unwrap());
        }
        out.sort_by_key(|(_, data)| data.len());
        assert_eq!(
            out,
            vec![
                (Delivery::Local, small),
                (Delivery::Tunnel(router, 77), large)
            ]
        );
    }

    #[test]
    fn build_records_open_for_their_hops() {
        // Play the hops: each opens its record with its own key, then
        // ChaCha20s the others, and the creator reads the replies.
        let secrets = (0..3)
            .map(|_| ExchangeSecret::generate().unwrap())
            .collect::<Vec<_>>();
        let peers = secrets
            .iter()
            .enumerate()
            .map(|(i, secret)| Peer {
                hash: [i as u8 + 1; 32],
                encryption_key: secret.public().0,
            })
            .collect::<Vec<_>>();
        let (tunnel, message) = Tunnel::inbound(&peers, [0xee; 32]);
        let mut records = message.payload[1..].to_vec();
        for (index, secret) in secrets.iter().enumerate() {
            let slot = (0..RECORDS)
                .find(|slot| {
                    records[slot * RECORD_LEN..slot * RECORD_LEN + 16] == peers[index].hash[..16]
                })
                .expect("each hop finds its record");
            let record = records[slot * RECORD_LEN..(slot + 1) * RECORD_LEN].to_vec();
            let mut symmetric = SymmetricState::new(b"Noise_N_25519_ChaChaPoly_SHA256");
            symmetric.mix_hash(&[]);
            symmetric.mix_hash(&secret.public().0);
            let ephemeral = ExchangePublic(record[16..48].try_into().unwrap());
            symmetric.mix_hash(&ephemeral.0);
            symmetric.mix_dh(secret, &ephemeral).unwrap();
            let clear = symmetric.decrypt_and_hash(&record[48..]).unwrap();
            assert_eq!(&clear[0..4], &tunnel.hops[index].tunnel.to_be_bytes());
            let (chain, reply_key) = hkdf(symmetric.chaining_key(), &[], b"SMTunnelReplyKey");
            let _ = chain;
            // Accept: reply record with return code 0, sealed with the hash.
            let mut reply = vec![0u8; RECORD_LEN - 16];
            reply[201] = 0;
            let mut cipher = CipherState::new(reply_key);
            cipher.set_nonce(slot as u64);
            let sealed = cipher.encrypt(symmetric.hash(), &reply).unwrap();
            records[slot * RECORD_LEN..(slot + 1) * RECORD_LEN].copy_from_slice(&sealed);
            for other in 0..RECORDS {
                if other != slot {
                    chacha_record(&mut records, other, &reply_key);
                }
            }
        }
        let mut payload = vec![RECORDS as u8];
        payload.extend_from_slice(&records);
        assert_eq!(tunnel.handle_reply(&payload).unwrap(), vec![0, 0, 0]);
    }
}
