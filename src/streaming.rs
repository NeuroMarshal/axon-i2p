//! I2P streaming: TCP-like connections between destinations, carried as
//! packets in garlic messages.
//!
//! [`Packet`] is the wire format. [`Stream`] is the client end of one
//! connection: it opens with a signed SYN, numbers and resends what it
//! sends, acknowledges what arrives and hands the bytes over in order.

use std::collections::BTreeMap;

use axon_addons::sign::{Signature, VerifyingKey};

use crate::{
    data::Reader,
    identity::{Identity, PrivateIdentity, SIGNING_ED25519, SIGNING_RED25519, signing_lengths},
};

pub const SYN: u16 = 0x0001;
pub const CLOSE: u16 = 0x0002;
pub const RESET: u16 = 0x0004;
pub const SIGNATURE: u16 = 0x0008;
pub const FROM: u16 = 0x0020;
pub const DELAY: u16 = 0x0040;
pub const MAX_PACKET: u16 = 0x0080;
pub const NO_ACK: u16 = 0x0400;
pub const OFFLINE_SIGNATURE: u16 = 0x0800;

/// The I2CP protocol number of streaming, in a Data message's header.
pub const PROTOCOL: u8 = 6;
/// Largest payload per packet over ECIES sessions.
pub const MTU: usize = 1812;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Packet {
    pub send_stream: u32,
    pub receive_stream: u32,
    pub seq: u32,
    pub ack_through: u32,
    pub nacks: Vec<u32>,
    pub resend_delay: u8,
    pub flags: u16,
    pub delay: Option<u16>,
    pub from: Option<Identity>,
    pub max_packet: Option<u16>,
    pub offline: Option<OfflineSignature>,
    pub signature: Option<Vec<u8>>,
    pub payload: Vec<u8>,
}

/// A transient key the destination signed; packets are then signed by the
/// transient key, so the destination's own key can stay offline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineSignature {
    /// Seconds since the Unix epoch.
    pub expires: u32,
    pub key_type: u16,
    pub key: Vec<u8>,
    /// The destination's signature over the expiry, type and key.
    pub signature: Vec<u8>,
}

impl OfflineSignature {
    fn signed_part(&self) -> Vec<u8> {
        let mut out = self.expires.to_be_bytes().to_vec();
        out.extend_from_slice(&self.key_type.to_be_bytes());
        out.extend_from_slice(&self.key);
        out
    }
}

impl Packet {
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut reader = Reader::new(bytes);
        let mut packet = Self {
            send_stream: reader.u32()?,
            receive_stream: reader.u32()?,
            seq: reader.u32()?,
            ack_through: reader.u32()?,
            ..Self::default()
        };
        for _ in 0..reader.u8()? {
            packet.nacks.push(reader.u32()?);
        }
        packet.resend_delay = reader.u8()?;
        packet.flags = reader.u16()?;
        let options_len = usize::from(reader.u16()?);
        let mut options = Reader::new(reader.take(options_len)?);
        if packet.flags & DELAY != 0 {
            packet.delay = Some(options.u16()?);
        }
        if packet.flags & FROM != 0 {
            let (identity, length) = Identity::parse(options.remaining())?;
            options.take(length)?;
            packet.from = Some(identity);
        }
        if packet.flags & MAX_PACKET != 0 {
            packet.max_packet = Some(options.u16()?);
        }
        // The signature closes the options, so its length is what is left.
        // Packets without FROM, such as a signed CLOSE, rely on that.
        let signed = packet.flags & SIGNATURE != 0;
        if packet.flags & OFFLINE_SIGNATURE != 0 {
            let expires = options.u32()?;
            let key_type = options.u16()?;
            let (key_len, transient_signature_len) = signing_lengths(key_type)?;
            let key = options.take(key_len)?.to_vec();
            let packet_signature_len = if signed { transient_signature_len } else { 0 };
            let offline_len = options
                .remaining()
                .len()
                .checked_sub(packet_signature_len)?;
            let signature = options.take(offline_len)?.to_vec();
            packet.offline = Some(OfflineSignature {
                expires,
                key_type,
                key,
                signature,
            });
        }
        if signed {
            packet.signature = Some(options.remaining().to_vec());
        }
        packet.payload = reader.remaining().to_vec();
        Some(packet)
    }

    /// The packet with the signature field zeroed, and where it is.
    fn encode_with_signature_at(&self) -> (Vec<u8>, Option<(usize, usize)>) {
        let mut out = Vec::with_capacity(32 + self.payload.len());
        out.extend_from_slice(&self.send_stream.to_be_bytes());
        out.extend_from_slice(&self.receive_stream.to_be_bytes());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.ack_through.to_be_bytes());
        out.push(self.nacks.len() as u8);
        for nack in &self.nacks {
            out.extend_from_slice(&nack.to_be_bytes());
        }
        out.push(self.resend_delay);
        out.extend_from_slice(&self.flags.to_be_bytes());
        let mut options = Vec::new();
        if let Some(delay) = self.delay {
            options.extend_from_slice(&delay.to_be_bytes());
        }
        if let Some(from) = &self.from {
            options.extend_from_slice(from.bytes());
        }
        if let Some(max) = self.max_packet {
            options.extend_from_slice(&max.to_be_bytes());
        }
        if let Some(offline) = &self.offline {
            options.extend_from_slice(&offline.signed_part());
            options.extend_from_slice(&offline.signature);
        }
        let mut signature_at = None;
        if let Some(signature) = &self.signature {
            signature_at = Some((out.len() + 2 + options.len(), signature.len()));
            options.extend(std::iter::repeat_n(0, signature.len()));
        }
        out.extend_from_slice(&(options.len() as u16).to_be_bytes());
        out.extend_from_slice(&options);
        out.extend_from_slice(&self.payload);
        (out, signature_at)
    }

    pub fn encode(&self) -> Vec<u8> {
        let (mut out, at) = self.encode_with_signature_at();
        if let (Some((start, length)), Some(signature)) = (at, &self.signature) {
            out[start..start + length].copy_from_slice(signature);
        }
        out
    }

    /// Encodes and signs with `keys`; the packet must carry a signature
    /// field of the right length.
    pub fn encode_signed(&self, keys: &PrivateIdentity) -> Vec<u8> {
        let (mut out, at) = self.encode_with_signature_at();
        let (start, length) = at.expect("a signed packet has a signature field");
        let signature = keys.sign(&out);
        out[start..start + length].copy_from_slice(&signature[..length]);
        out
    }

    /// Checks the signature of a decoded packet against `identity`, through
    /// the transient key when the packet carries an offline signature.
    pub fn verify(&self, identity: &Identity) -> bool {
        let Some(signature) = &self.signature else {
            return false;
        };
        let (out, _) = self.encode_with_signature_at();
        let Some(offline) = &self.offline else {
            return identity.verify(&out, signature);
        };
        if !identity.verify(&offline.signed_part(), &offline.signature)
            || !matches!(offline.key_type, SIGNING_ED25519 | SIGNING_RED25519)
        {
            return false;
        }
        let (Ok(key), Ok(signature)) = (
            <[u8; 32]>::try_from(offline.key.as_slice()),
            <[u8; 64]>::try_from(signature.as_slice()),
        ) else {
            return false;
        };
        VerifyingKey(key)
            .verify(&out, &Signature(signature))
            .is_ok()
    }
}

/// What a stream did with a packet that arrived.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Arrival {
    /// The peer answered our SYN.
    pub opened: bool,
    /// Bytes now in order for the application.
    pub data: Vec<u8>,
    /// The peer closed or reset the stream.
    pub closed: bool,
    /// The packet should be acknowledged.
    pub ack: bool,
}

struct Unacked {
    packet: Packet,
    sent_at: u64,
    attempts: u32,
}

/// The client end of a streaming connection.
pub struct Stream {
    local_id: u32,
    remote_id: u32,
    remote_hash: [u8; 32],
    next_seq: u32,
    received_through: Option<u32>,
    out_of_order: BTreeMap<u32, Vec<u8>>,
    unacked: BTreeMap<u32, Unacked>,
    closed_by_peer: bool,
    closing: bool,
}

/// Resend after this long without an acknowledgement.
const RESEND_MS: u64 = 3_000;
const MAX_ATTEMPTS: u32 = 8;

impl Stream {
    pub fn new(local_id: u32, remote_hash: [u8; 32]) -> Self {
        Self {
            local_id,
            remote_id: 0,
            remote_hash,
            next_seq: 0,
            received_through: None,
            out_of_order: BTreeMap::new(),
            unacked: BTreeMap::new(),
            closed_by_peer: false,
            closing: false,
        }
    }

    pub const fn local_id(&self) -> u32 {
        self.local_id
    }

    pub fn is_open(&self) -> bool {
        self.remote_id != 0
    }

    pub fn is_finished(&self) -> bool {
        self.closed_by_peer && self.unacked.is_empty()
    }

    /// The SYN, signed by `keys`, with the first data.
    pub fn syn(&mut self, keys: &PrivateIdentity, data: &[u8], now: u64) -> Vec<u8> {
        // The NACK list carries the target's hash, so the SYN cannot be
        // replayed to another destination.
        let nacks = self
            .remote_hash
            .chunks(4)
            .map(|chunk| u32::from_be_bytes(chunk.try_into().expect("4 bytes")))
            .collect();
        let packet = Packet {
            send_stream: 0,
            receive_stream: self.local_id,
            seq: self.next_seq,
            ack_through: 0,
            nacks,
            resend_delay: 3,
            flags: SYN | FROM | MAX_PACKET | SIGNATURE | NO_ACK,
            from: Some(keys.identity.clone()),
            max_packet: Some(MTU as u16),
            signature: Some(vec![0; keys.identity.signature_len()]),
            payload: data.to_vec(),
            ..Packet::default()
        };
        let bytes = packet.encode_signed(keys);
        let mut stored = Packet::decode(&bytes).expect("own packet decodes");
        stored.signature = Packet::decode(&bytes).and_then(|p| p.signature);
        self.unacked.insert(
            self.next_seq,
            Unacked {
                packet: stored,
                sent_at: now,
                attempts: 1,
            },
        );
        self.next_seq += 1;
        bytes
    }

    /// Packets carrying `data`, numbered on from the SYN.
    pub fn send(&mut self, data: &[u8], now: u64) -> Vec<Vec<u8>> {
        data.chunks(MTU)
            .map(|chunk| {
                let packet = Packet {
                    send_stream: self.remote_id,
                    receive_stream: self.local_id,
                    seq: self.next_seq,
                    ack_through: self.received_through.unwrap_or(0),
                    resend_delay: 3,
                    payload: chunk.to_vec(),
                    ..Packet::default()
                };
                self.next_seq += 1;
                let bytes = packet.encode();
                self.unacked.insert(
                    packet.seq,
                    Unacked {
                        packet,
                        sent_at: now,
                        attempts: 1,
                    },
                );
                bytes
            })
            .collect()
    }

    /// The closing packet.
    pub fn close(&mut self, now: u64) -> Vec<u8> {
        self.closing = true;
        let packet = Packet {
            send_stream: self.remote_id,
            receive_stream: self.local_id,
            seq: self.next_seq,
            ack_through: self.received_through.unwrap_or(0),
            resend_delay: 3,
            flags: CLOSE,
            ..Packet::default()
        };
        self.next_seq += 1;
        let bytes = packet.encode();
        self.unacked.insert(
            packet.seq,
            Unacked {
                packet,
                sent_at: now,
                attempts: 1,
            },
        );
        bytes
    }

    /// An acknowledgement of everything received in order, with NACKs for
    /// the gaps before packets that came early.
    pub fn ack(&self) -> Option<Vec<u8>> {
        let through = self.received_through?;
        let mut nacks = Vec::new();
        if let Some(&last) = self.out_of_order.keys().next_back() {
            for seq in through + 1..last {
                if !self.out_of_order.contains_key(&seq) && nacks.len() < 255 {
                    nacks.push(seq);
                }
            }
        }
        let ack_through = self
            .out_of_order
            .keys()
            .next_back()
            .copied()
            .unwrap_or(through);
        Some(
            Packet {
                send_stream: self.remote_id,
                receive_stream: self.local_id,
                seq: 0,
                ack_through,
                nacks,
                ..Packet::default()
            }
            .encode(),
        )
    }

    /// Handles a packet for this stream.
    pub fn arrive(&mut self, packet: Packet) -> Arrival {
        let mut arrival = Arrival::default();
        if packet.flags & SYN != 0 && self.remote_id == 0 {
            self.remote_id = packet.receive_stream;
            arrival.opened = true;
        }
        if packet.flags & RESET != 0 {
            self.closed_by_peer = true;
            self.unacked.clear();
            arrival.closed = true;
            return arrival;
        }
        // Acknowledgements of what we sent; plain ACKs never ack our SYN
        // through a zero.
        if packet.flags & NO_ACK == 0 {
            let nacked = packet.nacks.clone();
            self.unacked
                .retain(|seq, _| !(*seq <= packet.ack_through && !nacked.contains(seq)));
        }
        let carries = !packet.payload.is_empty() || packet.flags & (SYN | CLOSE) != 0;
        if !carries || packet.seq == 0 && packet.flags & SYN == 0 && packet.payload.is_empty() {
            return arrival;
        }
        arrival.ack = true;
        let next = self.received_through.map_or(0, |seq| seq + 1);
        if packet.seq < next {
            return arrival; // a resend of something already delivered
        }
        if packet.flags & CLOSE != 0 {
            self.closed_by_peer = true;
        }
        self.out_of_order.insert(packet.seq, packet.payload);
        let mut next = next;
        while let Some(payload) = self.out_of_order.remove(&next) {
            arrival.data.extend_from_slice(&payload);
            self.received_through = Some(next);
            next += 1;
        }
        arrival.closed = self.closed_by_peer && self.out_of_order.is_empty();
        arrival
    }

    /// Packets to send again. Returns `None` once the peer stopped
    /// answering.
    pub fn resend(&mut self, now: u64, keys: &PrivateIdentity) -> Option<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        let remote_id = self.remote_id;
        let through = self.received_through.unwrap_or(0);
        for unacked in self.unacked.values_mut() {
            if now.saturating_sub(unacked.sent_at) < RESEND_MS * u64::from(unacked.attempts) {
                continue;
            }
            if unacked.attempts >= MAX_ATTEMPTS {
                return None;
            }
            unacked.attempts += 1;
            unacked.sent_at = now;
            let mut packet = unacked.packet.clone();
            if packet.flags & SYN != 0 {
                out.push(packet.encode_signed(keys));
                continue;
            }
            packet.send_stream = remote_id;
            packet.ack_through = through;
            out.push(packet.encode());
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signed_close_without_its_sender_decodes() {
        let packet = Packet {
            send_stream: 1,
            receive_stream: 2,
            seq: 11,
            flags: CLOSE | SIGNATURE,
            signature: Some(vec![9; 40]),
            payload: b"0\r\n\r\n".to_vec(),
            ..Packet::default()
        };
        let decoded = Packet::decode(&packet.encode()).unwrap();
        assert_eq!(decoded.signature.as_deref(), Some(&[9u8; 40][..]));
        assert_eq!(decoded.payload, packet.payload);
    }

    #[test]
    fn packets_signed_by_a_transient_key_decode_and_verify() {
        let keys = PrivateIdentity::generate_destination();
        let transient = axon_addons::sign::SigningKey::generate().unwrap();
        let mut offline = OfflineSignature {
            expires: 2_000_000_000,
            key_type: SIGNING_ED25519,
            key: transient.verifying_key().0.to_vec(),
            signature: Vec::new(),
        };
        offline.signature = keys.sign(&offline.signed_part()).to_vec();
        let packet = Packet {
            receive_stream: 5,
            flags: SYN | FROM | SIGNATURE | OFFLINE_SIGNATURE | MAX_PACKET | DELAY,
            delay: Some(0),
            from: Some(keys.identity.clone()),
            max_packet: Some(1812),
            offline: Some(offline),
            signature: Some(vec![0; 64]),
            payload: b"HTTP/1.1 200 OK\r\n\r\n".to_vec(),
            ..Packet::default()
        };
        let (mut bytes, at) = packet.encode_with_signature_at();
        let (start, length) = at.unwrap();
        let signature = transient.sign(&bytes).0;
        bytes[start..start + length].copy_from_slice(&signature);
        let decoded = Packet::decode(&bytes).unwrap();
        assert_eq!(decoded.payload, packet.payload);
        assert!(decoded.verify(&keys.identity));
        let mut tampered = decoded.clone();
        tampered.payload[0] ^= 1;
        assert!(!tampered.verify(&keys.identity));
    }

    #[test]
    fn a_signed_syn_decodes_and_verifies() {
        let keys = PrivateIdentity::generate_destination();
        let mut stream = Stream::new(7, [9; 32]);
        let syn = stream.syn(&keys, b"GET / HTTP/1.1\r\n\r\n", 0);
        let packet = Packet::decode(&syn).unwrap();
        assert_eq!(packet.flags & SYN, SYN);
        assert_eq!(packet.nacks.len(), 8);
        assert_eq!(packet.payload, b"GET / HTTP/1.1\r\n\r\n");
        assert!(packet.verify(&keys.identity));
        let mut tampered = packet.clone();
        tampered.payload[0] ^= 1;
        assert!(!tampered.verify(&keys.identity));
    }

    #[test]
    fn data_arrives_in_order_and_close_ends_the_stream() {
        let mut stream = Stream::new(7, [9; 32]);
        let packet = |seq: u32, flags: u16, payload: &[u8]| Packet {
            send_stream: 7,
            receive_stream: 99,
            seq,
            ack_through: 0,
            flags,
            payload: payload.to_vec(),
            ..Packet::default()
        };
        let syn_ack = stream.arrive(packet(0, SYN, b"HTTP/1.1 200 OK\r\n"));
        assert_eq!(syn_ack.data, b"HTTP/1.1 200 OK\r\n");
        assert!(stream.is_open());
        // Packet 2 comes before packet 1.
        let early = stream.arrive(packet(2, CLOSE, b"world"));
        assert!(early.data.is_empty() && !early.closed);
        let ack = Packet::decode(&stream.ack().unwrap()).unwrap();
        assert_eq!((ack.ack_through, ack.nacks.clone()), (2, vec![1]));
        let late = stream.arrive(packet(1, 0, b"hello "));
        assert_eq!(late.data, b"hello world");
        assert!(late.closed);
    }
}
