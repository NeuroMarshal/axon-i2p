//! NTCP2, I2P's TCP link protocol, as a wire protocol for an Axon edge.
//!
//! The handshake is Noise XK with the initiator's ephemeral key hidden by
//! AES-256-CBC under the responder's router hash; the data phase sends frames
//! of blocks, each encrypted with ChaCha20-Poly1305, behind a length that
//! SipHash masks. Envelopes are I2NP messages with the standard 16-byte
//! header; on the wire NTCP2 uses a short 9-byte one.
//!
//! This side always dials: the router has no published address.

use std::sync::Arc;

use axon_addons::{
    cipher::{aes256_cbc_decrypt, aes256_cbc_encrypt, siphash24},
    keys::{ExchangePublic, ExchangeSecret},
    noise::{CipherState, SymmetricState, hkdf2, hmac_sha256},
    wire::{WireOutput, WireProtocol},
};
use axon_core::{node::AuthenticatedIdentity, time::Instant};
use bytes::Bytes;

use crate::{data::now_ms, i2np::Message, identity::node_of, router_info::Ntcp2Address};

const PROTOCOL_NAME: &[u8] = b"Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256";
const NETWORK_ID: u8 = 2;
const MAXIMUM_FRAME: usize = 65535;

const BLOCK_DATE_TIME: u8 = 0;
const BLOCK_ROUTER_INFO: u8 = 2;
const BLOCK_I2NP: u8 = 3;
const BLOCK_TERMINATION: u8 = 4;
const BLOCK_PADDING: u8 = 254;

/// What this router needs for every NTCP2 link it opens.
pub struct LocalRouter {
    /// The NTCP2 static key published in the router info.
    pub static_key: ExchangeSecret,
    /// The signed router info sent in the third handshake message.
    pub router_info: Vec<u8>,
}

/// The peer to dial.
#[derive(Debug, Clone, Copy)]
pub struct Remote {
    pub hash: [u8; 32],
    pub address: Ntcp2Address,
}

/// One direction of the data phase: frame key and length mask.
struct Direction {
    cipher: CipherState,
    sip_key: [u8; 16],
    sip_iv: [u8; 8],
}

impl Direction {
    fn new(key: [u8; 32], sip: [u8; 32]) -> Self {
        Self {
            cipher: CipherState::new(key),
            sip_key: sip[..16].try_into().expect("fixed slice"),
            sip_iv: sip[16..24].try_into().expect("fixed slice"),
        }
    }

    /// The next length mask: the IV is replaced by its own SipHash.
    fn next_mask(&mut self) -> u16 {
        self.sip_iv = siphash24(&self.sip_key, &self.sip_iv).to_le_bytes();
        u16::from_le_bytes([self.sip_iv[0], self.sip_iv[1]])
    }
}

enum State {
    /// Waiting for SessionCreated.
    Requested {
        symmetric: SymmetricState,
        ephemeral: ExchangeSecret,
        next_iv: [u8; 16],
        m3p2: Vec<u8>,
    },
    /// SessionCreated's options were read; waiting for its padding.
    Padding {
        symmetric: SymmetricState,
        remote_ephemeral: ExchangePublic,
        padding: usize,
        m3p2: Vec<u8>,
    },
    Established {
        send: Direction,
        receive: Direction,
        /// Length of the frame being read, once its length field was read.
        frame: Option<usize>,
    },
    Closed,
}

/// The initiator side of an NTCP2 link.
pub struct Ntcp2 {
    local: Arc<LocalRouter>,
    remote: Remote,
    state: State,
    buffer: Vec<u8>,
    queued: Vec<Bytes>,
}

impl Ntcp2 {
    pub fn new(local: Arc<LocalRouter>, remote: Remote) -> Self {
        Self {
            local,
            remote,
            state: State::Closed,
            buffer: Vec::new(),
            queued: Vec::new(),
        }
    }

    pub fn is_established(&self) -> bool {
        matches!(self.state, State::Established { .. })
    }

    fn router_info_block(&self) -> Vec<u8> {
        let mut block = vec![BLOCK_ROUTER_INFO];
        block.extend_from_slice(&((self.local.router_info.len() + 1) as u16).to_be_bytes());
        block.push(0); // flags: not a flood request
        block.extend_from_slice(&self.local.router_info);
        block
    }

    /// Encrypts blocks into a frame.
    fn frame(send: &mut Direction, blocks: &[u8]) -> Result<Vec<u8>, String> {
        let sealed = send
            .cipher
            .encrypt(&[], blocks)
            .map_err(|e| e.to_string())?;
        let mask = send.next_mask();
        let mut frame = ((sealed.len() as u16) ^ mask).to_be_bytes().to_vec();
        frame.extend_from_slice(&sealed);
        Ok(frame)
    }

    /// Frames for envelopes, packing as many I2NP blocks per frame as fit.
    fn frames(send: &mut Direction, envelopes: &[Bytes]) -> Result<Vec<Bytes>, String> {
        let mut out = Vec::new();
        let mut blocks = Vec::new();
        for envelope in envelopes {
            let Some(message) = Message::decode(envelope) else {
                continue;
            };
            let block = block_for(&message);
            if !blocks.is_empty() && blocks.len() + block.len() + 16 > MAXIMUM_FRAME {
                out.push(Bytes::from(Self::frame(send, &blocks)?));
                blocks.clear();
            }
            if block.len() + 16 > MAXIMUM_FRAME {
                return Err("I2NP message is too large for a frame".to_owned());
            }
            blocks.extend_from_slice(&block);
        }
        if !blocks.is_empty() {
            out.push(Bytes::from(Self::frame(send, &blocks)?));
        }
        Ok(out)
    }

    fn handle(&mut self, output: &mut WireOutput) -> Result<(), String> {
        loop {
            match std::mem::replace(&mut self.state, State::Closed) {
                State::Requested {
                    mut symmetric,
                    ephemeral,
                    next_iv,
                    m3p2,
                } => {
                    if self.buffer.len() < 64 {
                        self.state = State::Requested {
                            symmetric,
                            ephemeral,
                            next_iv,
                            m3p2,
                        };
                        return Ok(());
                    }
                    let message: Vec<u8> = self.buffer.drain(..64).collect();
                    let mut y: [u8; 32] = message[..32].try_into().expect("fixed slice");
                    aes256_cbc_decrypt(&self.remote.hash, &next_iv, &mut y);
                    let remote_ephemeral = ExchangePublic(y);
                    symmetric.mix_hash(&y);
                    symmetric
                        .mix_dh(&ephemeral, &remote_ephemeral)
                        .map_err(|e| e.to_string())?;
                    let options = symmetric
                        .decrypt_and_hash(&message[32..64])
                        .map_err(|_| "SessionCreated does not decrypt".to_owned())?;
                    let padding = usize::from(u16::from_be_bytes([options[2], options[3]]));
                    let their_time = u64::from(u32::from_be_bytes(
                        options[8..12].try_into().expect("fixed slice"),
                    ));
                    if their_time.abs_diff(now_ms() / 1000) > 120 {
                        return Err("clock skew with the peer".to_owned());
                    }
                    self.state = State::Padding {
                        symmetric,
                        remote_ephemeral,
                        padding,
                        m3p2,
                    };
                }
                State::Padding {
                    mut symmetric,
                    remote_ephemeral,
                    padding,
                    m3p2,
                } => {
                    if self.buffer.len() < padding {
                        self.state = State::Padding {
                            symmetric,
                            remote_ephemeral,
                            padding,
                            m3p2,
                        };
                        return Ok(());
                    }
                    let padding_bytes: Vec<u8> = self.buffer.drain(..padding).collect();
                    if padding > 0 {
                        symmetric.mix_hash(&padding_bytes);
                    }
                    // SessionConfirmed: our static key, then our router info.
                    let part1 = symmetric
                        .encrypt_and_hash(&self.local.static_key.public().0)
                        .map_err(|e| e.to_string())?;
                    symmetric
                        .mix_dh(&self.local.static_key, &remote_ephemeral)
                        .map_err(|e| e.to_string())?;
                    let part2 = symmetric
                        .encrypt_and_hash(&m3p2)
                        .map_err(|e| e.to_string())?;
                    let mut confirmed = part1;
                    confirmed.extend_from_slice(&part2);
                    output.transmit.push(Bytes::from(confirmed));

                    let (send, receive) = data_phase_keys(&symmetric);
                    let mut send = send;
                    let queued = std::mem::take(&mut self.queued);
                    output.transmit.extend(Self::frames(&mut send, &queued)?);
                    output.authenticated = Some(AuthenticatedIdentity {
                        node: node_of(&self.remote.hash),
                        principal: Bytes::copy_from_slice(&self.remote.hash),
                        properties: 0,
                    });
                    self.state = State::Established {
                        send,
                        receive,
                        frame: None,
                    };
                }
                State::Established {
                    send,
                    mut receive,
                    frame,
                } => {
                    let length = match frame {
                        Some(length) => length,
                        None => {
                            if self.buffer.len() < 2 {
                                self.state = State::Established {
                                    send,
                                    receive,
                                    frame: None,
                                };
                                return Ok(());
                            }
                            let field = u16::from_be_bytes([self.buffer[0], self.buffer[1]]);
                            self.buffer.drain(..2);
                            let length = usize::from(field ^ receive.next_mask());
                            if length < 16 {
                                return Err("frame is too short".to_owned());
                            }
                            length
                        }
                    };
                    if self.buffer.len() < length {
                        self.state = State::Established {
                            send,
                            receive,
                            frame: Some(length),
                        };
                        return Ok(());
                    }
                    let sealed: Vec<u8> = self.buffer.drain(..length).collect();
                    let blocks = receive
                        .cipher
                        .decrypt(&[], &sealed)
                        .map_err(|_| "frame does not decrypt".to_owned())?;
                    let terminated = read_blocks(&blocks, output)?;
                    self.state = State::Established {
                        send,
                        receive,
                        frame: None,
                    };
                    if terminated {
                        self.state = State::Closed;
                        return Err("peer terminated the link".to_owned());
                    }
                }
                State::Closed => return Err("link is closed".to_owned()),
            }
        }
    }
}

/// k_ab, k_ba and the SipHash keys of the data phase.
fn data_phase_keys(symmetric: &SymmetricState) -> (Direction, Direction) {
    let chaining_key = symmetric.chaining_key();
    let (key_ab, key_ba) = hkdf2(chaining_key, &[]);
    let ask_master = hmac_sha256(&hmac_sha256(chaining_key, &[&[]]), &[b"ask", &[1]]);
    let sip_master = hmac_sha256(
        &hmac_sha256(&ask_master, &[symmetric.hash(), b"siphash"]),
        &[&[1]],
    );
    let (sip_ab, sip_ba) = hkdf2(&sip_master, &[]);
    (
        Direction::new(key_ab, sip_ab),
        Direction::new(key_ba, sip_ba),
    )
}

/// An I2NP block with the short header NTCP2 uses.
fn block_for(message: &Message) -> Vec<u8> {
    let mut block = vec![BLOCK_I2NP];
    block.extend_from_slice(&((9 + message.payload.len()) as u16).to_be_bytes());
    block.push(message.kind);
    block.extend_from_slice(&message.id.to_be_bytes());
    block.extend_from_slice(&((message.expiration / 1000) as u32).to_be_bytes());
    block.extend_from_slice(&message.payload);
    block
}

/// Reads the blocks of a frame; I2NP messages become envelopes. Returns
/// whether the peer terminated the link.
fn read_blocks(mut blocks: &[u8], output: &mut WireOutput) -> Result<bool, String> {
    while blocks.len() >= 3 {
        let kind = blocks[0];
        let size = usize::from(u16::from_be_bytes([blocks[1], blocks[2]]));
        let body = blocks.get(3..3 + size).ok_or("block overruns its frame")?;
        blocks = &blocks[3 + size..];
        match kind {
            BLOCK_I2NP if body.len() >= 9 => {
                let message = Message {
                    kind: body[0],
                    id: u32::from_be_bytes(body[1..5].try_into().expect("fixed slice")),
                    expiration: u64::from(u32::from_be_bytes(
                        body[5..9].try_into().expect("fixed slice"),
                    )) * 1000,
                    payload: Bytes::copy_from_slice(&body[9..]),
                };
                output.envelopes.push(message.encode());
            }
            BLOCK_TERMINATION => return Ok(true),
            BLOCK_DATE_TIME | BLOCK_ROUTER_INFO | BLOCK_PADDING => {}
            _ => {}
        }
    }
    Ok(false)
}

impl WireProtocol for Ntcp2 {
    fn start(&mut self, _now: Instant) -> Result<WireOutput, String> {
        let ephemeral = ExchangeSecret::generate().map_err(|e| e.to_string())?;
        let mut symmetric = SymmetricState::new(PROTOCOL_NAME);
        symmetric.mix_hash(&[]);
        symmetric.mix_hash(&self.remote.address.static_key);

        // X, hidden by AES-CBC under Bob's router hash and published IV.
        let mut x = ephemeral.public().0;
        let next_iv = aes256_cbc_encrypt(&self.remote.hash, &self.remote.address.iv, &mut x);
        symmetric.mix_hash(&ephemeral.public().0);
        symmetric
            .mix_dh(&ephemeral, &ExchangePublic(self.remote.address.static_key))
            .map_err(|e| e.to_string())?;

        let m3p2 = self.router_info_block();
        let mut random = [0u8; 2];
        getrandom::getrandom(&mut random).map_err(|e| e.to_string())?;
        let padding = usize::from(u16::from_le_bytes(random) % 64);
        let mut options = [0u8; 16];
        options[0] = NETWORK_ID;
        options[1] = 2;
        options[2..4].copy_from_slice(&(padding as u16).to_be_bytes());
        options[4..6].copy_from_slice(&((m3p2.len() + 16) as u16).to_be_bytes());
        options[8..12].copy_from_slice(&(((now_ms() + 500) / 1000) as u32).to_be_bytes());
        let options = symmetric
            .encrypt_and_hash(&options)
            .map_err(|e| e.to_string())?;
        let mut padding_bytes = vec![0u8; padding];
        getrandom::getrandom(&mut padding_bytes).map_err(|e| e.to_string())?;
        if padding > 0 {
            symmetric.mix_hash(&padding_bytes);
        }
        let mut request = x.to_vec();
        request.extend_from_slice(&options);
        request.extend_from_slice(&padding_bytes);
        self.state = State::Requested {
            symmetric,
            ephemeral,
            next_iv,
            m3p2,
        };
        Ok(WireOutput::transmit(Bytes::from(request)))
    }

    fn send(&mut self, envelope: Bytes, _now: Instant) -> Result<WireOutput, String> {
        match &mut self.state {
            State::Established { send, .. } => Ok(WireOutput {
                transmit: Self::frames(send, &[envelope])?,
                ..WireOutput::default()
            }),
            State::Closed => Err("link is closed".to_owned()),
            _ => {
                self.queued.push(envelope);
                Ok(WireOutput::default())
            }
        }
    }

    fn receive(&mut self, unit: Bytes, _now: Instant) -> Result<WireOutput, String> {
        self.buffer.extend_from_slice(&unit);
        let mut output = WireOutput::default();
        self.handle(&mut output)?;
        Ok(output)
    }
}
