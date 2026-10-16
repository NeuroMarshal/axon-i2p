//! I2NP, the messages routers exchange: the standard 16-byte header and the
//! payloads of the network database messages.

use bytes::Bytes;

use crate::{
    data::{Reader, now_ms},
    identity::sha256,
};

pub const DATABASE_STORE: u8 = 1;
pub const DATABASE_LOOKUP: u8 = 2;
pub const DATABASE_SEARCH_REPLY: u8 = 3;
pub const DELIVERY_STATUS: u8 = 10;
pub const GARLIC: u8 = 11;
pub const TUNNEL_DATA: u8 = 18;
pub const TUNNEL_GATEWAY: u8 = 19;
pub const DATA: u8 = 20;
pub const SHORT_TUNNEL_BUILD: u8 = 25;
pub const SHORT_TUNNEL_BUILD_REPLY: u8 = 26;

pub const HEADER_LEN: usize = 16;

/// An I2NP message: type, id, expiration in milliseconds and payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub kind: u8,
    pub id: u32,
    pub expiration: u64,
    pub payload: Bytes,
}

impl Message {
    /// A message with a random id that expires in a minute.
    pub fn new(kind: u8, payload: impl Into<Bytes>) -> Self {
        Self {
            kind,
            id: random_u32(),
            expiration: now_ms() + 60_000,
            payload: payload.into(),
        }
    }

    /// The message with the standard header.
    pub fn encode(&self) -> Bytes {
        let mut bytes = Vec::with_capacity(HEADER_LEN + self.payload.len());
        bytes.push(self.kind);
        bytes.extend_from_slice(&self.id.to_be_bytes());
        bytes.extend_from_slice(&self.expiration.to_be_bytes());
        bytes.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        bytes.push(sha256(&self.payload)[0]);
        bytes.extend_from_slice(&self.payload);
        Bytes::from(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut reader = Reader::new(bytes);
        let kind = reader.u8()?;
        let id = reader.u32()?;
        let expiration = reader.u64()?;
        let size = usize::from(reader.u16()?);
        reader.u8()?; // checksum, not checked as I2P routers do not either
        let payload = reader.take(size)?;
        Some(Self {
            kind,
            id,
            expiration,
            payload: Bytes::copy_from_slice(payload),
        })
    }

    /// Reads a message from the start of `bytes` and returns its length too.
    pub fn decode_prefix(bytes: &[u8]) -> Option<(Self, usize)> {
        let size = usize::from(u16::from_be_bytes(bytes.get(13..15)?.try_into().ok()?));
        let total = HEADER_LEN + size;
        Some((Self::decode(bytes.get(..total)?)?, total))
    }
}

pub fn random_u32() -> u32 {
    let mut bytes = [0u8; 4];
    getrandom::getrandom(&mut bytes).expect("system random source");
    u32::from_be_bytes(bytes)
}

pub const STORE_ROUTER_INFO: u8 = 0;
pub const STORE_LEASE_SET: u8 = 1;
pub const STORE_LEASE_SET2: u8 = 3;

/// DatabaseStore: a router info (gzip-compressed on the wire) or a lease set
/// under its key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseStore {
    pub key: [u8; 32],
    pub kind: u8,
    pub reply_token: u32,
    /// The record: an uncompressed router info or a lease set.
    pub data: Vec<u8>,
}

impl DatabaseStore {
    pub fn decode(payload: &[u8]) -> Option<Self> {
        let mut reader = Reader::new(payload);
        let key = reader.array()?;
        let kind = reader.u8()?;
        let reply_token = reader.u32()?;
        if reply_token != 0 {
            reader.take(4 + 32)?;
        }
        let data = if kind == STORE_ROUTER_INFO {
            let length = usize::from(reader.u16()?);
            gunzip(reader.take(length)?)?
        } else {
            reader.remaining().to_vec()
        };
        Some(Self {
            key,
            kind,
            reply_token,
            data,
        })
    }

    /// Payload for a lease set or a router info, without a reply token.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.key.to_vec();
        out.push(self.kind);
        out.extend_from_slice(&0u32.to_be_bytes());
        if self.kind == STORE_ROUTER_INFO {
            let compressed = gzip(&self.data);
            out.extend_from_slice(&(compressed.len() as u16).to_be_bytes());
            out.extend_from_slice(&compressed);
        } else {
            out.extend_from_slice(&self.data);
        }
        out
    }
}

pub const LOOKUP_DELIVERY: u8 = 0x01;
pub const LOOKUP_ECIES: u8 = 0x10;
pub const LOOKUP_LEASE_SET: u8 = 0x04;
pub const LOOKUP_ROUTER_INFO: u8 = 0x08;
pub const LOOKUP_EXPLORATORY: u8 = 0x0c;

/// DatabaseLookup. With `reply_tunnel` the answer goes to that tunnel at the
/// `from` gateway; otherwise straight to the router `from`. With
/// `reply_key` it comes back encrypted for that key and tag.
#[derive(Debug, Clone)]
pub struct DatabaseLookup {
    pub key: [u8; 32],
    pub from: [u8; 32],
    pub lookup: u8,
    pub reply_tunnel: Option<u32>,
    pub exclude: Vec<[u8; 32]>,
    pub reply_key: Option<([u8; 32], [u8; 8])>,
}

impl DatabaseLookup {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.key.to_vec();
        out.extend_from_slice(&self.from);
        let mut flags = self.lookup;
        if self.reply_tunnel.is_some() {
            flags |= LOOKUP_DELIVERY;
        }
        if self.reply_key.is_some() {
            flags |= LOOKUP_ECIES;
        }
        out.push(flags);
        if let Some(tunnel) = self.reply_tunnel {
            out.extend_from_slice(&tunnel.to_be_bytes());
        }
        out.extend_from_slice(&(self.exclude.len() as u16).to_be_bytes());
        for peer in &self.exclude {
            out.extend_from_slice(peer);
        }
        if let Some((key, tag)) = &self.reply_key {
            out.extend_from_slice(key);
            out.push(1);
            out.extend_from_slice(tag);
        }
        out
    }
}

/// DatabaseSearchReply: floodfills closer to the key than the one asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchReply {
    pub key: [u8; 32],
    pub peers: Vec<[u8; 32]>,
    pub from: [u8; 32],
}

impl SearchReply {
    pub fn decode(payload: &[u8]) -> Option<Self> {
        let mut reader = Reader::new(payload);
        let key = reader.array()?;
        let count = reader.u8()?;
        let peers = (0..count)
            .map(|_| reader.array())
            .collect::<Option<Vec<_>>>()?;
        let from = reader.array()?;
        Some(Self { key, peers, from })
    }
}

/// Decompresses gzip data.
pub fn gunzip(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 18 || data[0] != 0x1f || data[1] != 0x8b || data[2] != 8 {
        return None;
    }
    let flags = data[3];
    let mut at = 10;
    if flags & 0x04 != 0 {
        let extra = usize::from(u16::from_le_bytes([*data.get(at)?, *data.get(at + 1)?]));
        at += 2 + extra;
    }
    for flag in [0x08, 0x10] {
        if flags & flag != 0 {
            at += data.get(at..)?.iter().position(|&byte| byte == 0)? + 1;
        }
    }
    if flags & 0x02 != 0 {
        at += 2;
    }
    let deflated = data.get(at..data.len().checked_sub(8)?)?;
    miniz_oxide::inflate::decompress_to_vec_with_limit(deflated, 1 << 20).ok()
}

/// Compresses with gzip.
pub fn gzip(data: &[u8]) -> Vec<u8> {
    gzip_with_header(data, [0; 4], 0xff)
}

/// gzip with chosen header fields; I2CP payloads keep their ports in the
/// modification time and their protocol in the operating system byte.
pub fn gzip_with_header(data: &[u8], mtime: [u8; 4], os: u8) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 8, 0];
    out.extend_from_slice(&mtime);
    out.extend_from_slice(&[2, os]);
    out.extend_from_slice(&miniz_oxide::deflate::compress_to_vec(data, 6));
    out.extend_from_slice(&crc32(data).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_round_trip() {
        let message = Message::new(DATA, vec![1, 2, 3]);
        let encoded = message.encode();
        assert_eq!(Message::decode(&encoded), Some(message.clone()));
        let mut two = encoded.to_vec();
        two.extend_from_slice(&encoded);
        assert_eq!(Message::decode_prefix(&two), Some((message, encoded.len())));
    }

    #[test]
    fn gzip_round_trips_and_crc_is_standard() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        let data = b"router info bytes ".repeat(20);
        assert_eq!(gunzip(&gzip(&data)), Some(data));
    }
}
