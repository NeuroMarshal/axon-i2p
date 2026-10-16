//! Garlic messages: blocks inside ECIES-X25519 encryption, and the clove
//! block that carries an I2NP message with delivery instructions.

use axon_addons::noise::CipherState;
use bytes::Bytes;

use crate::{data::now_ms, i2np::Message};

pub const BLOCK_DATE_TIME: u8 = 0;
pub const BLOCK_NEXT_KEY: u8 = 7;
pub const BLOCK_ACK: u8 = 8;
pub const BLOCK_ACK_REQUEST: u8 = 9;
pub const BLOCK_CLOVE: u8 = 11;
pub const BLOCK_PADDING: u8 = 254;

/// One block of a garlic payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub kind: u8,
    pub data: Vec<u8>,
}

pub fn parse_blocks(mut bytes: &[u8]) -> Vec<Block> {
    let mut blocks = Vec::new();
    while bytes.len() >= 3 {
        let kind = bytes[0];
        let size = usize::from(u16::from_be_bytes([bytes[1], bytes[2]]));
        let Some(data) = bytes.get(3..3 + size) else {
            break;
        };
        blocks.push(Block {
            kind,
            data: data.to_vec(),
        });
        bytes = &bytes[3 + size..];
    }
    blocks
}

pub fn write_block(out: &mut Vec<u8>, kind: u8, data: &[u8]) {
    out.push(kind);
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

/// Where a clove's message goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloveDelivery {
    Local,
    Destination([u8; 32]),
    Router([u8; 32]),
    Tunnel([u8; 32], u32),
}

/// Reads a clove block: delivery instructions and an I2NP message with the
/// short header.
pub fn parse_clove(data: &[u8]) -> Option<(CloveDelivery, Message)> {
    let flag = *data.first()?;
    let mut at = 1;
    let mut hash = || -> Option<[u8; 32]> {
        let hash = data.get(at..at + 32)?.try_into().ok()?;
        at += 32;
        Some(hash)
    };
    let delivery = match (flag >> 5) & 3 {
        0 => CloveDelivery::Local,
        1 => CloveDelivery::Destination(hash()?),
        2 => CloveDelivery::Router(hash()?),
        _ => {
            let hash = hash()?;
            let tunnel = u32::from_be_bytes(data.get(at..at + 4)?.try_into().ok()?);
            at += 4;
            CloveDelivery::Tunnel(hash, tunnel)
        }
    };
    let header = data.get(at..at + 9)?;
    Some((
        delivery,
        Message {
            kind: header[0],
            id: u32::from_be_bytes(header[1..5].try_into().ok()?),
            expiration: u64::from(u32::from_be_bytes(header[5..9].try_into().ok()?)) * 1000,
            payload: Bytes::copy_from_slice(&data[at + 9..]),
        },
    ))
}

/// A clove block for `message`.
pub fn clove(delivery: CloveDelivery, message: &Message) -> Vec<u8> {
    let mut data = Vec::new();
    match delivery {
        CloveDelivery::Local => data.push(0),
        CloveDelivery::Destination(hash) => {
            data.push(1 << 5);
            data.extend_from_slice(&hash);
        }
        CloveDelivery::Router(hash) => {
            data.push(2 << 5);
            data.extend_from_slice(&hash);
        }
        CloveDelivery::Tunnel(hash, tunnel) => {
            data.push(3 << 5);
            data.extend_from_slice(&hash);
            data.extend_from_slice(&tunnel.to_be_bytes());
        }
    }
    data.push(message.kind);
    data.extend_from_slice(&message.id.to_be_bytes());
    data.extend_from_slice(&((message.expiration / 1000) as u32).to_be_bytes());
    data.extend_from_slice(&message.payload);
    let mut block = Vec::new();
    write_block(&mut block, BLOCK_CLOVE, &data);
    block
}

pub fn date_time_block() -> Vec<u8> {
    let mut block = Vec::new();
    write_block(
        &mut block,
        BLOCK_DATE_TIME,
        &((now_ms() / 1000) as u32).to_be_bytes(),
    );
    block
}

/// The messages of the clove blocks in a payload.
pub fn cloves(payload: &[u8]) -> Vec<(CloveDelivery, Message)> {
    parse_blocks(payload)
        .iter()
        .filter(|block| block.kind == BLOCK_CLOVE)
        .filter_map(|block| parse_clove(&block.data))
        .collect()
}

/// Opens a garlic message encrypted with a one-time key under a tag: the
/// tag, then ChaCha20-Poly1305 with nonce zero and the tag as associated
/// data.
pub fn open_with_tag(key: &[u8; 32], sealed: &[u8]) -> Option<Vec<u8>> {
    let tag = sealed.get(..8)?;
    CipherState::new(*key).decrypt(tag, sealed.get(8..)?).ok()
}

/// The garlic message payload (with its length) for blocks sealed with a
/// one-time key and tag.
pub fn seal_with_tag(key: &[u8; 32], tag: &[u8; 8], blocks: &[u8]) -> Vec<u8> {
    let sealed = CipherState::new(*key)
        .encrypt(tag, blocks)
        .expect("fresh key");
    let mut payload = ((8 + sealed.len()) as u32).to_be_bytes().to_vec();
    payload.extend_from_slice(tag);
    payload.extend_from_slice(&sealed);
    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloves_and_one_time_keys_round_trip() {
        let message = Message::new(crate::i2np::DATA, vec![4u8; 50]);
        let mut blocks = date_time_block();
        blocks.extend(clove(CloveDelivery::Router([3; 32]), &message));
        let (key, tag) = ([8u8; 32], [1u8; 8]);
        let payload = seal_with_tag(&key, &tag, &blocks);
        let opened = open_with_tag(&key, &payload[4..]).unwrap();
        let found = cloves(&opened);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, CloveDelivery::Router([3; 32]));
        assert_eq!(found[0].1.payload, message.payload);
        assert_eq!(found[0].1.kind, message.kind);
    }
}
