//! ECIES-X25519-AEAD-Ratchet from the side that starts a session, as an I2P
//! client does towards a service: a New Session message (Noise IK with an
//! Elligator2-encoded ephemeral key), the New Session Reply, and Existing
//! Session messages under tags from ratcheting tag sets.

use std::collections::HashMap;

use axon_addons::{
    elligator,
    keys::{ExchangePublic, ExchangeSecret},
    noise::{CipherState, SymmetricState, hkdf, hkdf2},
};

const PROTOCOL_NAME: &[u8] = b"Noise_IKelg2+hs2_25519_ChaChaPoly_SHA256";
/// Tags generated ahead on each receiving tag set.
const TAGS_AHEAD: u32 = 24;

/// One direction of a tag set: session tags and message keys, each a chain
/// of HKDFs.
pub struct TagSet {
    tag_chain: [u8; 32],
    tag_constant: [u8; 32],
    next_tag: u32,
    key_chain_start: [u8; 32],
    key_chain: Option<[u8; 32]>,
    next_key: u32,
    keys: HashMap<u32, [u8; 32]>,
}

impl TagSet {
    /// DH_INITIALIZE(rootKey, k) followed by the session tag ratchet.
    pub fn new(root_key: &[u8; 32], k: &[u8; 32]) -> Self {
        let (_next_root, key_data) = hkdf(root_key, k, b"KDFDHRatchetStep");
        let (tag_chain, key_chain_start) = hkdf(&key_data, &[], b"TagAndKeyGenKeys");
        let (tag_chain, tag_constant) = hkdf(&tag_chain, &[], b"STInitialization");
        Self {
            tag_chain,
            tag_constant,
            next_tag: 0,
            key_chain_start,
            key_chain: None,
            next_key: 0,
            keys: HashMap::new(),
        }
    }

    /// The next tag and its index.
    pub fn next_tag(&mut self) -> (u32, [u8; 8]) {
        let index = self.next_tag;
        self.next_tag += 1;
        let (chain, data) = hkdf(&self.tag_chain, &self.tag_constant, b"SessionTagKeyGen");
        self.tag_chain = chain;
        (index, data[..8].try_into().expect("fixed slice"))
    }

    /// The message key for tag `index`.
    pub fn key(&mut self, index: u32) -> Option<[u8; 32]> {
        if let Some(key) = self.keys.remove(&index) {
            return Some(key);
        }
        if index < self.next_key {
            return None;
        }
        let mut key = [0u8; 32];
        while self.next_key <= index {
            let input = self.key_chain.unwrap_or(self.key_chain_start);
            let (chain, derived) = hkdf(&input, &[], b"SymmetricRatchet");
            self.key_chain = Some(chain);
            if self.next_key < index {
                self.keys.insert(self.next_key, derived);
            } else {
                key = derived;
            }
            self.next_key += 1;
        }
        Some(key)
    }
}

/// A tag set we receive on, with tags generated ahead.
pub struct ReceiveTags {
    set: TagSet,
    tags: HashMap<[u8; 8], u32>,
}

impl ReceiveTags {
    fn new(set: TagSet) -> Self {
        let mut tags = Self {
            set,
            tags: HashMap::new(),
        };
        tags.extend(TAGS_AHEAD);
        tags
    }

    fn extend(&mut self, count: u32) {
        for _ in 0..count {
            let (index, tag) = self.set.next_tag();
            self.tags.insert(tag, index);
        }
    }

    /// Tags currently accepted.
    pub fn tags(&self) -> impl Iterator<Item = &[u8; 8]> {
        self.tags.keys()
    }

    /// Takes a tag: returns its message key and keeps tags ahead.
    fn take(&mut self, tag: &[u8; 8]) -> Option<(u32, [u8; 32])> {
        let index = self.tags.remove(tag)?;
        self.extend(1);
        Some((index, self.set.key(index)?))
    }
}

struct Pending {
    symmetric: SymmetricState,
    ephemeral: ExchangeSecret,
    reply_tags: ReceiveTags,
}

/// A session we started.
pub struct OutboundSession {
    pending: Option<Pending>,
    send: Option<TagSet>,
    receive: Option<ReceiveTags>,
}

fn encrypt_with(key: &[u8; 32], nonce: u64, ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut cipher = CipherState::new(*key);
    cipher.set_nonce(nonce);
    cipher.encrypt(ad, plaintext).expect("nonce is fresh")
}

fn decrypt_with(key: &[u8; 32], nonce: u64, ad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
    let mut cipher = CipherState::new(*key);
    cipher.set_nonce(nonce);
    cipher.decrypt(ad, sealed).ok()
}

impl OutboundSession {
    /// Starts a session to `remote` (its X25519 key) from `ours` with a
    /// first payload. Returns the session and the New Session message.
    pub fn start(ours: &ExchangeSecret, remote: &[u8; 32], payload: &[u8]) -> (Self, Vec<u8>) {
        // Only about half of all keys have an Elligator2 encoding.
        let (ephemeral, encoded) = loop {
            let ephemeral = ExchangeSecret::generate().expect("system random source");
            let mut random = [0u8; 1];
            getrandom::getrandom(&mut random).expect("system random source");
            if let Some(encoded) = elligator::encode(&ephemeral.public().0, random[0]) {
                break (ephemeral, encoded);
            }
        };
        let remote_key = ExchangePublic(*remote);
        let mut symmetric = SymmetricState::new(PROTOCOL_NAME);
        symmetric.mix_hash(&[]);
        symmetric.mix_hash(remote);
        symmetric.mix_hash(&ephemeral.public().0);
        symmetric
            .mix_dh(&ephemeral, &remote_key)
            .expect("valid destination key");
        let static_section = symmetric
            .encrypt_and_hash(&ours.public().0)
            .expect("fresh key");
        symmetric
            .mix_dh(ours, &remote_key)
            .expect("valid destination key");
        let sealed_payload = symmetric.encrypt_and_hash(payload).expect("fresh key");
        let mut message = encoded.to_vec();
        message.extend_from_slice(&static_section);
        message.extend_from_slice(&sealed_payload);
        let (tag_key, _) = hkdf(symmetric.chaining_key(), &[], b"SessionReplyTags");
        let reply_tags = ReceiveTags::new(TagSet::new(symmetric.chaining_key(), &tag_key));
        (
            Self {
                pending: Some(Pending {
                    symmetric,
                    ephemeral,
                    reply_tags,
                }),
                send: None,
                receive: None,
            },
            message,
        )
    }

    pub fn is_established(&self) -> bool {
        self.send.is_some()
    }

    /// Every tag a message for this session may arrive under.
    pub fn tags(&self) -> Vec<[u8; 8]> {
        let mut tags = Vec::new();
        if let Some(pending) = &self.pending {
            tags.extend(pending.reply_tags.tags().copied());
        }
        if let Some(receive) = &self.receive {
            tags.extend(receive.tags().copied());
        }
        tags
    }

    /// Opens a message for this session (tag first) and returns its payload.
    pub fn open(&mut self, ours: &ExchangeSecret, message: &[u8]) -> Option<Vec<u8>> {
        let tag: [u8; 8] = message.get(..8)?.try_into().ok()?;
        if let Some(receive) = &mut self.receive
            && let Some((index, key)) = receive.take(&tag)
        {
            return decrypt_with(&key, u64::from(index), &tag, &message[8..]);
        }
        let pending = self.pending.as_mut()?;
        pending.reply_tags.take(&tag)?;
        self.open_reply(ours, &tag, &message[8..])
    }

    /// The New Session Reply: Bob's ephemeral key, an empty sealed section
    /// that proves the handshake, and the payload.
    fn open_reply(&mut self, ours: &ExchangeSecret, tag: &[u8; 8], rest: &[u8]) -> Option<Vec<u8>> {
        let pending = self.pending.as_ref()?;
        let mut symmetric = pending.symmetric.clone();
        let encoded: [u8; 32] = rest.get(..32)?.try_into().ok()?;
        let bob = ExchangePublic(elligator::decode(&encoded)?);
        symmetric.mix_hash(tag);
        symmetric.mix_hash(&bob.0);
        symmetric.mix_dh(&pending.ephemeral, &bob).ok()?;
        symmetric.mix_dh(ours, &bob).ok()?;
        symmetric.decrypt_and_hash(rest.get(32..48)?).ok()?;
        let (key_ab, key_ba) = hkdf2(symmetric.chaining_key(), &[]);
        if self.send.is_none() {
            self.send = Some(TagSet::new(symmetric.chaining_key(), &key_ab));
            self.receive = Some(ReceiveTags::new(TagSet::new(
                symmetric.chaining_key(),
                &key_ba,
            )));
        }
        let (payload_key, _) = hkdf(&key_ba, &[], b"AttachPayloadKDF");
        decrypt_with(&payload_key, 0, symmetric.hash(), rest.get(48..)?)
    }

    /// An Existing Session message, once the session is established.
    pub fn seal(&mut self, payload: &[u8]) -> Option<Vec<u8>> {
        let send = self.send.as_mut()?;
        let (index, tag) = send.next_tag();
        let key = send.key(index)?;
        let mut message = tag.to_vec();
        message.extend_from_slice(&encrypt_with(&key, u64::from(index), &tag, payload));
        Some(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Plays Bob: opens the New Session message, answers with a New Session
    /// Reply, then exchanges existing-session messages.
    #[test]
    fn a_session_is_set_up_and_carries_messages_both_ways() {
        let alice = ExchangeSecret::generate().unwrap();
        let bob = ExchangeSecret::generate().unwrap();
        let (mut session, message) = OutboundSession::start(&alice, &bob.public().0, b"hello bob");

        // Bob's side of the New Session message.
        let alice_ephemeral =
            ExchangePublic(elligator::decode(&message[..32].try_into().unwrap()).unwrap());
        let mut symmetric = SymmetricState::new(PROTOCOL_NAME);
        symmetric.mix_hash(&[]);
        symmetric.mix_hash(&bob.public().0);
        symmetric.mix_hash(&alice_ephemeral.0);
        symmetric.mix_dh(&bob, &alice_ephemeral).unwrap();
        let alice_static = symmetric.decrypt_and_hash(&message[32..80]).unwrap();
        assert_eq!(alice_static, alice.public().0);
        symmetric
            .mix_dh(&bob, &ExchangePublic(alice_static.try_into().unwrap()))
            .unwrap();
        assert_eq!(
            symmetric.decrypt_and_hash(&message[80..]).unwrap(),
            b"hello bob"
        );

        // Bob's New Session Reply.
        let (tag_key, _) = hkdf(symmetric.chaining_key(), &[], b"SessionReplyTags");
        let (_, tag) = TagSet::new(symmetric.chaining_key(), &tag_key).next_tag();
        let (bob_ephemeral, encoded) = loop {
            let key = ExchangeSecret::generate().unwrap();
            if let Some(encoded) = elligator::encode(&key.public().0, 0) {
                break (key, encoded);
            }
        };
        symmetric.mix_hash(&tag);
        symmetric.mix_hash(&bob_ephemeral.public().0);
        symmetric.mix_dh(&bob_ephemeral, &alice_ephemeral).unwrap();
        symmetric
            .mix_dh(&bob_ephemeral, &ExchangePublic(alice.public().0))
            .unwrap();
        let proof = symmetric.encrypt_and_hash(&[]).unwrap();
        let (key_ab, key_ba) = hkdf2(symmetric.chaining_key(), &[]);
        let (payload_key, _) = hkdf(&key_ba, &[], b"AttachPayloadKDF");
        let mut reply = tag.to_vec();
        reply.extend_from_slice(&encoded);
        reply.extend_from_slice(&proof);
        reply.extend_from_slice(&encrypt_with(
            &payload_key,
            0,
            symmetric.hash(),
            b"hello alice",
        ));
        assert_eq!(session.open(&alice, &reply).unwrap(), b"hello alice");
        assert!(session.is_established());

        // Existing session, Alice to Bob and back.
        let mut bob_receive = TagSet::new(symmetric.chaining_key(), &key_ab);
        let sealed = session.seal(b"GET /").unwrap();
        let (index, expected_tag) = bob_receive.next_tag();
        assert_eq!(sealed[..8], expected_tag);
        let key = bob_receive.key(index).unwrap();
        assert_eq!(
            decrypt_with(&key, u64::from(index), &expected_tag, &sealed[8..]).unwrap(),
            b"GET /"
        );
        let mut bob_send = TagSet::new(symmetric.chaining_key(), &key_ba);
        let (index, tag) = bob_send.next_tag();
        let key = bob_send.key(index).unwrap();
        let mut message = tag.to_vec();
        message.extend_from_slice(&encrypt_with(&key, u64::from(index), &tag, b"200 OK"));
        assert_eq!(session.open(&alice, &message).unwrap(), b"200 OK");
    }
}
