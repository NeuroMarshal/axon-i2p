//! Router identities and destinations: a 256-byte encryption key field, a
//! 128-byte signing key field and a certificate saying which key types the
//! fields hold. The SHA-256 of the whole structure names the router or the
//! destination.

use axon_addons::{
    ecdsa::{self, Curve},
    netdb::RecordKey,
    sign::{Signature, SigningKey, VerifyingKey},
};

use crate::data::Reader;

pub const STANDARD_LEN: usize = 387;
pub const CERTIFICATE_KEY: u8 = 5;
pub const CERTIFICATE_NULL: u8 = 0;

pub const SIGNING_DSA_SHA1: u16 = 0;
pub const SIGNING_ECDSA_P256: u16 = 1;
pub const SIGNING_ECDSA_P384: u16 = 2;
pub const SIGNING_ECDSA_P521: u16 = 3;
pub const SIGNING_ED25519: u16 = 7;
pub const SIGNING_RED25519: u16 = 11;
pub const CRYPTO_ELGAMAL: u16 = 0;
pub const CRYPTO_X25519: u16 = 4;

/// A router identity or a destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    bytes: Vec<u8>,
    signing_type: u16,
    crypto_type: u16,
    hash: [u8; 32],
}

/// Public key and signature lengths of a signing type.
pub fn signing_lengths(signing_type: u16) -> Option<(usize, usize)> {
    Some(match signing_type {
        SIGNING_DSA_SHA1 => (128, 40),
        SIGNING_ECDSA_P256 => (64, 64),
        SIGNING_ECDSA_P384 => (96, 96),
        SIGNING_ECDSA_P521 => (132, 132),
        4 => (256, 256),
        5 => (384, 384),
        6 => (512, 512),
        SIGNING_ED25519 | 8 | SIGNING_RED25519 => (32, 64),
        9 => (64, 64),
        10 => (128, 128),
        _ => return None,
    })
}

impl Identity {
    /// Reads an identity from the start of `bytes`; returns it and its length.
    pub fn parse(bytes: &[u8]) -> Option<(Self, usize)> {
        let mut reader = Reader::new(bytes);
        reader.take(256 + 128)?;
        let certificate_type = reader.u8()?;
        let certificate_len = usize::from(reader.u16()?);
        let certificate = reader.take(certificate_len)?;
        let (signing_type, crypto_type) = match certificate_type {
            CERTIFICATE_NULL => (SIGNING_DSA_SHA1, CRYPTO_ELGAMAL),
            CERTIFICATE_KEY if certificate_len >= 4 => (
                u16::from_be_bytes([certificate[0], certificate[1]]),
                u16::from_be_bytes([certificate[2], certificate[3]]),
            ),
            _ => return None,
        };
        signing_lengths(signing_type)?;
        let length = reader.position();
        let bytes = bytes[..length].to_vec();
        let hash = sha256(&bytes);
        Some((
            Self {
                bytes,
                signing_type,
                crypto_type,
                hash,
            },
            length,
        ))
    }

    /// A router identity: an X25519 encryption key and an Ed25519 signing
    /// key.
    pub fn new(encryption_key: [u8; 32], signing_key: &VerifyingKey) -> Self {
        Self::build(Some(encryption_key), signing_key)
    }

    /// A destination identity: an Ed25519 signing key and no encryption key.
    /// Destinations publish their encryption keys in their lease sets; the
    /// key field here is random and marked ElGamal, the only type Java
    /// routers send to.
    pub fn new_destination(signing_key: &VerifyingKey) -> Self {
        Self::build(None, signing_key)
    }

    /// The unused parts of the key fields repeat one random block, so the
    /// structure compresses well.
    fn build(encryption_key: Option<[u8; 32]>, signing_key: &VerifyingKey) -> Self {
        let mut padding = [0u8; 32];
        getrandom::getrandom(&mut padding).expect("system random source");
        let mut bytes = Vec::with_capacity(STANDARD_LEN + 4);
        bytes.extend_from_slice(&encryption_key.unwrap_or(padding));
        for _ in 0..7 {
            bytes.extend_from_slice(&padding);
        }
        for _ in 0..3 {
            bytes.extend_from_slice(&padding);
        }
        bytes.extend_from_slice(&signing_key.0);
        let crypto_type = if encryption_key.is_some() {
            CRYPTO_X25519
        } else {
            CRYPTO_ELGAMAL
        };
        bytes.push(CERTIFICATE_KEY);
        bytes.extend_from_slice(&4u16.to_be_bytes());
        bytes.extend_from_slice(&SIGNING_ED25519.to_be_bytes());
        bytes.extend_from_slice(&crypto_type.to_be_bytes());
        let hash = sha256(&bytes);
        Self {
            bytes,
            signing_type: SIGNING_ED25519,
            crypto_type,
            hash,
        }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub const fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    pub const fn signing_type(&self) -> u16 {
        self.signing_type
    }

    pub const fn crypto_type(&self) -> u16 {
        self.crypto_type
    }

    pub fn signature_len(&self) -> usize {
        signing_lengths(self.signing_type).map_or(0, |(_, signature)| signature)
    }

    /// The X25519 encryption key, if the identity has one.
    pub fn encryption_key(&self) -> Option<[u8; 32]> {
        (self.crypto_type == CRYPTO_X25519).then(|| self.bytes[..32].try_into().expect("fixed"))
    }

    /// The Ed25519 signing key, if the identity uses one.
    pub fn verifying_key(&self) -> Option<VerifyingKey> {
        matches!(self.signing_type, SIGNING_ED25519 | SIGNING_RED25519).then(|| {
            VerifyingKey(
                self.bytes[256 + 96..256 + 128]
                    .try_into()
                    .expect("fixed slice"),
            )
        })
    }

    /// The public signing key. Keys longer than the 128-byte field continue
    /// in the key certificate, after the two type codes.
    fn signing_key(&self) -> Option<Vec<u8>> {
        let (length, _) = signing_lengths(self.signing_type)?;
        if length <= 128 {
            return Some(self.bytes[384 - length..384].to_vec());
        }
        let mut key = self.bytes[256..384].to_vec();
        key.extend_from_slice(self.bytes.get(391..391 + length - 128)?);
        Some(key)
    }

    /// Checks a signature by this identity. Ed25519, RedDSA (which verifies
    /// the same way), ECDSA on P-256, P-384 and P-521, and the legacy
    /// DSA-SHA1 are supported; other types never verify.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let curve = match self.signing_type {
            SIGNING_DSA_SHA1 => return dsa_verify(&self.bytes[256..384], message, signature),
            SIGNING_ECDSA_P256 => Curve::P256,
            SIGNING_ECDSA_P384 => Curve::P384,
            SIGNING_ECDSA_P521 => Curve::P521,
            _ => {
                let (Some(key), Ok(signature)) =
                    (self.verifying_key(), <[u8; 64]>::try_from(signature))
                else {
                    return false;
                };
                return key.verify(message, &Signature(signature)).is_ok();
            }
        };
        self.signing_key()
            .is_some_and(|key| ecdsa::verify(curve, &key, message, signature))
    }
}

// The DSA group every I2P DSA-SHA1 key uses.
const DSA_P: &str = "9c05b2aa960d9b97b8931963c9cc9e8c3026e9b8ed92fad0a69cc886d5bf8015fcadae31a0ad18fab3f01b00a358de237655c4964afaa2b337e96ad316b9fb1cc564b5aec5b69a9ff6c3e4548707fef8503d91dd8602e867e6d35d2235c1869ce2479c3b9d5401de04e0727fb33d6511285d4cf29538d9e3b6051f5b22cc1c93";
const DSA_Q: &str = "a5dfc28fef4ca1e286744cd8eed9d29d684046b7";
const DSA_G: &str = "0c1f4d27d40093b429e962d7223824e0bbc47e7c832a39236fc683af84889581075ff9082ed32353d4374d7301cda1d23c431f4698599dda02451824ff369752593647cc3ddc197de985e43d136cdcfc6bd5409cd2f450821142a5e6f8eb1c3ab5d0484b8129fcf17bce4f7f33321c3cb3dbb14a905e7b2b3e93be4708cbcc82";

/// DSA-SHA1 verification: the signature is r and s, 20 bytes each.
fn dsa_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use num_bigint::BigUint;
    use sha1::{Digest, Sha1};
    if signature.len() != 40 {
        return false;
    }
    let number = |hex: &str| BigUint::parse_bytes(hex.as_bytes(), 16).expect("valid constant");
    let (p, q, g) = (number(DSA_P), number(DSA_Q), number(DSA_G));
    let y = BigUint::from_bytes_be(public_key);
    let r = BigUint::from_bytes_be(&signature[..20]);
    let s = BigUint::from_bytes_be(&signature[20..]);
    let zero = BigUint::from(0u8);
    if r == zero || s == zero || r >= q || s >= q {
        return false;
    }
    // s^-1 mod q by Fermat, since q is prime.
    let w = s.modpow(&(&q - 2u8), &q);
    let hash = BigUint::from_bytes_be(&Sha1::digest(message));
    let u1 = (hash * &w) % &q;
    let u2 = (&r * &w) % &q;
    let v = (g.modpow(&u1, &p) * y.modpow(&u2, &p)) % &p % &q;
    v == r
}

/// The keys of a router or a destination of ours.
#[derive(Clone)]
pub struct PrivateIdentity {
    pub identity: Identity,
    pub signing: SigningKey,
    pub encryption: axon_addons::keys::ExchangeSecret,
}

impl PrivateIdentity {
    /// Keys for a router.
    pub fn generate_router() -> Self {
        Self::generate(true)
    }

    /// Keys for a destination; the X25519 key goes in its lease sets.
    pub fn generate_destination() -> Self {
        Self::generate(false)
    }

    fn generate(router: bool) -> Self {
        let signing = SigningKey::generate().expect("system random source");
        let encryption =
            axon_addons::keys::ExchangeSecret::generate().expect("system random source");
        let identity = if router {
            Identity::new(encryption.public().0, &signing.verifying_key())
        } else {
            Identity::new_destination(&signing.verifying_key())
        };
        Self {
            identity,
            signing,
            encryption,
        }
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).0
    }
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    axon_addons::noise::sha256(&[bytes])
}

/// The id a router or destination hash has in the forwarding plane.
pub fn node_of(hash: &[u8; 32]) -> axon_core::node::NodeId {
    RecordKey(*hash).as_node()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_identities_parse_back_and_verify() {
        let ours = PrivateIdentity::generate_router();
        let (parsed, length) = Identity::parse(ours.identity.bytes()).unwrap();
        assert_eq!(length, STANDARD_LEN + 4);
        assert_eq!(parsed, ours.identity);
        assert_eq!(parsed.encryption_key(), Some(ours.encryption.public().0));
        let signature = ours.sign(b"message");
        assert!(parsed.verify(b"message", &signature));
        assert!(!parsed.verify(b"other", &signature));
    }

    fn bytes(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn ecdsa_destinations_verify() {
        let key = bytes(
            "51c317099f613d3b1c9b38d8534e725c7428ac818a070956ff2a767596ed67cc\
             b9efb0f0f16ba6e7763a3325c07ba6ecff70e66b8005faa2f733894f86d273b7",
        );
        let signature = bytes(
            "284904a42bd1dec70f1d9df2a5e2de4dd1a6f6c17d956eafafac778b23040974\
             caa3617ba92624d86af48e9e2f047651676249a4245868a707cff9f23f5d6927",
        );
        let mut raw = vec![7u8; 256 + 64];
        raw.extend_from_slice(&key);
        raw.extend_from_slice(&[CERTIFICATE_KEY, 0, 4, 0, 1, 0, 0]);
        let (identity, _) = Identity::parse(&raw).unwrap();
        assert_eq!(identity.signing_type(), SIGNING_ECDSA_P256);
        assert!(identity.verify(b"axon ecdsa vector", &signature));
        assert!(!identity.verify(b"another message", &signature));
    }

    #[test]
    fn destinations_are_marked_elgamal() {
        let ours = PrivateIdentity::generate_destination();
        let (parsed, _) = Identity::parse(ours.identity.bytes()).unwrap();
        assert_eq!(parsed.signing_type(), SIGNING_ED25519);
        assert_eq!(parsed.crypto_type(), CRYPTO_ELGAMAL);
        assert!(parsed.verify(b"message", &ours.sign(b"message")));
    }
}
