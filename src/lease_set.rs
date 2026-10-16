//! LeaseSet2: how to reach a destination. It names the destination, the keys
//! to encrypt garlic messages to it, and its inbound tunnels (leases), signed
//! by the destination or by a transient key the destination signed.

use crate::{
    data::{Reader, write_mapping},
    i2np::STORE_LEASE_SET2,
    identity::{CRYPTO_X25519, Identity, PrivateIdentity, SIGNING_ED25519, SIGNING_RED25519},
};

const FLAG_OFFLINE_KEYS: u16 = 1;
const FLAG_UNPUBLISHED: u16 = 2;

/// One inbound tunnel of a destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lease {
    pub gateway: [u8; 32],
    pub tunnel: u32,
    /// Seconds since the Unix epoch.
    pub end: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseSet {
    pub destination: Identity,
    /// Seconds since the Unix epoch.
    pub published: u32,
    pub expires: u32,
    /// The X25519 key for ECIES garlic, if the destination has one.
    pub encryption_key: Option<[u8; 32]>,
    pub leases: Vec<Lease>,
    pub raw: Vec<u8>,
}

impl LeaseSet {
    /// Parses a standard LeaseSet2 and checks its signature.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        Self::parse_checked(bytes).ok()
    }

    /// Like [`LeaseSet::parse`], with the reason when it fails.
    pub fn parse_checked(bytes: &[u8]) -> Result<Self, String> {
        let truncated = || "truncated".to_owned();
        let (destination, identity_len) =
            Identity::parse(bytes).ok_or("destination does not parse")?;
        Self::parse_body(bytes, destination, identity_len).ok_or_else(truncated)?
    }

    fn parse_body(
        bytes: &[u8],
        destination: Identity,
        identity_len: usize,
    ) -> Option<Result<Self, String>> {
        let mut reader = Reader::new(bytes);
        reader.take(identity_len)?;
        let published = reader.u32()?;
        let expires = published + u32::from(reader.u16()?);
        let flags = reader.u16()?;
        // With offline keys, the destination signed a transient key that
        // signs the lease set.
        let transient = if flags & FLAG_OFFLINE_KEYS != 0 {
            let start = reader.position();
            reader.u32()?; // expiry of the transient key
            let key_type = reader.u16()?;
            if !matches!(key_type, SIGNING_ED25519 | SIGNING_RED25519) {
                return Some(Err(format!("transient key type {key_type}")));
            }
            let key: [u8; 32] = reader.array()?;
            let signed = &bytes[start..reader.position()];
            let signature = reader.take(destination.signature_len())?;
            if !destination.verify(signed, signature) {
                return Some(Err(format!(
                    "offline signature of a type {} destination does not verify",
                    destination.signing_type()
                )));
            }
            Some(key)
        } else {
            None
        };
        reader.mapping()?; // options
        let mut encryption_key = None;
        for _ in 0..reader.u8()? {
            let key_type = reader.u16()?;
            let length = usize::from(reader.u16()?);
            let key = reader.take(length)?;
            if key_type == CRYPTO_X25519 && length == 32 {
                encryption_key = Some(key.try_into().expect("checked length"));
            }
        }
        let mut leases = Vec::new();
        for _ in 0..reader.u8()? {
            leases.push(Lease {
                gateway: reader.array()?,
                tunnel: reader.u32()?,
                end: reader.u32()?,
            });
        }
        let signed_len = reader.position();
        let mut signed = vec![STORE_LEASE_SET2];
        signed.extend_from_slice(&bytes[..signed_len]);
        let verified = match transient {
            Some(key) => reader.take(64).is_some_and(|signature| {
                axon_addons::sign::VerifyingKey(key)
                    .verify(
                        &signed,
                        &axon_addons::sign::Signature(signature.try_into().expect("64 bytes")),
                    )
                    .is_ok()
            }),
            None => reader
                .take(destination.signature_len())
                .is_some_and(|signature| destination.verify(&signed, signature)),
        };
        if !verified {
            return Some(Err(format!(
                "signature of a type {} destination (offline keys: {}) does not verify",
                destination.signing_type(),
                transient.is_some()
            )));
        }
        let raw = bytes[..reader.position()].to_vec();
        Some(Ok(Self {
            destination,
            published,
            expires,
            encryption_key,
            leases,
            raw,
        }))
    }

    /// Builds and signs a lease set for one of our destinations.
    pub fn build(
        keys: &PrivateIdentity,
        published: u32,
        leases: &[Lease],
        unpublished: bool,
    ) -> Self {
        let expires = leases
            .iter()
            .map(|lease| lease.end)
            .max()
            .unwrap_or(published + 600)
            .max(published + 60);
        let mut bytes = keys.identity.bytes().to_vec();
        bytes.extend_from_slice(&published.to_be_bytes());
        bytes.extend_from_slice(
            &((expires - published).min(u32::from(u16::MAX)) as u16).to_be_bytes(),
        );
        let flags = if unpublished { FLAG_UNPUBLISHED } else { 0 };
        bytes.extend_from_slice(&flags.to_be_bytes());
        write_mapping(&mut bytes, &[]);
        bytes.push(1);
        bytes.extend_from_slice(&CRYPTO_X25519.to_be_bytes());
        bytes.extend_from_slice(&32u16.to_be_bytes());
        bytes.extend_from_slice(&keys.encryption.public().0);
        bytes.push(leases.len() as u8);
        for lease in leases {
            bytes.extend_from_slice(&lease.gateway);
            bytes.extend_from_slice(&lease.tunnel.to_be_bytes());
            bytes.extend_from_slice(&lease.end.to_be_bytes());
        }
        let mut signed = vec![STORE_LEASE_SET2];
        signed.extend_from_slice(&bytes);
        bytes.extend_from_slice(&keys.sign(&signed));
        Self {
            destination: keys.identity.clone(),
            published,
            expires,
            encryption_key: Some(keys.encryption.public().0),
            leases: leases.to_vec(),
            raw: bytes,
        }
    }

    pub const fn hash(&self) -> &[u8; 32] {
        self.destination.hash()
    }

    /// Leases still valid `margin` seconds from `now`.
    pub fn live_leases(&self, now: u32, margin: u32) -> Vec<Lease> {
        self.leases
            .iter()
            .copied()
            .filter(|lease| lease.end > now + margin)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_lease_sets_parse_and_verify() {
        let keys = PrivateIdentity::generate_destination();
        let lease = Lease {
            gateway: [5; 32],
            tunnel: 77,
            end: 1_700_000_600,
        };
        let set = LeaseSet::build(&keys, 1_700_000_000, &[lease], false);
        let parsed = LeaseSet::parse(&set.raw).unwrap();
        assert_eq!(parsed.leases, vec![lease]);
        assert_eq!(parsed.encryption_key, Some(keys.encryption.public().0));
        assert_eq!(parsed.hash(), keys.identity.hash());
        let mut tampered = set.raw.clone();
        let at = tampered.len() - 70;
        tampered[at] ^= 1;
        assert!(LeaseSet::parse(&tampered).is_none());
    }
}
