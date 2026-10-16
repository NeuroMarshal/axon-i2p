//! RouterInfo: a router's identity, its transport addresses and capabilities,
//! signed by the router.

use std::net::{IpAddr, SocketAddr};

use crate::{
    data::{self, Reader, get, write_mapping, write_string},
    identity::{Identity, PrivateIdentity},
};

/// One transport address of a router.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterAddress {
    pub cost: u8,
    pub transport: String,
    pub options: Vec<(String, String)>,
}

impl RouterAddress {
    pub fn option(&self, key: &str) -> Option<&str> {
        get(&self.options, key)
    }

    /// The host, port, static key and IV of a published NTCP2 address.
    pub fn ntcp2(&self) -> Option<Ntcp2Address> {
        if !self.transport.starts_with("NTCP") {
            return None;
        }
        let host: IpAddr = self.option("host")?.parse().ok()?;
        let port: u16 = self.option("port")?.parse().ok()?;
        let static_key: [u8; 32] = data::base64()
            .decode(self.option("s")?.as_bytes())
            .ok()?
            .try_into()
            .ok()?;
        let iv: [u8; 16] = data::base64()
            .decode(self.option("i")?.as_bytes())
            .ok()?
            .try_into()
            .ok()?;
        Some(Ntcp2Address {
            address: SocketAddr::new(host, port),
            static_key,
            iv,
        })
    }
}

/// What a router publishes to be reached over NTCP2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ntcp2Address {
    pub address: SocketAddr,
    pub static_key: [u8; 32],
    pub iv: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterInfo {
    pub identity: Identity,
    pub published: u64,
    pub addresses: Vec<RouterAddress>,
    pub options: Vec<(String, String)>,
    /// The signed bytes as received, for passing the router info on.
    pub raw: Vec<u8>,
}

impl RouterInfo {
    /// Parses a router info and checks its signature.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let (identity, identity_len) = Identity::parse(bytes)?;
        let signature_len = identity.signature_len();
        let signed_len = bytes.len().checked_sub(signature_len)?;
        if signed_len < identity_len || !identity.verify(&bytes[..signed_len], &bytes[signed_len..])
        {
            return None;
        }
        let mut reader = Reader::new(&bytes[identity_len..signed_len]);
        let published = reader.u64()?;
        let mut addresses = Vec::new();
        for _ in 0..reader.u8()? {
            let cost = reader.u8()?;
            reader.u64()?; // expiration, always zero
            let transport = reader.string()?;
            let options = reader.mapping()?;
            addresses.push(RouterAddress {
                cost,
                transport,
                options,
            });
        }
        let peers = usize::from(reader.u8()?);
        reader.take(peers * 32)?;
        let options = reader.mapping()?;
        Some(Self {
            identity,
            published,
            addresses,
            options,
            raw: bytes.to_vec(),
        })
    }

    /// Builds and signs a router info for `keys`.
    pub fn build(
        keys: &PrivateIdentity,
        published: u64,
        addresses: Vec<RouterAddress>,
        options: Vec<(String, String)>,
    ) -> Self {
        let mut bytes = keys.identity.bytes().to_vec();
        bytes.extend_from_slice(&published.to_be_bytes());
        bytes.push(addresses.len() as u8);
        for address in &addresses {
            bytes.push(address.cost);
            bytes.extend_from_slice(&0u64.to_be_bytes());
            write_string(&mut bytes, &address.transport);
            write_mapping(&mut bytes, &address.options);
        }
        bytes.push(0); // no peers
        write_mapping(&mut bytes, &options);
        let signature = keys.sign(&bytes);
        bytes.extend_from_slice(&signature);
        Self {
            identity: keys.identity.clone(),
            published,
            addresses,
            options,
            raw: bytes,
        }
    }

    pub const fn hash(&self) -> &[u8; 32] {
        self.identity.hash()
    }

    pub fn option(&self, key: &str) -> Option<&str> {
        get(&self.options, key)
    }

    pub fn caps(&self) -> &str {
        self.option("caps").unwrap_or("")
    }

    pub fn is_floodfill(&self) -> bool {
        self.caps().contains('f')
    }

    /// Not hidden, reachable, and on the main network.
    pub fn is_usable(&self) -> bool {
        let caps = self.caps();
        self.option("netId") == Some("2")
            && !caps.contains('U')
            && !caps.contains('H')
            && !caps.contains('D')
            && !caps.contains('E')
    }

    /// The first published NTCP2 address on IPv4.
    pub fn ntcp2(&self) -> Option<Ntcp2Address> {
        self.addresses
            .iter()
            .filter_map(RouterAddress::ntcp2)
            .find(|address| address.address.is_ipv4())
    }

    /// The X25519 key this router answers tunnel builds and garlic with.
    pub fn encryption_key(&self) -> Option<[u8; 32]> {
        self.identity.encryption_key()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_router_infos_parse_and_verify() {
        let keys = PrivateIdentity::generate_router();
        let address = RouterAddress {
            cost: 14,
            transport: "NTCP2".into(),
            options: vec![
                ("host".into(), "192.0.2.1".into()),
                ("port".into(), "12345".into()),
                ("s".into(), data::base64().encode(&[1u8; 32])),
                ("i".into(), data::base64().encode(&[2u8; 16])),
                ("v".into(), "2".into()),
            ],
        };
        let info = RouterInfo::build(
            &keys,
            1_700_000_000_000,
            vec![address],
            vec![("caps".into(), "LR".into()), ("netId".into(), "2".into())],
        );
        let parsed = RouterInfo::parse(&info.raw).unwrap();
        assert_eq!(parsed.hash(), keys.identity.hash());
        assert_eq!(
            parsed.ntcp2().unwrap().address,
            "192.0.2.1:12345".parse().unwrap()
        );
        assert!(parsed.is_usable() && !parsed.is_floodfill());
        let mut tampered = info.raw.clone();
        tampered[400] ^= 1;
        assert!(RouterInfo::parse(&tampered).is_none());
    }
}
