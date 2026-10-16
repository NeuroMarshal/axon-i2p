//! I2P's structures and protocols, written for an Axon node: router infos
//! and lease sets with their signatures, reseed files, I2NP messages, NTCP2
//! links as an Axon wire protocol, tunnel builds and tunnel messages, garlic
//! cloves, ECIES-X25519 sessions and streaming packets.

pub mod data;
pub mod garlic;
pub mod i2np;
pub mod identity;
pub mod lease_set;
pub mod netdb;
pub mod ntcp2;
pub mod ratchet;
pub mod reseed;
pub mod router_info;
pub mod streaming;
pub mod tunnel;
