//! An I2P router built on Axon that works in the real I2P network.
//!
//! The router is an Axon node: [`plane::I2pPlane`] is its forwarding plane,
//! its links speak NTCP2 through Axon's foreign wire layer, and the runtime
//! drives it like any other node. It joins the network from the reseed
//! servers, keeps tunnels through other routers and gives a client
//! destination the means to reach I2P sites.
//!
//! It is a client: it publishes no address, routes no tunnels for others and
//! hosts no sites yet.

pub mod data;
pub mod destination;
pub mod garlic;
pub mod i2np;
pub mod identity;
pub mod lease_set;
pub mod netdb;
pub mod ntcp2;
pub mod plane;
pub mod pool;
pub mod ratchet;
pub mod reseed;
pub mod router;
pub mod router_info;
pub mod streaming;
pub mod tunnel;
