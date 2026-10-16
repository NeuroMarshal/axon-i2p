//! The tunnels of one router: builds in progress, established inbound and
//! outbound tunnels, and what arrives at the end of our inbound tunnels.
//!
//! Without published addresses, this router can only be reached over links
//! it opened. So the last hop of an inbound tunnel, which sends the tunnel's
//! data here, is always a router we keep a link to, and outbound tunnels
//! send their build replies back through an inbound tunnel.

use std::collections::{BTreeSet, HashMap};

use crate::{
    garlic::{self, CloveDelivery},
    i2np::{self, Message},
    tunnel::{Delivery, Peer, Reassembler, TUNNEL_DATA_LEN, Tunnel, tunnel_data, tunnel_messages},
};

/// How long a tunnel lives.
pub const TUNNEL_LIFETIME_MS: u64 = 10 * 60_000;
/// Tunnels are replaced this long before they expire.
const REPLACE_BEFORE_MS: u64 = 2 * 60_000;
/// How long a build may take.
const BUILD_TIMEOUT_MS: u64 = 20_000;

pub struct Established {
    pub tunnel: Tunnel,
    pub created: u64,
}

impl Established {
    pub fn expires(&self) -> u64 {
        self.created + TUNNEL_LIFETIME_MS
    }
}

struct Planned {
    peers: Vec<Peer>,
    created: u64,
}

struct Pending {
    tunnel: Tunnel,
    started: u64,
}

#[derive(Default)]
pub struct TunnelPool {
    pub inbound: Vec<Established>,
    pub outbound: Vec<Established>,
    planned: Vec<Planned>,
    pending: HashMap<u32, Pending>,
    garlic_keys: HashMap<[u8; 8], ([u8; 32], u64)>,
    reassemblers: HashMap<u32, Reassembler>,
    pub built: usize,
    pub failed: usize,
    pub trace: Vec<String>,
}

impl TunnelPool {
    /// Plans an inbound tunnel through `peers`. It starts once there is a
    /// link to its last hop, which the caller should keep.
    pub fn plan_inbound(&mut self, peers: Vec<Peer>, now: u64) {
        self.planned.push(Planned {
            peers,
            created: now,
        });
    }

    /// Routers that planned and live inbound tunnels need links to.
    pub fn routers_to_keep(&self) -> BTreeSet<[u8; 32]> {
        self.planned
            .iter()
            .filter_map(|plan| plan.peers.last().map(|peer| peer.hash))
            .chain(self.inbound.iter().map(|tunnel| *tunnel.tunnel.last_hop()))
            .collect()
    }

    /// Starts planned inbound builds whose last hop is linked. Returns the
    /// build messages and the routers to send them to.
    pub fn start_planned(
        &mut self,
        linked: &BTreeSet<[u8; 32]>,
        us: [u8; 32],
        now: u64,
    ) -> Vec<([u8; 32], Message)> {
        let mut out = Vec::new();
        let mut waiting = Vec::new();
        for plan in std::mem::take(&mut self.planned) {
            let last = plan.peers.last().expect("tunnels have hops").hash;
            if linked.contains(&last) {
                let (tunnel, message) = Tunnel::inbound(&plan.peers, us);
                out.push((*tunnel.first_hop(), message));
                self.pending.insert(
                    tunnel.reply_id,
                    Pending {
                        tunnel,
                        started: now,
                    },
                );
            } else if now.saturating_sub(plan.created) < BUILD_TIMEOUT_MS {
                waiting.push(plan);
            } else {
                self.failed += 1;
            }
        }
        self.planned = waiting;
        out
    }

    /// Starts an outbound tunnel whose build reply comes back through one of
    /// our inbound tunnels.
    pub fn start_outbound(&mut self, peers: &[Peer], now: u64) -> Option<([u8; 32], Message)> {
        let reply = self.inbound.iter().max_by_key(|tunnel| tunnel.created)?;
        let (tunnel, message) = Tunnel::outbound(
            peers,
            *reply.tunnel.first_hop(),
            reply.tunnel.first_tunnel(),
        );
        if let Some((key, tag)) = tunnel.reply_garlic {
            self.garlic_keys.insert(tag, (key, now));
        }
        let first = *tunnel.first_hop();
        self.pending.insert(
            tunnel.reply_id,
            Pending {
                tunnel,
                started: now,
            },
        );
        Some((first, message))
    }

    /// Handles a build reply, or returns false if it is for no build of ours.
    pub fn handle_build_reply(&mut self, message: &Message, now: u64) -> bool {
        let Some(pending) = self.pending.remove(&message.id) else {
            return false;
        };
        match pending.tunnel.handle_reply(&message.payload) {
            Ok(codes) if codes.iter().all(|&code| code == 0) => {
                self.built += 1;
                self.trace.push(format!(
                    "{} tunnel built in {} ms",
                    if pending.tunnel.inbound {
                        "inbound"
                    } else {
                        "outbound"
                    },
                    now.saturating_sub(pending.started)
                ));
                let established = Established {
                    tunnel: pending.tunnel,
                    created: now,
                };
                if established.tunnel.inbound {
                    self.inbound.push(established);
                } else {
                    self.outbound.push(established);
                }
            }
            Ok(codes) => {
                self.failed += 1;
                self.trace
                    .push(format!("tunnel refused by hops: {codes:?}"));
            }
            Err(error) => {
                self.failed += 1;
                self.trace.push(format!("tunnel reply unreadable: {error}"));
            }
        }
        true
    }

    /// Reads tunnel data for one of our inbound tunnels and returns the I2NP
    /// messages that arrive for this router.
    pub fn handle_tunnel_data(&mut self, payload: &[u8]) -> Vec<Message> {
        let Some(id) = payload
            .get(..4)
            .map(|id| u32::from_be_bytes(id.try_into().expect("4")))
        else {
            return Vec::new();
        };
        let Some(tunnel) = self
            .inbound
            .iter()
            .find(|tunnel| tunnel.tunnel.receive_tunnel == id)
        else {
            return Vec::new();
        };
        let Some(data) = payload.get(4..4 + TUNNEL_DATA_LEN) else {
            return Vec::new();
        };
        let mut data: [u8; TUNNEL_DATA_LEN] = data.try_into().expect("fixed slice");
        tunnel.tunnel.remove_layers(&mut data);
        let delivered = match self.reassemblers.entry(id).or_default().read(&data) {
            Ok(delivered) => delivered,
            Err(error) => {
                self.trace.push(format!("tunnel data: {error}"));
                return Vec::new();
            }
        };
        delivered
            .into_iter()
            .filter(|(delivery, _)| *delivery == Delivery::Local)
            .filter_map(|(_, bytes)| Message::decode(&bytes))
            .collect()
    }

    /// Opens a garlic message sealed with a one-time key of ours. Returns the
    /// messages of its local cloves, or None if no key matches.
    pub fn open_garlic(&mut self, payload: &[u8]) -> Option<Vec<Message>> {
        let sealed = payload.get(4..)?;
        let tag: [u8; 8] = sealed.get(..8)?.try_into().ok()?;
        let (key, _) = self.garlic_keys.remove(&tag)?;
        let blocks = garlic::open_with_tag(&key, sealed)?;
        Some(
            garlic::cloves(&blocks)
                .into_iter()
                .filter(|(delivery, _)| *delivery == CloveDelivery::Local)
                .map(|(_, message)| message)
                .collect(),
        )
    }

    /// Accepts garlic under a one-time key and tag, such as a lookup reply.
    pub fn expect_garlic(&mut self, key: [u8; 32], tag: [u8; 8], now: u64) {
        self.garlic_keys.insert(tag, (key, now));
    }

    /// Wraps `messages` for an outbound tunnel: the first hop to send to and
    /// the TunnelData messages.
    pub fn through_outbound(
        &self,
        messages: &[(Delivery, Vec<u8>)],
    ) -> Option<([u8; 32], Vec<Message>)> {
        let tunnel = self.outbound.iter().max_by_key(|tunnel| tunnel.created)?;
        let data = tunnel_messages(messages)
            .into_iter()
            .map(|mut data| {
                tunnel.tunnel.remove_layers(&mut data);
                tunnel_data(tunnel.tunnel.first_tunnel(), &data)
            })
            .collect();
        Some((*tunnel.tunnel.first_hop(), data))
    }

    /// Drops expired tunnels, builds that never answered and stale keys.
    /// Returns how many inbound and outbound tunnels are due for
    /// replacement.
    pub fn expire(&mut self, now: u64) -> (usize, usize) {
        self.inbound.retain(|tunnel| tunnel.expires() > now);
        self.outbound.retain(|tunnel| tunnel.expires() > now);
        let before = self.pending.len();
        self.pending
            .retain(|_, pending| now.saturating_sub(pending.started) < BUILD_TIMEOUT_MS);
        self.failed += before - self.pending.len();
        self.garlic_keys
            .retain(|_, (_, added)| now.saturating_sub(*added) < TUNNEL_LIFETIME_MS);
        let live_inbound = self
            .inbound
            .iter()
            .filter(|tunnel| tunnel.expires() > now + REPLACE_BEFORE_MS)
            .count()
            + self.planned.len()
            + self.pending.values().filter(|p| p.tunnel.inbound).count();
        let live_outbound = self
            .outbound
            .iter()
            .filter(|tunnel| tunnel.expires() > now + REPLACE_BEFORE_MS)
            .count()
            + self.pending.values().filter(|p| !p.tunnel.inbound).count();
        (live_inbound, live_outbound)
    }

    pub fn is_build_reply(&self, message: &Message) -> bool {
        matches!(
            message.kind,
            i2np::SHORT_TUNNEL_BUILD | i2np::SHORT_TUNNEL_BUILD_REPLY
        ) && self.pending.contains_key(&message.id)
    }
}
