//! The I2P router as an Axon forwarding plane. Envelopes are I2NP messages,
//! neighbours are routers named by their hashes, and links speak NTCP2.
//!
//! The plane does not open connections. Messages for a router without a link
//! wait here, [`I2pPlane::wanted_connections`] tells the runtime whom to dial,
//! and the messages leave once the link is up.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use axon_core::node::{
    ExtensionError, ExtensionId, ExtensionVersion, ForwardingDecision, ForwardingOutput,
    ForwardingPlane, ForwardingTransmission, InboundRouteContext, NodeId, OutboundRouteContext,
    PollContext, RouteEnvelope,
};
use bytes::Bytes;

use tokio::sync::mpsc::UnboundedSender;

use crate::{
    data::now_ms,
    destination::{ClientDestination, Outgoing, StreamEvent},
    i2np::{self, DatabaseLookup, DatabaseStore, Message, SearchReply},
    identity::PrivateIdentity,
    lease_set::{Lease, LeaseSet},
    netdb::NetDb,
    pool::TunnelPool,
    router_info::{Ntcp2Address, RouterInfo},
    tunnel::{Delivery, Peer},
};

pub const I2P_PLANE: ExtensionId = ExtensionId(0x4932_5052); // I2PR
pub const I2P_PLANE_VERSION: ExtensionVersion = ExtensionVersion(1);

/// How long a lookup waits for one floodfill before asking the next.
const LOOKUP_STEP_MS: u64 = 5_000;
/// Floodfills one lookup asks at most.
const LOOKUP_ATTEMPTS: usize = 8;
/// How long a new link waits before it carries the end of an inbound
/// tunnel.
const LINK_SETTLE_MS: u64 = 2_000;
/// How long a router that could not be reached is left alone.
const UNREACHABLE_MS: u64 = 10 * 60_000;
/// Inbound tunnels closer than this to their end are left out of the lease
/// set.
const LEASE_MARGIN_MS: u64 = 60_000;

pub fn hash_of(node: NodeId) -> [u8; 32] {
    *node.as_bytes()
}

pub fn node_of(hash: &[u8; 32]) -> NodeId {
    NodeId::from_bytes(*hash)
}

/// What a lookup is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupKind {
    RouterInfo,
    LeaseSet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupState {
    Pending,
    Found,
    Failed,
}

struct Lookup {
    kind: LookupKind,
    queried: Vec<[u8; 32]>,
    /// Floodfills that search replies pointed to.
    suggested: Vec<[u8; 32]>,
    in_flight: Option<([u8; 32], u64)>,
    state: LookupState,
}

pub struct I2pPlane {
    keys: PrivateIdentity,
    netdb: NetDb,
    neighbours: BTreeSet<[u8; 32]>,
    /// When each current link appeared.
    linked_since: HashMap<[u8; 32], u64>,
    outbox: HashMap<[u8; 32], VecDeque<Bytes>>,
    unreachable: HashMap<[u8; 32], u64>,
    lookups: BTreeMap<[u8; 32], Lookup>,
    now_ms: u64,
    trace: VecDeque<String>,
    pool: TunnelPool,
    /// Inbound and outbound tunnels to keep, and their hops.
    targets: Targets,
    /// The destination local programs speak from, if any.
    client: Option<ClientDestination>,
    /// Tunnel tests under way: message id and when it was sent.
    tests: HashMap<u32, u64>,
    tests_passed: usize,
}

/// How many tunnels to keep and how long they are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Targets {
    pub inbound: usize,
    pub outbound: usize,
    pub inbound_hops: usize,
    pub outbound_hops: usize,
}

/// Tunnel counts and lengths for a router.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Status {
    pub routers: usize,
    pub links: usize,
    pub inbound: usize,
    pub outbound: usize,
    pub built: usize,
    pub failed: usize,
    /// Tunnel tests that came back.
    pub tests_passed: usize,
}

/// Events kept for diagnosis.
const TRACE_LEN: usize = 256;

fn short(hash: &[u8; 32]) -> String {
    crate::data::base64().encode(&hash[..4])
}

impl I2pPlane {
    pub fn new(keys: PrivateIdentity, routers: Vec<RouterInfo>) -> Self {
        let mut netdb = NetDb::default();
        for info in routers {
            if info.hash() != keys.identity.hash() {
                netdb.add_router(info);
            }
        }
        Self {
            keys,
            netdb,
            neighbours: BTreeSet::new(),
            linked_since: HashMap::new(),
            outbox: HashMap::new(),
            unreachable: HashMap::new(),
            lookups: BTreeMap::new(),
            now_ms: now_ms(),
            trace: VecDeque::new(),
            pool: TunnelPool::default(),
            targets: Targets {
                inbound: 0,
                outbound: 0,
                inbound_hops: 2,
                outbound_hops: 2,
            },
            client: None,
            tests: HashMap::new(),
            tests_passed: 0,
        }
    }

    fn note(&mut self, event: String) {
        if self.trace.len() == TRACE_LEN {
            self.trace.pop_front();
        }
        self.trace.push_back(event);
    }

    /// Recent events: lookups sent, answers, failures. For diagnosis.
    pub fn take_trace(&mut self) -> Vec<String> {
        self.trace.drain(..).collect()
    }

    pub fn netdb(&self) -> &NetDb {
        &self.netdb
    }

    pub fn our_hash(&self) -> &[u8; 32] {
        self.keys.identity.hash()
    }

    /// Sends an I2NP message to a router, now if there is a link and once
    /// there is one otherwise.
    pub fn send_to(&mut self, router: [u8; 32], message: &Message) {
        self.outbox
            .entry(router)
            .or_default()
            .push_back(message.encode());
    }

    /// Routers this one needs a link to and has none: those it has messages
    /// for and the last hops of its inbound tunnels. With where to dial.
    pub fn wanted_connections(&self) -> Vec<([u8; 32], Ntcp2Address)> {
        let mut wanted = self
            .outbox
            .iter()
            .filter(|(_, queue)| !queue.is_empty())
            .map(|(router, _)| *router)
            .collect::<BTreeSet<_>>();
        wanted.extend(self.pool.routers_to_keep());
        wanted
            .into_iter()
            .filter(|router| !self.neighbours.contains(router) && self.reachable(router))
            .filter_map(|router| Some((router, self.netdb.router(&router)?.ntcp2()?)))
            .collect()
    }

    /// Keeps `inbound` and `outbound` tunnels of `hops` hops each.
    pub fn set_tunnels(&mut self, inbound: usize, outbound: usize, hops: usize) {
        let hops = hops.clamp(1, 4);
        self.targets = Targets {
            inbound,
            outbound,
            inbound_hops: hops,
            outbound_hops: hops,
        };
    }

    pub fn set_targets(&mut self, targets: Targets) {
        self.targets = Targets {
            inbound_hops: targets.inbound_hops.clamp(1, 4),
            outbound_hops: targets.outbound_hops.clamp(1, 4),
            ..targets
        };
    }

    pub fn status(&self) -> Status {
        Status {
            routers: self.netdb.len(),
            links: self.neighbours.len(),
            inbound: self.pool.inbound.len(),
            outbound: self.pool.outbound.len(),
            built: self.pool.built,
            failed: self.pool.failed,
            tests_passed: self.tests_passed,
        }
    }

    pub fn pool(&self) -> &TunnelPool {
        &self.pool
    }

    /// Tests the newest tunnels: a delivery status message goes out through
    /// the outbound tunnel and comes back through the inbound one, `padding`
    /// bytes longer than it needs to be. Returns false when there is no
    /// pair to test.
    pub fn test_tunnels(&mut self, padding: usize) -> bool {
        let Some(inbound) = self.pool.inbound.iter().max_by_key(|tunnel| tunnel.created) else {
            return false;
        };
        let delivery = Delivery::Tunnel(*inbound.tunnel.first_hop(), inbound.tunnel.first_tunnel());
        let mut payload = Vec::with_capacity(12);
        let id = i2np::random_u32();
        payload.extend_from_slice(&id.to_be_bytes());
        payload.extend_from_slice(&self.now_ms.to_be_bytes());
        payload.resize(12 + padding, 0);
        let message = Message::new(i2np::DELIVERY_STATUS, payload);
        let Some((first_hop, data)) = self
            .pool
            .through_outbound(&[(delivery, message.encode().to_vec())])
        else {
            return false;
        };
        for message in data {
            self.send_to(first_hop, &message);
        }
        self.tests.insert(id, self.now_ms);
        true
    }

    /// Gives the router a client destination with `keys`. Its lease set
    /// lists our inbound tunnels and travels inside our garlic messages, so
    /// it is never published to the floodfills.
    pub fn set_client(&mut self, keys: PrivateIdentity) {
        self.client = Some(ClientDestination::new(keys));
    }

    /// The client's current lease set.
    pub fn client_lease_set(&self) -> Option<LeaseSet> {
        self.client.as_ref()?.lease_set().cloned()
    }

    /// Keeps a lease set learned some other way, such as from an address
    /// book or a test.
    pub fn add_lease_set(&mut self, set: LeaseSet) {
        self.netdb.add_lease_set(set);
    }

    pub fn client_hash(&self) -> Option<[u8; 32]> {
        self.client.as_ref().map(|client| *client.hash())
    }

    /// Whether the client destination can reach others: it has inbound
    /// tunnels for the replies and an outbound tunnel to send through.
    pub fn client_ready(&self) -> bool {
        self.client
            .as_ref()
            .is_some_and(ClientDestination::has_lease_set)
            && !self.pool.outbound.is_empty()
    }

    /// Opens a stream from the client destination to the destination with
    /// hash `remote`, whose lease set must be known. Returns the stream id.
    pub fn open_stream(
        &mut self,
        remote: [u8; 32],
        port: u16,
        data: &[u8],
        events: UnboundedSender<StreamEvent>,
    ) -> Option<u32> {
        let set = self.netdb.lease_set(&remote)?.clone();
        let id = self.client.as_mut()?.open_stream(&set, port, data, events);
        self.flush_client();
        Some(id)
    }

    pub fn stream_send(&mut self, id: u32, data: &[u8]) {
        if let Some(client) = &mut self.client {
            client.stream_send(id, data);
        }
        self.flush_client();
    }

    pub fn stream_close(&mut self, id: u32) {
        if let Some(client) = &mut self.client {
            client.stream_close(id);
        }
        self.flush_client();
    }

    /// Sends the client's garlic messages through an outbound tunnel to the
    /// remote inbound gateways, and keeps the lease sets it learned.
    fn flush_client(&mut self) {
        let Some(client) = &mut self.client else {
            return;
        };
        let outgoing = client.take_outgoing();
        let learned = std::mem::take(&mut client.learned);
        for line in std::mem::take(&mut client.trace) {
            self.note(line);
        }
        for set in learned {
            self.netdb.add_lease_set(set);
        }
        for Outgoing { lease, garlic } in outgoing {
            let message = (
                Delivery::Tunnel(lease.gateway, lease.tunnel),
                garlic.encode().to_vec(),
            );
            match self.pool.through_outbound(&[message]) {
                Some((first_hop, data)) => {
                    for message in data {
                        self.send_to(first_hop, &message);
                    }
                }
                None => self.note("no outbound tunnel for a garlic message".to_owned()),
            }
        }
    }

    /// Lists our inbound tunnels in the client's lease set and lets its
    /// streams resend.
    fn maintain_client(&mut self) {
        let now = self.now_ms;
        let Some(client) = &mut self.client else {
            return;
        };
        let leases = self
            .pool
            .inbound
            .iter()
            .filter(|tunnel| tunnel.expires() > now + LEASE_MARGIN_MS)
            .map(|tunnel| Lease {
                gateway: *tunnel.tunnel.first_hop(),
                tunnel: tunnel.tunnel.first_tunnel(),
                end: (tunnel.expires() / 1000) as u32,
            })
            .collect();
        client.set_leases(leases);
        client.tick();
        self.flush_client();
    }

    /// `count` distinct random routers fit to be tunnel hops.
    fn pick_peers(&self, count: usize) -> Option<Vec<Peer>> {
        let mut candidates = self
            .netdb
            .tunnel_candidates()
            .into_iter()
            .filter(|info| info.hash() != self.keys.identity.hash() && self.reachable(info.hash()))
            .filter_map(|info| {
                Some(Peer {
                    hash: *info.hash(),
                    encryption_key: info.encryption_key()?,
                })
            })
            .collect::<Vec<_>>();
        if candidates.len() < count {
            return None;
        }
        let mut chosen = Vec::with_capacity(count);
        for _ in 0..count {
            let index = (i2np::random_u32() as usize) % candidates.len();
            chosen.push(candidates.swap_remove(index));
        }
        Some(chosen)
    }

    fn maintain_tunnels(&mut self) {
        let now = self.now_ms;
        let us = *self.keys.identity.hash();
        let (inbound, outbound) = self.pool.expire(now);
        let targets = self.targets;
        for _ in inbound..targets.inbound {
            if let Some(peers) = self.pick_peers(targets.inbound_hops) {
                self.pool.plan_inbound(peers, now);
            }
        }
        for _ in outbound..targets.outbound {
            let Some(peers) = self.pick_peers(targets.outbound_hops) else {
                break;
            };
            let Some((router, message)) = self.pool.start_outbound(&peers, now) else {
                break;
            };
            self.note(format!("outbound build sent to {}", short(&router)));
            self.send_to(router, &message);
        }
        // A link counts once its handshake had time to finish, so the last
        // hop of an inbound tunnel knows this router when it answers.
        let linked = self
            .linked_since
            .iter()
            .filter(|(_, since)| now.saturating_sub(**since) >= LINK_SETTLE_MS)
            .map(|(router, _)| *router)
            .collect::<BTreeSet<_>>();
        for (router, message) in self.pool.start_planned(&linked, us, now) {
            self.note(format!(
                "inbound build {} sent to {}",
                message.id,
                short(&router)
            ));
            self.send_to(router, &message);
        }
        for line in std::mem::take(&mut self.pool.trace) {
            self.note(line);
        }
    }

    /// The runtime could not reach `router`: its messages are dropped and it
    /// is left alone for a while.
    pub fn connection_failed(&mut self, router: [u8; 32]) {
        self.note(format!("could not reach {}", short(&router)));
        self.outbox.remove(&router);
        self.unreachable.insert(router, self.now_ms);
        for lookup in self.lookups.values_mut() {
            if lookup
                .in_flight
                .is_some_and(|(floodfill, _)| floodfill == router)
            {
                lookup.in_flight = None;
            }
        }
    }

    fn reachable(&self, router: &[u8; 32]) -> bool {
        self.unreachable
            .get(router)
            .is_none_or(|since| self.now_ms.saturating_sub(*since) > UNREACHABLE_MS)
    }

    /// Starts looking up a router info or a lease set, unless a lookup for
    /// the key is under way.
    pub fn lookup(&mut self, key: [u8; 32], kind: LookupKind) {
        let known = match kind {
            LookupKind::RouterInfo => self.netdb.router(&key).is_some(),
            LookupKind::LeaseSet => self.netdb.lease_set(&key).is_some(),
        };
        if known {
            return;
        }
        if self
            .lookups
            .get(&key)
            .is_some_and(|lookup| lookup.state == LookupState::Pending)
        {
            return;
        }
        self.lookups.insert(
            key,
            Lookup {
                kind,
                queried: Vec::new(),
                suggested: Vec::new(),
                in_flight: None,
                state: LookupState::Pending,
            },
        );
        self.advance_lookup(key);
    }

    pub fn lookup_state(&self, key: &[u8; 32]) -> Option<LookupState> {
        match self.lookups.get(key) {
            Some(lookup) => Some(lookup.state),
            None if self.netdb.lease_set(key).is_some() || self.netdb.router(key).is_some() => {
                Some(LookupState::Found)
            }
            None => None,
        }
    }

    pub fn lease_set(&self, key: &[u8; 32]) -> Option<&LeaseSet> {
        self.netdb.lease_set(key)
    }

    /// Asks the next floodfill: one a search reply suggested, or else the
    /// closest one not asked yet.
    fn advance_lookup(&mut self, key: [u8; 32]) {
        let now = self.now_ms;
        let Some(lookup) = self.lookups.get(&key) else {
            return;
        };
        if lookup.state != LookupState::Pending || lookup.in_flight.is_some() {
            return;
        }
        if lookup.queried.len() >= LOOKUP_ATTEMPTS {
            self.lookups.get_mut(&key).expect("present").state = LookupState::Failed;
            return;
        }
        let queried = lookup.queried.clone();
        let suggested = lookup.suggested.iter().copied().find(|floodfill| {
            !queried.contains(floodfill)
                && self
                    .netdb
                    .router(floodfill)
                    .is_some_and(|info| info.ntcp2().is_some())
                && self.reachable(floodfill)
        });
        let next = suggested.or_else(|| {
            self.netdb
                .closest_floodfills(&key, now, 16, &queried)
                .into_iter()
                .find(|floodfill| self.reachable(floodfill))
        });
        let Some(floodfill) = next else {
            self.lookups.get_mut(&key).expect("present").state = LookupState::Failed;
            return;
        };
        self.note(format!("asking {} for {}", short(&floodfill), short(&key)));
        let lookup = self.lookups.get_mut(&key).expect("present");
        lookup.queried.push(floodfill);
        lookup.in_flight = Some((floodfill, now));
        let kind = lookup.kind;
        let message = Message::new(
            i2np::DATABASE_LOOKUP,
            DatabaseLookup {
                key,
                from: *self.keys.identity.hash(),
                lookup: match kind {
                    LookupKind::RouterInfo => i2np::LOOKUP_ROUTER_INFO,
                    LookupKind::LeaseSet => i2np::LOOKUP_LEASE_SET,
                },
                reply_tunnel: None,
                exclude: Vec::new(),
                reply_key: None,
            }
            .encode(),
        );
        self.send_to(floodfill, &message);
    }

    fn handle_store(&mut self, store: DatabaseStore) {
        self.note(format!(
            "store of {} type {} ({} bytes)",
            short(&store.key),
            store.kind,
            store.data.len()
        ));
        match store.kind {
            i2np::STORE_ROUTER_INFO => {
                if let Some(info) = RouterInfo::parse(&store.data)
                    && *info.hash() == store.key
                {
                    self.netdb.add_router(info);
                    self.finish(store.key);
                }
            }
            i2np::STORE_LEASE_SET2 => match LeaseSet::parse_checked(&store.data) {
                Ok(set) if *set.hash() == store.key => {
                    self.netdb.add_lease_set(set);
                    self.finish(store.key);
                }
                Ok(_) => self.note("lease set is stored under another key".to_owned()),
                Err(reason) => self.note(format!("lease set rejected: {reason}")),
            },
            _ => {}
        }
        // Router infos looked up for search replies may unblock lookups.
        let waiting = self
            .lookups
            .iter()
            .filter(|(_, lookup)| {
                lookup.state == LookupState::Pending && lookup.in_flight.is_none()
            })
            .map(|(key, _)| *key)
            .collect::<Vec<_>>();
        for key in waiting {
            self.advance_lookup(key);
        }
    }

    fn finish(&mut self, key: [u8; 32]) {
        if let Some(lookup) = self.lookups.get_mut(&key) {
            lookup.state = LookupState::Found;
            lookup.in_flight = None;
        }
    }

    fn handle_search_reply(&mut self, from: [u8; 32], reply: SearchReply) {
        self.note(format!(
            "{} has no {}, suggests {}",
            short(&from),
            short(&reply.key),
            reply.peers.len()
        ));
        let Some(lookup) = self.lookups.get_mut(&reply.key) else {
            return;
        };
        if lookup
            .in_flight
            .is_some_and(|(floodfill, _)| floodfill == from)
        {
            lookup.in_flight = None;
        }
        let mut unknown = Vec::new();
        for peer in reply.peers {
            if !lookup.suggested.contains(&peer) && peer != *self.keys.identity.hash() {
                lookup.suggested.push(peer);
                if self.netdb.router(&peer).is_none() {
                    unknown.push(peer);
                }
            }
        }
        // Ask the floodfill that answered for the router infos it named.
        for peer in unknown {
            let message = Message::new(
                i2np::DATABASE_LOOKUP,
                DatabaseLookup {
                    key: peer,
                    from: *self.keys.identity.hash(),
                    lookup: i2np::LOOKUP_ROUTER_INFO,
                    reply_tunnel: None,
                    exclude: Vec::new(),
                    reply_key: None,
                }
                .encode(),
            );
            self.send_to(from, &message);
        }
        self.advance_lookup(reply.key);
    }

    /// Handles one I2NP message from a neighbour, and the messages it
    /// carries for this router.
    fn handle(&mut self, from: [u8; 32], message: Message) {
        if !matches!(
            message.kind,
            i2np::DATABASE_STORE | i2np::DATABASE_SEARCH_REPLY
        ) {
            self.note(format!(
                "message type {} id {} from {}",
                message.kind,
                message.id,
                short(&from)
            ));
        }
        let mut work = VecDeque::from([message]);
        while let Some(message) = work.pop_front() {
            if self.pool.is_build_reply(&message) {
                let now = self.now_ms;
                self.pool.handle_build_reply(&message, now);
                continue;
            }
            match message.kind {
                i2np::TUNNEL_DATA => work.extend(self.pool.handle_tunnel_data(&message.payload)),
                i2np::GARLIC => match self.pool.open_garlic(&message.payload) {
                    Some(messages) => work.extend(messages),
                    None if self
                        .client
                        .as_mut()
                        .is_some_and(|client| client.handle_garlic(&message.payload)) =>
                    {
                        self.flush_client();
                    }
                    None => self.note("garlic for no key of ours".to_owned()),
                },
                _ => self.handle_one(from, message),
            }
        }
    }

    fn handle_one(&mut self, from: [u8; 32], message: Message) {
        match message.kind {
            i2np::DATABASE_STORE => {
                if let Some(store) = DatabaseStore::decode(&message.payload) {
                    self.handle_store(store);
                }
            }
            i2np::DATABASE_SEARCH_REPLY => {
                if let Some(reply) = SearchReply::decode(&message.payload) {
                    self.handle_search_reply(from, reply);
                }
            }
            i2np::DELIVERY_STATUS => {
                let id = message
                    .payload
                    .get(..4)
                    .map(|id| u32::from_be_bytes(id.try_into().expect("4 bytes")));
                if let Some(sent) = id.and_then(|id| self.tests.remove(&id)) {
                    self.tests_passed += 1;
                    let elapsed = self.now_ms.saturating_sub(sent);
                    self.note(format!("tunnel test came back in {elapsed} ms"));
                }
            }
            _ => {}
        }
    }

    fn tick(&mut self) {
        let now = self.now_ms;
        let expired = self
            .lookups
            .iter()
            .filter(|(_, lookup)| {
                lookup
                    .in_flight
                    .is_some_and(|(_, sent)| now.saturating_sub(sent) > LOOKUP_STEP_MS)
            })
            .map(|(key, _)| *key)
            .collect::<Vec<_>>();
        for key in expired {
            self.note(format!("no answer for {}", short(&key)));
            if let Some(lookup) = self.lookups.get_mut(&key) {
                lookup.in_flight = None;
            }
            self.advance_lookup(key);
        }
    }
}

impl ForwardingPlane for I2pPlane {
    fn extension_id(&self) -> ExtensionId {
        I2P_PLANE
    }

    fn extension_version(&self) -> ExtensionVersion {
        I2P_PLANE_VERSION
    }

    fn originate(
        &mut self,
        _context: OutboundRouteContext<'_>,
        _payload: Bytes,
    ) -> Result<Vec<ForwardingTransmission>, ExtensionError> {
        Err(ExtensionError::provider(
            I2P_PLANE,
            "I2P carries no Axon sessions; use the plane's own streams".to_owned(),
        ))
    }

    fn receive(
        &mut self,
        context: InboundRouteContext<'_>,
    ) -> Result<ForwardingDecision, ExtensionError> {
        self.now_ms = now_ms();
        if let Some(message) = Message::decode(&context.envelope.0) {
            self.handle(hash_of(context.previous_hop), message);
        }
        Ok(ForwardingDecision::Consumed)
    }

    fn poll(&mut self, context: PollContext<'_>) -> Result<ForwardingOutput, ExtensionError> {
        self.now_ms = now_ms();
        self.neighbours = context
            .topology
            .outgoing(context.local_node)
            .map(|link| hash_of(link.key.destination))
            .collect();
        let now = self.now_ms;
        self.linked_since
            .retain(|router, _| self.neighbours.contains(router));
        for router in &self.neighbours {
            self.linked_since.entry(*router).or_insert(now);
        }
        self.tick();
        self.maintain_tunnels();
        self.maintain_client();
        let mut output = ForwardingOutput::default();
        for router in self.neighbours.clone() {
            if let Some(queue) = self.outbox.get_mut(&router) {
                for envelope in queue.drain(..) {
                    output.transmissions.push(ForwardingTransmission {
                        next_hop: node_of(&router),
                        flow_hash: 0,
                        envelope: RouteEnvelope(envelope),
                    });
                }
            }
        }
        Ok(output)
    }
}
