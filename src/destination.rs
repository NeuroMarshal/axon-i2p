//! A client destination: the address local programs speak from. It keeps
//! garlic sessions to remote destinations and the streams inside them.
//!
//! This module only shapes messages. The plane looks up lease sets, builds
//! tunnels and carries what [`ClientDestination::take_outgoing`] returns to
//! the remote inbound gateways.

use std::collections::HashMap;

use tokio::sync::mpsc::UnboundedSender;

use crate::{
    data::now_ms,
    garlic::{self, CloveDelivery},
    i2np::{self, DatabaseStore, Message},
    identity::PrivateIdentity,
    lease_set::{Lease, LeaseSet},
    ratchet::OutboundSession,
    streaming::{self, Packet, Stream},
};

/// What a local program sees of its stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamEvent {
    /// The remote destination accepted the stream.
    Opened,
    Data(Vec<u8>),
    /// The remote side finished sending.
    Closed,
    Failed(String),
}

/// A garlic message ready for a remote destination's inbound tunnel.
pub struct Outgoing {
    pub lease: Lease,
    pub garlic: Message,
}

/// New sessions kept per remote while waiting for a reply.
const PENDING_SESSIONS: usize = 8;

struct Session {
    established: Option<OutboundSession>,
    /// New sessions sent and not answered yet, oldest first. Until one is
    /// answered every message goes out as a new session of its own, so a
    /// lost or refused first message does not stall the stream.
    pending: Vec<OutboundSession>,
    lease_set: LeaseSet,
    /// When the lease set of ours the remote last got was published.
    sent_lease_set: u32,
}

struct StreamEntry {
    stream: Stream,
    remote: [u8; 32],
    port: u16,
    events: UnboundedSender<StreamEvent>,
}

pub struct ClientDestination {
    keys: PrivateIdentity,
    lease_set: Option<LeaseSet>,
    sessions: HashMap<[u8; 32], Session>,
    tags: HashMap<[u8; 8], [u8; 32]>,
    streams: HashMap<u32, StreamEntry>,
    outgoing: Vec<Outgoing>,
    /// Lease sets of remote destinations that arrived in garlic.
    pub learned: Vec<LeaseSet>,
    /// Events kept for diagnosis.
    pub trace: Vec<String>,
}

fn short(hash: &[u8; 32]) -> String {
    crate::data::base64().encode(&hash[..4])
}

/// An I2NP Data message with a streaming packet: a gzip I2CP payload with
/// the ports in the modification time and the protocol in the OS byte.
fn data_message(packet: &[u8], from_port: u16, to_port: u16) -> Message {
    let mut ports = [0u8; 4];
    ports[..2].copy_from_slice(&from_port.to_be_bytes());
    ports[2..].copy_from_slice(&to_port.to_be_bytes());
    let gzip = i2np::gzip_with_header(packet, ports, streaming::PROTOCOL);
    let mut payload = (gzip.len() as u32).to_be_bytes().to_vec();
    payload.extend_from_slice(&gzip);
    Message::new(i2np::DATA, payload)
}

fn random_id() -> u32 {
    loop {
        let id = i2np::random_u32();
        if id != 0 {
            return id;
        }
    }
}

impl ClientDestination {
    pub fn new(keys: PrivateIdentity) -> Self {
        Self {
            keys,
            lease_set: None,
            sessions: HashMap::new(),
            tags: HashMap::new(),
            streams: HashMap::new(),
            outgoing: Vec::new(),
            learned: Vec::new(),
            trace: Vec::new(),
        }
    }

    pub fn hash(&self) -> &[u8; 32] {
        self.keys.identity.hash()
    }

    /// Republishes our lease set over the given inbound tunnels.
    pub fn set_leases(&mut self, leases: Vec<Lease>) {
        let changed = self
            .lease_set
            .as_ref()
            .is_none_or(|set| set.leases != leases);
        if changed && !leases.is_empty() {
            self.lease_set = Some(LeaseSet::build(
                &self.keys,
                (now_ms() / 1000) as u32,
                &leases,
                true,
            ));
        }
    }

    pub fn has_lease_set(&self) -> bool {
        self.lease_set.is_some()
    }

    pub fn lease_set(&self) -> Option<&LeaseSet> {
        self.lease_set.as_ref()
    }

    /// Opens a stream to `remote` on `port`, sending `data` with the SYN.
    pub fn open_stream(
        &mut self,
        remote: &LeaseSet,
        port: u16,
        data: &[u8],
        events: UnboundedSender<StreamEvent>,
    ) -> u32 {
        let id = random_id();
        let mut stream = Stream::new(id, *remote.hash());
        let syn = stream.syn(&self.keys, data, now_ms());
        self.streams.insert(
            id,
            StreamEntry {
                stream,
                remote: *remote.hash(),
                port,
                events,
            },
        );
        let session = self.sessions.entry(*remote.hash()).or_insert(Session {
            established: None,
            pending: Vec::new(),
            lease_set: remote.clone(),
            sent_lease_set: 0,
        });
        if remote.published > session.lease_set.published {
            session.lease_set = remote.clone();
        }
        self.send_packet(*remote.hash(), port, &syn);
        id
    }

    pub fn stream_send(&mut self, id: u32, data: &[u8]) {
        let Some(entry) = self.streams.get_mut(&id) else {
            return;
        };
        let packets = entry.stream.send(data, now_ms());
        let (remote, port) = (entry.remote, entry.port);
        for packet in packets {
            self.send_packet(remote, port, &packet);
        }
    }

    pub fn stream_close(&mut self, id: u32) {
        let Some(entry) = self.streams.get_mut(&id) else {
            return;
        };
        let packet = entry.stream.close(now_ms());
        let (remote, port) = (entry.remote, entry.port);
        self.send_packet(remote, port, &packet);
    }

    /// Sends a streaming packet. Our lease set rides along until the remote
    /// has the current one, so it knows where to answer.
    fn send_packet(&mut self, remote: [u8; 32], port: u16, packet: &[u8]) {
        let message = data_message(packet, 0, port);
        let mut blocks = garlic::date_time_block();
        let own = self.lease_set.as_ref().filter(|own| {
            self.sessions.get(&remote).is_none_or(|session| {
                session.established.is_none() || session.sent_lease_set < own.published
            })
        });
        if let Some(own) = own {
            let store = DatabaseStore {
                key: *own.hash(),
                kind: i2np::STORE_LEASE_SET2,
                reply_token: 0,
                data: own.raw.clone(),
            };
            blocks.extend(garlic::clove(
                CloveDelivery::Local,
                &Message::new(i2np::DATABASE_STORE, store.encode()),
            ));
        }
        blocks.extend(garlic::clove(CloveDelivery::Destination(remote), &message));
        self.send_garlic(remote, blocks);
    }

    /// Seals a garlic payload for `remote`: an existing-session message once
    /// a reply came, a new session before that.
    fn send_garlic(&mut self, remote: [u8; 32], blocks: Vec<u8>) {
        let Some(session) = self.sessions.get_mut(&remote) else {
            return;
        };
        let new_session = session.established.is_none();
        if let Some(own) = &self.lease_set {
            session.sent_lease_set = own.published;
        }
        let sealed = match &mut session.established {
            Some(ratchet) => ratchet.seal(&blocks).expect("an established session seals"),
            None => {
                let Some(key) = session.lease_set.encryption_key else {
                    return;
                };
                let (ratchet, message) =
                    OutboundSession::start(&self.keys.encryption, &key, &blocks);
                for tag in ratchet.tags() {
                    self.tags.insert(tag, remote);
                }
                if session.pending.len() == PENDING_SESSIONS {
                    let oldest = session.pending.remove(0);
                    for tag in oldest.tags() {
                        self.tags.remove(&tag);
                    }
                }
                session.pending.push(ratchet);
                message
            }
        };
        let now = (now_ms() / 1000) as u32;
        let leases = session.lease_set.live_leases(now, 10);
        let Some(&lease) = leases.get((i2np::random_u32() as usize) % leases.len().max(1)) else {
            return;
        };
        if new_session {
            self.trace.push(format!(
                "new session to {} through {}",
                short(&remote),
                short(&lease.gateway)
            ));
        }
        let mut payload = (sealed.len() as u32).to_be_bytes().to_vec();
        payload.extend_from_slice(&sealed);
        self.outgoing.push(Outgoing {
            lease,
            garlic: Message::new(i2np::GARLIC, payload),
        });
    }

    /// Garlic messages ready to go.
    pub fn take_outgoing(&mut self) -> Vec<Outgoing> {
        std::mem::take(&mut self.outgoing)
    }

    /// Opens a garlic message under one of our session tags. Returns false
    /// when no session of this destination has the tag.
    pub fn handle_garlic(&mut self, payload: &[u8]) -> bool {
        let Some(sealed) = payload.get(4..) else {
            return false;
        };
        let Some(tag) = sealed
            .get(..8)
            .and_then(|tag| <[u8; 8]>::try_from(tag).ok())
        else {
            return false;
        };
        let Some(&remote) = self.tags.get(&tag) else {
            return false;
        };
        let Some(session) = self.sessions.get_mut(&remote) else {
            return false;
        };
        let blocks = match &mut session.established {
            Some(ratchet) => ratchet.open(&self.keys.encryption, sealed),
            None => None,
        };
        let blocks = match blocks {
            Some(blocks) => blocks,
            None => {
                // A reply to one of the new sessions: it becomes the session
                // and the others are dropped.
                let Some((index, blocks)) =
                    session
                        .pending
                        .iter_mut()
                        .enumerate()
                        .find_map(|(index, ratchet)| {
                            Some((index, ratchet.open(&self.keys.encryption, sealed)?))
                        })
                else {
                    self.trace
                        .push(format!("garlic from {} did not open", short(&remote)));
                    return true;
                };
                self.trace.push(format!("{} answered", short(&remote)));
                let answered = session.pending.swap_remove(index);
                for other in session.pending.drain(..) {
                    for tag in other.tags() {
                        self.tags.remove(&tag);
                    }
                }
                session.established = Some(answered);
                blocks
            }
        };
        if let Some(ratchet) = &session.established {
            for tag in ratchet.tags() {
                self.tags.insert(tag, remote);
            }
        }
        for (_, message) in garlic::cloves(&blocks) {
            self.handle_clove(message);
        }
        true
    }

    fn handle_clove(&mut self, message: Message) {
        match message.kind {
            i2np::DATA => self.handle_data(&message.payload),
            i2np::DATABASE_STORE => {
                if let Some(store) = DatabaseStore::decode(&message.payload)
                    && let Some(set) = LeaseSet::parse(&store.data)
                {
                    if let Some(session) = self.sessions.get_mut(set.hash())
                        && set.published > session.lease_set.published
                    {
                        session.lease_set = set.clone();
                    }
                    self.learned.push(set);
                }
            }
            _ => {}
        }
    }

    fn handle_data(&mut self, payload: &[u8]) {
        let Some(gzip) = payload.get(4..) else {
            return;
        };
        if gzip.get(9) != Some(&streaming::PROTOCOL) {
            return;
        }
        let Some(bytes) = i2np::gunzip(gzip) else {
            return;
        };
        let Some(packet) = Packet::decode(&bytes) else {
            self.trace.push(format!(
                "a streaming packet of {} bytes did not decode",
                bytes.len()
            ));
            return;
        };
        let Some(entry) = self.streams.get_mut(&packet.send_stream) else {
            return;
        };
        let arrival = entry.stream.arrive(packet);
        if arrival.opened {
            let _ = entry.events.send(StreamEvent::Opened);
        }
        if !arrival.data.is_empty() {
            let _ = entry.events.send(StreamEvent::Data(arrival.data));
        }
        if arrival.closed {
            let _ = entry.events.send(StreamEvent::Closed);
        }
        let ack = arrival.ack.then(|| entry.stream.ack()).flatten();
        let (remote, port) = (entry.remote, entry.port);
        if let Some(ack) = ack {
            self.send_packet(remote, port, &ack);
        }
    }

    /// Resends what was not acknowledged and drops finished streams.
    pub fn tick(&mut self) {
        let now = now_ms();
        let mut resends = Vec::new();
        let mut failed = Vec::new();
        for (id, entry) in &mut self.streams {
            match entry.stream.resend(now, &self.keys) {
                Some(packets) => {
                    for packet in packets {
                        resends.push((entry.remote, entry.port, packet));
                    }
                }
                None => failed.push(*id),
            }
        }
        for id in failed {
            if let Some(entry) = self.streams.remove(&id) {
                let _ = entry.events.send(StreamEvent::Failed(
                    "the remote destination stopped answering".to_owned(),
                ));
            }
        }
        for (remote, port, packet) in resends {
            self.send_packet(remote, port, &packet);
        }
        self.streams
            .retain(|_, entry| !entry.stream.is_finished() && !entry.events.is_closed());
    }
}
