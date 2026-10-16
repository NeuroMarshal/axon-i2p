//! A running I2P router: an Axon node whose forwarding plane is
//! [`I2pPlane`] and whose links speak NTCP2, on the current tokio runtime.

use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
    time::Duration,
};

use axon_addons::{
    keys::ExchangeSecret,
    wire::{ForeignLink, foreign_link},
};
use axon_core::node::{EdgeId, ExtensionId, NodeCore};
use axon_runtime::{NodeHandle, RuntimeConfig, RuntimeError};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    net::TcpStream,
    sync::mpsc,
    time::{Instant, sleep, timeout, timeout_at},
};

use crate::{
    data,
    destination::StreamEvent,
    identity::PrivateIdentity,
    ntcp2::{LocalRouter, Ntcp2, Remote},
    plane::{I2P_PLANE, I2P_PLANE_VERSION, I2pPlane, LookupKind, LookupState, Targets, node_of},
    router_info::{Ntcp2Address, RouterAddress, RouterInfo},
    streaming::MTU,
};

/// Extension id of NTCP2 links.
pub const NTCP2_LINK: ExtensionId = ExtensionId(0x4e54_4332); // NTC2
/// Largest I2NP message a link carries, with room for the header.
const MAXIMUM_ENVELOPE: usize = 64 * 1024 + 64;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(100);
/// The version this router claims; peers refuse very old ones.
pub const ROUTER_VERSION: &str = "0.9.70";

/// Our router info: an NTCP2 address without host or port (we only dial
/// out), marked unreachable.
pub fn our_router_info(keys: &PrivateIdentity, static_key: &ExchangeSecret) -> RouterInfo {
    let address = RouterAddress {
        cost: 14,
        transport: "NTCP2".into(),
        options: vec![
            ("caps".into(), "4".into()),
            ("s".into(), data::base64().encode(&static_key.public().0)),
            ("v".into(), "2".into()),
        ],
    };
    RouterInfo::build(
        keys,
        data::now_ms(),
        vec![address],
        vec![
            ("caps".into(), "LU".into()),
            ("netId".into(), "2".into()),
            ("router.version".into(), ROUTER_VERSION.into()),
        ],
    )
}

#[derive(Clone)]
pub struct I2pRouter {
    handle: NodeHandle,
    local: Arc<LocalRouter>,
    hash: [u8; 32],
}

impl I2pRouter {
    /// Starts a router that knows `routers`, usually from a reseed.
    pub fn start(routers: Vec<RouterInfo>) -> Result<Self, RuntimeError> {
        let keys = PrivateIdentity::generate_router();
        let static_key =
            ExchangeSecret::generate().map_err(|e| RuntimeError::Node(e.to_string()))?;
        let info = our_router_info(&keys, &static_key);
        let hash = *keys.identity.hash();
        let local = Arc::new(LocalRouter {
            static_key,
            router_info: info.raw,
        });
        let core = NodeCore::builder(node_of(&hash), I2pPlane::new(keys, routers)).build()?;
        let handle = axon_runtime::spawn(core, RuntimeConfig::default());
        let router = Self {
            handle,
            local,
            hash,
        };
        tokio::spawn(router.clone().dial_loop());
        Ok(router)
    }

    pub fn handle(&self) -> &NodeHandle {
        &self.handle
    }

    pub const fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    /// Runs `call` on the plane inside the node and sends what it queued.
    pub async fn with_plane<R: Send + 'static>(
        &self,
        call: impl FnOnce(&mut I2pPlane) -> R + Send + 'static,
    ) -> Result<R, RuntimeError> {
        self.handle
            .with_core(move |core, now| {
                let plane = core.forwarding_mut::<I2pPlane>().expect("an I2P router");
                let result = call(plane);
                let _ = core.poll_forwarding(now);
                result
            })
            .await
    }

    /// Creates the client destination and the tunnels it needs.
    pub async fn start_client(&self, targets: Targets) -> Result<[u8; 32], RuntimeError> {
        let keys = PrivateIdentity::generate_destination();
        let hash = *keys.identity.hash();
        self.with_plane(move |plane| {
            plane.set_client(keys);
            plane.set_targets(targets);
        })
        .await?;
        Ok(hash)
    }

    /// Waits until the client destination has tunnels both ways.
    pub async fn client_ready(&self, deadline: Instant) -> Result<(), RuntimeError> {
        while !self.with_plane(|plane| plane.client_ready()).await? {
            if Instant::now() > deadline {
                return Err(RuntimeError::Node(
                    "no tunnels for the client yet".to_owned(),
                ));
            }
            sleep(POLL_INTERVAL).await;
        }
        Ok(())
    }

    /// Finds the lease set of the destination with hash `remote`.
    pub async fn find_lease_set(
        &self,
        remote: [u8; 32],
        deadline: Instant,
    ) -> Result<(), RuntimeError> {
        self.with_plane(move |plane| plane.lookup(remote, LookupKind::LeaseSet))
            .await?;
        loop {
            match self
                .with_plane(move |plane| plane.lookup_state(&remote))
                .await?
            {
                Some(LookupState::Found) => return Ok(()),
                Some(LookupState::Failed) => {
                    return Err(RuntimeError::Node(
                        "no floodfill knows the destination".to_owned(),
                    ));
                }
                _ if Instant::now() > deadline => {
                    return Err(RuntimeError::Node("the lookup timed out".to_owned()));
                }
                _ => sleep(POLL_INTERVAL).await,
            }
        }
    }

    /// Opens a stream from the client destination to `remote` on `port`,
    /// sending `first` with the SYN, and waits until the remote answers.
    /// The returned end reads and writes the stream's bytes.
    pub async fn connect(
        &self,
        remote: [u8; 32],
        port: u16,
        first: Vec<u8>,
        wait: Duration,
    ) -> Result<DuplexStream, RuntimeError> {
        let deadline = Instant::now() + wait;
        self.client_ready(deadline).await?;
        self.find_lease_set(remote, deadline).await?;
        let (events, mut arrivals) = mpsc::unbounded_channel();
        let id = self
            .with_plane(move |plane| plane.open_stream(remote, port, &first, events))
            .await?
            .ok_or_else(|| RuntimeError::Node("the lease set expired".to_owned()))?;
        let first_event = match timeout_at(deadline, arrivals.recv()).await {
            Ok(Some(StreamEvent::Failed(reason))) => return Err(RuntimeError::Node(reason)),
            Ok(Some(event)) => event,
            Ok(None) => return Err(RuntimeError::Node("the stream was dropped".to_owned())),
            Err(_) => return Err(RuntimeError::Node("the site did not answer".to_owned())),
        };
        let (local, ours) = tokio::io::duplex(4 * MTU);
        tokio::spawn(self.clone().carry(id, ours, first_event, arrivals));
        Ok(local)
    }

    /// Moves bytes between a local stream end and an I2P stream.
    async fn carry(
        self,
        id: u32,
        mut local: DuplexStream,
        first_event: StreamEvent,
        mut arrivals: mpsc::UnboundedReceiver<StreamEvent>,
    ) {
        let mut buffer = vec![0u8; MTU];
        let mut sending = true;
        let mut next = Some(first_event);
        loop {
            let event = match next.take() {
                Some(event) => Some(event),
                None => tokio::select! {
                    read = local.read(&mut buffer), if sending => {
                        match read {
                            Ok(0) | Err(_) => {
                                sending = false;
                                let _ = self.with_plane(move |plane| plane.stream_close(id)).await;
                            }
                            Ok(read) => {
                                let data = buffer[..read].to_vec();
                                if self.with_plane(move |plane| plane.stream_send(id, &data)).await.is_err() {
                                    return;
                                }
                            }
                        }
                        continue;
                    }
                    event = arrivals.recv() => event,
                },
            };
            match event {
                Some(StreamEvent::Opened) => {}
                Some(StreamEvent::Data(data)) => {
                    if local.write_all(&data).await.is_err() {
                        let _ = self.with_plane(move |plane| plane.stream_close(id)).await;
                        return;
                    }
                }
                Some(StreamEvent::Closed) => {
                    let _ = local.shutdown().await;
                    if !sending {
                        return;
                    }
                }
                Some(StreamEvent::Failed(_)) | None => return,
            }
        }
    }

    /// Opens NTCP2 links to the routers the plane has messages for.
    async fn dial_loop(self) {
        let dialing = Arc::new(Mutex::new(BTreeSet::<[u8; 32]>::new()));
        loop {
            let Ok(wanted) = self.with_plane(|plane| plane.wanted_connections()).await else {
                return;
            };
            for (router, address) in wanted {
                if !dialing.lock().is_ok_and(|mut set| set.insert(router)) {
                    continue;
                }
                let (this, dialing) = (self.clone(), dialing.clone());
                tokio::spawn(async move {
                    if this.dial(router, address).await.is_err() {
                        let _ = this
                            .with_plane(move |plane| plane.connection_failed(router))
                            .await;
                    }
                    if let Ok(mut set) = dialing.lock() {
                        set.remove(&router);
                    }
                });
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn dial(&self, router: [u8; 32], address: Ntcp2Address) -> Result<(), RuntimeError> {
        let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(address.address))
            .await
            .map_err(|_| RuntimeError::Io("connect timed out".to_owned()))?
            .map_err(|error| RuntimeError::Io(error.to_string()))?;
        let link = foreign_link(
            ForeignLink {
                neighbour: node_of(&router),
                edge: EdgeId(u64::from_be_bytes(router[..8].try_into().expect("fixed"))),
                id: NTCP2_LINK,
                forwarding_id: I2P_PLANE,
                forwarding_version: I2P_PLANE_VERSION,
                maximum_envelope: MAXIMUM_ENVELOPE,
            },
            Ntcp2::new(
                self.local.clone(),
                Remote {
                    hash: router,
                    address,
                },
            ),
        );
        self.handle.attach_tcp(link, stream).await
    }
}
