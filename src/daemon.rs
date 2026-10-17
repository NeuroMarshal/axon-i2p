//! The router as a long-running process, set up from a TOML file.
//!
//! Local programs reach I2P sites through a SOCKS5 proxy or an HTTP proxy.
//! Both take `name.i2p` names from the address book and `<base32>.b32.i2p`
//! names directly; nothing leaves for the clearnet. The address book fills
//! from the hosts.txt files of its subscriptions, fetched through I2P.

use std::{
    fmt, fs, io,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::Duration,
};

use axon_runtime::{
    RuntimeError,
    http::{self, Response, Rewrite},
    socks::{self, Host, Reply},
};
use serde::Deserialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{sleep, timeout},
};

use crate::{
    addressbook::AddressBook,
    plane::Targets,
    reseed::{self, ReseedError},
    router::I2pRouter,
    router_info::RouterInfo,
};

/// What the HTTP proxy sends as every program's User-Agent, the same value
/// other I2P proxies send.
pub const USER_AGENT: &str = "MYOB/6.66 (AN/ON)";
/// Headers the HTTP proxy drops because they tell sites where a visitor
/// comes from.
const DROPPED_HEADERS: [&str; 7] = [
    "referer",
    "via",
    "from",
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-server",
];
/// How long a connection may wait for tunnels and the site's lease set.
const CONNECT_WAIT: Duration = Duration::from_secs(60);
/// A cached router list older than this is replaced by a new reseed.
const ROUTER_CACHE_AGE: Duration = Duration::from_secs(24 * 3600);
/// A cached router list with fewer routers is not enough to start from.
const ROUTER_CACHE_MINIMUM: usize = 50;
const STATUS_INTERVAL: Duration = Duration::from_secs(60);

fn default_inbound() -> usize {
    2
}

fn default_hops() -> usize {
    3
}

fn default_refresh_hours() -> u64 {
    12
}

fn default_subscriptions() -> Vec<String> {
    vec![
        "http://i2p-projekt.i2p/hosts.txt".to_owned(),
        "http://stats.i2p/cgi-bin/newhosts.txt".to_owned(),
    ]
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Where the address book and the known routers are kept.
    pub data_dir: PathBuf,
    /// A SOCKS5 proxy for local programs.
    pub socks: Option<SocketAddr>,
    /// An HTTP proxy for browsers.
    pub http_proxy: Option<SocketAddr>,
    #[serde(default)]
    pub tunnels: TunnelConfig,
    #[serde(default)]
    pub addressbook: AddressBookConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelConfig {
    #[serde(default = "default_inbound")]
    pub inbound: usize,
    #[serde(default = "default_inbound")]
    pub outbound: usize,
    /// Routers in each tunnel, 1 to 4. Fewer is faster and less anonymous.
    #[serde(default = "default_hops")]
    pub hops: usize,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            inbound: default_inbound(),
            outbound: default_inbound(),
            hops: default_hops(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddressBookConfig {
    /// hosts.txt files to merge into the address book.
    #[serde(default = "default_subscriptions")]
    pub subscriptions: Vec<String>,
    #[serde(default = "default_refresh_hours")]
    pub refresh_hours: u64,
}

impl Default for AddressBookConfig {
    fn default() -> Self {
        Self {
            subscriptions: default_subscriptions(),
            refresh_hours: default_refresh_hours(),
        }
    }
}

#[derive(Debug)]
pub enum DaemonError {
    Config(String),
    Io(io::Error),
    Reseed(ReseedError),
    Runtime(RuntimeError),
}

impl fmt::Display for DaemonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(message) => write!(formatter, "configuration: {message}"),
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Reseed(error) => write!(formatter, "reseed: {error}"),
            Self::Runtime(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for DaemonError {}

impl From<io::Error> for DaemonError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<RuntimeError> for DaemonError {
    fn from(error: RuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl Config {
    /// Reads a configuration file. A relative `data_dir` is taken from the
    /// file's directory.
    pub fn load(path: &Path) -> Result<Self, DaemonError> {
        let text = fs::read_to_string(path)?;
        let mut config: Self =
            toml::from_str(&text).map_err(|error| DaemonError::Config(error.to_string()))?;
        if config.data_dir.is_relative()
            && let Some(directory) = path.parent()
        {
            config.data_dir = directory.join(&config.data_dir);
        }
        if config.socks.is_none() && config.http_proxy.is_none() {
            return Err(DaemonError::Config(
                "set socks, http_proxy or both".to_owned(),
            ));
        }
        Ok(config)
    }
}

/// Routers saved by an earlier run, if the list is recent and long enough.
fn cached_routers(path: &Path) -> Option<Vec<RouterInfo>> {
    let age = fs::metadata(path).ok()?.modified().ok()?.elapsed().ok()?;
    if age > ROUTER_CACHE_AGE {
        return None;
    }
    let bytes = fs::read(path).ok()?;
    let mut routers = Vec::new();
    let mut rest = bytes.as_slice();
    while rest.len() >= 4 {
        let length = u32::from_be_bytes(rest[..4].try_into().expect("4 bytes")) as usize;
        let info = rest.get(4..4 + length)?;
        routers.extend(RouterInfo::parse(info));
        rest = &rest[4 + length..];
    }
    (routers.len() >= ROUTER_CACHE_MINIMUM).then_some(routers)
}

/// Saves router infos as length-prefixed records.
fn save_routers(path: &Path, routers: &[Vec<u8>]) -> io::Result<()> {
    let mut bytes = Vec::new();
    for raw in routers {
        bytes.extend_from_slice(&(raw.len() as u32).to_be_bytes());
        bytes.extend_from_slice(raw);
    }
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, bytes)?;
    fs::rename(temporary, path)
}

type Book = Arc<RwLock<AddressBook>>;

fn resolve(book: &Book, host: &str) -> Option<[u8; 32]> {
    book.read().ok()?.resolve(host)
}

async fn serve_socks(router: I2pRouter, book: Book, mut stream: TcpStream) -> io::Result<()> {
    let target = socks::accept(&mut stream).await?;
    let Host::Name(name) = &target.host else {
        return socks::reply(&mut stream, Reply::NotAllowed).await;
    };
    let Some(hash) = resolve(&book, name) else {
        return socks::reply(&mut stream, Reply::HostUnreachable).await;
    };
    match router
        .connect(hash, target.port, Vec::new(), CONNECT_WAIT)
        .await
    {
        Ok(mut site) => {
            socks::reply(&mut stream, Reply::Succeeded).await?;
            tokio::io::copy_bidirectional(&mut stream, &mut site).await?;
            Ok(())
        }
        Err(_) => socks::reply(&mut stream, Reply::HostUnreachable).await,
    }
}

async fn serve_http(router: I2pRouter, book: Book, mut stream: TcpStream) -> io::Result<()> {
    let rewrite = Rewrite {
        user_agent: Some(USER_AGENT),
        drop: &DROPPED_HEADERS,
    };
    let request = match http::accept_proxy_request(&mut stream, &rewrite).await {
        Ok(request) => request,
        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
            let page = http::status_page(400, "Bad Request", &error.to_string());
            return stream.write_all(&page).await;
        }
        Err(error) => return Err(error),
    };
    let host = request.target.host.to_string();
    let Some(hash) = resolve(&book, &host) else {
        let message = format!("{host} is not in the address book and is not a b32 name");
        let page = http::status_page(404, "Not Found", &message);
        return stream.write_all(&page).await;
    };
    // A plain request rides with the SYN.
    let first = if request.tunnel {
        Vec::new()
    } else {
        request.forward.clone()
    };
    let mut site = match router
        .connect(hash, request.target.port, first, CONNECT_WAIT)
        .await
    {
        Ok(site) => site,
        Err(error) => {
            let page = http::status_page(504, "Gateway Timeout", &format!("{host}: {error}"));
            return stream.write_all(&page).await;
        }
    };
    if request.tunnel {
        stream
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await?;
        site.write_all(&request.forward).await?;
    }
    tokio::io::copy_bidirectional(&mut stream, &mut site).await?;
    Ok(())
}

async fn listen<F, Fut>(
    address: SocketAddr,
    router: I2pRouter,
    book: Book,
    serve: F,
) -> io::Result<()>
where
    F: Fn(I2pRouter, Book, TcpStream) -> Fut + Send + Copy + 'static,
    Fut: Future<Output = io::Result<()>> + Send + 'static,
{
    let listener = TcpListener::bind(address).await?;
    loop {
        let (stream, _) = listener.accept().await?;
        let (router, book) = (router.clone(), book.clone());
        tokio::spawn(async move {
            let _ = serve(router, book, stream).await;
        });
    }
}

/// Downloads a hosts.txt file through I2P.
async fn fetch_hosts(router: &I2pRouter, book: &Book, url: &str) -> Result<String, String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or("subscriptions are http:// URLs")?;
    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
    let hash = resolve(book, host).ok_or_else(|| format!("{host} is unknown"))?;
    let request = format!(
        "GET /{path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\nConnection: close\r\n\r\n"
    );
    let mut site = router
        .connect(hash, 80, request.into_bytes(), CONNECT_WAIT)
        .await
        .map_err(|error| error.to_string())?;
    let mut raw = Vec::new();
    timeout(Duration::from_secs(300), site.read_to_end(&mut raw))
        .await
        .map_err(|_| "the download timed out".to_owned())?
        .map_err(|error| error.to_string())?;
    let response = Response::parse(&raw).map_err(|error| error.to_string())?;
    if response.status != 200 {
        return Err(format!("{host} answered {}", response.status));
    }
    Ok(String::from_utf8_lossy(&response.body).into_owned())
}

/// Merges the subscriptions into the address book now and then.
async fn refresh_addressbook(
    router: I2pRouter,
    book: Book,
    config: AddressBookConfig,
    path: PathBuf,
) {
    loop {
        for url in &config.subscriptions {
            match fetch_hosts(&router, &book, url).await {
                Ok(text) => {
                    let added = book
                        .write()
                        .map(|mut book| book.add_hosts(&text))
                        .unwrap_or(0);
                    eprintln!("address book: {added} new names from {url}");
                    let saved = book.read().map(|book| book.save(&path));
                    if let Ok(Err(error)) = saved {
                        eprintln!("address book: could not save: {error}");
                    }
                }
                Err(error) => eprintln!("address book: {url}: {error}"),
            }
        }
        sleep(Duration::from_secs(config.refresh_hours.max(1) * 3600)).await;
    }
}

/// Prints the router's state and saves the routers it knows.
async fn report(router: I2pRouter, routers_path: PathBuf) {
    loop {
        sleep(STATUS_INTERVAL).await;
        let Ok((status, routers)) = router
            .with_plane(|plane| {
                let routers = plane
                    .netdb()
                    .routers()
                    .map(|info| info.raw.clone())
                    .collect::<Vec<_>>();
                (plane.status(), routers)
            })
            .await
        else {
            return;
        };
        eprintln!(
            "{} routers known, {} links, tunnels {} in / {} out ({} built, {} failed)",
            status.routers,
            status.links,
            status.inbound,
            status.outbound,
            status.built,
            status.failed
        );
        if let Err(error) = save_routers(&routers_path, &routers) {
            eprintln!("could not save the router list: {error}");
        }
    }
}

/// Runs the router until interrupted.
pub async fn run(config: Config) -> Result<(), DaemonError> {
    fs::create_dir_all(&config.data_dir)?;
    let routers_path = config.data_dir.join("routers.dat");
    let book_path = config.data_dir.join("names.txt");

    let routers = match cached_routers(&routers_path) {
        Some(routers) => routers,
        None => {
            eprintln!("downloading router infos from the reseed servers");
            let routers = reseed::fetch(reseed::RESEED_URLS)
                .await
                .map_err(DaemonError::Reseed)?;
            let raw = routers
                .iter()
                .map(|info| info.raw.clone())
                .collect::<Vec<_>>();
            save_routers(&routers_path, &raw)?;
            routers
        }
    };
    eprintln!("starting with {} routers", routers.len());
    let router = I2pRouter::start(routers)?;
    let destination = router
        .start_client(Targets {
            inbound: config.tunnels.inbound,
            outbound: config.tunnels.outbound,
            inbound_hops: config.tunnels.hops,
            outbound_hops: config.tunnels.hops,
        })
        .await?;
    eprintln!("client destination {}", crate::data::b32_name(&destination));

    let mut book = AddressBook::load(&book_path)?;
    eprintln!("address book: {} saved names", book.len());
    book.add_bootstrap();
    let book = Arc::new(RwLock::new(book));

    if let Some(address) = config.socks {
        let (router, book) = (router.clone(), book.clone());
        tokio::spawn(async move {
            if let Err(error) = listen(address, router, book, serve_socks).await {
                eprintln!("SOCKS proxy on {address}: {error}");
            }
        });
        eprintln!("SOCKS5 proxy on {address}");
    }
    if let Some(address) = config.http_proxy {
        let (router, book) = (router.clone(), book.clone());
        tokio::spawn(async move {
            if let Err(error) = listen(address, router, book, serve_http).await {
                eprintln!("HTTP proxy on {address}: {error}");
            }
        });
        eprintln!("HTTP proxy on {address}");
    }
    tokio::spawn(refresh_addressbook(
        router.clone(),
        book.clone(),
        config.addressbook,
        book_path,
    ));
    tokio::spawn(report(router.clone(), routers_path));

    tokio::signal::ctrl_c().await?;
    Ok(())
}
