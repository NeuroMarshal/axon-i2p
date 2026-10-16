//! Checks against the real I2P network. They need internet access and take
//! a while, so they only run when asked for: `cargo test -- --ignored`.

use axon_i2p::reseed;

#[tokio::test]
#[ignore = "needs the real I2P network"]
async fn reseed_gives_signed_router_infos() {
    let infos = reseed::fetch(reseed::RESEED_URLS).await.unwrap();
    assert!(infos.len() > 20, "{} router infos", infos.len());
    let floodfills = infos.iter().filter(|info| info.is_floodfill()).count();
    let reachable = infos.iter().filter(|info| info.ntcp2().is_some()).count();
    println!(
        "{} router infos, {floodfills} floodfills, {reachable} with NTCP2",
        infos.len()
    );
    assert!(floodfills > 0 && reachable > 0);
}

mod ntcp2_live {
    use std::sync::Arc;

    use axon_addons::{keys::ExchangeSecret, wire::WireProtocol};
    use axon_core::time::Instant;
    use axon_i2p::{
        data, i2np,
        identity::PrivateIdentity,
        ntcp2::{LocalRouter, Ntcp2, Remote},
        reseed,
        router_info::{RouterAddress, RouterInfo},
    };
    use bytes::Bytes;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
        time::{Duration, timeout},
    };

    fn our_router() -> (PrivateIdentity, LocalRouter) {
        let keys = PrivateIdentity::generate_router();
        let static_key = ExchangeSecret::generate().unwrap();
        let address = RouterAddress {
            cost: 14,
            transport: "NTCP2".into(),
            options: vec![
                ("caps".into(), "4".into()),
                ("s".into(), data::base64().encode(&static_key.public().0)),
                ("v".into(), "2".into()),
            ],
        };
        let info = RouterInfo::build(
            &keys,
            data::now_ms(),
            vec![address],
            vec![
                ("caps".into(), "LU".into()),
                ("netId".into(), "2".into()),
                ("router.version".into(), "0.9.70".into()),
            ],
        );
        (
            keys,
            LocalRouter {
                static_key,
                router_info: info.raw,
            },
        )
    }

    #[tokio::test]
    #[ignore = "needs the real I2P network"]
    async fn a_real_floodfill_answers_a_lookup_over_ntcp2() {
        let infos = reseed::fetch(reseed::RESEED_URLS).await.unwrap();
        let (keys, local) = our_router();
        let local = Arc::new(local);
        let floodfills = infos
            .iter()
            .filter(|info| info.is_floodfill() && info.ntcp2().is_some())
            .collect::<Vec<_>>();
        let target = infos.iter().find(|info| !info.is_floodfill()).unwrap();
        let mut answered = 0;
        for floodfill in floodfills.iter().take(6) {
            let address = floodfill.ntcp2().unwrap();
            let Ok(Ok(mut stream)) =
                timeout(Duration::from_secs(5), TcpStream::connect(address.address)).await
            else {
                println!("{}: no TCP connection", address.address);
                continue;
            };
            let mut link = Ntcp2::new(
                local.clone(),
                Remote {
                    hash: *floodfill.hash(),
                    address,
                },
            );
            let now = Instant::from_nanos(1);
            let lookup = i2np::Message::new(
                i2np::DATABASE_LOOKUP,
                i2np::DatabaseLookup {
                    key: *target.hash(),
                    from: *keys.identity.hash(),
                    lookup: i2np::LOOKUP_ROUTER_INFO,
                    reply_tunnel: None,
                    exclude: Vec::new(),
                    reply_key: None,
                }
                .encode(),
            );
            let mut out = link.start(now).unwrap().transmit;
            out.extend(link.send(lookup.encode(), now).unwrap().transmit);
            for unit in out {
                stream.write_all(&unit).await.unwrap();
            }
            let mut buffer = vec![0u8; 65536];
            let result = timeout(Duration::from_secs(15), async {
                loop {
                    let read = stream.read(&mut buffer).await.map_err(|e| e.to_string())?;
                    if read == 0 {
                        return Err("closed by the peer".to_owned());
                    }
                    let output = link.receive(Bytes::copy_from_slice(&buffer[..read]), now)?;
                    for unit in output.transmit {
                        stream.write_all(&unit).await.map_err(|e| e.to_string())?;
                    }
                    for envelope in output.envelopes {
                        let message = i2np::Message::decode(&envelope).unwrap();
                        if message.kind == i2np::DATABASE_STORE {
                            let store = i2np::DatabaseStore::decode(&message.payload).unwrap();
                            let info = RouterInfo::parse(&store.data).unwrap();
                            return Ok(format!(
                                "store of {}",
                                data::base64().encode(&info.hash()[..4])
                            ));
                        }
                        if message.kind == i2np::DATABASE_SEARCH_REPLY {
                            let reply = i2np::SearchReply::decode(&message.payload).unwrap();
                            return Ok(format!("search reply with {} peers", reply.peers.len()));
                        }
                    }
                }
            })
            .await;
            println!(
                "{} {}: {:?}",
                address.address,
                floodfill.option("router.version").unwrap_or("?"),
                result
            );
            if matches!(result, Ok(Ok(_))) {
                answered += 1;
            }
        }
        assert!(answered > 0);
    }
}

mod router_live {
    use std::time::Duration;

    use axon_i2p::{
        data,
        plane::{LookupKind, LookupState},
        reseed,
        router::I2pRouter,
    };

    /// i2p-projekt.i2p, the I2P project's site.
    const I2P_PROJECT: &str = "udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna.b32.i2p";

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs the real I2P network"]
    async fn the_router_finds_a_lease_set_through_the_floodfills() {
        let routers = reseed::fetch(reseed::RESEED_URLS).await.unwrap();
        let router = I2pRouter::start(routers).unwrap();
        let key = data::parse_b32_name(I2P_PROJECT).unwrap();
        router
            .with_plane(move |plane| plane.lookup(key, LookupKind::LeaseSet))
            .await
            .unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        loop {
            let state = router
                .with_plane(move |plane| plane.lookup_state(&key))
                .await
                .unwrap();
            match state {
                Some(LookupState::Found) => break,
                Some(LookupState::Failed) => {
                    for line in router.with_plane(|plane| plane.take_trace()).await.unwrap() {
                        println!("  {line}");
                    }
                    panic!("lookup failed");
                }
                _ => {}
            }
            assert!(tokio::time::Instant::now() < deadline, "lookup timed out");
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let (leases, has_key, known) = router
            .with_plane(move |plane| {
                let set = plane.lease_set(&key).unwrap();
                (
                    set.leases.len(),
                    set.encryption_key.is_some(),
                    plane.netdb().len(),
                )
            })
            .await
            .unwrap();
        println!("lease set: {leases} leases, X25519 key: {has_key}; {known} routers known");
        assert!(leases > 0);
    }
}

mod tunnels_live {
    use std::time::Duration;

    use axon_i2p::{reseed, router::I2pRouter};

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs the real I2P network"]
    async fn real_routers_accept_our_tunnels() {
        let routers = reseed::fetch(reseed::RESEED_URLS).await.unwrap();
        let router = I2pRouter::start(routers).unwrap();
        router
            .with_plane(|plane| {
                plane.set_tunnels(
                    2,
                    2,
                    std::env::var("HOPS")
                        .ok()
                        .and_then(|h| h.parse().ok())
                        .unwrap_or(2),
                )
            })
            .await
            .unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        let status = loop {
            let status = router.with_plane(|plane| plane.status()).await.unwrap();
            if status.inbound >= 1 && status.outbound >= 1 {
                break status;
            }
            if tokio::time::Instant::now() > deadline {
                for line in router.with_plane(|plane| plane.take_trace()).await.unwrap() {
                    println!("  {line}");
                }
                panic!("no tunnels: {status:?}");
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        };
        for line in router.with_plane(|plane| plane.take_trace()).await.unwrap() {
            println!("  {line}");
        }
        println!("{status:?}");
    }
}

mod stream_live {
    use std::time::Duration;

    use axon_i2p::{data, plane::Targets, reseed, router::I2pRouter};
    use tokio::io::AsyncReadExt;

    /// i2p-projekt.i2p, the I2P project's site. `SITES` can name others as
    /// `host=b32,host=b32`.
    const I2P_PROJECT: &str =
        "i2p-projekt.i2p=udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna.b32.i2p";

    async fn fetch(router: &I2pRouter, host: &str, b32: &str) -> Result<String, String> {
        let (host, path) = host.split_once('/').unwrap_or((host, ""));
        let remote = data::parse_b32_name(b32).ok_or("bad b32 name")?;
        let request = format!(
            "GET /{path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: MYOB/6.66 (AN/ON)\r\nConnection: close\r\n\r\n"
        );
        let mut stream = router
            .connect(remote, 80, request.into_bytes(), Duration::from_secs(90))
            .await
            .map_err(|error| error.to_string())?;
        let mut page = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(90), stream.read_to_end(&mut page)).await;
        let text = String::from_utf8_lossy(&page);
        match text.lines().next() {
            Some(status) if status.starts_with("HTTP/1.") => {
                if std::env::var("SHOW").is_ok() {
                    println!("--- {host}\n{text}");
                }
                Ok(format!("{status} ({} bytes)", page.len()))
            }
            _ => Err(format!("no HTTP answer ({} bytes)", page.len())),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs the real I2P network"]
    async fn a_page_loads_from_an_i2p_site() {
        let routers = reseed::fetch(reseed::RESEED_URLS).await.unwrap();
        let router = I2pRouter::start(routers).unwrap();
        router
            .start_client(Targets {
                inbound: 2,
                outbound: 2,
                inbound_hops: 2,
                outbound_hops: 2,
            })
            .await
            .unwrap();
        let sites = std::env::var("SITES").unwrap_or_else(|_| I2P_PROJECT.to_owned());
        let fetches = sites.split(',').map(|site| {
            let (host, b32) = site.split_once('=').expect("host=b32");
            let (host, b32, router) = (host.to_owned(), b32.to_owned(), router.clone());
            async move {
                let result = fetch(&router, &host, &b32).await;
                (host, result)
            }
        });
        let results = futures_join(fetches.collect()).await;
        for line in router.with_plane(|plane| plane.take_trace()).await.unwrap() {
            println!("  {line}");
        }
        for (host, result) in &results {
            println!("{host}: {result:?}");
        }
        assert!(
            results.iter().any(|(_, result)| result.is_ok()),
            "no site answered"
        );
    }

    async fn futures_join<T: Send + 'static>(
        futures: Vec<impl std::future::Future<Output = T> + Send + 'static>,
    ) -> Vec<T> {
        let handles = futures.into_iter().map(tokio::spawn).collect::<Vec<_>>();
        let mut results = Vec::new();
        for handle in handles {
            results.push(handle.await.unwrap());
        }
        results
    }
}

mod tunnel_test_live {
    use std::time::Duration;

    use axon_i2p::{plane::Targets, reseed, router::I2pRouter};

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs the real I2P network"]
    async fn a_message_goes_round_our_tunnels() {
        let routers = reseed::fetch(reseed::RESEED_URLS).await.unwrap();
        let router = I2pRouter::start(routers).unwrap();
        router
            .with_plane(|plane| {
                plane.set_targets(Targets {
                    inbound: 2,
                    outbound: 2,
                    inbound_hops: 2,
                    outbound_hops: 2,
                })
            })
            .await
            .unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
        let mut sent = 0;
        loop {
            let status = router.with_plane(|plane| plane.status()).await.unwrap();
            if status.tests_passed > 0 {
                break;
            }
            if status.inbound > 0 && status.outbound > 0 && sent < 5 {
                let padding = std::env::var("PADDING")
                    .ok()
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(0);
                router
                    .with_plane(move |plane| plane.test_tunnels(padding))
                    .await
                    .unwrap();
                sent += 1;
            }
            if tokio::time::Instant::now() > deadline {
                for line in router.with_plane(|plane| plane.take_trace()).await.unwrap() {
                    println!("  {line}");
                }
                panic!("no test came back: {status:?}, {sent} sent");
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
        for line in router.with_plane(|plane| plane.take_trace()).await.unwrap() {
            println!("  {line}");
        }
    }
}

mod self_garlic_live {
    use std::time::Duration;

    use axon_i2p::{plane::Targets, reseed, router::I2pRouter};

    /// Sends a new session to our own lease set: it should come back
    /// through our inbound tunnel as garlic no session of ours opens.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs the real I2P network"]
    async fn garlic_reaches_our_own_lease_set() {
        let routers = reseed::fetch(reseed::RESEED_URLS).await.unwrap();
        let router = I2pRouter::start(routers).unwrap();
        let ours = router
            .start_client(Targets {
                inbound: 2,
                outbound: 2,
                inbound_hops: 2,
                outbound_hops: 2,
            })
            .await
            .unwrap();
        router
            .client_ready(tokio::time::Instant::now() + Duration::from_secs(90))
            .await
            .unwrap();
        router
            .with_plane(|plane| {
                let set = plane.client_lease_set().unwrap();
                plane.add_lease_set(set);
            })
            .await
            .unwrap();
        let (events, _arrivals) = tokio::sync::mpsc::unbounded_channel();
        router
            .with_plane(move |plane| plane.open_stream(ours, 80, b"hello", events))
            .await
            .unwrap()
            .unwrap();
        tokio::time::sleep(Duration::from_secs(10)).await;
        let trace = router.with_plane(|plane| plane.take_trace()).await.unwrap();
        for line in &trace {
            println!("  {line}");
        }
        assert!(trace.iter().any(|line| line.contains("garlic")));
    }
}
