# axon-i2p

> **USE AT YOUR OWN RISK.** This is a personal project, not a product. Much of
> the code and nearly all of the documentation were written with AI, so the
> documentation may contain mistakes; the code and its tests are the reference.
> Nobody has reviewed it for security, nothing here is guaranteed to be stable,
> correct or fit for any purpose, and the license gives no warranty. Whatever
> you do with it is at your own risk. It does not make anyone anonymous; do not
> use it to protect anyone.

An I2P router built on [Axon](https://github.com/NeuroMarshal/axon). It joins
the real I2P network and opens I2P sites through a local SOCKS5 or HTTP proxy.

It is a proof of concept: it shows that an Axon node can speak another
network's own protocols. The router is an Axon `NodeCore`; I2P's link protocol,
tunnels, garlic encryption and streaming are written in this crate on top of
Axon's interfaces. It does not give the anonymity of a full I2P router.

## What works

- Reseed from the public reseed servers, with their signatures checked
- NTCP2 links to other routers
- Router info and lease set lookups in the network database
- Inbound and outbound tunnels through other routers
- A client destination with ECIES-X25519 garlic sessions and streaming
- An address book filled from hosts.txt subscriptions

It has loaded pages from i2p-projekt.i2p, zzz.i2p and stats.i2p.

## What it leaves out

It is a client only: it publishes no router info, routes no tunnels for other
routers and hosts no sites. There is no SSU2, no peer profiling and no
encrypted lease sets. The router identity and the client destination are new
on every start.

## Running it

Axon is a path dependency, so clone both repositories side by side:

```bash
git clone https://github.com/NeuroMarshal/axon
git clone https://github.com/NeuroMarshal/axon-i2p
cd axon-i2p
cp axon-i2p.example.toml axon-i2p.toml
cargo run --release -- axon-i2p.toml
```

Then, from another terminal:

```bash
curl -x http://127.0.0.1:4444 http://i2p-projekt.i2p/en/
curl --socks5-hostname 127.0.0.1:4447 http://zzz.i2p/
```

The first request waits for tunnels, usually less than a minute.

## Tests

`cargo test` runs the offline tests. `cargo test --test live -- --ignored`
runs the checks against the real network: reseed, NTCP2, lookups, tunnels and
page loads.

## License

MIT or Apache-2.0, at your option: you may use the code under either license
(`LICENSE-MIT`, `LICENSE-APACHE`).
