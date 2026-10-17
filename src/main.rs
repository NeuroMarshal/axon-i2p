//! `axon-i2p CONFIG` runs a router with the local proxies the TOML file at
//! CONFIG asks for.

use std::{path::Path, process::ExitCode};

use axon_i2p::daemon::{self, Config, DaemonError};

fn main() -> ExitCode {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let [config] = arguments.as_slice() else {
        eprintln!("usage: axon-i2p CONFIG");
        return ExitCode::from(2);
    };
    let result = Config::load(Path::new(config)).and_then(|config| {
        tokio::runtime::Runtime::new()
            .map_err(DaemonError::Io)?
            .block_on(daemon::run(config))
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("axon-i2p: {error}");
            ExitCode::FAILURE
        }
    }
}
