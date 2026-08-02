//! The P0 agent console binary.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use osprey_svc::cli::{Cli, Command};
use osprey_svc::commands::{pair, run, unpair};
use osprey_svc::host::{default_display_name, Host};
use osprey_svc::paths::DataLayout;
use osprey_svc::state::PeerSelector;

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing();

    let layout = match &cli.data_dir {
        Some(dir) => DataLayout::under(dir),
        None => DataLayout::create_default()?,
    };
    let mut host = Host::open(layout, &default_display_name())?;
    let mut out = std::io::stdout().lock();

    match cli.command {
        Command::Pair {
            relay_url,
            enrollment_secret,
            lan_only,
            port,
            ttl,
        } => {
            let options = pair::PairOptions {
                relay_url,
                enrollment_secret,
                lan_only,
                port,
                ttl: Command::pairing_ttl(ttl),
            };
            pair::execute(&mut host, &options, &mut out)?;
            Ok(())
        }
        Command::Run { port } => {
            let running = Arc::new(AtomicBool::new(true));
            let flag = Arc::clone(&running);
            // Ctrl-C stops the accept loop, hangs up on live sessions and joins
            // the revocation watcher, rather than terminating mid-write.
            ctrlc::set_handler(move || flag.store(false, Ordering::Relaxed))
                .context("could not install the Ctrl-C handler")?;
            run::execute(&host, &run::RunOptions { port }, running, &mut out)
        }
        Command::Unpair { target } => {
            let selector = PeerSelector::parse(&target)?;
            // No live-session registry: this process is not the one serving
            // sessions. The pin store on disk is the shared authority, and the
            // running agent's watcher acts on it (see `osprey_svc::registry`).
            unpair::execute(&mut host, &selector, None, &mut out)?;
            Ok(())
        }
    }
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_env("OSPREY_LOG")
        .unwrap_or_else(|_| EnvFilter::new("osprey_svc=info,osprey_core=info"));
    // Diagnostics go to stderr so the QR and the fingerprint on stdout stay
    // clean enough to pipe or screenshot.
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}
