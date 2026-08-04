//! The Osprey session helper.
//!
//! Runs as the logged-in user, in their session, because the service cannot:
//! a Windows service lives in Session 0 with no desktop and may never draw a
//! window, capture a screen or inject input (brief §9.1).
//!
//! In P1 it does exactly two things — connect to the service's pipe and stay
//! alive — and that is the whole point. The gate measures that killing it
//! brings it back and that it follows the user across a logout. Capture arrives
//! at P4 and input at P6; anything resembling either of those here now would be
//! the plausible-looking fiction the anti-slop rules exist to prevent.

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "osprey-helper",
    version,
    about = "Osprey session helper — started by the Osprey service, not by hand"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Attach to the service and stay resident.
    Run,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing();

    match cli.command {
        Command::Run => osprey_helper::run(),
    }
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_env("OSPREY_LOG")
        .unwrap_or_else(|_| EnvFilter::new("osprey_helper=info"));
    // The helper is started DETACHED_PROCESS and has no console, so this goes
    // nowhere useful in production — it is here for running the binary by hand
    // during development. Its real diagnostics travel over the pipe to the
    // service, which owns the log file.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}
