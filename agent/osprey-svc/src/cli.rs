//! Command-line surface of the P0 agent console.

use std::time::Duration;

use clap::{Parser, Subcommand};
use osprey_core::pairing::DEFAULT_PAIRING_TTL;

use crate::lan::DEFAULT_LAN_PORT;

#[derive(Debug, Parser)]
#[command(
    name = "osprey-svc",
    version,
    about = "Osprey agent (P0 console build)",
    long_about = "P0 agent console. Pairing runs from a terminal because the tray \
                  helper and the Windows service wrapper are both P1 deliverables; \
                  the pairing, session and revocation logic is the same code the \
                  tray will call."
)]
pub struct Cli {
    /// Override the data directory. Ignored on Windows, where the ACL on
    /// %ProgramData%\Osprey is the only thing protecting the sealed keys.
    #[arg(long, global = true, value_name = "DIR")]
    pub data_dir: Option<std::path::PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Display a pairing QR and enrol one controller.
    Pair {
        /// Relay base url, e.g. https://relay.example. Remembered after the
        /// first successful enrolment.
        #[arg(long, value_name = "URL")]
        relay_url: Option<String>,

        /// Deploy-time enrolment secret. Also read from OSPREY_ENROLLMENT_SECRET.
        #[arg(long, value_name = "SECRET")]
        enrollment_secret: Option<String>,

        /// Pair over the LAN with no relay involved at all.
        #[arg(long, conflicts_with_all = ["relay_url", "enrollment_secret"])]
        lan_only: bool,

        /// TCP port to listen on. 0 asks the OS for an ephemeral port.
        #[arg(long, default_value_t = DEFAULT_LAN_PORT)]
        port: u16,

        /// Seconds the QR stays valid.
        #[arg(long, default_value_t = DEFAULT_PAIRING_TTL.as_secs(), value_name = "SECONDS")]
        ttl: u64,

        /// Also print the QR's decoded JSON. It contains the pairing secret, so
        /// it persists in scrollback and in anything capturing stdout — ask for
        /// it only when a scan is impossible.
        #[arg(long)]
        print_payload: bool,
    },

    /// Serve sessions to already-paired controllers.
    Run {
        #[arg(long, default_value_t = DEFAULT_LAN_PORT)]
        port: u16,
    },

    /// Revoke a controller. Takes effect locally and immediately.
    Unpair {
        /// `all`, a relay device uuid, or a prefix of the fingerprint that
        /// `pair` displayed.
        #[arg(value_name = "DEVICE-ID|all")]
        target: String,
    },
}

impl Command {
    pub fn pairing_ttl(seconds: u64) -> Duration {
        Duration::from_secs(seconds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_command_tree_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn lan_only_and_relay_url_are_mutually_exclusive() {
        let parsed = Cli::try_parse_from([
            "osprey-svc",
            "pair",
            "--lan-only",
            "--relay-url",
            "https://relay.example",
        ]);
        assert!(parsed.is_err());
    }

    #[test]
    fn unpair_requires_a_target() {
        assert!(Cli::try_parse_from(["osprey-svc", "unpair"]).is_err());
        let parsed = Cli::try_parse_from(["osprey-svc", "unpair", "all"]).expect("parse");
        assert!(matches!(parsed.command, Command::Unpair { target } if target == "all"));
    }
}
