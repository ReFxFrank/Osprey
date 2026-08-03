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

        /// Do not advertise `_osprey._tcp` on the LAN while pairing.
        #[arg(long)]
        no_mdns: bool,

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

        /// Do not advertise `_osprey._tcp` on the LAN.
        ///
        /// Advertising is on by default because it is the discovery path that
        /// survives the host changing address (amendment A6); without it a
        /// paired phone is limited to the addresses frozen into its QR scan.
        #[arg(long)]
        no_mdns: bool,
    },

    /// Revoke a controller. Takes effect locally and immediately.
    Unpair {
        /// `all`, a relay device uuid, or a prefix of the fingerprint that
        /// `pair` displayed.
        #[arg(value_name = "DEVICE-ID|all")]
        target: String,
    },

    /// Register the Windows service. Requires elevation.
    ///
    /// The one interactive step the product ever asks for: after this the
    /// service starts at boot and nothing needs launching by hand.
    Install {
        /// Port the installed service listens on. Baked into its command line.
        #[arg(long, default_value_t = DEFAULT_LAN_PORT)]
        port: u16,

        /// Install with LAN discovery advertising disabled.
        #[arg(long)]
        no_mdns: bool,

        /// Do not create the inbound firewall rule for `--port`.
        ///
        /// Without the rule the direct-LAN path is silently unreachable until
        /// somebody answers a Windows firewall prompt, so this exists for
        /// operators who manage firewall policy centrally, not as a default.
        #[arg(long)]
        no_firewall_rule: bool,

        /// Register the service but do not start it.
        #[arg(long)]
        no_start: bool,
    },

    /// Remove the Windows service. Requires elevation.
    ///
    /// Leaves `%ProgramData%\Osprey` alone: it holds the device identity, the
    /// pins and the audit log, and deleting an audit log as a side effect of
    /// uninstalling is exactly what brief §6.4 forbids.
    Uninstall {
        /// Also remove the firewall rule this installer created.
        #[arg(long)]
        remove_firewall_rule: bool,
    },

    /// Entry point the Service Control Manager invokes. Not for humans.
    #[command(hide = true)]
    Service {
        #[arg(long, default_value_t = DEFAULT_LAN_PORT)]
        port: u16,

        #[arg(long)]
        no_mdns: bool,
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
    fn mdns_is_on_unless_the_operator_turns_it_off() {
        let on = Cli::try_parse_from(["osprey-svc", "run"]).expect("parse");
        assert!(matches!(on.command, Command::Run { no_mdns: false, .. }));
        let off = Cli::try_parse_from(["osprey-svc", "run", "--no-mdns"]).expect("parse");
        assert!(matches!(off.command, Command::Run { no_mdns: true, .. }));
        let paired_off =
            Cli::try_parse_from(["osprey-svc", "pair", "--lan-only", "--no-mdns"]).expect("parse");
        assert!(matches!(
            paired_off.command,
            Command::Pair { no_mdns: true, .. }
        ));
    }

    #[test]
    fn the_service_entry_point_is_hidden_from_help() {
        // It is invoked by the SCM with the command line `install` wrote, and
        // an operator who runs it by hand gets a process that waits for a
        // dispatcher connection that will never come. Keeping it out of --help
        // is the difference between an internal detail and a trap.
        let help = Cli::command().render_help().to_string();
        // Matched against the subcommand column rather than the whole page:
        // the word "service" legitimately appears in prose describing what the
        // agent is.
        let listed: Vec<&str> = help
            .lines()
            .filter_map(|line| line.strip_prefix("  "))
            .filter_map(|line| line.split_whitespace().next())
            .collect();
        assert!(
            !listed.contains(&"service"),
            "the SCM entry point must not be advertised in help:\n{help}"
        );
        assert!(
            listed.contains(&"install") && listed.contains(&"uninstall"),
            "install and uninstall must be discoverable:\n{help}"
        );
    }

    #[test]
    fn install_defaults_to_creating_the_firewall_rule_and_starting() {
        let parsed = Cli::try_parse_from(["osprey-svc", "install"]).expect("parse");
        assert!(matches!(
            parsed.command,
            Command::Install {
                no_firewall_rule: false,
                no_start: false,
                ..
            }
        ));
    }

    #[test]
    fn uninstall_keeps_the_audit_log_unless_asked() {
        // There is deliberately no flag that deletes %ProgramData%\Osprey.
        let parsed = Cli::try_parse_from(["osprey-svc", "uninstall"]).expect("parse");
        assert!(matches!(
            parsed.command,
            Command::Uninstall {
                remove_firewall_rule: false
            }
        ));
    }

    #[test]
    fn unpair_requires_a_target() {
        assert!(Cli::try_parse_from(["osprey-svc", "unpair"]).is_err());
        let parsed = Cli::try_parse_from(["osprey-svc", "unpair", "all"]).expect("parse");
        assert!(matches!(parsed.command, Command::Unpair { target } if target == "all"));
    }
}
