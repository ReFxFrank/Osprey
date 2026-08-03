//! The Osprey agent binary: console commands and the Windows service entry.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use osprey_svc::cli::{Cli, Command};
use osprey_svc::commands::{pair, run, unpair};
use osprey_svc::host::{default_display_name, Host};
use osprey_svc::paths::DataLayout;
use osprey_svc::service::{self, Dispatched, InstallOptions, ServiceOptions, UninstallOptions};
use osprey_svc::state::PeerSelector;

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        // Registration runs before any data directory exists and has no session
        // to serve, so it never opens a Host of its own.
        Command::Install {
            port,
            no_mdns,
            no_firewall_rule,
            no_start,
        } => {
            init_console_tracing();
            service::install(&InstallOptions {
                port,
                advertise_mdns: !no_mdns,
                firewall_rule: !no_firewall_rule,
                start: !no_start,
            })?;
            println!("Osprey is installed and will start automatically at boot.");
            if no_start {
                println!("It was not started; start it from services.msc when you are ready.");
            }
            Ok(())
        }
        Command::Uninstall {
            remove_firewall_rule,
        } => {
            init_console_tracing();
            service::uninstall(&UninstallOptions {
                remove_firewall_rule,
            })?;
            println!(
                "Osprey is uninstalled. Its keys, pairings and audit log are still in \
                 %ProgramData%\\Osprey; remove that directory by hand if you mean to."
            );
            Ok(())
        }
        Command::Service { port, no_mdns } => {
            let layout = resolve_layout(cli.data_dir.as_deref())?;
            // A service has no console: diagnostics have to reach a file or
            // they reach nowhere.
            init_service_tracing(&layout);
            let options = ServiceOptions {
                port,
                advertise_mdns: !no_mdns,
                data_dir: cli.data_dir.clone(),
            };
            match service::dispatch(&options)? {
                Dispatched::AsService => Ok(()),
                Dispatched::NotUnderScm => {
                    // Reached when someone runs the hidden subcommand by hand.
                    // Falling back beats hanging on a dispatcher that will
                    // never connect.
                    init_console_tracing();
                    tracing::warn!(
                        "not started by the service manager; running in the foreground instead"
                    );
                    serve_in_foreground(layout, port, !no_mdns)
                }
            }
        }
        Command::Pair {
            relay_url,
            enrollment_secret,
            lan_only,
            port,
            ttl,
            no_mdns,
            print_payload,
        } => {
            init_console_tracing();
            let mut host = open_host(cli.data_dir.as_deref())?;
            let options = pair::PairOptions {
                relay_url,
                enrollment_secret,
                lan_only,
                port,
                ttl: Command::pairing_ttl(ttl),
                advertise_mdns: !no_mdns,
                print_payload,
            };
            let mut out = std::io::stdout().lock();
            pair::execute(&mut host, &options, &mut out)?;
            Ok(())
        }
        Command::Run { port, no_mdns } => {
            init_console_tracing();
            let host = open_host(cli.data_dir.as_deref())?;
            let running = Arc::new(AtomicBool::new(true));
            let flag = Arc::clone(&running);
            // Ctrl-C stops the accept loop, hangs up on live sessions and joins
            // the revocation watcher, rather than terminating mid-write.
            ctrlc::set_handler(move || flag.store(false, Ordering::Relaxed))
                .context("could not install the Ctrl-C handler")?;
            let options = run::RunOptions {
                port,
                advertise_mdns: !no_mdns,
                require_paired_controller: true,
            };
            let mut out = std::io::stdout().lock();
            run::execute(&host, &options, running, &mut out)
        }
        Command::Unpair { target } => {
            init_console_tracing();
            let mut host = open_host(cli.data_dir.as_deref())?;
            let selector = PeerSelector::parse(&target)?;
            // No live-session registry: this process is not the one serving
            // sessions. The pin store on disk is the shared authority, and the
            // running agent's watcher acts on it (see `osprey_svc::registry`).
            let mut out = std::io::stdout().lock();
            unpair::execute(&mut host, &selector, None, &mut out)?;
            Ok(())
        }
    }
}

fn resolve_layout(data_dir: Option<&Path>) -> Result<DataLayout> {
    match data_dir {
        Some(dir) => {
            let layout = DataLayout::under(dir);
            layout.create()?;
            Ok(layout)
        }
        None => DataLayout::create_default(),
    }
}

fn open_host(data_dir: Option<&Path>) -> Result<Host> {
    Host::open(resolve_layout(data_dir)?, &default_display_name())
}

fn serve_in_foreground(layout: DataLayout, port: u16, advertise_mdns: bool) -> Result<()> {
    let host = Host::open(layout, &default_display_name())?;
    let running = Arc::new(AtomicBool::new(true));
    let flag = Arc::clone(&running);
    ctrlc::set_handler(move || flag.store(false, Ordering::Relaxed))
        .context("could not install the Ctrl-C handler")?;
    run::execute(
        &host,
        &run::RunOptions {
            port,
            advertise_mdns,
            require_paired_controller: false,
        },
        running,
        &mut std::io::sink(),
    )
}

fn filter() -> tracing_subscriber::EnvFilter {
    tracing_subscriber::EnvFilter::try_from_env("OSPREY_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("osprey_svc=info,osprey_core=info"))
}

fn init_console_tracing() {
    // Diagnostics go to stderr so the QR and the fingerprint on stdout stay
    // clean enough to pipe or screenshot.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter())
        .with_writer(std::io::stderr)
        .try_init();
}

/// Send diagnostics to `logs/osprey-svc.log`, rotating one generation.
///
/// Deliberately *not* the audit directory: that is a security record the
/// operator may not delete (brief §6.4), and a rotating diagnostic log sharing
/// the directory would eventually mean writing a cleanup task that could reach
/// it. If the file cannot be opened the service still starts — losing logs is
/// bad, refusing to run because of it is worse.
fn init_service_tracing(layout: &DataLayout) {
    const MAX_BYTES: u64 = 8 * 1024 * 1024;
    let path = layout.logs.join("osprey-svc.log");

    if let Ok(metadata) = std::fs::metadata(&path) {
        if metadata.len() > MAX_BYTES {
            let previous = layout.logs.join("osprey-svc.log.1");
            if let Err(err) = std::fs::rename(&path, &previous) {
                eprintln!("could not rotate the service log: {err}");
            }
        }
    }

    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        Ok(file) => {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter())
                .with_ansi(false)
                .with_writer(file)
                .try_init();
        }
        Err(err) => {
            eprintln!("could not open {}: {err}", path.display());
            init_console_tracing();
        }
    }
}
