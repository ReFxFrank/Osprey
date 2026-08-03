//! Service Control Manager integration.

use std::ffi::OsString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

use crate::commands::run;
use crate::host::{default_display_name, Host};
use crate::paths::DataLayout;
use crate::service::{
    Dispatched, InstallOptions, ServiceOptions, UninstallOptions, SERVICE_DESCRIPTION,
    SERVICE_DISPLAY_NAME, SERVICE_NAME,
};

pub use crate::service::acl::harden_data_dir;
use crate::service::firewall;

/// `StartServiceCtrlDispatcherW` failed because the process was not launched by
/// the SCM. The crate collapses every dispatcher failure into one `Winapi`
/// variant, so this code is the only way to tell "run from a console" apart
/// from a real fault such as ERROR_SERVICE_ALREADY_RUNNING.
const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: i32 = 1063;

/// How long the SCM should wait for a pending transition before deciding the
/// service is wedged. Held as a constant, never derived from input: the
/// dependency converts it with `expect`, so a value over ~49 days would panic
/// inside the crate.
const PENDING_WAIT_HINT: Duration = Duration::from_secs(20);

/// Restart delays for the first, second, and third-and-later failures.
const RESTART_DELAYS: [Duration; 3] = [
    Duration::from_secs(1),
    Duration::from_secs(5),
    Duration::from_secs(30),
];

/// A day without a failure clears the count, so an agent that dies once a week
/// keeps getting the fast first retry instead of the slow third one.
const FAILURE_RESET_PERIOD: Duration = Duration::from_secs(86_400);

/// Set by `dispatch` before the SCM calls back.
///
/// The service entry point's signature is fixed by the dependency's macro at
/// `fn(Vec<OsString>)`, and those arguments come from `StartService`, not from
/// the registered command line — the port and mDNS flags this process was
/// installed with arrive through `main`'s argv and are parked here.
static OPTIONS: OnceLock<ServiceOptions> = OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

/// Hand the process to the SCM, or report that there is no SCM to hand it to.
pub fn dispatch(options: &ServiceOptions) -> Result<Dispatched> {
    // Ignore a second call rather than failing: the value is identical, and the
    // only caller is `main`.
    let _ = OPTIONS.set(options.clone());

    match service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
        Ok(()) => Ok(Dispatched::AsService),
        Err(windows_service::Error::Winapi(err))
            if err.raw_os_error() == Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) =>
        {
            Ok(Dispatched::NotUnderScm)
        }
        Err(err) => Err(anyhow!(err).context("the service control dispatcher failed to start")),
    }
}

/// Runs on a thread the SCM creates. Returns only when the service is stopping.
fn service_main(_scm_arguments: Vec<OsString>) {
    if let Err(err) = serve() {
        // Nothing can be returned to the SCM from here, and there is no
        // console, so the log file is the only place this can go.
        tracing::error!(error = ?err, "the service stopped because of an error");
    }
}

fn serve() -> Result<()> {
    let options = OPTIONS
        .get()
        .context("the service started without its options being set")?;

    let running = Arc::new(AtomicBool::new(true));
    let shutdown = Arc::clone(&running);

    let status_handle = service_control_handler::register(SERVICE_NAME, move |control| {
        match control {
            // Answered by every service, and the SCM uses it to poll liveness.
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop => {
                shutdown.store(false, Ordering::Relaxed);
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    })
    .map_err(|err| anyhow!(err).context("could not register the service control handler"))?;

    report(&status_handle, ServiceState::StartPending, 1)?;

    let layout = match &options.data_dir {
        Some(dir) => DataLayout::under(dir),
        None => DataLayout::create_default()?,
    };
    let host = Host::open(layout, &default_display_name())?;

    report(&status_handle, ServiceState::Running, 0)?;
    tracing::info!(port = options.port, "the Osprey service is running");

    let outcome = run::execute(
        &host,
        &run::RunOptions {
            port: options.port,
            advertise_mdns: options.advertise_mdns,
            // A service installed before anyone has paired must listen and
            // wait, not exit. `channel::accept` refuses every unpinned peer, so
            // an agent with no pins is merely useless, never unsafe — and P9's
            // flow is install first, pair second.
            require_paired_controller: false,
        },
        running,
        &mut std::io::sink(),
    );

    // Reported before the result is inspected: the SCM must learn the service
    // is on its way down whether it is stopping cleanly or because the accept
    // loop failed.
    report(&status_handle, ServiceState::StopPending, 1)?;

    let exit_code = match &outcome {
        Ok(()) => ServiceExitCode::NO_ERROR,
        Err(err) => {
            tracing::error!(error = ?err, "the accept loop ended with an error");
            // A non-zero code is what makes the SCM run the recovery actions,
            // which is the whole point of registering them.
            ServiceExitCode::ServiceSpecific(1)
        }
    };
    stop(&status_handle, exit_code)?;
    outcome
}

/// Report a transition. `controls_accepted` is deliberately empty for anything
/// other than `Running`.
///
/// The dependency's static trampoline reclaims its boxed handler with
/// `Box::from_raw` on Stop, Shutdown *or* Preshutdown, so two terminating
/// controls would be a double free. This service therefore accepts only `Stop`,
/// and stops accepting even that the moment it begins stopping.
fn report(
    handle: &service_control_handler::ServiceStatusHandle,
    state: ServiceState,
    checkpoint: u32,
) -> Result<()> {
    let controls_accepted = if state == ServiceState::Running {
        ServiceControlAccept::STOP
    } else {
        ServiceControlAccept::empty()
    };
    let wait_hint = if checkpoint == 0 {
        Duration::default()
    } else {
        PENDING_WAIT_HINT
    };

    handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted,
            exit_code: ServiceExitCode::NO_ERROR,
            checkpoint,
            wait_hint,
            // Output-only: set by `query_status`, never by the service.
            process_id: None,
        })
        .map_err(|err| anyhow!(err).context("could not report service status"))
}

fn stop(
    handle: &service_control_handler::ServiceStatusHandle,
    exit_code: ServiceExitCode,
) -> Result<()> {
    handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code,
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
        .map_err(|err| anyhow!(err).context("could not report the service as stopped"))
}

/// Register the service, harden the data directory, and open the firewall.
pub fn install(options: &InstallOptions) -> Result<()> {
    let executable = std::env::current_exe().context("could not locate the agent executable")?;

    // Created and hardened before the service is registered: the SCM could
    // start the service the moment `create_service` returns, and the keystore
    // must never exist with inherited permissions while that happens.
    let layout = DataLayout::create_default()?;
    harden_data_dir(&layout.root)
        .with_context(|| format!("could not secure {}", layout.root.display()))?;

    let mut launch_arguments = vec![
        OsString::from("service"),
        OsString::from("--port"),
        OsString::from(options.port.to_string()),
    ];
    if !options.advertise_mdns {
        launch_arguments.push(OsString::from("--no-mdns"));
    }

    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(|err| {
        anyhow!(err).context("could not open the service manager; run this from an elevated prompt")
    })?;

    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        // `Critical` would let a failed start roll back the boot configuration.
        // A remote-administration agent has no business doing that.
        error_control: ServiceErrorControl::Normal,
        executable_path: executable,
        launch_arguments,
        dependencies: Vec::new(),
        // None means LocalSystem, which is what Session 0 work requires.
        account_name: None,
        account_password: None,
    };

    // CHANGE_CONFIG has to be requested here; the access mask is fixed when the
    // handle is opened and cannot be widened later.
    let service = manager
        .create_service(
            &info,
            ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS,
        )
        .map_err(|err| anyhow!(err).context("could not create the service"))?;

    service
        .set_description(SERVICE_DESCRIPTION)
        .map_err(|err| anyhow!(err).context("could not set the service description"))?;

    let actions = RESTART_DELAYS
        .iter()
        .map(|delay| ServiceAction {
            action_type: ServiceActionType::Restart,
            delay: *delay,
        })
        .collect();
    service
        .update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(FAILURE_RESET_PERIOD),
            reboot_msg: None,
            command: None,
            actions: Some(actions),
        })
        .map_err(|err| anyhow!(err).context("could not set the service recovery actions"))?;
    // Without this the recovery actions fire only when the process dies without
    // reporting Stopped. The accept loop reports a service-specific exit code
    // on failure precisely so that it counts as a failure too.
    service
        .set_failure_actions_on_non_crash_failures(true)
        .map_err(|err| anyhow!(err).context("could not enable recovery on reported failures"))?;

    if options.firewall_rule {
        firewall::allow_inbound(options.port)
            .context("the service was registered, but the firewall rule could not be created")?;
    }

    if options.start {
        service
            .start(&[] as &[&OsString])
            .map_err(|err| anyhow!(err).context("the service was registered but would not start"))?;
    }
    Ok(())
}

/// Stop and remove the service. Leaves `%ProgramData%\Osprey` untouched.
pub fn uninstall(options: &UninstallOptions) -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|err| {
            anyhow!(err)
                .context("could not open the service manager; run this from an elevated prompt")
        })?;

    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .map_err(|err| anyhow!(err).context("could not open the service; is it installed?"))?;

    let status = service
        .query_status()
        .map_err(|err| anyhow!(err).context("could not query the service state"))?;
    if status.current_state != ServiceState::Stopped {
        service
            .stop()
            .map_err(|err| anyhow!(err).context("could not stop the service"))?;
        wait_for_stop(&service)?;
    }

    service
        .delete()
        .map_err(|err| anyhow!(err).context("could not delete the service"))?;
    // `delete` only marks the service; the SCM removes it once every handle is
    // closed. Dropping here rather than at end of scope is what stops a
    // reinstall immediately afterwards failing with ERROR_SERVICE_MARKED_FOR_DELETE.
    drop(service);

    if options.remove_firewall_rule {
        firewall::remove_inbound().context("the service was removed, but its firewall rule was not")?;
    }
    Ok(())
}

/// Poll until the service reports Stopped.
fn wait_for_stop(service: &windows_service::service::Service) -> Result<()> {
    const POLL: Duration = Duration::from_millis(200);
    const LIMIT: Duration = Duration::from_secs(30);

    let deadline = std::time::Instant::now() + LIMIT;
    loop {
        let status = service
            .query_status()
            .map_err(|err| anyhow!(err).context("could not query the service state"))?;
        if status.current_state == ServiceState::Stopped {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            bail!(
                "the service did not stop within {} seconds",
                LIMIT.as_secs()
            );
        }
        std::thread::sleep(POLL);
    }
}
