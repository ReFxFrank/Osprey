// DO NOT EDIT — generated from proto/messages.toml by proto/generate.ts.
// Run `pnpm generate` in proto/ after changing the registry.

//! The complete message type registry.

use serde::{Deserialize, Serialize};

use super::enums::{Capability, Channel};
use crate::error::UnknownMessageType;

/// Every message type the protocol reserves.
///
/// Closed on purpose: an unrecognised `t` cannot be routed, so it is a hard
/// error rather than something to ignore. Contrast the value enums, which are
/// open. Types whose body schema is not yet designed are still listed here so
/// the registry stays the single source of truth for the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MessageType {
    #[serde(rename = "error")]
    Error,
    #[serde(rename = "hello")]
    Hello,
    #[serde(rename = "hello.ok")]
    HelloOk,
    #[serde(rename = "ping")]
    Ping,
    #[serde(rename = "pong")]
    Pong,
    #[serde(rename = "bye")]
    Bye,
    #[serde(rename = "pair.request")]
    PairRequest,
    #[serde(rename = "pair.confirm")]
    PairConfirm,
    #[serde(rename = "pair.revoke")]
    PairRevoke,
    #[serde(rename = "metrics.subscribe")]
    MetricsSubscribe,
    #[serde(rename = "metrics.tick")]
    MetricsTick,
    #[serde(rename = "metrics.history")]
    MetricsHistory,
    #[serde(rename = "proc.list")]
    ProcList,
    #[serde(rename = "proc.kill")]
    ProcKill,
    #[serde(rename = "proc.start")]
    ProcStart,
    #[serde(rename = "proc.priority")]
    ProcPriority,
    #[serde(rename = "svc.list")]
    SvcList,
    #[serde(rename = "svc.start")]
    SvcStart,
    #[serde(rename = "svc.stop")]
    SvcStop,
    #[serde(rename = "svc.restart")]
    SvcRestart,
    #[serde(rename = "svc.startup_type")]
    SvcStartupType,
    #[serde(rename = "power.reboot")]
    PowerReboot,
    #[serde(rename = "power.shutdown")]
    PowerShutdown,
    #[serde(rename = "power.sleep")]
    PowerSleep,
    #[serde(rename = "power.lock")]
    PowerLock,
    #[serde(rename = "power.logoff")]
    PowerLogoff,
    #[serde(rename = "power.wol")]
    PowerWol,
    #[serde(rename = "exec.run")]
    ExecRun,
    #[serde(rename = "exec.result")]
    ExecResult,
    #[serde(rename = "term.open")]
    TermOpen,
    #[serde(rename = "term.data")]
    TermData,
    #[serde(rename = "term.resize")]
    TermResize,
    #[serde(rename = "term.close")]
    TermClose,
    #[serde(rename = "fs.list")]
    FsList,
    #[serde(rename = "fs.stat")]
    FsStat,
    #[serde(rename = "fs.mkdir")]
    FsMkdir,
    #[serde(rename = "fs.delete")]
    FsDelete,
    #[serde(rename = "fs.rename")]
    FsRename,
    #[serde(rename = "fs.read.begin")]
    FsReadBegin,
    #[serde(rename = "fs.chunk")]
    FsChunk,
    #[serde(rename = "fs.write.begin")]
    FsWriteBegin,
    #[serde(rename = "fs.transfer.status")]
    FsTransferStatus,
    #[serde(rename = "evt.query")]
    EvtQuery,
    #[serde(rename = "evt.tail")]
    EvtTail,
    #[serde(rename = "app.list")]
    AppList,
    #[serde(rename = "app.uninstall")]
    AppUninstall,
    #[serde(rename = "task.list")]
    TaskList,
    #[serde(rename = "task.run")]
    TaskRun,
    #[serde(rename = "task.enable")]
    TaskEnable,
    #[serde(rename = "net.interfaces")]
    NetInterfaces,
    #[serde(rename = "net.connections")]
    NetConnections,
    #[serde(rename = "net.speedtest")]
    NetSpeedtest,
    #[serde(rename = "alert.rules.get")]
    AlertRulesGet,
    #[serde(rename = "alert.rules.set")]
    AlertRulesSet,
    #[serde(rename = "alert.fired")]
    AlertFired,
    #[serde(rename = "alert.ack")]
    AlertAck,
    #[serde(rename = "stream.start")]
    StreamStart,
    #[serde(rename = "stream.stop")]
    StreamStop,
    #[serde(rename = "stream.quality")]
    StreamQuality,
    #[serde(rename = "stream.monitors")]
    StreamMonitors,
    #[serde(rename = "stream.select_monitor")]
    StreamSelectMonitor,
    #[serde(rename = "input.mouse")]
    InputMouse,
    #[serde(rename = "input.key")]
    InputKey,
    #[serde(rename = "input.scroll")]
    InputScroll,
    #[serde(rename = "input.text")]
    InputText,
    #[serde(rename = "input.sas")]
    InputSas,
    #[serde(rename = "clip.push")]
    ClipPush,
    #[serde(rename = "clip.pull")]
    ClipPull,
    #[serde(rename = "clip.changed")]
    ClipChanged,
    #[serde(rename = "audio.start")]
    AudioStart,
    #[serde(rename = "audio.stop")]
    AudioStop,
    #[serde(rename = "privacy.blank")]
    PrivacyBlank,
    #[serde(rename = "privacy.block_local_input")]
    PrivacyBlockLocalInput,
}

impl MessageType {
    /// Every registered type, in registry order.
    pub const ALL: &'static [MessageType] = &[
        MessageType::Error,
        MessageType::Hello,
        MessageType::HelloOk,
        MessageType::Ping,
        MessageType::Pong,
        MessageType::Bye,
        MessageType::PairRequest,
        MessageType::PairConfirm,
        MessageType::PairRevoke,
        MessageType::MetricsSubscribe,
        MessageType::MetricsTick,
        MessageType::MetricsHistory,
        MessageType::ProcList,
        MessageType::ProcKill,
        MessageType::ProcStart,
        MessageType::ProcPriority,
        MessageType::SvcList,
        MessageType::SvcStart,
        MessageType::SvcStop,
        MessageType::SvcRestart,
        MessageType::SvcStartupType,
        MessageType::PowerReboot,
        MessageType::PowerShutdown,
        MessageType::PowerSleep,
        MessageType::PowerLock,
        MessageType::PowerLogoff,
        MessageType::PowerWol,
        MessageType::ExecRun,
        MessageType::ExecResult,
        MessageType::TermOpen,
        MessageType::TermData,
        MessageType::TermResize,
        MessageType::TermClose,
        MessageType::FsList,
        MessageType::FsStat,
        MessageType::FsMkdir,
        MessageType::FsDelete,
        MessageType::FsRename,
        MessageType::FsReadBegin,
        MessageType::FsChunk,
        MessageType::FsWriteBegin,
        MessageType::FsTransferStatus,
        MessageType::EvtQuery,
        MessageType::EvtTail,
        MessageType::AppList,
        MessageType::AppUninstall,
        MessageType::TaskList,
        MessageType::TaskRun,
        MessageType::TaskEnable,
        MessageType::NetInterfaces,
        MessageType::NetConnections,
        MessageType::NetSpeedtest,
        MessageType::AlertRulesGet,
        MessageType::AlertRulesSet,
        MessageType::AlertFired,
        MessageType::AlertAck,
        MessageType::StreamStart,
        MessageType::StreamStop,
        MessageType::StreamQuality,
        MessageType::StreamMonitors,
        MessageType::StreamSelectMonitor,
        MessageType::InputMouse,
        MessageType::InputKey,
        MessageType::InputScroll,
        MessageType::InputText,
        MessageType::InputSas,
        MessageType::ClipPush,
        MessageType::ClipPull,
        MessageType::ClipChanged,
        MessageType::AudioStart,
        MessageType::AudioStop,
        MessageType::PrivacyBlank,
        MessageType::PrivacyBlockLocalInput,
    ];

    /// Wire spelling of this type.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Hello => "hello",
            Self::HelloOk => "hello.ok",
            Self::Ping => "ping",
            Self::Pong => "pong",
            Self::Bye => "bye",
            Self::PairRequest => "pair.request",
            Self::PairConfirm => "pair.confirm",
            Self::PairRevoke => "pair.revoke",
            Self::MetricsSubscribe => "metrics.subscribe",
            Self::MetricsTick => "metrics.tick",
            Self::MetricsHistory => "metrics.history",
            Self::ProcList => "proc.list",
            Self::ProcKill => "proc.kill",
            Self::ProcStart => "proc.start",
            Self::ProcPriority => "proc.priority",
            Self::SvcList => "svc.list",
            Self::SvcStart => "svc.start",
            Self::SvcStop => "svc.stop",
            Self::SvcRestart => "svc.restart",
            Self::SvcStartupType => "svc.startup_type",
            Self::PowerReboot => "power.reboot",
            Self::PowerShutdown => "power.shutdown",
            Self::PowerSleep => "power.sleep",
            Self::PowerLock => "power.lock",
            Self::PowerLogoff => "power.logoff",
            Self::PowerWol => "power.wol",
            Self::ExecRun => "exec.run",
            Self::ExecResult => "exec.result",
            Self::TermOpen => "term.open",
            Self::TermData => "term.data",
            Self::TermResize => "term.resize",
            Self::TermClose => "term.close",
            Self::FsList => "fs.list",
            Self::FsStat => "fs.stat",
            Self::FsMkdir => "fs.mkdir",
            Self::FsDelete => "fs.delete",
            Self::FsRename => "fs.rename",
            Self::FsReadBegin => "fs.read.begin",
            Self::FsChunk => "fs.chunk",
            Self::FsWriteBegin => "fs.write.begin",
            Self::FsTransferStatus => "fs.transfer.status",
            Self::EvtQuery => "evt.query",
            Self::EvtTail => "evt.tail",
            Self::AppList => "app.list",
            Self::AppUninstall => "app.uninstall",
            Self::TaskList => "task.list",
            Self::TaskRun => "task.run",
            Self::TaskEnable => "task.enable",
            Self::NetInterfaces => "net.interfaces",
            Self::NetConnections => "net.connections",
            Self::NetSpeedtest => "net.speedtest",
            Self::AlertRulesGet => "alert.rules.get",
            Self::AlertRulesSet => "alert.rules.set",
            Self::AlertFired => "alert.fired",
            Self::AlertAck => "alert.ack",
            Self::StreamStart => "stream.start",
            Self::StreamStop => "stream.stop",
            Self::StreamQuality => "stream.quality",
            Self::StreamMonitors => "stream.monitors",
            Self::StreamSelectMonitor => "stream.select_monitor",
            Self::InputMouse => "input.mouse",
            Self::InputKey => "input.key",
            Self::InputScroll => "input.scroll",
            Self::InputText => "input.text",
            Self::InputSas => "input.sas",
            Self::ClipPush => "clip.push",
            Self::ClipPull => "clip.pull",
            Self::ClipChanged => "clip.changed",
            Self::AudioStart => "audio.start",
            Self::AudioStop => "audio.stop",
            Self::PrivacyBlank => "privacy.blank",
            Self::PrivacyBlockLocalInput => "privacy.block_local_input",
        }
    }

    /// Capability that must be negotiated before this type may be sent.
    ///
    /// `None` means the type is mandatory for every peer.
    pub fn capability(&self) -> Option<Capability> {
        match self {
            Self::Error => None,
            Self::Hello
            | Self::HelloOk
            | Self::Ping
            | Self::Pong
            | Self::Bye => None,
            Self::PairRequest
            | Self::PairConfirm
            | Self::PairRevoke => None,
            Self::MetricsSubscribe
            | Self::MetricsTick
            | Self::MetricsHistory => Some(Capability::Metrics),
            Self::ProcList
            | Self::ProcKill
            | Self::ProcStart
            | Self::ProcPriority => Some(Capability::Process),
            Self::SvcList
            | Self::SvcStart
            | Self::SvcStop
            | Self::SvcRestart
            | Self::SvcStartupType => Some(Capability::Service),
            Self::PowerReboot
            | Self::PowerShutdown
            | Self::PowerSleep
            | Self::PowerLock
            | Self::PowerLogoff
            | Self::PowerWol => Some(Capability::Power),
            Self::ExecRun
            | Self::ExecResult => Some(Capability::Exec),
            Self::TermOpen
            | Self::TermData
            | Self::TermResize
            | Self::TermClose => Some(Capability::Terminal),
            Self::FsList
            | Self::FsStat
            | Self::FsMkdir
            | Self::FsDelete
            | Self::FsRename
            | Self::FsReadBegin
            | Self::FsChunk
            | Self::FsWriteBegin
            | Self::FsTransferStatus => Some(Capability::Files),
            Self::EvtQuery
            | Self::EvtTail => Some(Capability::Events),
            Self::AppList
            | Self::AppUninstall => Some(Capability::Apps),
            Self::TaskList
            | Self::TaskRun
            | Self::TaskEnable => Some(Capability::Tasks),
            Self::NetInterfaces
            | Self::NetConnections
            | Self::NetSpeedtest => Some(Capability::Network),
            Self::AlertRulesGet
            | Self::AlertRulesSet
            | Self::AlertFired
            | Self::AlertAck => Some(Capability::Alerts),
            Self::StreamStart
            | Self::StreamStop
            | Self::StreamQuality
            | Self::StreamMonitors
            | Self::StreamSelectMonitor => Some(Capability::SessionPlane),
            Self::InputMouse
            | Self::InputKey
            | Self::InputScroll
            | Self::InputText
            | Self::InputSas => Some(Capability::Input),
            Self::ClipPush
            | Self::ClipPull
            | Self::ClipChanged => Some(Capability::Clipboard),
            Self::AudioStart
            | Self::AudioStop => Some(Capability::Audio),
            Self::PrivacyBlank
            | Self::PrivacyBlockLocalInput => Some(Capability::Privacy),
        }
    }

    /// Data channel this type must travel on (brief §5.3).
    pub fn channel(&self) -> Channel {
        match self {
            Self::InputMouse
            | Self::InputScroll => Channel::Unreliable,
            _ => Channel::Reliable,
        }
    }
}

impl core::fmt::Display for MessageType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl core::str::FromStr for MessageType {
    type Err = UnknownMessageType;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .iter()
            .copied()
            .find(|candidate| candidate.as_str() == value)
            .ok_or_else(|| UnknownMessageType(value.to_owned()))
    }
}
