// DO NOT EDIT — generated from proto/messages.toml by proto/generate.ts.
// Run `pnpm generate` in proto/ after changing the registry.

import Foundation

/// Every message type the protocol reserves.
///
/// Closed on purpose: an unrecognised `t` cannot be routed, so decoding one is
/// an error rather than something to ignore. Contrast the value enums, which
/// are open. Types whose body schema is not yet designed are still listed here
/// so the registry stays the single source of truth for the wire.
public enum MessageType: String, Codable, Hashable, Sendable, CaseIterable {
    case error = "error"
    case hello = "hello"
    case helloOk = "hello.ok"
    case ping = "ping"
    case pong = "pong"
    case bye = "bye"
    case pairRequest = "pair.request"
    case pairConfirm = "pair.confirm"
    case pairRevoke = "pair.revoke"
    case metricsSubscribe = "metrics.subscribe"
    case metricsTick = "metrics.tick"
    case metricsHistory = "metrics.history"
    case procList = "proc.list"
    case procKill = "proc.kill"
    case procStart = "proc.start"
    case procPriority = "proc.priority"
    case svcList = "svc.list"
    case svcStart = "svc.start"
    case svcStop = "svc.stop"
    case svcRestart = "svc.restart"
    case svcStartupType = "svc.startup_type"
    case powerReboot = "power.reboot"
    case powerShutdown = "power.shutdown"
    case powerSleep = "power.sleep"
    case powerLock = "power.lock"
    case powerLogoff = "power.logoff"
    case powerWol = "power.wol"
    case execRun = "exec.run"
    case execResult = "exec.result"
    case termOpen = "term.open"
    case termData = "term.data"
    case termResize = "term.resize"
    case termClose = "term.close"
    case fsList = "fs.list"
    case fsStat = "fs.stat"
    case fsMkdir = "fs.mkdir"
    case fsDelete = "fs.delete"
    case fsRename = "fs.rename"
    case fsReadBegin = "fs.read.begin"
    case fsChunk = "fs.chunk"
    case fsWriteBegin = "fs.write.begin"
    case fsTransferStatus = "fs.transfer.status"
    case evtQuery = "evt.query"
    case evtTail = "evt.tail"
    case appList = "app.list"
    case appUninstall = "app.uninstall"
    case taskList = "task.list"
    case taskRun = "task.run"
    case taskEnable = "task.enable"
    case netInterfaces = "net.interfaces"
    case netConnections = "net.connections"
    case netSpeedtest = "net.speedtest"
    case alertRulesGet = "alert.rules.get"
    case alertRulesSet = "alert.rules.set"
    case alertFired = "alert.fired"
    case alertAck = "alert.ack"
    case streamStart = "stream.start"
    case streamStop = "stream.stop"
    case streamQuality = "stream.quality"
    case streamMonitors = "stream.monitors"
    case streamSelectMonitor = "stream.select_monitor"
    case inputMouse = "input.mouse"
    case inputKey = "input.key"
    case inputScroll = "input.scroll"
    case inputText = "input.text"
    case inputSas = "input.sas"
    case clipPush = "clip.push"
    case clipPull = "clip.pull"
    case clipChanged = "clip.changed"
    case audioStart = "audio.start"
    case audioStop = "audio.stop"
    case privacyBlank = "privacy.blank"
    case privacyBlockLocalInput = "privacy.block_local_input"

    /// Capability that must be negotiated before this type may be sent.
    ///
    /// `nil` means the type is mandatory for every peer.
    public var capability: Capability? {
        switch self {
        case .error:
            return nil
        case .hello,
             .helloOk,
             .ping,
             .pong,
             .bye:
            return nil
        case .pairRequest,
             .pairConfirm,
             .pairRevoke:
            return nil
        case .metricsSubscribe,
             .metricsTick,
             .metricsHistory:
            return .metrics
        case .procList,
             .procKill,
             .procStart,
             .procPriority:
            return .process
        case .svcList,
             .svcStart,
             .svcStop,
             .svcRestart,
             .svcStartupType:
            return .service
        case .powerReboot,
             .powerShutdown,
             .powerSleep,
             .powerLock,
             .powerLogoff,
             .powerWol:
            return .power
        case .execRun,
             .execResult:
            return .exec
        case .termOpen,
             .termData,
             .termResize,
             .termClose:
            return .terminal
        case .fsList,
             .fsStat,
             .fsMkdir,
             .fsDelete,
             .fsRename,
             .fsReadBegin,
             .fsChunk,
             .fsWriteBegin,
             .fsTransferStatus:
            return .files
        case .evtQuery,
             .evtTail:
            return .events
        case .appList,
             .appUninstall:
            return .apps
        case .taskList,
             .taskRun,
             .taskEnable:
            return .tasks
        case .netInterfaces,
             .netConnections,
             .netSpeedtest:
            return .network
        case .alertRulesGet,
             .alertRulesSet,
             .alertFired,
             .alertAck:
            return .alerts
        case .streamStart,
             .streamStop,
             .streamQuality,
             .streamMonitors,
             .streamSelectMonitor:
            return .sessionPlane
        case .inputMouse,
             .inputKey,
             .inputScroll,
             .inputText,
             .inputSas:
            return .input
        case .clipPush,
             .clipPull,
             .clipChanged:
            return .clipboard
        case .audioStart,
             .audioStop:
            return .audio
        case .privacyBlank,
             .privacyBlockLocalInput:
            return .privacy
        }
    }

    /// Data channel this type must travel on (brief §5.3).
    public var channel: Channel {
        switch self {
        case .inputMouse,
             .inputScroll:
            return .unreliable
        default:
            return .reliable
        }
    }
}
