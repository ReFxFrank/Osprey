import Foundation
import Observation

/// One paired machine: its connection, and the metrics it is streaming.
///
/// Per-device rather than global (amendment A23): the app opens to a list, and
/// each row's dashboard has its own session, its own chart series and its own
/// failure. Folding these into one shared object was P0's shape and does not
/// survive a second machine.
@MainActor
@Observable
public final class DeviceModel: Identifiable, Hashable {
    /// How much history to ask for when a dashboard opens.
    public static let backfillSeconds: UInt32 = 3_600

    /// Cap on charted points. A 24-hour backfill is decimated by the agent to
    /// at most 512, and an hour of live ticks adds 3,600 — past a few thousand
    /// the chart costs more to draw than it conveys.
    public static let maxSamples = 2_000

    public nonisolated var id: String { hostSnapshot.agentDeviceID }

    public private(set) var host: PairedHost
    public private(set) var connection: ConnectionState = .idle
    public private(set) var samples: [MetricSample] = []
    public private(set) var volumes: [VolumeUsage] = []
    public private(set) var installedMemoryBytes: UInt64?
    /// True once the host has said it implements the metrics group. A host that
    /// has not is shown an explicit "not reported" state rather than an empty
    /// chart that looks like a quiet machine.
    public private(set) var hostServesMetrics = false
    public var banner: String?

    @ObservationIgnored private let engine: any NoiseEngine
    @ObservationIgnored private let identity: DeviceIdentity
    @ObservationIgnored private let pinStore: PinStore
    @ObservationIgnored private var session: OpenSession?
    @ObservationIgnored private var subscriptionID: UUID?
    @ObservationIgnored private var tickTask: Task<Void, Never>?
    @ObservationIgnored private var pingSequence: UInt64 = 0
    /// Read by the `nonisolated` id without hopping to the main actor.
    @ObservationIgnored private nonisolated let hostSnapshot: PairedHost

    public init(
        host: PairedHost,
        engine: any NoiseEngine,
        identity: DeviceIdentity,
        pinStore: PinStore
    ) {
        self.host = host
        self.hostSnapshot = host
        self.engine = engine
        self.identity = identity
        self.pinStore = pinStore
    }

    public var isConnected: Bool {
        if case .connected = connection { return true }
        return false
    }

    /// Whether the operator wants this machine connected.
    ///
    /// Distinct from whether it *is* connected: iOS suspends the app in the
    /// background and the socket dies unnoticed, so on return to the foreground
    /// the app has to tell "the user closed this" apart from "the system took it
    /// away while they were not looking". Only the second is worth redialling.
    public private(set) var shouldStayConnected = false

    /// The newest sample, which is what the summary tiles show.
    public var latest: MetricSample? { samples.last }

    // MARK: - Session

    public func connect() async {
        shouldStayConnected = true
        if case .connected = connection { return }
        if case .connecting = connection { return }
        connection = .connecting
        do {
            let opened = try await SessionCoordinator(engine: engine, identity: identity)
                .connect(to: host)
            session = opened
            pingSequence = 0
            connection = .connected(
                ConnectedSession(
                    sessionID: opened.helloOk.sessionId,
                    hostDeviceID: opened.helloOk.deviceId,
                    hostSoftwareVersion: opened.helloOk.softwareVersion,
                    lastRoundTripMilliseconds: nil,
                    pingsSent: 0))
            hostServesMetrics = opened.helloOk.capabilities.contains(.metrics)
            adoptDisplayName(opened.helloOk.displayName)

            if hostServesMetrics {
                await startMetrics(on: opened)
            }
        } catch {
            connection = .failed(error.localizedMessage)
        }
    }

    public func disconnect() async {
        shouldStayConnected = false
        await tearDown()
        connection = .idle
    }

    /// Drop the transport without changing what the operator asked for.
    private func tearDown() async {
        tickTask?.cancel()
        tickTask = nil
        subscriptionID = nil
        if let session {
            await session.close()
        }
        session = nil
        pingSequence = 0
    }

    /// Called when the app returns to the foreground.
    ///
    /// iOS suspends the process in the background, so a session that looked
    /// healthy at suspend is usually dead by the time the operator looks again —
    /// but the app cannot tell without trying. The stale samples stay on screen
    /// while this runs, marked by [`isStale`], rather than the chart blanking
    /// and redrawing (§9.3).
    public func refreshAfterForeground() async {
        guard shouldStayConnected else { return }

        // Probe before redialling. `scenePhase` becomes `.active` again for
        // reasons that have nothing to do with the app having been suspended —
        // a notification banner, Control Centre, the screenshot UI — and a
        // teardown here costs a working session, its metrics subscription and
        // the live chart. Measured on the device: sessions were being closed
        // 5 and 14 seconds after opening, and the host logged them as clean
        // client-initiated goodbyes.
        if isConnected {
            await sendPing()
            if isConnected { return }
        }

        await tearDown()
        connection = .connecting
        await connect()
    }

    /// Whether what is on screen predates the current connection.
    public var isStale: Bool {
        !isConnected && !samples.isEmpty
    }

    /// An authenticated encrypted round trip, and the dashboard's latency figure.
    public func sendPing() async {
        guard let session, case .connected(var connected) = connection else { return }
        pingSequence += 1
        do {
            let result = try await session.client.ping(sequence: pingSequence)
            connected.lastRoundTripMilliseconds = result.roundTripMilliseconds
            connected.pingsSent = pingSequence
            connection = .connected(connected)
        } catch {
            let message = error.localizedMessage
            // `tearDown`, not `disconnect`: the operator still wants this
            // machine connected, and clearing that intent would stop the
            // foreground refresh from ever redialling it.
            await tearDown()
            connection = .failed(message)
        }
    }

    // MARK: - Metrics

    private func startMetrics(on opened: OpenSession) async {
        do {
            let (id, history) = try await opened.client.subscribeToMetrics(
                backfillSeconds: Self.backfillSeconds)
            subscriptionID = id
            samples = history.samples
            installedMemoryBytes = history.memTotalBytes
            listenForTicks(on: opened)
        } catch {
            // The session is still usable for everything else, so this reports
            // rather than tearing the connection down.
            banner = "Metrics are unavailable: \(error.localizedMessage)"
        }
    }

    private func listenForTicks(on opened: OpenSession) {
        tickTask?.cancel()
        tickTask = Task { [weak self] in
            let stream = await opened.mux.metricsTicks()
            for await tick in stream {
                if Task.isCancelled { return }
                await self?.append(tick)
            }
        }
    }

    private func append(_ tick: MetricsTickBody) {
        // A subscribe supersedes the previous one, and ticks from the old
        // subscription can still be in flight; charting them would interleave
        // two series.
        guard tick.sub == subscriptionID else { return }

        samples.append(tick.sample)
        if samples.count > Self.maxSamples {
            samples.removeFirst(samples.count - Self.maxSamples)
        }
        volumes = tick.volumes
        installedMemoryBytes = tick.memTotalBytes
    }

    /// Record the machine's own name the first time it introduces itself.
    private func adoptDisplayName(_ name: String?) {
        guard let name, !name.isEmpty, name != host.displayName else { return }
        host.displayName = name
        do {
            try pinStore.save(host)
        } catch {
            // Cosmetic: the name is display-only, so failing to persist it must
            // not look like a pairing problem.
            OspreyLog.session.notice(
                "could not store the host name: \(error.localizedMessage, privacy: .public)")
        }
    }

    // MARK: - Unpair

    /// Drop this pin, telling the host first if it can be reached.
    ///
    /// Returns the sentence to show the operator. The local pin goes whether or
    /// not the host answered — this phone stops connecting the moment it is
    /// gone — but the host's own pin is authoritative for the host (amendment
    /// A18), so a revocation that did not land says so instead of showing a
    /// green checkmark.
    public func unpair() async -> String {
        let hostOutcome = await tellHostToUnpair()
        await disconnect()
        do {
            try pinStore.remove(agentDeviceID: host.agentDeviceID)
            return "Unpaired. " + hostOutcome
        } catch {
            return "The stored pairing could not be removed: \(error.localizedMessage)"
        }
    }

    /// Identity for `NavigationStack`'s value-based routing.
    ///
    /// By object, not by pinned host: pushing a device and then re-pairing that
    /// machine replaces its model, and matching on the host's contents would
    /// leave the pushed screen bound to a record that no longer exists.
    public nonisolated static func == (lhs: DeviceModel, rhs: DeviceModel) -> Bool {
        lhs === rhs
    }

    public nonisolated func hash(into hasher: inout Hasher) {
        hasher.combine(ObjectIdentifier(self))
    }

    private func tellHostToUnpair() async -> String {
        do {
            let live: OpenSession
            if let session {
                live = session
            } else {
                live = try await SessionCoordinator(engine: engine, identity: identity)
                    .connect(to: host)
            }
            let bye = try await UnpairService.revoke(on: live, identity: identity)
            await live.close()
            return "The host confirmed it (\(bye.reason.wireValue))."
        } catch {
            return "The host was not told (\(error.localizedMessage)). "
                + "Remove the pairing there with `osprey-svc unpair`."
        }
    }
}
