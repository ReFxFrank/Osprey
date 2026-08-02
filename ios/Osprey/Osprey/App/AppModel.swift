import Foundation
import Observation

/// Everything the UI observes, and the only place app state is mutated.
///
/// `@MainActor` throughout: every property here is read during a SwiftUI view
/// update. The long-running work is `await`ed on the coordinators, which are
/// value types over an actor-isolated Noise channel, so nothing blocks the main
/// thread and nothing mutates this object off it.
@MainActor
@Observable
public final class AppModel {
    public private(set) var identityState: IdentityState = .loading
    public private(set) var pairingState: PairingState = .idle
    public private(set) var connectionState: ConnectionState = .idle
    public private(set) var pairedHost: PairedHost?
    /// One line of feedback for the action the operator just took.
    public var banner: String?

    @ObservationIgnored private let engine: any NoiseEngine
    @ObservationIgnored private let keychain: KeychainStore
    @ObservationIgnored private let pinStore: PinStore
    @ObservationIgnored private var openSession: OpenSession?
    @ObservationIgnored private var pingSequence: UInt64 = 0

    public init(
        engine: any NoiseEngine,
        keychain: KeychainStore = KeychainStore(service: DeviceIdentityStore.keychainService)
    ) {
        self.engine = engine
        self.keychain = keychain
        self.pinStore = PinStore(keychain: keychain)
    }

    public var identity: DeviceIdentity? { identityState.identity }

    /// Load or create the identity and read back any stored pin.
    ///
    /// Idempotent: the second call returns immediately unless the first failed,
    /// so a view may call it from `.task` without guarding.
    public func load() {
        if case .ready = identityState { return }
        do {
            let identity = try DeviceIdentityStore.loadOrCreate(keychain: keychain)
            identityState = .ready(identity)
            OspreyLog.identity.notice(
                "identity ready: \(identity.fingerprint.short, privacy: .public)")
        } catch IdentityError.secureEnclaveUnavailable {
            identityState = .unsupported(IdentityError.secureEnclaveUnavailable.localizedMessage)
            return
        } catch {
            identityState = .failed(error.localizedMessage)
            return
        }
        do {
            pairedHost = try pinStore.load()
        } catch {
            banner = error.localizedMessage
        }
    }

    // MARK: - Pairing

    public func beginScanning() {
        banner = nil
        pairingState = .scanning
    }

    public func cancelScanning() {
        pairingState = .idle
    }

    /// Handle one decoded QR string. Everything it can reject, it rejects before
    /// opening a socket.
    public func pair(withScannedText text: String) async {
        guard let identity else { return }
        guard pairedHost == nil else {
            pairingState = .failed(PairingError.alreadyPaired.localizedMessage)
            return
        }
        let payload: QRPayload
        do {
            payload = try QRPayload.decode(text)
        } catch {
            pairingState = .failed(error.localizedMessage)
            return
        }

        pairingState = .pairing
        do {
            let coordinator = PairingCoordinator(engine: engine, identity: identity)
            let host = try await coordinator.pair(with: payload)
            try pinStore.save(host)
            pairedHost = host
            pairingState = .idle
            banner = "Paired. Compare the fingerprint below with the one the host printed."
        } catch {
            pairingState = .failed(error.localizedMessage)
        }
    }

    // MARK: - Session

    public func connect() async {
        guard let identity, let host = pairedHost else { return }
        if case .connected = connectionState { return }
        if case .connecting = connectionState { return }
        connectionState = .connecting
        do {
            let coordinator = SessionCoordinator(engine: engine, identity: identity)
            let session = try await coordinator.connect(to: host)
            openSession = session
            pingSequence = 0
            connectionState = .connected(
                ConnectedSession(
                    sessionID: session.helloOk.sessionId,
                    hostDeviceID: session.helloOk.deviceId,
                    hostSoftwareVersion: session.helloOk.softwareVersion,
                    lastRoundTripMilliseconds: nil,
                    pingsSent: 0))
        } catch {
            connectionState = .failed(error.localizedMessage)
        }
    }

    public func disconnect() async {
        if let openSession {
            await openSession.close()
        }
        openSession = nil
        pingSequence = 0
        connectionState = .idle
    }

    /// Gate P0 criterion 1's second half: an authenticated encrypted round trip.
    public func sendPing() async {
        guard let openSession, case .connected(var connected) = connectionState else { return }
        pingSequence += 1
        do {
            let result = try await openSession.client.ping(sequence: pingSequence)
            connected.lastRoundTripMilliseconds = result.roundTripMilliseconds
            connected.pingsSent = pingSequence
            connectionState = .connected(connected)
        } catch {
            let message = error.localizedMessage
            await disconnect()
            connectionState = .failed(message)
        }
    }

    // MARK: - Unpair

    /// Drop the pin, telling the host first if it can be reached.
    ///
    /// The local pin goes whether or not the host answered: this phone stops
    /// connecting the moment it is gone. The host's own pin is authoritative for
    /// the host (amendment A18), so if the revocation did not land, the operator
    /// is told to remove it there rather than being shown a green checkmark.
    public func unpair() async {
        guard let identity, let host = pairedHost else { return }
        let hostOutcome = await tellHostToUnpair(identity: identity, host: host)

        openSession = nil
        pingSequence = 0
        connectionState = .idle
        do {
            try pinStore.clear()
            pairedHost = nil
            banner = "Unpaired. " + hostOutcome
        } catch {
            banner = "The stored pairing could not be removed: \(error.localizedMessage)"
        }
    }

    private func tellHostToUnpair(identity: DeviceIdentity, host: PairedHost) async -> String {
        do {
            let session: OpenSession
            if let openSession {
                session = openSession
            } else {
                session = try await SessionCoordinator(engine: engine, identity: identity)
                    .connect(to: host)
            }
            let bye = try await UnpairService.revoke(on: session, identity: identity)
            await session.close()
            return "The host confirmed it (\(bye.reason.wireValue))."
        } catch {
            return "The host was not told (\(error.localizedMessage)). "
                + "Remove the pairing there with `osprey-svc unpair`."
        }
    }
}
