import Foundation
import Observation

/// The app's top level: this phone's identity, the pairing flow, and the list of
/// machines it is paired with.
///
/// Per-machine state lives in [`DeviceModel`], one per paired host (amendment
/// A23). This object owns only what is genuinely global.
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
    public private(set) var devices: [DeviceModel] = []
    /// One line of feedback for the action the operator just took.
    public var banner: String?

    @ObservationIgnored private let engine: any NoiseEngine
    @ObservationIgnored private let keychain: KeychainStore
    @ObservationIgnored private let pinStore: PinStore

    public init(
        engine: any NoiseEngine,
        keychain: KeychainStore = KeychainStore(service: DeviceIdentityStore.keychainService)
    ) {
        self.engine = engine
        self.keychain = keychain
        self.pinStore = PinStore(keychain: keychain)
    }

    public var identity: DeviceIdentity? { identityState.identity }

    /// Load or create the identity and read back the stored pins.
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
        reloadDevices()
    }

    private func reloadDevices() {
        guard let identity else { return }
        do {
            devices = try pinStore.loadAll().map { host in
                DeviceModel(
                    host: host, engine: engine, identity: identity, pinStore: pinStore)
            }
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
    ///
    /// Re-pairing a machine that is already pinned is allowed and *replaces* its
    /// record: the host may have rotated its Noise static, and keeping the old
    /// entry alongside the new one would leave a stale pin that still looks
    /// usable. P0 refused this outright because it stored exactly one host.
    public func pair(withScannedText text: String) async {
        guard let identity else { return }
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
            reloadDevices()
            pairingState = .idle
            banner = "Paired. Compare the fingerprint with the one the host printed."
        } catch {
            pairingState = .failed(error.localizedMessage)
        }
    }

    // MARK: - Device list

    /// Unpair one machine and drop it from the list.
    public func forget(_ device: DeviceModel) async {
        banner = await device.unpair()
        reloadDevices()
    }

    /// Redial anything the operator left connected (§9.3).
    public func refreshAfterForeground() async {
        for device in devices {
            await device.refreshAfterForeground()
        }
    }
}
