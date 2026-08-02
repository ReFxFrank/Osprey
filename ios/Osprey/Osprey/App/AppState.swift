import Foundation

/// Whether this build has a usable hardware identity.
public enum IdentityState {
    case loading
    /// No Secure Enclave. The Simulator is the usual reason, and it is a stated
    /// state rather than a crash or a software-key fallback: a software identity
    /// would be a different, weaker security model wearing the same UI.
    case unsupported(String)
    case failed(String)
    case ready(DeviceIdentity)

    public var identity: DeviceIdentity? {
        if case .ready(let identity) = self { return identity }
        return nil
    }
}

public enum PairingState: Equatable, Sendable {
    case idle
    case scanning
    /// Dialling the host and running the PSK handshake. The two are one visible
    /// step because the phone has nothing useful to say between them.
    case pairing
    case failed(String)
}

/// What the host reported about a live session.
public struct ConnectedSession: Equatable, Sendable {
    public var sessionID: UUID
    public var hostDeviceID: UUID
    public var hostSoftwareVersion: String
    public var lastRoundTripMilliseconds: Int64?
    public var pingsSent: UInt64
}

public enum ConnectionState: Equatable, Sendable {
    case idle
    case connecting
    case connected(ConnectedSession)
    case failed(String)
}

extension Error {
    /// The operator-facing text for an error, preferring a written message over
    /// a type dump.
    var localizedMessage: String {
        (self as? LocalizedError)?.errorDescription ?? localizedDescription
    }
}
