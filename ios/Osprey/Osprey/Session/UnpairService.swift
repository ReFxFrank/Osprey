import CryptoKit
import Foundation

/// The phone's half of "unpair works from both sides".
///
/// The operator standing at the host removes a pin with `osprey-svc unpair`; the
/// operator holding the phone cannot, so the phone signs a revocation under the
/// Secure Enclave key the host pinned and sends it inside the already
/// authenticated Noise channel. The host verifies it against its own store, so
/// a relay can neither forge nor suppress it (amendment A18).
///
/// Dropping the local pin does not depend on any of this succeeding: the phone
/// stops connecting the moment the pin is gone, whether or not the host was
/// reachable.
public enum UnpairService {
    /// Ask the host to drop this phone's pin.
    ///
    /// Issuer and target are both this device: the phone is saying "forget me",
    /// which is the only direction it has standing to assert. The agent accepts a
    /// revocation whose target is either end of the pairing and refuses one that
    /// names a third device.
    ///
    /// `TODO(frank):` `osprey_core::pairing::REVOKE_CLOCK_WINDOW` is five minutes
    /// and both ends must agree on it. A phone that has been offline for days
    /// resyncs its clock on reconnect, so five minutes is probably fine — but the
    /// decision recorded in that Rust `TODO(frank)` (widen the window, or replace
    /// the clock dependency with a host-issued challenge) has not been made, and
    /// this call will fail closed with `stale clock` until it is, on any phone
    /// whose clock is off by more than five minutes.
    public static func revoke(
        on session: OpenSession,
        identity: DeviceIdentity
    ) async throws -> ByeBody {
        let issuedAt = SessionClient.nowMilliseconds()
        let nonce = randomNonce()
        let message = SignedBytes.revocation(
            issuerDeviceID: identity.deviceID,
            revokedDeviceID: identity.deviceID,
            issuedAtMilliseconds: issuedAt,
            nonce: nonce)
        let signature = try identity.sign(message)
        return try await session.client.revokePairing(
            issuerDeviceID: identity.deviceID,
            revokedDeviceID: identity.deviceID,
            nonce: nonce,
            signature: signature,
            issuedAtMilliseconds: issuedAt)
    }

    /// 32 bytes from the system CSPRNG, which is what `SymmetricKey(size:)` is.
    static func randomNonce() -> Data {
        SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
    }
}
