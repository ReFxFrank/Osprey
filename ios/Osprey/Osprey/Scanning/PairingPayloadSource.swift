import Foundation

/// A source of scanned pairing payloads.
///
/// The camera is the shipping path and the only one compiled into the app
/// target. This protocol exists because the Simulator has no camera, so the
/// pairing flow has to be drivable from a test that feeds it a payload string;
/// the substitute lives in the test target and is not reachable at runtime.
/// There is deliberately no built-in fallback source — a plausible fake payload
/// on a shipping path is worse than an app that says it cannot scan.
public protocol PairingPayloadSource: Sendable {
    /// Decoded QR text, one element per distinct code seen.
    ///
    /// The stream finishes when `stop()` is called.
    func payloads() -> AsyncStream<String>
    func start() async throws
    func stop() async
}
