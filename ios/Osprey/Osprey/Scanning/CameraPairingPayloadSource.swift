import AVFoundation
import Foundation

/// The shipping QR scanner: an `AVCaptureSession` decoding `.qr` metadata.
///
/// `@unchecked Sendable` with one serial queue behind it. `AVCaptureSession` is
/// not `Sendable`, and its own contract is that configuration and
/// `startRunning()` happen off the main thread — `startRunning()` blocks. Every
/// method here hops to `queue` before touching the session, and the session is
/// exposed only to the preview layer, which reads it on the main thread as
/// AVFoundation requires.
public final class CameraPairingPayloadSource: NSObject, PairingPayloadSource,
    AVCaptureMetadataOutputObjectsDelegate, @unchecked Sendable
{
    /// Read on the main thread by `CameraPreviewView`. Handing the session to a
    /// preview layer is the documented way to render it and does not mutate it.
    public let session = AVCaptureSession()

    private let queue = DispatchQueue(label: "com.osprey.app.scanner")
    private let lock = NSLock()
    private var continuation: AsyncStream<String>.Continuation?
    private var configured = false
    private var seen: Set<String> = []

    public override init() {
        super.init()
    }

    public func payloads() -> AsyncStream<String> {
        AsyncStream { continuation in
            lock.lock()
            self.continuation = continuation
            lock.unlock()
            continuation.onTermination = { [weak self] _ in
                self?.detachContinuation()
            }
        }
    }

    public func start() async throws {
        guard await Self.requestCameraAccess() else {
            throw ScannerError.cameraAccessDenied
        }
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, any Error>) in
            queue.async {
                do {
                    try self.configureIfNeeded()
                    if !self.session.isRunning {
                        self.session.startRunning()
                    }
                    continuation.resume()
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    public func stop() async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            queue.async {
                if self.session.isRunning {
                    self.session.stopRunning()
                }
                continuation.resume()
            }
        }
        finishStream()
    }

    /// Configure on `queue`, once.
    private func configureIfNeeded() throws {
        guard !configured else { return }
        guard
            let device = AVCaptureDevice.default(
                .builtInWideAngleCamera, for: .video, position: .back)
        else {
            throw ScannerError.noCamera
        }
        let input: AVCaptureDeviceInput
        do {
            input = try AVCaptureDeviceInput(device: device)
        } catch {
            throw ScannerError.couldNotConfigure(String(describing: error))
        }

        session.beginConfiguration()
        defer { session.commitConfiguration() }

        guard session.canAddInput(input) else {
            throw ScannerError.couldNotConfigure("the camera input was refused")
        }
        session.addInput(input)

        let output = AVCaptureMetadataOutput()
        guard session.canAddOutput(output) else {
            throw ScannerError.couldNotConfigure("the metadata output was refused")
        }
        session.addOutput(output)
        // Both of these are only valid after `addOutput`: before it, the output
        // has no connection and reports no available types.
        output.setMetadataObjectsDelegate(self, queue: queue)
        guard output.availableMetadataObjectTypes.contains(.qr) else {
            throw ScannerError.qrNotSupported
        }
        output.metadataObjectTypes = [.qr]

        configured = true
    }

    public func metadataOutput(
        _ output: AVCaptureMetadataOutput,
        didOutput metadataObjects: [AVMetadataObject],
        from connection: AVCaptureConnection
    ) {
        for object in metadataObjects {
            guard let code = object as? AVMetadataMachineReadableCodeObject,
                code.type == .qr,
                let text = code.stringValue
            else { continue }
            emit(text)
        }
    }

    /// A QR in frame is re-decoded many times a second; the pairing flow must
    /// see each distinct code once.
    private func emit(_ text: String) {
        lock.lock()
        let isNew = seen.insert(text).inserted
        let sink = continuation
        lock.unlock()
        guard isNew else { return }
        sink?.yield(text)
    }

    private func detachContinuation() {
        lock.lock()
        continuation = nil
        lock.unlock()
    }

    private func finishStream() {
        lock.lock()
        let sink = continuation
        continuation = nil
        seen.removeAll()
        lock.unlock()
        sink?.finish()
    }

    private static func requestCameraAccess() async -> Bool {
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            return true
        case .notDetermined:
            return await AVCaptureDevice.requestAccess(for: .video)
        case .denied, .restricted:
            return false
        @unknown default:
            return false
        }
    }
}

public enum ScannerError: Error, Hashable, Sendable {
    case cameraAccessDenied
    case noCamera
    case qrNotSupported
    case couldNotConfigure(String)
}

extension ScannerError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .cameraAccessDenied:
            return "Osprey needs camera access to scan the pairing code. "
                + "Enable it in Settings › Osprey › Camera."
        case .noCamera:
            return "This device has no back camera, so it cannot scan a pairing code. "
                + "The iOS Simulator has no camera; a physical iPhone is required."
        case .qrNotSupported:
            return "This device's camera cannot decode QR codes."
        case .couldNotConfigure(let detail):
            return "The camera could not be started: \(detail)"
        }
    }
}
