import Foundation
import Network

/// A TCP connection to the agent's direct-LAN listener.
///
/// ## Transport-security notes that decide whether this works at all
///
/// * **App Transport Security does not apply to Network.framework.** ATS governs
///   `URLSession`. `NWConnection` over plain TCP is unaffected, which is why no
///   ATS exception is needed for this path — and why iOS 17's default refusal to
///   let `URLSession` talk to a bare IP address is also irrelevant here. It
///   *would* bite the moment anything on the phone reaches the relay's
///   `relay_url` over HTTP(S) with `URLSession`, since in development that url
///   is a LAN IP.
/// * **The local-network privacy prompt does apply.** From iOS 14, the first
///   connection to a local address triggers a system prompt, and
///   `NSLocalNetworkUsageDescription` must be in `Info.plist` or the connection
///   silently never becomes ready. `NSBonjourServices` must list `_osprey._tcp`
///   as well, because that is the service the durable discovery path browses for
///   (amendment A6).
///
/// The class is `@unchecked Sendable` and holds no actor isolation: every
/// `NWConnection` callback lands on `queue`, and the connection object is never
/// handed out. The alternative — an actor — would have to smuggle a
/// non-`Sendable` `NWConnection` across an isolation boundary.
public final class TCPByteStream: ByteStream, @unchecked Sendable {
    private let connection: NWConnection
    private let queue: DispatchQueue

    private init(connection: NWConnection, queue: DispatchQueue) {
        self.connection = connection
        self.queue = queue
    }

    /// Open a connection, or throw if it is not ready within `timeout` seconds.
    public static func connect(
        host: String,
        port: UInt16,
        timeout: TimeInterval
    ) async throws -> TCPByteStream {
        guard let endpointPort = NWEndpoint.Port(rawValue: port) else {
            throw TCPStreamError.invalidEndpoint("port \(port)")
        }
        let parameters = NWParameters.tcp
        if let tcp = parameters.defaultProtocolStack.transportProtocol as? NWProtocolTCP.Options {
            // The protocol is request/response with small messages; Nagle would
            // add up to 40 ms to every round trip the P0 gate measures.
            tcp.noDelay = true
        }
        let connection = NWConnection(
            host: NWEndpoint.Host(host), port: endpointPort, using: parameters)
        let queue = DispatchQueue(label: "com.osprey.app.tcp")
        let stream = TCPByteStream(connection: connection, queue: queue)
        do {
            try await stream.start(timeout: timeout)
        } catch {
            await stream.close()
            throw error
        }
        return stream
    }

    private func start(timeout: TimeInterval) async throws {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, any Error>) in
            let once = ResumeOnce<Void>(continuation)
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    once.resume(.success(()))
                case .failed(let error):
                    once.resume(.failure(TCPStreamError.connectionFailed(String(describing: error))))
                case .cancelled:
                    once.resume(.failure(TCPStreamError.cancelled))
                case .waiting(let error):
                    // Not fatal: this is what a pending local-network permission
                    // prompt or a momentarily unreachable route looks like, and
                    // the connection can still become ready. The deadline below
                    // is what bounds it.
                    OspreyLog.network.notice(
                        "connection waiting: \(String(describing: error), privacy: .public)")
                case .preparing, .setup:
                    break
                @unknown default:
                    break
                }
            }
            connection.start(queue: queue)
            queue.asyncAfter(deadline: .now() + timeout) { [weak self] in
                once.resume(.failure(TCPStreamError.timedOut(seconds: timeout)))
                self?.connection.cancel()
            }
        }
    }

    public func write(_ data: Data) async throws {
        guard !data.isEmpty else { return }
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, any Error>) in
            connection.send(
                content: data,
                completion: .contentProcessed { error in
                    if let error {
                        continuation.resume(
                            throwing: TCPStreamError.sendFailed(String(describing: error)))
                    } else {
                        continuation.resume()
                    }
                })
        }
    }

    public func read(exactly count: Int) async throws -> Data? {
        guard count > 0 else { return Data() }
        return try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Data?, any Error>) in
            let once = ResumeOnce<Data?>(continuation)
            connection.receive(minimumIncompleteLength: count, maximumLength: count) {
                data, _, isComplete, error in
                if let error {
                    once.resume(.failure(TCPStreamError.receiveFailed(String(describing: error))))
                    return
                }
                let received = data ?? Data()
                if received.count == count {
                    once.resume(.success(received))
                } else if isComplete && received.isEmpty {
                    // A clean close on a frame boundary. The caller decides
                    // whether that is an orderly end or a truncation.
                    once.resume(.success(nil))
                } else {
                    once.resume(
                        .failure(
                            TCPStreamError.truncated(expected: count, received: received.count)))
                }
            }
        }
    }

    public func close() async {
        // Cleared before cancelling: the handler retains `self`, and `self`
        // retains the connection, so leaving it in place would keep the pair
        // alive for as long as the framework holds the connection.
        connection.stateUpdateHandler = nil
        connection.cancel()
    }
}

/// Resumes a continuation exactly once.
///
/// `stateUpdateHandler` fires repeatedly and the connection deadline fires
/// independently of it, so both paths race for the same continuation and
/// resuming twice would trap.
private final class ResumeOnce<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Value, any Error>?

    init(_ continuation: CheckedContinuation<Value, any Error>) {
        self.continuation = continuation
    }

    func resume(_ result: Result<Value, any Error>) {
        lock.lock()
        let pending = continuation
        continuation = nil
        lock.unlock()
        pending?.resume(with: result)
    }
}

public enum TCPStreamError: Error, Hashable, Sendable {
    case invalidEndpoint(String)
    case connectionFailed(String)
    case cancelled
    case timedOut(seconds: TimeInterval)
    case sendFailed(String)
    case receiveFailed(String)
    case truncated(expected: Int, received: Int)
}

extension TCPStreamError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidEndpoint(let detail):
            return "Not a usable address: \(detail)"
        case .connectionFailed(let detail):
            return "The connection failed: \(detail)"
        case .cancelled:
            return "The connection was closed."
        case .timedOut(let seconds):
            return "The host did not answer within \(Int(seconds)) seconds. "
                + "Check that the phone and the host are on the same network, and that "
                + "Osprey is allowed to find devices on the local network in Settings."
        case .sendFailed(let detail):
            return "Could not send to the host: \(detail)"
        case .receiveFailed(let detail):
            return "Could not read from the host: \(detail)"
        case .truncated(let expected, let received):
            return "The host closed the connection mid-message "
                + "(\(received) of \(expected) bytes)."
        }
    }
}
