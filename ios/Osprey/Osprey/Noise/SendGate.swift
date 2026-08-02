import Foundation

/// Runs async operations strictly one at a time, in call order.
///
/// An `actor` alone does not give this. Actors are *reentrant*: the moment an
/// actor method suspends on an `await`, another call may enter. That is fine for
/// guarding a single mutation, and wrong for guarding a sequence of them — which
/// is exactly what sealing a Noise message and then writing it to the socket is.
///
/// The gate works by chaining: each operation keeps a handle on its predecessor
/// and does not begin until that predecessor has finished. Appending to the
/// chain happens inside the actor and never suspends, so the order operations
/// are enqueued is the order they run.
actor SendGate {
    private var tail: Task<Void, Never>?

    /// Run `operation` after every operation already enqueued has completed.
    ///
    /// A failure is delivered to its own caller and does not break the chain:
    /// the queue is a serialisation mechanism, not a transaction, and a caller
    /// blocked behind someone else's error would be a worse failure mode than
    /// the error itself.
    func serialized<T: Sendable>(
        _ operation: @Sendable @escaping () async throws -> T
    ) async throws -> T {
        let predecessor = tail
        let result = Task<Result<T, Error>, Never> {
            // Predecessors are `Task<Void, Never>`, so awaiting one cannot throw
            // and cannot cancel this operation — it only orders it.
            await predecessor?.value
            do {
                return .success(try await operation())
            } catch {
                return .failure(error)
            }
        }
        // Erase the result so the next caller waits on completion only, and a
        // failure here does not propagate sideways into an unrelated send.
        tail = Task { _ = await result.value }
        return try await result.value.get()
    }
}
