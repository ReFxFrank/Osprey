import Foundation

/// Opens a steady-state session to an already-pinned host.
///
/// Plain `Noise_IK` on the pinned statics — no PSK, because after pairing the
/// pin *is* the authentication and carrying the pairing secret forward would
/// only widen its blast radius.
public struct SessionCoordinator: Sendable {
    public static let connectTimeout: TimeInterval = 15
    public static let exchangeTimeout: TimeInterval = 30

    let engine: any NoiseEngine
    let identity: DeviceIdentity

    public init(engine: any NoiseEngine, identity: DeviceIdentity) {
        self.engine = engine
        self.identity = identity
    }

    /// Connect, negotiate `hello`, and hand back both the open session and what
    /// the host said about itself.
    public func connect(to host: PairedHost) async throws -> OpenSession {
        let endpoints = host.lanHints.dialOrder
        guard !endpoints.isEmpty else { throw QRPayloadError.noReachableAddress }

        let stream = try await PairingCoordinator.dial(endpoints)
        return try await withStreamDeadline(
            seconds: Self.exchangeTimeout, stream: stream
        ) {
            let channel = NoiseChannel(engine: engine)
            let framed = FramedStream(stream: stream)

            let first = try await channel.begin(
                pattern: .session,
                localStaticPrivateKey: identity.noiseStaticPrivateKey,
                remoteStaticPublicKey: host.pinnedIdentity.noiseStaticPublicKey,
                payload: Data())
            try await framed.writeFrame(first)
            guard let second = try await framed.readFrame() else {
                throw PairingError.hostClosedDuringHandshake
            }
            let result = try await channel.complete(second)

            // IK authenticates the responder cryptographically, but the check is
            // stated rather than assumed so a future pattern change cannot
            // quietly drop it.
            guard result.remoteStaticPublicKey == host.pinnedIdentity.noiseStaticPublicKey else {
                throw SessionError.hostIsNotThePinnedOne
            }

            let client = SessionClient(
                session: NoiseSession(channel: channel, stream: stream))
            let helloOk = try await client.openSession(
                deviceID: identity.deviceID,
                softwareVersion: AppVersion.current)
            return OpenSession(client: client, stream: stream, helloOk: helloOk)
        }
    }
}

/// A live session and the host's answer to `hello`.
public struct OpenSession: Sendable {
    public let client: SessionClient
    public let stream: any ByteStream
    public let helloOk: HelloOkBody

    public func close() async {
        if let failure = await client.sayGoodbye() {
            OspreyLog.session.notice(
                "could not send bye: \(String(describing: failure), privacy: .public)")
        }
        await stream.close()
    }
}

/// The build string reported in `hello`.
///
/// Read from the bundle rather than hard-coded so the audit entry the host
/// writes names the build that actually connected.
public enum AppVersion {
    public static let current: String = {
        let info = Bundle.main.infoDictionary
        let short = info?["CFBundleShortVersionString"] as? String ?? "0"
        let build = info?["CFBundleVersion"] as? String ?? "0"
        return "osprey-ios/\(short)+\(build)"
    }()
}
