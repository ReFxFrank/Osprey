// DO NOT EDIT — generated from proto/messages.toml by proto/generate.ts.
// Run `pnpm generate` in proto/ after changing the registry.

import Foundation

/// Failure modes of envelope decoding that `DecodingError` does not cover.
public enum OspreyProtocolError: Error, Hashable, Sendable {
    /// Peer offered an envelope version outside the supported range.
    case unsupportedVersion(found: UInt32, min: UInt32, max: UInt32)
    /// The message type is reserved but its body schema is not yet defined.
    case bodyDeferred(MessageType)
}

/// The envelope fields that can be read before the body schema is known.
///
/// Decoding this from a full envelope ignores `body`, which is what makes the
/// two-step decode possible.
public struct EnvelopeHeader: Codable, Hashable, Sendable {
    /// Envelope version. Peers reject a version outside [min_protocol_version, protocol_version].
    public var v: UInt32
    /// Correlation id. A response carries the id of the request it answers.
    public var id: UUID
    /// Message type; selects the body schema.
    public var t: MessageType
    /// Sender clock, milliseconds since the Unix epoch. Advisory only — never used for authentication or expiry.
    public var ts: Int64

    public init(v: UInt32, id: UUID, t: MessageType, ts: Int64) {
        self.v = v
        self.id = id
        self.t = t
        self.ts = ts
    }

    private enum CodingKeys: String, CodingKey {
        case v = "v"
        case id = "id"
        case t = "t"
        case ts = "ts"
    }
}

/// Wire envelope common to every Osprey message.
public struct Envelope<Body: OspreyMessageBody>: Codable, Hashable, Sendable {
    /// Envelope version. Peers reject a version outside [min_protocol_version, protocol_version].
    public var v: UInt32
    /// Correlation id. A response carries the id of the request it answers.
    public var id: UUID
    /// Message type; selects the body schema.
    public var t: MessageType
    /// Sender clock, milliseconds since the Unix epoch. Advisory only — never used for authentication or expiry.
    public var ts: Int64
    /// Type-specific payload. Decoded in a second step so an unparseable body reports which type it belonged to.
    public var body: Body

    public init(id: UUID = UUID(), ts: Int64, body: Body) {
        self.v = OspreyProtocol.protocolVersion
        self.id = id
        self.t = Body.messageType
        self.ts = ts
        self.body = body
    }

    private enum CodingKeys: String, CodingKey {
        case v = "v"
        case id = "id"
        case t = "t"
        case ts = "ts"
        case body = "body"
    }
}

/// A decoded envelope body, one case per fully defined message type.
public enum MessageBody: Hashable, Sendable {
    /// `error`
    case error(ErrorBody)
    /// `hello`
    case hello(HelloBody)
    /// `hello.ok`
    case helloOk(HelloOkBody)
    /// `ping`
    case ping(PingBody)
    /// `pong`
    case pong(PongBody)
    /// `bye`
    case bye(ByeBody)
    /// `pair.request`
    case pairRequest(PairRequestBody)
    /// `pair.confirm`
    case pairConfirm(PairConfirmBody)
    /// `pair.revoke`
    case pairRevoke(PairRevokeBody)

    /// The registry type this body belongs to.
    public var messageType: MessageType {
        switch self {
        case .error: return .error
        case .hello: return .hello
        case .helloOk: return .helloOk
        case .ping: return .ping
        case .pong: return .pong
        case .bye: return .bye
        case .pairRequest: return .pairRequest
        case .pairConfirm: return .pairConfirm
        case .pairRevoke: return .pairRevoke
        }
    }
}

/// An envelope whose body has been resolved against its message type.
public struct DecodedEnvelope: Hashable, Sendable {
    /// Envelope version. Peers reject a version outside [min_protocol_version, protocol_version].
    public var v: UInt32
    /// Correlation id. A response carries the id of the request it answers.
    public var id: UUID
    /// Message type; selects the body schema.
    public var t: MessageType
    /// Sender clock, milliseconds since the Unix epoch. Advisory only — never used for authentication or expiry.
    public var ts: Int64
    /// Decoded payload.
    public var body: MessageBody

    public init(v: UInt32, id: UUID, t: MessageType, ts: Int64, body: MessageBody) {
        self.v = v
        self.id = id
        self.t = t
        self.ts = ts
        self.body = body
    }
}

/// Protocol constants and the encode/decode entry points.
public enum OspreyProtocol {
    /// Highest envelope version this build speaks.
    public static let protocolVersion: UInt32 = 1
    /// Lowest envelope version this build accepts from a peer.
    public static let minProtocolVersion: UInt32 = 1

    /// The base64 strategy is set explicitly rather than left to Foundation's
    /// default, because the Rust peer encodes `bytes` with the padded RFC 4648
    /// standard alphabet and interop must not rest on an unstated default.
    public static func decoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dataDecodingStrategy = .base64
        return decoder
    }

    public static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dataEncodingStrategy = .base64
        return encoder
    }

    public static func encode<Body: OspreyMessageBody>(
        id: UUID = UUID(),
        ts: Int64,
        body: Body,
        using encoder: JSONEncoder = OspreyProtocol.encoder()
    ) throws -> Data {
        try encoder.encode(Envelope(id: id, ts: ts, body: body))
    }

    /// Reads the envelope fields that do not depend on the body schema.
    public static func decodeHeader(
        _ data: Data,
        using decoder: JSONDecoder = OspreyProtocol.decoder()
    ) throws -> EnvelopeHeader {
        try decoder.decode(EnvelopeHeader.self, from: data)
    }

    /// Decodes a full envelope, resolving the body against `t`.
    ///
    /// The payload is parsed twice: `Codable` cannot select a body type from a
    /// sibling key in one pass, and a wrong guess would have to be recovered
    /// from mid-stream. Control-plane rates make the second parse irrelevant,
    /// and `input.*` never travels this path.
    public static func decode(
        _ data: Data,
        using decoder: JSONDecoder = OspreyProtocol.decoder()
    ) throws -> DecodedEnvelope {
        let header = try decodeHeader(data, using: decoder)
        guard header.v >= minProtocolVersion, header.v <= protocolVersion else {
            throw OspreyProtocolError.unsupportedVersion(
                found: header.v, min: minProtocolVersion, max: protocolVersion)
        }
        let body: MessageBody
        switch header.t {
        case .error:
            let decoded = try decoder.decode(Envelope<ErrorBody>.self, from: data)
            body = .error(decoded.body)
        case .hello:
            let decoded = try decoder.decode(Envelope<HelloBody>.self, from: data)
            body = .hello(decoded.body)
        case .helloOk:
            let decoded = try decoder.decode(Envelope<HelloOkBody>.self, from: data)
            body = .helloOk(decoded.body)
        case .ping:
            let decoded = try decoder.decode(Envelope<PingBody>.self, from: data)
            body = .ping(decoded.body)
        case .pong:
            let decoded = try decoder.decode(Envelope<PongBody>.self, from: data)
            body = .pong(decoded.body)
        case .bye:
            let decoded = try decoder.decode(Envelope<ByeBody>.self, from: data)
            body = .bye(decoded.body)
        case .pairRequest:
            let decoded = try decoder.decode(Envelope<PairRequestBody>.self, from: data)
            body = .pairRequest(decoded.body)
        case .pairConfirm:
            let decoded = try decoder.decode(Envelope<PairConfirmBody>.self, from: data)
            body = .pairConfirm(decoded.body)
        case .pairRevoke:
            let decoded = try decoder.decode(Envelope<PairRevokeBody>.self, from: data)
            body = .pairRevoke(decoded.body)
        default:
            throw OspreyProtocolError.bodyDeferred(header.t)
        }
        return DecodedEnvelope(v: header.v, id: header.id, t: header.t, ts: header.ts, body: body)
    }
}
