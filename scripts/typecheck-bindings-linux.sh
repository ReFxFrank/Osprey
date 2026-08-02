#!/usr/bin/env bash
#
# Typecheck the generated UniFFI Swift bindings — on Linux, with no Mac.
#
# `swiftc -typecheck` needs declarations, not an Apple SDK and not a linker, so
# a Linux Swift toolchain can prove the bindings are well-formed Swift 6 and
# that the FFI surface is callable in strict-concurrency mode. That catches the
# whole class of breakage where a Rust-side signature change generates Swift
# that does not compile — which would otherwise surface only on the cloud Mac,
# hours later.
#
# What this does NOT prove: linking, running, or anything about UIKit,
# CryptoKit, or the Security framework. Those need the real SDK.
#
# Requires: a Linux Swift toolchain. Point SWIFTC at it, or put swiftc on PATH.
#   SWIFTC=/opt/swift/usr/bin/swiftc scripts/typecheck-bindings-linux.sh

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
BINDINGS="$REPO_ROOT/agent/target/xcframework"
SWIFTC=${SWIFTC:-swiftc}

die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

command -v "$SWIFTC" >/dev/null || die "no Swift compiler; set SWIFTC=/path/to/swiftc"
[ -f "$BINDINGS/bindings/osprey_ffi.swift" ] ||
    die "bindings not generated. Run: scripts/build-xcframework.sh --partial"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/inc"
cp "$BINDINGS/headers/osprey_ffiFFI.h" "$WORK/inc/"
cp "$BINDINGS/bindings/osprey_ffi.swift" "$WORK/"

# The shipped modulemap `use`s Darwin and the _Builtin_std* submodules, which
# exist only under the Apple SDK. The header itself is identical, so a plain
# modulemap is a faithful stand-in for a typecheck.
cat >"$WORK/inc/module.modulemap" <<'EOF'
module osprey_ffiFFI {
    header "osprey_ffiFFI.h"
    export *
}
EOF

# A consumer that walks the whole pairing sequence. Its job is to fail to
# compile if any name, argument label, or thrown-error shape drifts.
cat >"$WORK/consumer.swift" <<'EOF'
import Foundation

/// Mirrors what the pairing screen does, minus the socket and the Enclave.
func pairFlow(qrText: String, noiseStaticPrivate: Data, phone: PeerIdentity) throws {
    let scanned: ScannedQr = try parseQrPayload(text: qrText)
    let _: String = scanned.accountId()
    let _: String = scanned.deviceId()
    let _: String = scanned.relayUrl()
    let _: [String] = scanned.lanHints()
    let _: Data = scanned.routingId()
    let fingerprint: IdentityFingerprint = scanned.agentFingerprint()
    let _: String = fingerprint.short

    try verifyIdentityBundle(identity: scanned.agentIdentity())

    let handshake: NoiseHandshake = try scanned.startPairing(
        localNoiseStaticPrivate: noiseStaticPrivate)
    let hello: Data = try encodeIdentityMessage(identity: phone)
    let _: Data = try handshake.writeMessage(payload: hello)
    try handshake.pushBytes(data: Data())
    if let reply: Data = try handshake.readMessage() {
        let _: PeerIdentity = try decodeIdentityMessage(message: reply)
    }
    let _: Bool = try handshake.isHandshakeFinished()

    let transport: NoiseTransport = try handshake.intoTransport()
    let _: Data = try transport.remoteStatic()
    let _: Data = try transport.encrypt(payload: pairConfirmTag())
    try transport.pushBytes(data: Data())
    if let accept: Data = try transport.nextMessage() {
        precondition(accept == pairAcceptTag())
    }
}

/// The Secure Enclave half: Rust states the message, Swift signs it.
func enclaveCrossCertificate(identityPub: Data, noiseStaticPub: Data) throws -> Data {
    try crossCertificateBytes(identityPub: identityPub, noiseStaticPub: noiseStaticPub)
}

func reconnect(noiseStaticPrivate: Data, pinnedAgentStatic: Data) throws -> NoiseHandshake {
    try NoiseHandshake.sessionInitiator(
        localStatic: noiseStaticPrivate, remoteStatic: pinnedAgentStatic)
}

/// The lower-level pairing constructor, for a phone that already holds the QR's
/// fields rather than the scanned object.
func pairDirect(noiseStaticPrivate: Data, agentStatic: Data, secret: Data) throws
    -> NoiseHandshake
{
    try NoiseHandshake.pairingInitiator(
        localStatic: noiseStaticPrivate, remoteStatic: agentStatic, psk: secret)
}

/// Every error the UI has to branch on must be a distinct, structured case.
func describe(_ error: OspreyError) -> String {
    switch error {
    case .HandshakeConfig(let detail): return "config: \(detail)"
    case .HandshakeRejected(let stage, let detail): return "handshake \(stage): \(detail)"
    case .TransportAuth(let detail): return "auth: \(detail)"
    case .Framing(let detail): return "framing: \(detail)"
    case .MessageTooLarge(let limit): return "too large: \(limit)"
    case .CrossSignature(let reason, _):
        switch reason {
        case .malformed: return "malformed signature"
        case .notSignedByIdentity: return "wrong signer"
        case .badIdentityKey: return "bad identity key"
        case .unsupportedAlgorithm(let raw): return "unsupported \(raw)"
        }
    case .UnpinnedPeer: return "unpinned peer"
    case .UnsupportedQrVersion(let found, let expected): return "qr v\(found) != v\(expected)"
    case .PayloadDecode(let detail): return "decode: \(detail)"
    case .PayloadEncode(let detail): return "encode: \(detail)"
    case .BadKeyLength(let label, let expected, let actual):
        return "\(label): want \(expected), got \(actual)"
    case .SessionState(let detail): return "state: \(detail)"
    case .InboundOverflow(let limit): return "overflow: \(limit)"
    case .Unexpected(let detail): return "unexpected: \(detail)"
    }
}

/// The objects must be Sendable, or the app cannot hold one across an actor
/// boundary — which is the whole reason the surface is synchronous.
func sendableAcrossActors(_ transport: sending NoiseTransport) async {
    await Task.detached { _ = try? transport.remoteStatic() }.value
}

func framingHelpers(_ buffer: Data) throws {
    let scan: FrameScan = try frameDecode(buffer: buffer)
    if let frame: Data = scan.frame {
        let _: Data = try frameEncode(message: frame)
    }
    let _: UInt64 = scan.consumed
    let _: UInt64 = noiseMaxMessageLen()
    let _: UInt64 = maxChunkPayloadLen()
    let _: Data = try routingIdFromSecret(pairingSecret: Data(count: 32))
    let _: IdentityFingerprint = try identityFingerprint(
        identity: PeerIdentity(
            identityAlgorithm: "p256", identityPub: Data(), noiseStaticPub: Data(),
            noiseStaticSig: Data()))
}
EOF

"$SWIFTC" -typecheck -swift-version 6 -I "$WORK/inc" \
    "$WORK/osprey_ffi.swift" "$WORK/consumer.swift"
echo "bindings typecheck clean (Swift 6 language mode)"
