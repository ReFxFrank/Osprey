# Gate Report — P0: Foundations

*Osprey (formerly codenamed TETHER). Report format per brief §15.*
*Last updated after the no-Mac completion pass.*

## Status

**FAIL**

A scope failure, not a defect failure. Everything buildable without a Mac is now
built and verified: the Windows agent, the relay, the protocol layer, the
Rust↔Swift bridge, and the complete iOS client **source**. What is missing is
verification: **no Swift in this repository has ever been compiled against the
Apple SDK, and nothing has run on the physical iPhone.**

Three gate criteria therefore remain unevaluated, including criterion 1, which is
the headline of the phase. Marking those green would put a checkmark over
untested code, so the gate stays FAIL until the cloud-Mac session closes them.

Nothing below is estimated. Every number came from a command run in this
environment and observed.

## Criteria

| # | Criterion (verbatim from brief) | Result | Evidence |
|---|---|---|---|
| 1 | Phone scans QR, pairs, exchanges an authenticated encrypted `ping`/`pong` over the local network. | **NOT MEASURED** | Still requires the phone, so it stays unmeasured — but substantially de-risked since this report was first written. The iOS Swift sources were linked against the real Rust library on Linux and the XCTest suite run against a live `osprey-core` responder: 46 tests, 0 failures, driving genuine IKpsk2 handshakes through the same UniFFI surface the phone will use. Agent-side, `pair_then_session_then_unpair_blocks_the_next_connection` covers pairing, session, ping/pong and unpair over real TCP. What remains unproven is the Apple-SDK half — Secure Enclave, camera, Keychain — and the app has never been compiled by Xcode. |
| 2 | Keys survive agent restart and app restart. | **PARTIAL** | Agent half PASS — `dev_keystore_survives_a_save_load_cycle` reopens the keystore as a restart proxy and asserts the reloaded bundle is byte-identical and still verifies. App half NOT MEASURED: Keychain/Secure Enclave persistence needs the device. |
| 3 | Unpair works from both sides and immediately blocks traffic. | **PASS** | Both directions. Agent side: `osprey-svc unpair`. Peer side: `pair.revoke` verified against the pinned identity with a freshness window, single-use nonce, and issuer/target binding; wrong-identity, replayed-nonce and stale-timestamp cases all rejected. Enforcement is local and authoritative — the relay is never the enforcement point. |
| 4 | Tampering with a handshake byte causes a clean logged failure, not a panic. | **PASS** | Byte-flip tests across handshake offsets return typed errors and write an audit entry. `#![deny(clippy::unwrap_used, clippy::expect_used)]` is active on the crypto crates and was proven to fire by inserting a deliberate `unwrap()`. |
| 5 | Cross-tenant test suite green: two accounts, every endpoint, 404 on foreign resources. **Report the endpoint count.** | **PASS — 8 endpoints** | The suite enumerates the live Fastify route table and fails if any registered route lacks a cross-tenant assertion, and also fails on assertions naming routes that no longer exist. One route is explicitly exempt (`GET /healthz`, a constant-returning liveness probe). |
| 6 | No raw `db.` access outside `src/repo/` — lint rule active and passing. | **PASS** | Two independent mechanisms (string-pattern `no-restricted-imports` + resolver-based `eslint-plugin-boundaries`). Proven to *fire*, not merely be configured: a violating file is planted and the error asserted, including in a nested subdirectory. |
| 7 | `cargo clippy -- -D warnings` and `swiftlint` clean. | **PARTIAL** | clippy PASS on the host **and** `x86_64-pc-windows-msvc` (exit 0, all targets). swiftlint **NOT MEASURED** — not installable here and the app cannot be compiled without the Apple SDK. |
| + | *(amendment A17)* Against a deliberately malicious relay, key substitution / self-redemption / token replay all fail closed. | **PASS** | Re-attacked after remediation: a relay holding only `routing_id` cannot complete the PSK handshake; replayed and expired tokens are refused; redeem is single-use and atomic. |

## Measurements

| Metric | Value |
|---|---|
| Agent tests (`cargo test --workspace`) | **146 passed, 0 failed, 2 ignored** (`mdns_discovery` and `relay_live` need a live network peer / running relay) |
| Relay tests (Node 24.18.1, live Postgres) | **70 passed, 0 failed** |
| clippy — host, `--all-targets -D warnings` | exit 0 |
| clippy — `x86_64-pc-windows-msvc`, `--all-targets -D warnings` | exit 0 |
| Relay lint / typecheck | clean / clean |
| Cross-tenant endpoints covered | **8** (+1 explicitly exempt) |
| `osprey-ffi` → `aarch64-apple-ios` | builds; `Mach-O 64-bit arm64` objects; 20,027,208 B |
| `osprey-ffi` → `aarch64-apple-ios-sim` | builds |
| `ring` (C dependency) in the Apple dependency tree | **0** |
| UniFFI Swift bindings generated on Linux | yes — `osprey_ffi.swift`, 73,285 B |
| Generated protocol Swift, `swiftc -typecheck -swift-version 6` | **clean** (Swift 6.0.3 for Linux) |
| iOS Swift ↔ real Rust, linked and run on Linux | **46 tests passed, 0 failed** — against a live `osprey-core` responder |
| Swift files | 47 |
| iOS app compiled against the **Apple SDK** | **NOT MEASURED** — no macOS/Xcode; Secure Enclave, camera and Keychain paths are unexercised |
| `swiftlint --strict` | **NOT MEASURED** — binary not installable here (GitHub releases 403 through the proxy) |
| `xcodegen generate` | **NOT MEASURED** — not installable here; `project.yml` parses but has never been consumed |
| Largest source file | 563 lines (`osprey-svc/src/state.rs`) — under the 600 limit |
| Codegen reproducibility | regenerating produces an empty git diff |
| Agent idle CPU / RSS | **NOT MEASURED** — a P1 criterion, not P0 |

### Reproduce

```bash
cd agent && cargo test --workspace
cd agent && cargo clippy --workspace --all-targets -- -D warnings
cd agent && cargo clippy --workspace --all-targets --target x86_64-pc-windows-msvc -- -D warnings
cd agent && cargo build -p osprey-ffi --release --target aarch64-apple-ios
cd relay && pnpm test && pnpm lint && pnpm typecheck     # needs Node >= 24 and Postgres
cd proto && pnpm generate                                 # then `git diff` must be empty
```

## Deviations from brief

All approved before implementation and recorded as amendments A1–A22 at the end
of `docs/osprey-build-brief.md`. The load-bearing ones:

- **A4 — the specified crypto was not implementable.** Ed25519 is a signature
  algorithm, not a DH function; Noise requires both parties on the same DH
  function; and a Secure Enclave key can never be a `snow` static because the
  Enclave never exports a private key. Resolved by keeping the mandated hardware
  identity keys as the pinned root of trust and adding an X25519 Noise static
  that each identity key cross-signs.
- **A5 — QR pairing was MITM-able by the relay.** The QR now carries a
  `pairing_secret` the relay never sees; the relay holds only
  `routing_id = SHA-256(pairing_secret)`, and the secret is the Noise PSK.
  Physical-access pairing became a cryptographic property rather than a UX
  convention.
- **A20 — peer verification had to become algorithm-agnostic.** See below.
- **A8** — P0's pairing entry point is a console binary; the tray menu lives in a
  component not built until P1.
- **A16/A17** — the audit log now records pairing and unpair, and the gate gained
  the hostile-relay criterion.

## Discovered problems

### Found by adversarial review, after the build reported success

All reproduced with live traffic; all fixed; each fix confirmed by re-running the
original attack rather than by re-reading the diff.

1. **Enrollment rate limit bypassable by an attacker-supplied header.**
   `trustProxy: true` made `request.ip` the leftmost `X-Forwarded-For` value —
   the limiter's own key. With a limit of 2, eight enrollments with a rotating
   header all returned 201. That limiter is the *only* structural bound on
   account creation, since per-account quotas cannot bound the creation of
   accounts.
2. **Unauthenticated cross-tenant write into another tenant's audit log.**
   `POST /v1/pairing/redeem` takes the account id from the request body and, on a
   miss, wrote an audit row into *that* tenant: 500 requests grew a victim's
   `audit_relay` by 147 KB. Anyone who had ever seen a QR — including a revoked
   controller, since the account id never rotates — could bury real security
   events. Now audited only once the caller has proved possession of the QR
   secret, and rate-limited per IP and per account.
3. **`pair.revoke` was specified, scaffolded, and unimplemented**, answering
   `unsupported` while its supporting types sat unused — so it *looked* done.
   A literal gate criterion, silently half-built, with no `TODO(frank):`.
4. **Chunk-count denial of service.** The framing layer bounded reassembled bytes
   but not chunk count, so authenticated empty-continuation chunks added zero
   bytes and pinned a session thread indefinitely — 200,000 accepted in 12.6 s.
5. **The pairing secret (the Noise PSK) was printed to stdout unconditionally**,
   behind a comment claiming the caller had opted in.
6. **RLS was one configuration mistake from silently inert** — no table forced it
   and the migrator URL fell back to the runtime URL.

### Found while preparing the iOS side

7. **The agent could not verify a Secure Enclave signature at all.** Verification
   was Ed25519-only, but the phone's identity key is P-256. Pairing with a real
   iPhone would have failed on the device with an opaque error. Fixed per
   amendment A20, including the encodings Apple actually emits: X9.63
   uncompressed public keys, variable-length ASN.1 DER signatures, and the
   message hashed once by `SecKeyCreateSignature` rather than twice.
8. **`FFINoiseEngine.swift` imported a module that does not exist.** It declared
   `import OspreyFFI`, but UniFFI emits `osprey_ffi.swift`, which the build
   script adds *directly to the Xcode target* and which itself imports the C shim
   `osprey_ffiFFI`. Confirmed by generating the real bindings on Linux and
   typechecking against them. This was a guaranteed first-compile failure on the
   Mac; removed.
9. **`project.yml` and `Info.plist` did not exist.** Without them nothing can be
   generated or built. Both now written and validated as parseable. The plist
   carries the three load-bearing keys: `NSCameraUsageDescription` (absent → hard
   crash on first capture), `NSLocalNetworkUsageDescription` (absent → the
   connection silently never becomes ready) and `NSBonjourServices`.

### Carried forward — will bite later

- **iOS measurement has no home yet.** Instruments is macOS-only and cloud Macs
  cannot attach a physical iPhone over USB, yet P5/P6 demand measured
  glass-to-glass latency and memory *on the phone*. Needs a plan — likely
  `os_signpost` plus a custom harness — before P5, not during it.
- **`snow` is formally unaudited.** Stated plainly because the whole trust model
  rests on it. It is the same implementation on both ends, which is exactly why
  one implementation was chosen over two.
- **The relay's rate limiters are in-process fixed windows.** A `TODO(frank):`
  records the decision if 1.0 ever runs more than one relay process.
- **`redeem` is deliberately an anonymous, tenant-targeted endpoint.**
  Amplification is closed and it is rate-limited, but it remains reachable by
  anyone holding an account id.

## Open TODO(frank) items encountered

| # | Item | Status |
|---|---|---|
| 1 | Final product name | **RESOLVED — Osprey** (A1) |
| 4 | Bundle identifier + APNs key id | **P0 half CLOSED** — `com.ospreyremote.app` (Explicit) and the iPhone UDID both registered 2026-08-02 under Team ID `FM8Z8BA64H` (A21). `com.osprey.app` was rejected: a wildcard `com.osprey.*` blocks every explicit id beneath it, so that prefix is unusable — do not retry it. The APNs `.p8` half remains open and is genuinely P8. |
| 5 | Relay domain + VPS | Open; not needed until P5. |
| 11 | One host or a device list | Open and **not blocking** — `devices.kind` plus the `pairings` join supports N agents per account without prejudging the UI. |
| 6, 8, 9, 10, 12, 13 | Sensors driver, signing cert, indicator style, denylist, review doc, desktop client | Open, all later phases. |

## Ready for P1?

**No — finish P0 first.** The remaining work is bounded, and all of it needs the
cloud Mac. Follow `docs/ios-build.md`.

1. ~~Register the App ID and the device~~ — **done 2026-08-02**.
   `com.ospreyremote.app` (Explicit) and the iPhone's UDID are both registered
   under Team ID `FM8Z8BA64H`, so the portal side is complete and Xcode's
   automatic signing can mint the certificate and profile on the Mac.
2. `cd ios/Osprey && xcodegen generate`.
3. `scripts/build-xcframework.sh` — note the Rust static libraries **and** the
   UniFFI Swift bindings already build on Linux, so only lipo,
   `xcodebuild -create-xcframework`, the Swift build, signing and upload need the
   Mac. That is why the session should be short.
4. Fix whatever the first real Swift compile surfaces. Expect some churn: 47
   Swift files have been type-checked only in the narrow sense the Apple SDK's
   absence permits.
5. Install to the physical iPhone — fastest loop is a development-signed IPA
   installed from the Windows PC with Sideloadly over USB; TestFlight for
   release candidates.
6. Measure criteria 1, 2 (app half) and 7 (swiftlint) **on the device**. The
   Simulator cannot substitute: it has neither a camera nor a Secure Enclave.

**The one thing to decide first:** nothing is now blocking. The identifier is
registered, so the next session can go straight to the Mac and work through
`docs/ios-build.md` from §3.
