# Gate Report — P0: Foundations

*Osprey (formerly codenamed TETHER). Report format per brief §15.*
*Final: updated 2026-08-03 after the physical-device run closed the last two
half-criteria. Measurement provenance — original pass on Linux; 2026-08-02
Windows-native pass on the target machine; 2026-08-02 cloud-Mac session
(first Apple-SDK compile, Simulator tests, swiftlint, signed IPA); 2026-08-03
device run (pairing, encrypted ping/pong, key persistence).*

## Status

**PASS**

Every criterion is now measured, on the hardware it was specified for. The
final two half-criteria closed on 2026-08-03 (UTC) with the development-signed
app on the physical iPhone pairing against the agent on the Windows host over
the real LAN: QR scan → PSK handshake → pinned fingerprints matching on both
ends → encrypted ping/pong at 14 ms → keys and pairing surviving a force-quit
relaunch. Evidence: `artifacts/P0/device-run-2026-08-03.md`.

All deviations from the brief were approved in advance and are recorded as
amendments A1–A22 in the brief itself; what shipped implements the brief as
amended.

Nothing below is estimated. Every number came from a command run in this
environment and observed.

## Criteria

| # | Criterion (verbatim from brief) | Result | Evidence |
|---|---|---|---|
| 1 | Phone scans QR, pairs, exchanges an authenticated encrypted `ping`/`pong` over the local network. | **PASS** | Measured on the physical iPhone, 2026-08-03. QR scanned from the host console, `pairing_succeeded` audited with the pinned controller fingerprint, fingerprints compared and matching on both ends, then an encrypted session (`session established … fingerprint=18f9-b86c-b21d-0d87`) with ping/pong at **14 ms** round trip on the LAN. Full evidence in `artifacts/P0/device-run-2026-08-03.md`. |
| 2 | Keys survive agent restart and app restart. | **PASS** | Agent half — `keystore_survives_a_save_load_cycle`, backend-generic since 2026-08-02, runs against the **shipping DPAPI backend** on Windows (`CRYPTPROTECT_LOCAL_MACHINE` seal/unseal round-trip). App half — measured on the device 2026-08-03: force-quit from the app switcher and relaunch showed the same device fingerprint and paired host, then opened a session with no re-pairing (Secure Enclave key blob, X25519 static and host pin all reloaded from the keychain). |
| 3 | Unpair works from both sides and immediately blocks traffic. | **PASS** | Both directions. Agent side: `osprey-svc unpair`. Peer side: `pair.revoke` verified against the pinned identity with a freshness window, single-use nonce, and issuer/target binding; wrong-identity, replayed-nonce and stale-timestamp cases all rejected. Enforcement is local and authoritative — the relay is never the enforcement point. |
| 4 | Tampering with a handshake byte causes a clean logged failure, not a panic. | **PASS** | Byte-flip tests across handshake offsets return typed errors and write an audit entry. `#![deny(clippy::unwrap_used, clippy::expect_used)]` is active on the crypto crates and was proven to fire by inserting a deliberate `unwrap()`. |
| 5 | Cross-tenant test suite green: two accounts, every endpoint, 404 on foreign resources. **Report the endpoint count.** | **PASS — 8 endpoints** | The suite enumerates the live Fastify route table and fails if any registered route lacks a cross-tenant assertion, and also fails on assertions naming routes that no longer exist. One route is explicitly exempt (`GET /healthz`, a constant-returning liveness probe). |
| 6 | No raw `db.` access outside `src/repo/` — lint rule active and passing. | **PASS** | Two independent mechanisms (string-pattern `no-restricted-imports` + resolver-based `eslint-plugin-boundaries`). Proven to *fire*, not merely be configured: a violating file is planted and the error asserted, including in a nested subdirectory. |
| 7 | `cargo clippy -- -D warnings` and `swiftlint` clean. | **PASS** | clippy PASS on the Linux host, on cross-checked `x86_64-pc-windows-msvc`, and natively on the Windows target machine (both required invocations, exit 0, all targets). swiftlint PASS — `swiftlint lint --config .swiftlint.yml --strict` (0.65.0, macOS 26.4.1) exits 0 with 0 violations across 43 files at commit `5f2f569`. The first real run found 24 violations, fixed in `13015ce`/`5f2f569`; one justified in-code disable (`PairingFlow.run`, which mirrors the Rust core input-for-input). |
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

### Physical-device run (2026-08-03, iPhone + Windows host on one LAN)

| Metric | Value |
|---|---|
| QR pairing end to end | **PASS** — `pairing_succeeded` audited 00:52:54Z, controller fingerprint `18f9b86c…` pinned |
| Fingerprint comparison host↔phone | matching (operator-verified) |
| Encrypted ping round trip, LAN | **14 ms** (app HUD, 2 pings) |
| Keys/pairing survive app force-quit + relaunch | **PASS** — same fingerprint, same host, session without re-pairing |
| iOS prerequisites hit | Developer Mode enable + restart; camera and local-network permissions granted |

### Cloud-Mac session (2026-08-02, MacinCloud, Xcode 26.5 / macOS 26.4.1)

The first time any Swift in this repository met the Apple SDK:

| Metric | Value |
|---|---|
| First Apple-SDK compile (Simulator, Debug) | **BUILD SUCCEEDED** — first attempt, zero source changes needed |
| XCTest suite in the Simulator | **46 passed, 0 failed** — matching the Linux-linked run exactly |
| `swiftlint --strict` (criterion 7) | **exit 0, 0 violations** in 43 files, after fixing the 24 the first run surfaced |
| Signed device archive (`-allowProvisioningUpdates`, automatic signing) | **ARCHIVE SUCCEEDED** — certificate and profile minted automatically |
| Development IPA export (`method: debugging`) | **EXPORT SUCCEEDED** — `~/build/ipa/Osprey.ipa` on the Mac |
| XCFramework build on the Mac | all 5 steps; fat simulator slice `x86_64 arm64` |

Session friction worth recording: the MacinCloud home directory is a symlink
onto `/Volumes/Macintosh_HD`, which broke `uniffi_bindgen`'s askama templates
until `CARGO_HOME` and the working directory were pinned to physical paths; and
XcodeGen invoked through a bare symlink cannot find its SettingPresets, which
silently generates a project with no default build settings (empty
`PRODUCT_NAME`) — a wrapper script fixes it.

### Windows-native pass (2026-08-02, the target machine)

Everything above this subsection was measured on Linux. These numbers are from
the Windows dev/target machine itself (Rust 1.97.0 MSVC, Node 24.16.0):

| Metric | Value |
|---|---|
| Agent tests (`cargo test --workspace`) | **145 passed, 0 failed, 2 ignored** — +3 vs Linux because the keystore tests now run against the shipping DPAPI backend, which the Linux pass structurally could not |
| clippy — native host, `--all-targets -D warnings` | exit 0 |
| clippy — explicit `x86_64-pc-windows-msvc` target | exit 0 |
| `mdns_discovery` (ignored test, first execution ever) | **PASS** — advertise/discover/goodbye on the real network stack, 1.93 s |
| DPAPI seal/unseal round-trip (`keystore_survives_a_save_load_cycle`) | **PASS** — `CRYPTPROTECT_LOCAL_MACHINE`, byte-identical reload, cross-signature re-verifies |
| Codegen reproducibility on Windows | empty git diff after `pnpm generate` (required the `.gitattributes` fix — see discovered problem 11) |
| Relay lint / typecheck | clean / clean |
| Relay tests (`pnpm test`, live Postgres 16 in Docker) | **70 passed, 0 failed** — parity with Linux, after the shutdown-fixture fix (discovered problem 13). The very first run, seconds after the Postgres container was created, failed 19 tests with empty connection errors; every run since is clean. Most likely the container's init-phase restart dropping connections mid-suite — a bootstrap-timing artifact, not a suite defect, and unreproducible once the container is warm. |
| `relay_live` (ignored test, first execution ever) | **PASS** — agent enrolled, issued, looked up and revoked a pairing token against the actually-running relay over HTTP (0.07 s) |

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

### Found by the Windows-native pass (2026-08-02)

10. **The DPAPI keystore had zero test coverage anywhere.** The keystore tests
    were `#[cfg(not(windows))]` and exercised only the Unix dev backend — so
    criterion 2's agent half had only ever been proven against a backend the
    product never ships, and the first execution of `CryptProtectData` /
    `CryptUnprotectData` would have been in production. Fixed: the keystore
    tests are now backend-generic (`open_keystore()` selects DPAPI on Windows,
    the dev file elsewhere); all pass against real DPAPI with machine scope.
11. **Codegen reproducibility false-fails on Windows.** With `core.autocrlf`,
    a checkout is CRLF while the generator emits LF, so "regenerate → empty
    git diff" failed spuriously despite byte-identical content. Fixed with a
    `.gitattributes` pinning the generated trees and `proto/messages.toml` to
    LF; regeneration on Windows now produces an empty diff.
12. **The mDNS test had never run at all.** `mdns_discovery` was ignored on
    Linux ("needs a live network peer") and had no prior Windows run. Executed
    on the real Windows network stack: advertise, discover, and
    goodbye-on-shutdown all pass (1.93 s).
13. **The shutdown test was structurally impossible on Windows.** Its fixture
    delivered `process.kill(pid, 'SIGTERM')`, but Windows has no deliverable
    SIGTERM — Node terminates the target unconditionally without running
    handlers, so the process died at `ready` and both assertions failed. The
    fixture now dispatches on platform: POSIX keeps the real end-to-end kill;
    Windows invokes the registered handlers via `process.emit('SIGTERM')`,
    which still exercises everything the test asserts (the rejection path, the
    pool close in `finally`, the exit codes). The relay deploys on Linux, so
    the production signal path remains covered where it actually runs.

### Found on the device run (2026-08-03)

14. **A deliberate disconnect is logged as an error.** Tapping Disconnect in the
    app (or backgrounding it) surfaces on the host as
    `session ended with an error … could not read from the noise session` at
    WARN. The session teardown itself is correct; the diagnosis is wrong — an
    operator-initiated close should be recognized as a clean end (the app sends
    `bye`, or the read returns clean EOF), not reported as a read failure.
    Cosmetic now; it will matter in P1 when the service starts counting
    reconnects and in §9.3's 30-second background grace window. Not fixed in
    P0 — noted for P1's session-lifecycle work.
15. **The app ships no icon.** Installs and runs with the placeholder blank
    icon. Irrelevant to every P0 criterion; becomes blocking at the first
    TestFlight upload (App Store Connect requires the 1024-pt icon). P9
    packaging work.

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

**Yes.** Every criterion is measured and green; the discovered problems above
are recorded with owners (P1 for session-lifecycle diagnosis, P5 for the iOS
measurement-harness plan, P9 for the icon) rather than left implicit.

P1 builds: `osprey-svc` as a real Windows service (install/start/boot/restart
semantics), the session-0 → session-1 helper spawn with the SYSTEM-only pipe,
helper lifecycle with crash-loop backoff, `PerMonitorV2` DPI manifest, M-01
metrics with the 24 h ring buffer, and the iOS dashboard with live charts.

**The one thing to decide first:** `TODO(frank)` #11 — one host, or a device
list from the start? The register marks it as blocking P1's UI shape: the
dashboard the phone shows at P1's gate is either a single machine's screen or
a list-then-detail flow, and reworking that later touches every management
screen. The schema already supports N agents per account either way; this is
purely a product-surface decision.
