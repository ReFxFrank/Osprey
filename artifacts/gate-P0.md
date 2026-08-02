# Gate Report — P0: Foundations

*Osprey (formerly codenamed TETHER). Report format per brief §15.*

## Status

**FAIL**

This is a scope failure, not a defect failure. The Windows-agent, relay, and
protocol two-thirds of P0 are complete and verified to the standard the brief
demands. **The iOS client was not built at all** — there is no Xcode project, no
app source, no Secure Enclave identity, no QR scanner, no pairing UI. Only the
generated protocol types exist, and no Swift compiler has ever read them.

Three of the seven gate criteria therefore cannot be evaluated, including
criterion 1, which is the headline of the phase. Reporting this as "PASS WITH
DEVIATIONS" would put a green checkmark over a third of the phase that does not
exist, so it is a FAIL until the iOS work is done on the cloud Mac.

Nothing below is estimated. Every number was produced by a command I ran in this
environment and observed.

## Criteria

| # | Criterion (verbatim from brief) | Result | Evidence |
|---|---|---|---|
| 1 | Phone scans QR, pairs, exchanges an authenticated encrypted `ping`/`pong` over the local network. | **NOT MEASURED** | No iOS app exists; no macOS/Xcode/Swift in this environment. The *protocol* equivalent is proven agent-side: `pair_then_session_then_unpair_blocks_the_next_connection` runs a full IKpsk2 pairing, steady-state IK session, and encrypted ping/pong over real TCP on loopback. That is not the criterion, which requires the phone. |
| 2 | Keys survive agent restart and app restart. | **PARTIAL** | Agent half PASS: `dev_keystore_survives_a_save_load_cycle` reopens the keystore as a restart proxy and asserts the reloaded bundle is byte-identical and still verifies. App half NOT MEASURED — no app. |
| 3 | Unpair works from both sides and immediately blocks traffic. | **PASS** | Both directions implemented and tested. Agent side: `osprey-svc unpair`. Peer side: `pair.revoke` verified against the pinned identity, with freshness window, single-use nonce, issuer/target binding. 4 `peer_revoke` tests, incl. wrong-identity, replayed-nonce and stale-timestamp rejection. Enforcement is local and authoritative; the relay is never the enforcement point. |
| 4 | Tampering with a handshake byte causes a clean logged failure, not a panic. | **PASS** | `cargo test -p osprey-core`; byte-flip tests across handshake offsets return typed errors and write an audit entry. `#![deny(clippy::unwrap_used, clippy::expect_used)]` is active on the crypto crates and was proven to fire by inserting a deliberate `unwrap()`. |
| 5 | Cross-tenant test suite green: two accounts, every endpoint, 404 on foreign resources. **Report the endpoint count.** | **PASS — 8 endpoints** | `relay/test/tenant-isolation.test.ts`, 8 tests. Coverage is not hand-maintained: the suite enumerates the live Fastify route table and fails if any registered route lacks a cross-tenant assertion, and also fails on assertions naming routes that no longer exist. 1 route is explicitly exempt (`GET /healthz`, a constant-returning liveness probe). |
| 6 | No raw `db.` access outside `src/repo/` — lint rule active and passing. | **PASS** | `pnpm lint` clean. Two independent mechanisms (string-pattern `no-restricted-imports` + resolver-based `eslint-plugin-boundaries`). Proven to actually fire, not merely configured: `test/lint-enforcement.test.ts` plants a violating file and asserts the error, including in a nested subdirectory. |
| 7 | `cargo clippy -- -D warnings` and `swiftlint` clean. | **PARTIAL** | clippy PASS on both the host and `x86_64-pc-windows-msvc` (exit 0, all targets). swiftlint **NOT MEASURED** — not installed and no Swift toolchain in this container. |
| + | *(added by amendment A17)* Against a deliberately malicious relay, key substitution / self-redemption / token replay all fail closed. | **PASS** | Re-attacked after remediation: relay-side key substitution cannot complete the PSK handshake; a replayed or expired token is refused; the redeem path is single-use and atomic. |

## Measurements

| Metric | Value |
|---|---|
| Agent tests (`cargo test --workspace`) | **94 passed, 0 failed, 0 ignored** |
| Relay tests (`pnpm test`, Node 24.18.1, live Postgres) | **70 passed, 0 failed** (10 files) |
| clippy, host target, `--all-targets -D warnings` | exit 0 |
| clippy, `x86_64-pc-windows-msvc`, `--all-targets -D warnings` | exit 0 |
| Relay lint / typecheck | clean / clean |
| Cross-tenant endpoints covered | **8** (+1 explicitly exempt) |
| Largest source file | 518 lines (`osprey-svc/src/state.rs`) — under the 600 limit |
| Protocol registry | 73 message types: 9 fully defined, 64 name-only reservations |
| Codegen reproducibility | regenerating produces an empty git diff |
| `ring` (C dependency) in agent tree | 0 |
| iOS-side anything | **NOT MEASURED** — no macOS, Xcode, or Swift compiler in this environment |
| Agent idle CPU / RSS | **NOT MEASURED** — a P1 criterion, not P0 |

### Reproduce

```bash
cd agent && cargo test --workspace
cd agent && cargo clippy --workspace --all-targets -- -D warnings
cd agent && cargo clippy --workspace --all-targets --target x86_64-pc-windows-msvc -- -D warnings
cd relay && pnpm test && pnpm lint && pnpm typecheck     # needs Node >= 24 and Postgres
cd proto && pnpm generate                                 # then `git diff` must be empty
```

## Deviations from brief

All were approved before implementation and are recorded in the brief's
amendment log (A1–A19). The load-bearing ones:

- **A4 — the specified crypto was not implementable.** Ed25519 is a signature
  algorithm, not a DH function; Noise needs both parties on the same DH
  function; and a Secure Enclave key can never be a `snow` static because the
  Enclave never exports a private key. Resolved by keeping the mandated hardware
  identity keys as the pinned root of trust and adding an X25519 Noise static
  that the identity key cross-signs. Verified before adoption.
- **A5 — QR pairing was MITM-able by the relay.** The brief's flow put the
  one-time token and the phone's public key through the untrusted relay. Now the
  QR carries a `pairing_secret` the relay never sees; the relay only ever holds
  `routing_id = SHA-256(pairing_secret)`, and the secret is the Noise PSK.
  Physical-access pairing is now a cryptographic property, not a UX convention.
- **A8** — P0's pairing entry point is a console binary, because the tray menu
  the brief assumes lives in a component not built until P1.
- **A16/A17** — the audit log now records pairing and unpair (it did not), and
  the gate gained the hostile-relay criterion above.

## Discovered problems

Adversarial review found these **after** the build reported success. All were
reproduced with live traffic, all are now fixed, and each fix was confirmed by
re-exploiting it rather than by reading the diff.

1. **Enrollment rate limit was bypassable by an attacker-supplied header.**
   `trustProxy: true` made `request.ip` the leftmost `X-Forwarded-For` value,
   which is the limiter's key. With a limit of 2, eight enrollments with a
   rotating header all returned 201. That limiter is the *only* structural bound
   on account creation, since per-account quotas cannot bound the creation of
   accounts. Fixed to `trustProxy: 1`; re-attack now yields `201 201 429…`.
2. **Unauthenticated cross-tenant write into another tenant's audit log.**
   `POST /v1/pairing/redeem` takes the account id from the request body and, on a
   miss, wrote an audit row into *that* tenant. 500 requests grew a victim's
   `audit_relay` by 147 KB. Anyone who ever saw a QR — including a revoked
   controller, since the account id never rotates — could bury real security
   events. Fixed; re-attack shows 500 bogus redeems now write 0 rows.
3. **`pair.revoke` was specified, scaffolded, and unimplemented.** The agent
   answered it `unsupported` while `UnpairInitiator::Peer` and
   `DeviceIdentity::sign` sat with zero callers, so it *looked* done. This was a
   literal gate criterion with no `TODO(frank):` marking the gap. Now implemented
   and tested.
4. **Chunk-count denial of service.** The framing layer bounded reassembled
   bytes but not chunk count, so authenticated empty-continuation chunks added
   zero bytes and pinned a session thread indefinitely — 200,000 accepted in
   12.6 s. Now refused at the first chunk.
5. **The pairing secret was printed to stdout unconditionally**, behind a comment
   claiming the caller opted in. It is now behind an explicit flag, default off.
6. **RLS was one config mistake from silently inert.** No table had `FORCE ROW
   LEVEL SECURITY`, and the migrator URL silently fell back to the runtime URL.
   Now forced on all 7 tables, and the relay refuses to boot as an owner or
   superuser role.

### Carried forward — things that will bite later

- **iOS measurement has no home.** Instruments is macOS-only, and cloud Macs
  cannot attach a physical iPhone over USB. P5/P6 demand measured glass-to-glass
  latency and memory on the phone. That needs a plan — likely `os_signpost` plus
  a custom harness — before P5, not during it.
- **`snow` is formally unaudited.** Stated plainly because the whole trust model
  rests on it. It is the same implementation on both ends, which is why one
  implementation was chosen over two.
- **The relay's single-process rate limiters** are in-memory fixed windows. A
  `TODO(frank):` records the decision needed if 1.0 ever runs more than one
  relay process.
- **Redeem remains a tenant-targeted anonymous endpoint by design.** Amplifica-
  tion is closed and it is rate-limited, but it is inherently reachable by
  anyone holding an account id.

## Open TODO(frank) items encountered

| # | Item | Status |
|---|---|---|
| 1 | Final product name | **RESOLVED — Osprey** (A1) |
| 4 | Bundle identifier + APNs key id | **Half resolved** — bundle id `com.refx.osprey` (A2). It must still be registered as an App ID in the Apple Developer portal before a provisioning profile can issue. The APNs `.p8` half is genuinely P8. |
| 5 | Relay domain + VPS | Open, not needed until P5. P0 used a local relay. |
| 11 | One host or a device list | Open, and **not blocking** — `devices.kind` plus the `pairings` join supports N agents per account without prejudging the UI. |
| 9, 10, 6, 8, 12, 13 | Indicator style, denylist, sensors, cert, review doc, desktop client | Open, all later phases. |

## Ready for P1?

**No — finish P0 first.** The remaining work is bounded and well understood:

1. Xcode project (via **XcodeGen**, so the project is a text file in git rather
   than a binary only Xcode can edit — this matters when authoring off-Mac).
2. iOS identity: P-256 in the Secure Enclave as the pinned root, cross-signing a
   Curve25519 Noise static in the Keychain.
3. `snow` as an XCFramework via UniFFI. **The Rust half is already de-risked** —
   the crypto core builds to real `Mach-O arm64` for device and simulator from
   Linux, with zero `ring`, so the Mac only has to package, build Swift, sign,
   and upload (`artifacts/P0-plan-evidence/ios-crossbuild.md`).
4. The pairing UI and QR scanner, then criteria 1, 2 and 7 measured for real on
   the physical iPhone.

**The one thing I would want decided first:** whether to register
`com.refx.osprey` as the App ID now. Everything in step 1–4 needs it, and
changing it after first pairing invalidates Keychain access groups and forces
every device to re-pair — cheap now, expensive later.

Note on how the iOS loop should run: builds reach the phone over the air, since
cloud Macs cannot attach a device over USB. Fastest iteration is a
development-signed IPA installed from the Windows PC with Sideloadly (seconds);
TestFlight is for release candidates. The Simulator cannot substitute — it has
neither a camera nor a Secure Enclave, which are precisely what criterion 1
exercises.
