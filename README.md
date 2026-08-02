# Osprey

Self-hosted remote access for Windows machines you own, controlled from an
iPhone. One product covering the useful half of TeamViewer (live screen and
input) and of Pulseway (headless metrics, terminal, files, alerts).

Not a support tool: there is no attended flow, no session codes, and no way to
reach a machine that has not completed physical-access QR pairing.

## Current state — P0, gate FAIL

`artifacts/gate-P0.md` is the authoritative status. Summary:

| Component | State |
|---|---|
| Protocol (`proto/`, codegen to Rust + Swift) | Built, tested |
| Agent core + service (`agent/`) | Built, tested — **142 tests**; clippy clean on host and `x86_64-pc-windows-msvc` |
| Relay (`relay/`) | Built, tested — **70 tests** on Node 24 against live Postgres |
| Rust↔Swift bridge (`agent/osprey-ffi`) | Cross-builds to `Mach-O arm64` for iOS device and simulator **from Linux** |
| iOS client (`ios/`) | Source written; **never compiled against the Apple SDK** |

The gate is FAIL because the iOS client is unverified: nothing has run on a
physical iPhone, so three criteria — including the phase's headline "phone scans
QR, pairs, exchanges an authenticated encrypted ping/pong" — are NOT MEASURED.
That is a scope failure, not a defect failure.

## Start here

| To… | Read |
|---|---|
| Understand the system | `docs/osprey-build-brief.md` — the specification. Its **Amendment Log (A1–A21)** at the end records every approved deviation and supersedes the body where they conflict. |
| Know exactly where things stand | `artifacts/gate-P0.md` |
| Finish P0 on the cloud Mac | `docs/ios-build.md` |
| Run what exists today | `docs/setup.md` |
| Know why a dependency is present | `docs/deps.md` |
| Work on the code | `CLAUDE.md` — operating rules, architecture invariants, anti-slop rules |

## Verify

```bash
cd agent && cargo test --workspace
cd agent && cargo clippy --workspace --all-targets -- -D warnings
cd agent && cargo clippy --workspace --all-targets --target x86_64-pc-windows-msvc -- -D warnings
cd agent && cargo build -p osprey-ffi --release --target aarch64-apple-ios
cd relay && pnpm test && pnpm lint && pnpm typecheck   # Node >= 24 + Postgres
cd proto && pnpm generate                               # then `git diff` must be empty
```

## What makes this defensible rather than malware

Load-bearing and non-negotiable:

- **Physical-access QR pairing, with no alternative path.** The QR carries a
  secret the relay never sees, used as the Noise pre-shared key — so this is a
  cryptographic property, not a UX convention.
- **A host-side session indicator that cannot be suppressed.**
- **An append-only audit log the client cannot delete**, recording pairing,
  unpair, and every command executed.
- **No stealth capability of any kind** — no hidden mode, no tray-icon
  suppression, no process-name obfuscation, no silent install.
- **The relay is assumed hostile.** Plaintext never reaches it, and the design
  holds even if the VPS is fully compromised.

## Architecture in one paragraph

`osprey-svc` is a SYSTEM service in Session 0 with no desktop, so it can never
touch the screen or inject input; `osprey-helper` does that from the user
session. The relay brokers signaling and push when the two endpoints cannot
reach each other directly, and is multi-tenant in its data model from day one
even though 1.0 ships no multi-tenant UX. The management and session planes are
separate: metrics, terminal, and files must work with video never negotiated.

Each device holds a hardware identity key — Ed25519 in DPAPI on the agent, P-256
in the Secure Enclave on the phone — which cross-signs a software X25519 static.
Noise runs on 25519 at both ends, so there is exactly one Noise implementation in
the product rather than two.
