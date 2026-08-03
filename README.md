<p align="center">
  <img src="branding/osprey-logo.png" alt="Osprey" width="160">
</p>

# Osprey

Self-hosted remote access for Windows machines you own, controlled from an
iPhone. One product covering the useful half of TeamViewer (live screen and
input) and of Pulseway (headless metrics, terminal, files, alerts).

Not a support tool: there is no attended flow, no session codes, and no way to
reach a machine that has not completed physical-access QR pairing.

## Current state — P0 **PASS**, P1 in progress

`artifacts/gate-P0.md` is the authoritative record for P0; it passed on
2026-08-03 with every criterion measured on the hardware it was specified for.

| Component | State |
|---|---|
| Protocol (`proto/`, codegen to Rust + Swift) | Built, tested |
| Agent (`agent/`) | **Registered Windows service**: boot start, auto-restart, hardened data directory. M-01 metrics streaming at 1 Hz |
| Relay (`relay/`) | Built, tested — **70 tests** on Node 24 against live Postgres |
| iOS client (`ios/`) | Compiled, signed, and **running on a physical iPhone**; pairs and holds encrypted sessions |

P0's headline criterion is measured: the phone scans the QR, pairs, and exchanges
authenticated encrypted traffic — **14 ms round trip** on the LAN, with the
pinned key fingerprint matching on both ends.

P1 work in flight is tracked in `docs/p1-plan.md`.

## Start here

| To… | Read |
|---|---|
| Understand the system | `docs/osprey-build-brief.md` — the specification. Its **Amendment Log** at the end records every approved deviation and supersedes the body where they conflict. |
| Know exactly where things stand | `artifacts/gate-P0.md`, then `artifacts/P1/` |
| See the P1 design decisions | `docs/p1-plan.md` |
| Build the iOS client | `docs/ios-build.md` |
| Run what exists today | `docs/setup.md` |
| Know why a dependency is present | `docs/deps.md` |
| Work on the code | `CLAUDE.md` — operating rules, architecture invariants, anti-slop rules |

## Install (Windows, elevated once)

```powershell
osprey-svc.exe install
```

That is the only interactive prompt the product ever shows. It registers the
service to start at boot, restarts it on failure, replaces the DACL on
`%ProgramData%\Osprey` with Administrators + SYSTEM, and creates the inbound
firewall rule on the **Private** profile only. Nothing has to be launched by
hand afterwards.

## Branding

`branding/osprey-logo.png` is the source mark. Everything else is generated:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/make-icons.ps1
```

That writes `branding/osprey.ico` (7 sizes, white keyed out so the taskbar does
not show a white tile) which `build.rs` embeds into the executable along with
its version metadata, and `branding/ios/AppIcon-1024.png` (opaque, because App
Store Connect rejects an icon with an alpha channel).

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
