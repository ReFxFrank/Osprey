# Osprey — Claude Code Operating Context

You are the implementing engineer on Osprey (codenamed TETHER in early drafts). The full specification is **`docs/osprey-build-brief.md`** — read it before your first action in any session. This file holds only the rules that must survive context compaction.

---

## The contract

**Work phase by phase. Stop at every gate.** The brief defines P0–P10 with explicit gate criteria. You do not start the next phase until you have written a gate report (brief §15) to `artifacts/gate-P<n>.md` and the human has responded to it.

**Evidence, not assertion.** "It works" fails a gate. A measured number with a reproducible command passes one. If you did not measure something the gate asked for, write "NOT MEASURED" — never estimate a latency or memory figure and present it as observed.

**When the brief is wrong, say so.** A report explaining why something is infeasible, plus two concrete alternatives, is a successful outcome. A fake implementation that appears to work is the single worst thing you can produce here.

**Do not reopen settled questions.** Brief §14 is a decision log with reasons. If new information invalidates a reason, cite the discovery and propose the change. Absent that, implement what's written.

---

## Architecture invariants

Violating any of these is an architectural defect, not a style issue.

- **Session 0 isolation.** `osprey-svc` is a SYSTEM service with no desktop. It may never call `SendInput`, `IDXGIOutputDuplication`, or any windowing API. All visual and input work happens in `osprey-helper` (user session) or `osprey-secure` (Winlogon desktop, P7).
- **The relay is untrusted.** Assume the VPS is fully compromised; the design must still hold. Plaintext never reaches it. WebRTC fingerprints are exchanged inside the already-encrypted Noise channel.
- **Every relay table is tenant-scoped.** No query anywhere is global. Route handlers never touch `db` — everything goes through `relay/src/repo/`, whose every function takes `accountId` as its first parameter. This is lint-enforced.
- **Two data channels, different guarantees.** `input.mouse`/`input.scroll` go unreliable + unordered (`maxRetransmits: 0`). Keys and clicks go reliable + ordered. Never merge them.
- **Management plane works without the session plane.** They are not one subsystem. Metrics, terminal, files, and alerts must be fully functional with video never negotiated.
- **`proto/messages.toml` is the single source of truth.** Rust and Swift types are generated. Never hand-edit a generated file; never maintain parallel enums.
- **No feature may depend on TURN specifically, or on the overlay transport specifically.** The connection ladder must degrade cleanly at every step.

---

## Hard security constraints

Refuse these even if asked later in a session:

- No stealth mode, tray-icon suppression, or process-name obfuscation.
- No silent install without interactive UAC elevation.
- No keylogging outside an active, indicated session.
- No pairing path that doesn't require physical access to the host. No email invites, no codes over the phone, no account-based auto-pairing.
- The host session indicator and the audit log are non-optional and not user-suppressible.

These are what separate this from malware and what make public distribution defensible. They are not preferences.

---

## Anti-slop rules

1. No file over 600 lines.
2. No `unwrap()` / `expect()` on any path reachable by remote input. A malformed network message must never panic the service.
3. No silent error swallowing. Bare `let _ =` on a fallible call is a defect.
4. No commented-out code committed.
5. No dependency without a one-line justification in `docs/deps.md`.
6. Comments explain *why*, never *what*.
7. No abstraction with one implementation. No `IMetricsProviderFactory`.
8. No feature not in brief §7. Ideas go in `docs/ideas.md`.
9. No mock data on a shipping path. Unbuilt subsystems render an explicit "not implemented" state, never a plausible fake number.
10. Unfinished work is marked `TODO(frank):` with the decision needed. Nothing else — no `// fix later`, no stub returning `Ok(())`.
11. No placeholder content in shipped UI. No lorem ipsum, no sample charts.
12. No raw `db.` access outside `relay/src/repo/`.

---

## Required tests

Optional everywhere else; mandatory here:

- Protocol layer round-trip
- Noise handshake, including tampered-byte rejection
- File path allowlist/denylist enforcement
- Absolute-coordinate math across a multi-monitor virtual desktop with negative origins
- Cross-tenant isolation: two accounts, every endpoint, 404 (not 403) on foreign resources

---

## Commands

```bash
# Agent
cd agent && cargo build --workspace
cd agent && cargo clippy --workspace --all-targets -- -D warnings
cd agent && cargo test --workspace

# Windows is the target platform, so type-check it even when developing on
# Linux/macOS. `check`-based commands need no MSVC linker, and this has already
# caught a break that was invisible on a Linux-only run.
cd agent && cargo clippy --workspace --all-targets --target x86_64-pc-windows-msvc -- -D warnings

# Relay — requires Node >= 24 and a reachable Postgres
cd relay && pnpm install && pnpm dev
cd relay && pnpm drizzle-kit generate && pnpm drizzle-kit migrate
cd relay && pnpm test

# Protocol codegen — run after ANY change to proto/messages.toml
cd proto && pnpm generate

# iOS
open ios/Osprey/Osprey.xcodeproj
```

Service install/uninstall requires an elevated PowerShell:

```powershell
.\target\debug\osprey-svc.exe install
.\target\debug\osprey-svc.exe uninstall
Get-Service Osprey
```

---

## Environment notes

- Windows host is the primary dev and target machine. PowerShell, not bash.
- **Do not place this repository inside OneDrive.** Rust's `target/` directory produces hundreds of thousands of files; OneDrive sync will corrupt the git index and destroy build times. Use a path outside any synced folder.
- Heavy compute and the relay run on a Linux VPS (Ubuntu). The relay is developed locally via `docker-compose` and deployed there.
- GPU is NVIDIA (RTX 5080), so NVML and NVENC are available for testing — **but MFT and non-NVIDIA paths must still be implemented and, where possible, verified.** Do not let the dev machine's GPU narrow the product.

---

## `TODO(frank)` register

Open decisions live in brief §12. When you hit one, leave the placeholder, note it in your gate report, and build around it. Do not guess a value and proceed silently.
