# TETHER — Agent-Ready Build Brief

**Version 1.1** — supersedes 1.0. Changes: relay retained and made tenant-scoped from P0; Tailscale demoted from architecture to optional transport; desktop client added as optional P10; App Store distribution posture defined.

**Codename:** TETHER *(TODO(frank): final product name)*
**Deliverable:** A self-hosted remote access system for Windows machines, controlled from iOS.
**Scope:** Feature parity with the useful subset of **TeamViewer** (live screen + input) **and Pulseway** (headless monitoring + management), in one product.
**Execution model:** Autonomous agent implementation, phased, with hard go/no-go gates.

---

## 0. Agent Operating Instructions — READ BEFORE WRITING CODE

You are implementing this brief end to end. Follow these rules without exception.

1. **Work phase by phase.** Do not start Phase N+1 until Phase N's gate criteria are demonstrably met. At each gate, stop and report: what was built, the measured numbers, what failed, and what you had to change from this brief.
2. **Every gate requires evidence, not assertion.** "Streaming works" is not acceptable. "1080p60 at 8 Mbps, p50 glass-to-glass 74 ms measured with the timestamp-overlay method in `tools/latency/`, over LTE, log at `artifacts/p5-latency.txt`" is acceptable.
3. **Do not fabricate APIs.** If you are unsure whether a Win32/WinRT/AVFoundation/WebRTC symbol exists with the signature you want, verify against the actual header/crate/framework in the workspace before using it. A build brief is not a license to invent function names.
4. **No mock data on a shipping path.** Fixtures live in `tests/`. If a real subsystem isn't ready yet, the UI shows an explicit "not implemented" state — never a plausible-looking fake number. A fake CPU graph is worse than no CPU graph.
5. **Unfinished work is marked `TODO(frank):`** with a one-line description of the decision needed. Nothing else. No `// fix later`, no silent stubs, no functions that return `Ok(())` and do nothing.
6. **Configuration is file-based.** TOML on the agent, JSON on the relay, a SwiftUI settings screen on iOS writing to a single `Config` struct. No settings GUI on the Windows side beyond a tray menu. No registry sprawl — one key for service install state, everything else in `%ProgramData%\Tether\config.toml`.
7. **When this brief is wrong, say so.** If Phase 7 turns out to be impossible as written on current Windows builds, the correct output is a report explaining why plus two concrete alternatives — not a fake implementation that appears to work.
8. **Ask nothing you can decide.** Where the brief says "locked," the decision is made; implement it. Where it says `TODO(frank)`, leave the placeholder and continue around it.

### 0.1 Distribution posture — read this before designing anything

Version 1.0 is for a single operator (the author) running his own relay on his own VPS. **But the product may be released publicly later, and that possibility constrains P0.**

The rule: **build the relay's data model multi-tenant from day one; build zero multi-tenant UX.**

Retrofitting tenancy into a single-user relay is one of the genuinely painful refactors in this design — it touches the device registry, pairing tokens, APNs token storage, TURN credential minting, and every query. Doing it correctly at the start costs perhaps 20% more work in P0. Doing it later costs a rewrite plus a migration of live device pairings.

Concretely:
- Every relay table has an `account_id`. No query anywhere is global.
- An account is created **implicitly** when the first agent enrolls. There is no signup form, no login screen, no password, no email in 1.0. The account exists in the database and is invisible in the product.
- Pairing a phone binds it to the enrolling agent's account.
- Per-account quotas exist and are enforced from P0 (max devices, TURN bandwidth, pairing attempts per hour) even though the author will never hit them.

If and when public release happens, what gets added is an account-recovery story and a billing integration. Not an architecture change.

---

## 1. What We Are Building

| Component | Runs on | Language | Purpose |
|---|---|---|---|
| **tether-agent** | Windows 10 1809+ / 11 | Rust | Windows service + session helper. Does all the actual work. |
| **tether-relay** | Linux VPS (Ubuntu) | TypeScript (Node 22) | Signaling, tenant-scoped device registry, push fan-out, TURN coordination. Never sees plaintext. |
| **Tether** (iOS) | iPhone, iOS 17+ | Swift 6 / SwiftUI | The primary operator console. |
| **Tether Desktop** *(P10, optional)* | Windows + macOS | Rust / Tauri v2 | Secondary console for controlling one machine from another. Post-1.0. |

Two operating planes over one connection:

- **Management plane** — always-on, low-bandwidth, headless. Metrics, processes, services, terminal, files, alerts. This is the Pulseway half. Works over cellular with the screen off, costs almost nothing in bandwidth, and is what you'll use 90% of the time.
- **Session plane** — on demand, high-bandwidth. Screen stream + input injection. This is the TeamViewer half. Negotiated only when the operator taps "Connect."

The management plane must be fully functional without the session plane ever being invoked. Do not build them as one coupled subsystem.

---

## 2. Non-Goals

- **Attended support flows.** No session codes to hand to a third party, no "join my session." Unattended access to machines you own, only. This is a deliberate product boundary and it is also what keeps the app defensible in App Review — see §9.8.
- **macOS/Linux *agents*.** Architect the protocol so they're possible later; implement the Windows agent only. (A macOS *client* is in scope at P10.)
- **A web dashboard.** Native clients only.
- **Accounts UX, org/team models, RBAC, billing, SSO.** The data model supports tenancy per §0.1; the product surfaces none of it in 1.0.
- **Any stealth capability.** See §6.6 — hard constraint, not a preference.
- Remote printing, session recording, meeting/collaboration features.

---

## 3. Architecture

```
┌─────────────────────────── Windows host ───────────────────────────┐
│                                                                     │
│  Session 0 (no desktop)              Session 1 (interactive)        │
│  ┌───────────────────────┐          ┌────────────────────────────┐  │
│  │ tether-svc            │          │ tether-helper.exe          │  │
│  │ Windows service, SYSTEM│  named  │ spawned per session via    │  │
│  │                       │◄────────►│ CreateProcessAsUser        │  │
│  │ • device identity/keys│  pipe    │                            │  │
│  │ • relay connection    │  (ACL:   │ • DXGI Desktop Duplication │  │
│  │ • metrics collection  │  SYSTEM  │ • WGC (per-window fallback)│  │
│  │ • process/service ctl │  only)   │ • MFT/NVENC encode         │  │
│  │ • ConPTY terminals    │          │ • SendInput injection      │  │
│  │ • file operations     │          │ • clipboard listener       │  │
│  │ • alert engine        │          │ • WASAPI loopback audio    │  │
│  │ • WebRTC peer         │          │ • tray icon + session UI   │  │
│  │ • survives logoff     │          │ • dies with the session    │  │
│  └───────────┬───────────┘          └────────────────────────────┘  │
│              │                                                       │
│              │              ┌──────────────────────────────────┐    │
│              └─────────────►│ tether-secure.exe (Phase 7)      │    │
│                             │ SYSTEM, Winlogon desktop         │    │
│                             │ GDI capture + input for UAC/lock │    │
│                             └──────────────────────────────────┘    │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ outbound only, TLS 1.3, :443
                               ▼
                    ┌──────────────────────┐
                    │  tether-relay (VPS)  │
                    │  Fastify + ws        │
                    │  Postgres + Drizzle  │
                    │  ALL TABLES TENANTED │
                    │  coturn (TURN)       │
                    │  APNs sender         │
                    │  ── zero plaintext ──│
                    └──────────┬───────────┘
                               │
                ┌──────────────┼──────────────┐
                │ E2E encrypted control       │
                │ + WebRTC media              │
                ▼              ▼              ▼
         ┌────────────┐  ┌──────────┐  ┌──────────────┐
         │ Tether iOS │  │  APNs    │  │ Tether Desktop│
         │  SwiftUI   │◄─│ (alerts) │  │  (P10, opt.)  │
         └────────────┘  └──────────┘  └──────────────┘
```

### 3.1 Connection ladder

Attempted in order; the active path is always shown in the client UI:

1. **Direct LAN** — mDNS discovery, direct connection on the local network. Zero relay involvement when you're home. Always try this first; it is both the fastest path and free.
2. **WebRTC over STUN** — direct P2P via NAT hole-punch, signaled through the relay.
3. **TURN relay** — coturn on the VPS. Always works, costs bandwidth. See §9.7.
4. **Overlay network (opt-in)** — if `transport.overlay_host` is set in `config.toml`, the client dials that hostname directly and skips 1–3 entirely.

**On step 4:** this is the Tailscale/WireGuard path. It is a **config option, not the architecture.** Because the iOS Tailscale client is a system VPN extension, the app needs no SDK integration whatsoever — a hostname in a config file is the entire implementation, which is why it costs almost nothing to support. For the author's personal use it will likely be the everyday path and will make the relay nearly idle. For public users it does not exist, because "install Tailscale and make an account first" is not a viable onboarding step for a general audience.

Do not let step 4 become load-bearing. Steps 1–3 must be complete and tested independently; the overlay path must never be the only way a feature works.

---

## 4. Locked Technology Decisions

Decided. Implement them; do not re-litigate. Deviation requires written justification at the phase gate.

### 4.1 Agent — Rust

- `windows` crate (windows-rs) for all Win32/WinRT. `windows-service` for service lifecycle. `tokio` for async.
- **Capture: DXGI Desktop Duplication (`IDXGIOutputDuplication`) as primary.** Not WGC. Reasons: no capture border, lower latency, and it provides **dirty rects and move rects** — which you will use to skip encoding idle frames and cut bandwidth by an order of magnitude on a static desktop. WGC (`Windows.Graphics.Capture`) is the **fallback** for single-window capture and for hybrid-GPU configs where Desktop Duplication fails.
- **Encode: Media Foundation hardware H.264 MFT first, NVENC second.** MFT is vendor-agnostic and gets a working pipeline fast — which matters enormously for a public release where users have AMD and Intel GPUs. Direct NVENC is a P4 optimization gated on measured latency; take it only if MFT p95 encode exceeds 12 ms. **Never make NVENC a hard requirement** — that would restrict the product to NVIDIA hosts.
- **WebRTC: `webrtc-rs`.** Pre-encoded H.264 through a `TrackLocalStaticSample`. Data channels for control and file transfer.
- Terminal: **ConPTY** (`CreatePseudoConsole`), one PTY per tab, PowerShell 7 default, cmd.exe selectable.
- Crypto: `ring` / `rustls` primitives only. No hand-rolled crypto, no exceptions.

### 4.2 Relay — TypeScript, tenant-scoped

- Node 22, Fastify, `ws`, Postgres 16 + **Drizzle**.
- **Every table carries `account_id`.** Route handlers never touch `db` directly — they go through a repository layer in `src/repo/` whose every function takes `accountId` as its first parameter. This is enforced by lint rule and by review: a raw `db.select()` outside `src/repo/` fails the build.
- Tables: `accounts`, `devices`, `pairings`, `pairing_tokens`, `push_tokens`, `quotas`, `audit_relay`.
- coturn alongside, credentials minted per-session via short-TTL REST auth, **quota-checked per account**.
- APNs via HTTP/2 with a `.p8` auth key. *TODO(frank): APNs key ID (Team ID is known — you're already enrolled).*
- Deployed via a single `docker-compose.yml` + Caddy for TLS. No Kubernetes.

### 4.3 iOS — Swift 6 / SwiftUI

- WebRTC via the `stasel/WebRTC` SwiftPM package (prebuilt xcframework, VideoToolbox HW decode automatic).
- Terminal rendering via **SwiftTerm**. Charts via **Swift Charts** (system framework).
- Keychain for device keys; private key in **Secure Enclave** where the algorithm permits.
- `async/await` and `@Observable` throughout. No Combine, no third-party architecture framework.

### 4.4 Desktop client — Tauri v2 *(P10 only)*

- Rust core reuses `tether-core` verbatim: protocol, crypto, transport. This is the reason Tauri wins over a native app — roughly half the client is already written.
- Video decode via the **webview's built-in WebRTC stack** (WebView2 on Windows, WKWebView on macOS), which gives hardware H.264 decode for free.
- Mouse capture via the **Pointer Lock API**; keyboard via `keydown`/`keyup` with `preventDefault`.
- **Known limitation to document, not fight:** the webview and the host OS intercept certain combinations (Cmd+Q, Alt+F4, F11, some Ctrl+Shift chords). Provide a "Send key combo" menu for these rather than attempting to capture everything. Ctrl+Alt+Del is unaffected — it is a control *message* to the host, per §8 P7.

---

## 5. Protocol

One bidirectional message stream, framed, over whichever transport won §3.1. Same message set regardless of transport — code above the transport layer must not know which path is live.

### 5.1 Envelope

```
{
  "v": 1,
  "id": "<uuid>",
  "t": "<type>",
  "ts": 1738000000000,
  "body": { ... }
}
```

Requests correlate by `id`. Every request type has exactly one response type or an `error`. Streams (metrics, terminal output, log tail) are server-push carrying a `sub` id from a prior `subscribe`.

### 5.2 Message type registry

Define in `proto/messages.toml` as the single source of truth and **generate** the Rust and Swift (and later TS) types from it. Do not hand-maintain parallel enums; they will drift.

| Group | Types |
|---|---|
| Session | `hello`, `hello.ok`, `ping`, `pong`, `bye` |
| Metrics | `metrics.subscribe`, `metrics.tick`, `metrics.history` |
| Process | `proc.list`, `proc.kill`, `proc.start`, `proc.priority` |
| Service | `svc.list`, `svc.start`, `svc.stop`, `svc.restart`, `svc.startup_type` |
| Power | `power.reboot`, `power.shutdown`, `power.sleep`, `power.lock`, `power.logoff`, `power.wol` |
| Exec | `exec.run`, `exec.result` |
| Terminal | `term.open`, `term.data`, `term.resize`, `term.close` |
| Files | `fs.list`, `fs.stat`, `fs.mkdir`, `fs.delete`, `fs.rename`, `fs.read.begin`, `fs.chunk`, `fs.write.begin`, `fs.transfer.status` |
| Events | `evt.query`, `evt.tail` |
| Apps | `app.list`, `app.uninstall` |
| Tasks | `task.list`, `task.run`, `task.enable` |
| Network | `net.interfaces`, `net.connections`, `net.speedtest` |
| Alerts | `alert.rules.get`, `alert.rules.set`, `alert.fired`, `alert.ack` |
| Session plane | `stream.start`, `stream.stop`, `stream.quality`, `stream.monitors`, `stream.select_monitor` |
| Input | `input.mouse`, `input.key`, `input.scroll`, `input.text`, `input.sas` |
| Clipboard | `clip.push`, `clip.pull`, `clip.changed` |
| Audio | `audio.start`, `audio.stop` |
| Privacy | `privacy.blank`, `privacy.block_local_input` |

### 5.3 Input channel rules

`input.*` goes over a **separate, unordered, unreliable** WebRTC data channel (`maxRetransmits: 0`). Mouse-move is the highest-frequency message in the system, and head-of-line blocking on a reliable channel is the single most common cause of remote desktops feeling laggy. Key events and clicks go on the **reliable ordered** channel — a dropped keystroke is unacceptable, a dropped mouse-move is invisible.

Two channels, different guarantees. Get this right the first time; it is not a later optimization.

Coalesce mouse-moves to the stream framerate on the sender. Never queue them.

---

## 6. Security Model

This system is, architecturally, a remote access trojan pointed at yourself on purpose. The security model is a primary deliverable, not a P9 cleanup task. If it is ever released publicly, it is also the entire basis on which the product is trustworthy.

### 6.1 Identity and pairing

- Agent generates an **Ed25519 device keypair** at install; private key in DPAPI-protected storage under `%ProgramData%\Tether\`, machine-scoped, service-account-only ACL.
- iOS generates its own keypair, private key in Secure Enclave (P-256 via `SecKeyCreateRandomKey`). Ed25519 is not Secure-Enclave-backed on iOS, so **use P-256 on the phone and Ed25519 on the agent** — do not force curve symmetry at the cost of hardware backing.
- **Pairing:** agent tray menu → "Pair new device" → displays a QR containing `{relay_url, account_id, device_id, agent_pubkey, one_time_token}`, valid 120 seconds, single use. Client scans, posts its pubkey, both sides pin the other's key permanently. The relay brokers the exchange and never holds a key that can decrypt traffic.
- **Physical access to the host is required to enroll a new controller.** This is the core safety property and the one that distinguishes this from a stalkerware product. Do not add any alternative pairing path — no email invite, no code-over-phone, no account-based auto-pairing. Ever.
- Unpair from either side; revocation is immediate and drops any live session.

### 6.2 Transport

- E2E: Noise IK handshake (`snow`) over whatever transport is live, keyed on pinned static keys. **The relay is untrusted.** Assume the VPS is fully compromised and the design must still hold.
- WebRTC media is DTLS-SRTP; fingerprints exchange *inside* the already-encrypted control channel, so a malicious relay cannot MITM media by swapping SDP.
- Agent makes **outbound connections only.** No listening WAN port, no UPnP, no port forwarding in any documentation or setup flow.

### 6.3 Authorization

- Biometric gate on the client for: any `exec.run`, `power.*`, `fs.delete`, `svc.*` mutation, and session start. Cached 5 minutes. Metrics viewing is ungated.
- `exec.run` is **opt-in per agent** in `config.toml`, **off by default**, and logs the full command line before execution.
- Rate limits and lockout on the relay for pairing attempts, **scoped per account**.

### 6.4 Audit

Append-only JSONL at `%ProgramData%\Tether\audit\`, one file per day: every command executed, every session start/stop with duration and peer device id, every file transferred with path and size, every failed auth. Viewable from the client. **Not deletable from the client.**

### 6.5 Consent and unattended access

Unattended access is the point, so it is on by default — but:

- A **persistent tray icon** changes state, and the host shows a small non-dismissible on-screen indicator whenever the session plane is active. *TODO(frank): indicator style — corner badge vs. thin screen-edge border.*
- Optional per-connect consent prompt on the host with timeout, off by default, in config.

### 6.6 Hard constraints

**Do not implement, and refuse if asked to add later:**
- Any hidden/stealth mode, tray-icon suppression, or process-name obfuscation.
- Silent/unattended install without an interactive UAC elevation.
- Keylogging outside an active, indicated session.
- Any capability to connect to a machine that has not completed the physical QR pairing flow in §6.1.

The session indicator, the audit log, and physical-access pairing are load-bearing. They are what separates this from malware, they are what every legitimate product in this category ships, and they are what makes public distribution defensible.

### 6.7 Tenant isolation

Once the relay is multi-tenant in shape, cross-tenant leakage is the highest-severity bug class in the system. Required from P0:

- Every repository function takes `accountId` first and filters on it. No exceptions, no "admin" bypass function.
- An integration test suite that creates two accounts with devices and asserts that **every** relay endpoint returns 404 (not 403 — do not leak existence) when account A requests account B's resource.
- Postgres row-level security enabled as defence in depth, not as the primary mechanism.

---

## 7. Feature Inventory

### 7.1 Management plane (Pulseway parity)

| ID | Feature | Notes |
|---|---|---|
| M-01 | CPU / RAM / disk / network metrics | 1 s tick while subscribed, 30 s background. 24 h ring buffer on agent. |
| M-02 | GPU metrics | NVML for NVIDIA; ADL/AGS or WMI fallback for AMD/Intel so the feature isn't NVIDIA-only. Utilization, VRAM, temp, clocks, power. |
| M-03 | Temperatures / fans | Best-effort. *TODO(frank): ship a signed kernel driver for board sensors? If no, this is GPU-only and CPU package temp is dropped. For public release the answer is almost certainly no.* |
| M-04 | Process list | Name, PID, CPU%, working set, user, path, uptime. Sortable, searchable. |
| M-05 | Kill / start process | Kill by PID with confirm. Start by path with args. |
| M-06 | Service list + control | Name, display name, state, startup type. Start/stop/restart/set-startup. |
| M-07 | Power actions | Reboot, shutdown, sleep, hibernate, lock, log off. Biometric + confirm. |
| M-08 | Wake-on-LAN | See P8 — requires an always-on LAN sender. |
| M-09 | File browser | Navigate, stat, mkdir, rename, delete. Path allowlist/denylist in config, **enforced agent-side**. |
| M-10 | File up/download | Chunked, resumable, SHA-256 verified, progress reporting. |
| M-11 | Interactive terminal | ConPTY. Multiple tabs. Full color, resize, scrollback. |
| M-12 | One-shot command exec | Captured stdout/stderr/exit code. |
| M-13 | Windows Event Log | Query by log/level/time range; tail live. |
| M-14 | Installed applications | List + uninstall via registered uninstall string. |
| M-15 | Scheduled tasks | List, run now, enable/disable. |
| M-16 | Network info | Interfaces, IPs, active connections with owning process. |
| M-17 | Alert rules | Thresholds with hysteresis. Evaluated **on the agent**, not the relay — this keeps the relay dumb and cheap, and it means alerts still work if the relay is down and the client is on LAN. |
| M-18 | Push notifications | Agent → relay → APNs. Actionable (Ack / Open / Kill process). |
| M-19 | Disk / SMART health | Best-effort via WMI. |
| M-20 | Uptime, logged-on user, pending reboot, Windows Update status | Cheap wins, one screen. |

### 7.2 Session plane (TeamViewer parity)

| ID | Feature | Notes |
|---|---|---|
| S-01 | Live screen stream | H.264, adaptive bitrate, target 1080p60. |
| S-02 | Multi-monitor | Enumerate, switch, composite "all monitors" view. |
| S-03 | Mouse input | Absolute + relative. Left/right/middle, drag, double-click. |
| S-04 | Keyboard input | Full scan-code passthrough, modifiers, Ctrl+Alt+Del (needs P7). |
| S-05 | Scroll | Two-finger with momentum matched to host expectations. |
| S-06 | Touch UX layer | See §7.3 — implement exactly as written. |
| S-07 | Clipboard sync | Bidirectional, text + images. Manual push/pull plus auto-sync toggle. |
| S-08 | In-session file transfer | Drag from Files app → configured host folder. |
| S-09 | Quality control | Auto / High / Balanced / Low-bandwidth, manual bitrate cap, HUD with live bitrate + RTT + FPS + loss. |
| S-10 | Audio | WASAPI loopback → Opus → WebRTC audio track. Toggle. |
| S-11 | Privacy screen | Read §9.2 before implementing. |
| S-12 | Elevation / UAC | P7. The feature that makes this actually usable. |
| S-13 | Lock screen access | Connect to a locked machine and log in. Requires P7. |
| S-14 | Session HUD | Latency, resolution, monitor picker, on-screen modifiers, disconnect. |

### 7.3 Touch interaction spec (do not improvise this)

This is where amateur remote desktop clients fail. Implement exactly:

- **Default: trackpad mode.** Finger drag moves the *host's real cursor* at a configurable accel curve. The finger is not the cursor. This is the only way precision work is possible on a phone.
- Single tap = left click at cursor. Two-finger tap = right click. Tap-and-a-half-drag = click-and-drag.
- Two-finger pan = scroll wheel. Pinch = zoom the *viewport* into the stream, not the remote display.
- Long-press (500 ms) = right-click at cursor, with haptic confirmation.
- **Direct mode toggle**: finger maps absolutely to screen coordinates. Fast for large targets, terrible for everything else. Not the default.
- Keyboard: system keyboard with a persistent accessory bar carrying Esc, Tab, Ctrl, Alt, Shift, Win, arrows, F1–F12. Modifiers sticky-on-tap, locked-on-double-tap.
- Hardware keyboard fully supported with raw passthrough, including Cmd→Win remap.
- Haptics on click, on modifier-lock, on connect/disconnect. Not on mouse-move.

---

## 8. Phase Plan

Each phase: deliverable, then a gate. **You may not proceed past a failed gate — report instead.**

---

### P0 — Foundations

**Build:**
- Cargo workspace (`tether-svc`, `tether-helper`, `tether-core`, `tether-proto`), Node relay, Xcode project. Layout per §11.
- `proto/messages.toml` + codegen producing Rust and Swift types.
- Ed25519/P-256 identity generation, DPAPI + Keychain storage.
- **Tenant-scoped relay schema and repository layer per §0.1 and §4.2.** Implicit account creation on first agent enrollment.
- QR pairing flow end to end.
- Noise IK channel over plain TCP (WebRTC comes later — do not couple pairing to WebRTC).
- Dev relay in Docker locally.

**Gate P0:**
- [ ] Phone scans QR, pairs, exchanges an authenticated encrypted `ping`/`pong` over the local network.
- [ ] Keys survive agent restart and app restart.
- [ ] Unpair works from both sides and immediately blocks traffic.
- [ ] Tampering with a handshake byte causes a clean logged failure, not a panic.
- [ ] **Cross-tenant test suite green**: two accounts, every endpoint, 404 on foreign resources. Report the endpoint count covered.
- [ ] No raw `db.` access outside `src/repo/` — lint rule active and passing.
- [ ] `cargo clippy -- -D warnings` and `swiftlint` clean.

---

### P1 — Service architecture + first real data

**Build:**
- `tether-svc` as a real Windows service: install/uninstall/start/stop, auto-restart on failure, survives logoff.
- Session-0 → session-1 helper spawn via `WTSQueryUserToken` + `CreateProcessAsUser`. Named pipe IPC with SYSTEM-only DACL.
- Helper lifecycle: spawn on session connect, die on disconnect, respawn on fast user switch and on crash, **with backoff for the crash-loop case**.
- Manifest the helper `PerMonitorV2` DPI-aware now, not at P6 (§9.5).
- M-01 collection + 24 h ring buffer.
- iOS: dashboard with live Swift Charts.

**Gate P1:**
- [ ] Service installs, starts on boot, reconnects to the relay after a network drop without intervention.
- [ ] Kill `tether-helper.exe` from Task Manager → respawns within 3 s.
- [ ] Log out and back in → helper follows the session. Lock screen → service stays connected.
- [ ] Live graphs on the phone at 1 Hz over LTE.
- [ ] Agent idle CPU < 1% and RSS < 60 MB with a metrics subscription active. **Report measured numbers.**

---

### P2 — Management plane, part 1

**Build:** M-02, M-04, M-05, M-06, M-07, M-16, M-19, M-20.

**Gate P2:**
- [ ] Kill a process and restart a service from the phone; both in the audit log.
- [ ] Reboot from the phone; agent reconnects automatically and the app shows recovery rather than hanging.
- [ ] 400+ process list renders and scrolls at 60 fps.
- [ ] Every mutating action is biometric-gated and audited.
- [ ] M-02 verified on at least one non-NVIDIA GPU, or explicitly reported as unverified with the reason.

---

### P3 — Terminal + files

**Build:** M-09, M-10, M-11, M-12.

**Gate P3:**
- [ ] Interactive PowerShell including a full-screen TUI app, correct rendering and colors.
- [ ] Rotate the phone mid-session → terminal reflows correctly.
- [ ] Transfer a 2 GB file both directions; kill the network at 50% and confirm resume, not restart.
- [ ] Denylisted path → clean refusal, audit entry, no partial data leak.

---

### P4 — Capture and encode (local only, no network)

Deliberately isolated. Get the media pipeline right before adding transport variables.

**Build:**
- Desktop Duplication loop with dirty-rect and move-rect extraction.
- Idle-frame suppression: no dirty rects → no encode, send keepalive.
- MFT hardware H.264, zero-copy from the captured `ID3D11Texture2D` where possible.
- Multi-monitor enumeration and selection (S-02). WGC fallback path.
- `tools/latency/` harness writing `.h264` to disk and measuring capture→encoded latency.

**Gate P4:**
- [ ] 1080p60 sustained; report p50/p95 capture-to-encoded latency. Target p95 < 20 ms.
- [ ] 60 s static desktop produces near-zero encoded bytes — report the byte count.
- [ ] Monitor switching without tearing down the pipeline.
- [ ] Resolution change / display hotplug / **forced GPU TDR** recovered from without a helper crash. Test the TDR deliberately.
- [ ] Report whether MFT met the 12 ms threshold. If not, NVENC enters scope now — say so and implement it as an *additional* path, never a replacement.

---

### P5 — Streaming to the phone

**Build:**
- `webrtc-rs` peer feeding encoded H.264 into a sample track.
- Relay signaling (SDP/ICE inside the E2E channel), STUN, coturn with short-TTL per-account credentials.
- iOS WebRTC client, `RTCMTLVideoView` rendering.
- Adaptive bitrate via REMB/transport-cc. S-09 presets and HUD.
- The §3.1 connection ladder, steps 1–3 complete, with a visible active-path indicator. Step 4 (overlay) implemented as a config branch and tested, but not required by any other feature.

**Gate P5:**
- [ ] Glass-to-glass latency measured properly (host shows a millisecond timestamp, phone camera captures both, diff the frames). Report p50/p95 on LAN, Wi-Fi→LTE, LTE→LTE.
- [ ] Target: LAN p50 < 60 ms, LTE p50 < 150 ms. Report actuals honestly even if missed.
- [ ] Degrade the link to 1.5 Mbps → stream stays connected and legible, no stall, no death-spiral.
- [ ] Path fallback verified: block STUN → TURN takes over; kill the relay mid-session → existing P2P session survives.
- [ ] TURN bandwidth is metered per account and a quota breach is enforced and surfaced in the client.
- [ ] 30-minute session, no memory growth on either end. Report numbers.

---

### P6 — Input and touch UX

**Build:** S-03 through S-08, S-14, and §7.3 in full.

- `SendInput` injection with correct absolute-coordinate normalization across the virtual desktop (§9.4).
- Dual data channels per §5.3.
- Clipboard listener via `AddClipboardFormatListener`.

**Gate P6:**
- [ ] **The subjective gate, and the most important one in this document:** open a browser, log into a site using the on-screen keyboard, navigate, close it — entirely from the phone, on LTE, without frustration. If it feels bad, it *is* bad. Fix it before proceeding.
- [ ] Precision test: hit a 16×16 px target first attempt, 8 of 10.
- [ ] Copy on phone → paste on host, and the reverse.
- [ ] Verified on a 3-monitor setup with mixed DPI and a non-primary-left arrangement.
- [ ] Input latency independently measured and reported.

---

### P7 — Elevation, UAC, and the lock screen

The hardest phase.

**The problem.** Windows renders UAC prompts on a separate desktop (`Winlogon`) within the same session; the lock screen likewise. Desktop Duplication and WGC both fail there. A normal user-session process cannot see or interact with either. UIPI additionally prevents a medium-integrity process from injecting input into elevated windows — so even after a UAC prompt is accepted, a non-elevated helper cannot drive the elevated app.

**The approach:**
1. `tether-svc` spawns **`tether-secure.exe` as SYSTEM in the target session**, which calls `OpenInputDesktop`/`SetThreadDesktop` to attach to whichever desktop currently has input.
2. Detect desktop switches and hand capture off between the normal and secure helper transparently. The client should see one continuous stream across a UAC prompt.
3. On the secure desktop, Desktop Duplication is unavailable — **fall back to GDI `BitBlt`** at 5–10 fps. Acceptable: UAC prompts and lock screens are nearly static. Do not make this path fast; make it correct.
4. Input injection on the secure desktop also runs from the SYSTEM process with `SetThreadDesktop` to Winlogon.
5. Ctrl+Alt+Del cannot be synthesized by `SendInput` — it is a Secure Attention Sequence. Use `SendSAS` from `sas.dll` in the SYSTEM service, which requires the Soft-SAS group policy value enabled. **Document this prerequisite in `docs/setup.md`** and detect + surface it in the client rather than failing silently.
6. Route input through the SYSTEM process whenever the foreground window's integrity level exceeds the helper's.

**Gate P7:**
- [ ] Trigger a UAC prompt → visible on the phone and acceptable from the phone.
- [ ] Lock the host → lock screen visible, password typed from the phone, login succeeds.
- [ ] Ctrl+Alt+Del works, prerequisite documented and detected.
- [ ] Fast user switch during an active session handled without a crash.
- [ ] 50-cycle lock/unlock loop; report handle count before and after (no leak).
- [ ] **If any of the above is infeasible on current Windows builds, stop and report with alternatives.** A driver-based approach (mirror driver / IddCx virtual display) is the escalation path — do not start it without checking in, and note that it raises the bar for public distribution considerably (driver signing).

---

### P8 — Alerts, push, and remote wake

**Build:** M-08, M-13, M-14, M-15, M-17, M-18.

- Alert rule engine on the agent. Rules in `config.toml`, editable from the client, with hysteresis and cooldown so one flapping condition doesn't produce 200 notifications.
- Agent → relay → APNs, with actionable notification categories.
- **Wake-on-LAN reality check:** WOL needs a magic packet originating *inside* the LAN. Options in order of preference:
  1. A second always-on tether-agent acting as a **wake proxy** — protocol supports "agent A, send a magic packet to MAC B." This is the robust answer and the only one that generalizes to public users.
  2. The router's own WOL API. *TODO(frank): confirm your UniFi gateway model supports this — but treat it as a personal convenience, not a shipped feature.*
  3. Document that the machine must be awake.
- Handle modern standby / hybrid sleep: verify the NIC's wake settings and **surface when they're wrong** rather than failing silently.

**Gate P8:**
- [ ] A disk-space alert fires and arrives on a locked phone within 30 s.
- [ ] Acting on the notification without opening the app works.
- [ ] A flapping condition produces exactly one notification plus cooldown, not a storm.
- [ ] Sleep the host → wake from the phone → reconnected and controllable within 45 s, via the wake-proxy path. If WOL can't be made to work, report which fallback shipped.

---

### P9 — Hardening, packaging, ship

**Build:**
- Audit log viewer in-app. Privacy screen (S-11) with the §9.2 limitation stated in the UI, not hidden. Audio (S-10).
- WiX/MSI installer, service registration, code signing. *TODO(frank): EV or standard cert? Standard means SmartScreen warnings until reputation accrues — for a public release EV is close to mandatory.*
- Agent auto-update: signature-verified, staged, with rollback.
- Crash reporting to **local files, not a third-party SaaS.** This app has access to everything on the machine and should not phone home to Sentry.
- TestFlight build. *TODO(frank): bundle identifier — Team ID already in hand.*
- `docs/setup.md`, `docs/security.md`, `docs/troubleshooting.md`, `docs/app-review.md` (§9.8).

**Gate P9:**
- [ ] Clean install on a fresh Windows VM from the signed installer; paired and controllable in under 5 minutes with **no manual config file editing**. This is the public-release bar even though 1.0 is personal — test it that way.
- [ ] Uninstall removes service, helpers, keys, scheduled tasks. Nothing left but the audit log, and its removal is prompted.
- [ ] Written threat model in `docs/security.md`: hostile relay, stolen phone, stolen agent machine, MITM, replayed pairing token, malicious tenant.
- [ ] Auto-update applies and rolls back correctly on a deliberately corrupted package.

---

### P10 — Desktop client *(optional, post-1.0)*

**Do not start this until P9 is signed off.** It is scoped here so the protocol and `tether-core` are built with it in mind, not so it gets built early.

**Build:** Tauri v2 app per §4.4. Windows + macOS. Full management plane; session plane with Pointer Lock mouse capture and keyboard passthrough.

**Gate P10:**
- [ ] Control the Windows host from a second machine with parity on every M-* feature.
- [ ] Session plane latency within 15% of the iOS client on the same network.
- [ ] The intercepted-key-combo list is documented and the "Send key combo" menu covers all of it.
- [ ] Zero new protocol messages were required. If any were, that is a design failure in P0 — report it.

---

## 9. Known Hard Problems — Do Not Discover These Late

### 9.1 Session 0 isolation
A Windows service cannot touch the desktop. Everything visual or input-related happens in a helper. If you find yourself calling `SendInput` or `IDXGIOutputDuplication` from `tether-svc`, you have made an architectural mistake — fix it rather than working around it.

### 9.2 Privacy screen is a lie without a driver
Genuinely blanking the host display requires a display driver (an IddCx virtual display adapter is the modern approach). A topmost black window can be dismissed by the local user, doesn't survive all fullscreen scenarios, and doesn't cover the login screen. `BlockInput` requires elevation and is unreliable.

**Implement the honest version:** topmost black overlay + `BlockInput` from the SYSTEM helper, labelled in the UI as *"Privacy screen (best effort — a local user with physical access can bypass this)."* Do not claim what it doesn't do.

### 9.3 iOS cannot hold a background connection
No persistent socket in the background, period. Design for it rather than fighting it:
- Alerts go through APNs. There is no alternative.
- Reconnect fast on foreground — under 2 s to a live dashboard. Cache last state, show it immediately with a staleness indicator while reconnecting.
- A session drops when the app backgrounds. Keep the agent-side session alive for a 30 s grace window so a quick app-switch doesn't force full renegotiation.

### 9.4 The absolute-coordinate bug
`SendInput` with `MOUSEEVENTF_ABSOLUTE` maps 0–65535 across the **entire virtual desktop**, not the current monitor. With any monitor left of primary (negative coordinates), naive math breaks. Use `SM_XVIRTUALSCREEN`/`SM_CXVIRTUALSCREEN` and test on a genuinely awkward arrangement.

### 9.5 DPI
The helper must be manifested `PerMonitorV2` or every coordinate is silently wrong on a scaled display. Do it in P1.

### 9.6 GPU driver resets
A TDR invalidates the D3D device, duplication interface, and encoder simultaneously. Detect `DXGI_ERROR_DEVICE_REMOVED`/`DXGI_ERROR_ACCESS_LOST` and rebuild the whole pipeline. This will happen in real use.

### 9.7 Relay bandwidth is the public-release cost bomb
TURN-relayed 1080p60 at 8 Mbps is ~3.6 GB/hour per session. Personally, that's a rounding error. With a hundred users it is the entire business model. Therefore:
- Instrument per-account TURN bytes from P5, not later.
- Make direct-P2P success rate a **tracked metric**, reported at the P5 gate. Anything under ~85% means the STUN/ICE configuration needs work before TURN costs matter.
- Never make a feature depend on TURN specifically.

### 9.8 App Store distribution
Remote desktop is a long-established and approved App Store category — this is not novel or borderline territory. What reviewers care about is that the app cannot be used to access someone else's machine without their knowledge. The design already answers this, but the answer must be *written down*:

Create `docs/app-review.md` covering: the physical-access QR pairing requirement, the non-suppressible host-side session indicator, the audit log, the absence of any attended/support flow, and the absence of any silent install path. Attach it to the review submission notes.

Also handle: encryption export compliance declaration (`ITSAppUsesNonExemptEncryption`), and a privacy manifest declaring that no data leaves the user's own infrastructure.

*TODO(frank): you've shipped before, so confirm whether you want the review-notes doc written for the first submission or deferred until public release is actually on the table.*

---

## 10. Anti-Slop Guardrails

Violating any of these fails the phase gate regardless of what else works.

1. **No file over 600 lines.** If a module grows past it, it's doing too much.
2. **No `unwrap()` / `expect()` on any path reachable by remote input.** A malformed network message must never panic the service.
3. **No silent error swallowing.** Every error is handled or propagated with context (`anyhow`/`thiserror`). A bare `let _ =` on a fallible call is a defect.
4. **No commented-out code committed.** Delete it; git remembers.
5. **No dependency without a one-line justification in `docs/deps.md`.** No dependency whose purpose is to save fifteen lines.
6. **Comments explain *why*, never *what*.** `// increment the counter` above `i += 1` is noise. Delete it.
7. **No "enterprise" abstraction with one implementation.** No `IMetricsProviderFactory`. Concrete types until a second implementation exists.
8. **No feature not in §7.** Good ideas go in `docs/ideas.md`; keep going.
9. **Every claim of "done" is backed by a runnable command.** Include it in the gate report.
10. **Measured numbers are measured.** Never estimate a latency, memory figure, or bitrate and present it as observed. If you didn't measure it, write "not measured."
11. **No placeholder content in shipped UI.** No lorem ipsum, no `Text("TODO")`, no sample charts with fake data.
12. **No raw database access outside `src/repo/`.** Lint-enforced. This is the tenancy guarantee and it is not negotiable.
13. **Tests exist for: the protocol layer, the crypto handshake, the path allowlist, the coordinate math, and cross-tenant isolation.** These five are where correctness bugs are both likely and expensive. Everything else is optional; these are not.

---

## 11. Repository Layout

```
tether/
├── proto/
│   ├── messages.toml         # single source of truth
│   └── generate.ts           # → Rust, Swift, TS
├── agent/
│   ├── tether-core/          # crypto, proto, config, transport — shared with P10
│   ├── tether-svc/           # Windows service, SYSTEM, session 0
│   ├── tether-helper/        # per-session: capture, encode, input
│   ├── tether-secure/        # P7: Winlogon desktop helper
│   └── tools/latency/
├── relay/
│   ├── src/
│   │   ├── repo/             # ONLY place that touches the db
│   │   ├── routes/
│   │   └── push/
│   ├── drizzle/
│   └── docker-compose.yml
├── ios/
│   └── Tether/
├── desktop/                  # P10, Tauri v2
├── docs/
│   ├── setup.md
│   ├── security.md
│   ├── app-review.md
│   ├── troubleshooting.md
│   ├── deps.md
│   └── ideas.md
└── artifacts/                # gate evidence: logs, measurements, recordings
```

---

## 12. TODO(frank) Register

| # | Decision | Blocks | Status |
|---|---|---|---|
| 1 | Final product name | P9 | open |
| 2 | ~~Tailscale as primary transport~~ | — | **resolved: optional transport only, relay is the default path** |
| 3 | ~~Apple Developer Program enrollment~~ | — | **resolved: enrolled** |
| 4 | Bundle identifier + APNs `.p8` key ID | P0, P8 | open |
| 5 | Relay domain name + which VPS | P5 | open |
| 6 | Signed kernel driver for board sensors? (public release ⇒ almost certainly no) | P2 | open |
| 7 | Wake-proxy device on the LAN (Pi / NAS / mini PC) | P8 | open |
| 8 | Code signing cert: EV or standard | P9 | open |
| 9 | Session indicator style | P6 | open |
| 10 | Default file-browser denylist paths | P3 | open |
| 11 | How many hosts at 1.0 — one, or a device list from the start? | P1 (UI shape) | open |
| 12 | Write `docs/app-review.md` now or defer to actual public release? | P9 | open |
| 13 | Build P10 desktop client, or stop at 1.0? | P10 | open |

---

## 13. Definition of Done

TETHER 1.0 is done when, from an iPhone on cellular, away from home:

1. You open the app and see live machine state in under 2 seconds.
2. You get a push notification when something is wrong, and can act on it from the lock screen.
3. You can open a terminal and fix most things without ever starting a video stream.
4. When you *do* need the screen, you connect in under 5 seconds and it is responsive enough to do real work — including clicking through a UAC prompt and logging in from the lock screen.
5. Nothing about it is hidden from someone sitting at the machine.
6. A stranger could install it from a signed installer, pair by scanning a QR, and be working in five minutes without editing a config file — **even though no stranger has one yet.**
7. You built it, you own it, and there is no subscription.

---

---

## 14. Decision Log — Settled Questions, Do Not Reopen

These alternatives were considered and rejected with reasons. If you find yourself about to propose one, read the reason first. If the reason no longer holds because of something you discovered, say so explicitly and cite the discovery — that is a legitimate amendment. Proposing them absent new information is not.

| Rejected | Reason |
|---|---|
| **No relay at all — pure Tailscale/WireGuard architecture** | Technically viable and cheaper, and for a single technical user it is strictly better. Rejected as the *primary* design because "install Tailscale, create an account, log in on both devices" is fatal onboarding friction for public distribution. Retained as an optional transport (§3.1 step 4) where it costs nearly nothing to support. |
| **WGC as the primary capture path** | No dirty rects, capture border on recent builds, higher latency. Kept as fallback only. |
| **NVENC as the primary encoder** | Vendor lock. A public release must work on AMD and Intel hosts. MFT first; NVENC as an additive fast path only. |
| **Single-tenant relay, add accounts later** | The retrofit touches device registry, pairing tokens, push tokens, TURN minting, and every query, and requires migrating live pairings. ~20% more work now versus a rewrite later. |
| **Native desktop client (Win32 + Cocoa) instead of Tauri** | Tauri reuses `tether-core` wholesale and inherits hardware H.264 decode from the webview. Native buys marginal input fidelity for roughly double the work. Revisit only if Pointer Lock proves inadequate in P10. |
| **Ed25519 on both agent and phone for symmetry** | iOS Secure Enclave does not back Ed25519. Hardware key storage beats curve symmetry. P-256 on iOS, Ed25519 on the agent. |
| **Alert evaluation on the relay** | Agent-side evaluation keeps the relay dumb and cheap, and means alerts still fire when the relay is down and the client is on LAN. |
| **Third-party crash/analytics SaaS (Sentry, Crashlytics)** | This process has access to everything on the user's machine. It does not phone home. Local crash files only. |
| **Attended support flow (session codes, "join my session")** | Deliberate product boundary. It is also the single feature that would turn a defensible remote-access tool into something App Review and abuse researchers treat as stalkerware-adjacent. |
| **Web dashboard** | Native clients only. A read-only web view is a post-1.0 conversation, not a 1.0 feature. |
| **Kernel driver for board/CPU sensors** | Open (`TODO(frank)` #6), leaning no. Driver signing raises the distribution bar substantially for one non-essential metric. |

---

## 15. Gate Report Format

At every gate, stop and emit exactly this structure. Do not proceed until it is written and the human has responded.

```markdown
# Gate Report — P<n>: <phase name>

## Status
PASS / FAIL / PASS WITH DEVIATIONS

## Criteria
| # | Criterion | Result | Evidence |
|---|-----------|--------|----------|
| 1 | <verbatim from brief> | PASS/FAIL | <path in artifacts/, or command to reproduce> |

## Measurements
<Every number the gate asked for. Actual values. If not measured, write "NOT MEASURED" and why.>

## Deviations from brief
<Anything built differently than specified, and why. "None" is a valid answer.>

## Discovered problems
<Things that will bite in a later phase. Be pessimistic here — this section existing is the point.>

## Open TODO(frank) items encountered
<Which placeholders you worked around, and what is blocked behind each.>

## Ready for P<n+1>?
<Your recommendation, with the one thing you'd want decided first.>
```

Write the report to `artifacts/gate-P<n>.md` as well as emitting it. Gate evidence — logs, measurement output, screen recordings — goes in `artifacts/P<n>/`.

---

*Brief version 1.1. Amend at gates as reality requires — and record amendments in this file rather than silently diverging.*
