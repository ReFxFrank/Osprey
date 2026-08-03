# P1 implementation plan

Grounded in a full survey of the codebase on 2026-08-03. P1's brief scope:
real Windows service, session-1 helper with lifecycle, M-01 metrics + 24 h
ring buffer, live iOS dashboard (device list per A23). This file records the
design decisions and their reasons; the gate report will cite it.

## 1. Concurrency model: synchronous threads, not tokio (yet)

The entire agent is deliberately synchronous — `NoiseSession` is
transport-agnostic over `std::io::Read + Write`, sessions are thread-per-peer
under `std::thread::scope`, and `run::execute`'s `Arc<AtomicBool>` stop flag
already documents the P1 service control handler as its intended caller.

P1 adds three long-lived concerns: the SCM control loop, a relay WS
connection, and a metrics sampler. Each fits a dedicated thread naturally.
Introducing tokio now would force blocking adapters around the sync Noise core
for zero concurrency benefit at P1 scale (a handful of sessions, one socket,
a 1 Hz timer). §4.1's "tokio for async" stands as the choice *when async
arrives* — which is P5, where `webrtc-rs` requires it. Recorded here so the
gate report can cite the deviation-that-isn't: no async exists yet.

## 2. Service (`osprey-svc`)

- `windows-service` crate (locked, §4.1). New subcommands: `install`,
  `uninstall`; a hidden `service` entry invoked by the SCM. `run` stays as the
  console mode for development.
- Install: `sc` semantics via the crate — auto-start, restart-on-failure
  recovery actions (1 s / 5 s / 30 s), display name "Osprey Agent". The single
  allowed registry key records install state; config stays in
  `%ProgramData%\Osprey\config.toml`.
- **One elevation, nothing to launch.** The installer is the only interactive
  prompt the product ever shows: it elevates once, registers the service, and
  from then on the service starts at boot and spawns the helper itself. The
  operator launches nothing and sees only the tray icon. The installer also
  pre-creates the Windows Firewall rule for the LAN listener on the *Private*
  profile (amendment A7), because otherwise the first `run` triggers a second
  prompt that the product has no reason to make a human answer. The three
  processes are a Session 0 requirement (§9.1), never something a user starts.
- The service main wraps exactly what console `run` wraps: `Host::open`,
  `LanListener`, sessions, plus the new relay thread and sampler. Stop request
  flips the existing `AtomicBool`.
- The installer (elevated `install` subcommand) also applies the
  `%ProgramData%\Osprey` ACL tightening that `DpapiKeystore::open`
  deliberately does not (Administrators + SYSTEM; the keystore docs name this
  as the P1 obligation).
- `state.rs` is at 563/600 lines and must be split before gaining fields.

## 3. Relay transport (agent and phone)

P0 proved the session plane over LAN TCP only; the relay WS path exists
server-side and is unused. P1 wires both ends so the management plane works
away from home (and the LTE gate criterion is measurable):

- **Agent**: a relay thread owning a `tungstenite` (blocking, native-tls)
  connection to `WS /v1/agent`, bearer = the stored enrollment token.
  Jittered exponential backoff (1 s → 60 s cap); application-level
  `{t:"ping"}` keepalive (~30 s) because the relay never probes; close 4000 /
  1006 / relay restart are retryable, close 4001 is terminal (device revoked —
  stop and surface). Incoming `{t:"relay"}` frames carry opaque Noise
  ciphertext: a `RelayByteStream` adapter presents them as `Read + Write` so
  `channel::accept` and the whole session layer run unchanged over the relay
  hop. 256 KiB relay frame cap respected end-to-end (metrics history is
  chunked by the endpoints).
- **Phone**: `RelayByteStream` over `URLSessionWebSocketTask` against
  `WS /v1/client`; dial order: LAN hints first, relay fallback. Requires the
  phone to hold a client device token, which only the relay redeem flow
  issues — so the full (non-`--lan-only`) pairing path gets exercised at last.
- Discovered problem 14 (deliberate disconnect logged as a read error) is
  fixed here: a `bye` or clean EOF ends the session without a WARN, because
  reconnect accounting is meaningless while a normal close counts as failure.

## 4. Metrics (M-01)

- **Source: raw Win32 via the `windows` crate** — `GetSystemTimes` (CPU),
  `GlobalMemoryStatusEx` (RAM), `GetDiskFreeSpaceExW` per fixed volume,
  `GetIfTable2` deltas (network). No `sysinfo`: rule 5 (a large polling crate
  to save four API calls), and the idle-CPU gate criterion rewards sampling
  exactly what we need. Non-Windows builds return an explicit
  "unavailable" — never zeros (rule 9).
- **Cadence**: background sampler at 30 s into the ring; 1 Hz only while at
  least one subscription is active (this is what keeps idle CPU < 1%).
- **Ring buffer**: in-memory, 24 h of 30 s samples (2,880 slots × ~100 B —
  trivial). Not persisted across restarts; the brief asks for a ring buffer,
  not a database, and the gate report will say so.
- **Protocol** (fills the reserved names only — P10's zero-new-messages rule):
  - `metrics.subscribe` request → its correlated response is a
    `metrics.history` body carrying the backfill; thereafter uncorrelated
    `metrics.tick` pushes carry the `sub` id (§5.1's stream model, verbatim).
  - `metrics.history` request (time range) → `metrics.history` response.
  - The body DSL has no nested structs: per-disk and per-interface data ride
    parallel arrays (`disk_labels: [string]`, `disk_total: [u64]`, …).
  - `hello.ok` gains an optional `display_name` field — the survey found the
    device list has no human-readable name anywhere (QR, pin, and hello all
    lack one). A field addition to an existing body is forward-compatible on
    both decoders and is not a new message type. Recorded as an amendment when
    it lands.

## 5. Helper (`osprey-helper`)

P1 scope: existence, lifecycle, and the tray — capture/input stay P4/P6.

- Spawn: session-change notifications drive `WTSQueryUserToken` +
  `CreateProcessAsUser` into the interactive session; helper dies on session
  disconnect; respawn on crash < 3 s with exponential backoff for the
  crash-loop case; follows fast user switch.
- IPC: named pipe served by the service. The brief's "SYSTEM-only DACL" is
  read as: only SYSTEM may create/own the pipe; the DACL additionally grants
  read/write to the interactive session's logon SID so the user-context
  helper can connect, and a per-spawn nonce passed on the helper command line
  authenticates the first message (pipe-squatting defence). This
  interpretation is surfaced in the gate report.
- Tray: minimal in P1 — status icon + "Pair new device" invoking the same
  console-free `pair::execute` over IPC (A8 anticipated exactly this).
- `PerMonitorV2` manifest embedded now (§9.5), plus the same
  `deny(unwrap/expect/panic)` posture as the other crates.

## 6. iOS

- `PinStore` single record → keyed set, migrating the existing P0 pin.
- `AppModel` state keyed per device; `alreadyPaired` guard removed.
- Root becomes `DeviceListView` (A23) → per-device dashboard,
  `NavigationStack`; Swift Charts (system framework, no new deps); explicit
  empty states until data flows.
- The lock-step `SessionClient` gains a demultiplexing receive loop (actor
  owning `NoiseSession.receive()`, routing correlated replies vs `metrics.tick`
  pushes) — the survey confirms this is a hard prerequisite for any
  server-push, and `SendGate`/Sendable-struct design anticipated it.
- Foreground reconnect (§9.3): `scenePhase` observation, cached last state
  with staleness indicator, target < 2 s to live dashboard.
- `SessionClient.capabilities` advertises `.metrics` only once the
  conversation actually works (rule 9).

## 7. The LTE question (the one open decision)

The gate criterion "live graphs on the phone at 1 Hz over LTE" requires the
phone to reach the agent from outside the LAN. The relay code path (this
plan, §3) is testable end-to-end locally, but LTE specifically needs either
the relay deployed on the VPS (pulls the TODO #5 domain/deploy decision
forward from P5) or the overlay transport (§3.1 step 4) standing in for the
measurement. Owner decision required; the build work is identical either way.

## Order of work

1. Protocol bodies + regenerate (everything downstream needs the types).
2. Metrics engine + ring buffer + session-plane serving (testable on LAN).
3. Service-ification + ACL + relay thread with reconnect.
4. Helper spawn/lifecycle/tray + IPC.
5. iOS: receive loop → device list → dashboard → foreground reconnect.
6. Gate measurements.
