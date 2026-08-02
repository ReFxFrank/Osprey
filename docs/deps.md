# Dependency register

CLAUDE.md rule 5: every dependency carries a one-line justification, and no
dependency exists to save fifteen lines. Anything added without an entry here
fails the phase gate.

## Agent — workspace (`agent/Cargo.toml`)

| Crate | Why |
|---|---|
| `anyhow` | Error propagation with context at binary boundaries, where the caller only needs a message, not a match. |
| `thiserror` | Typed errors in library crates, so remote input produces a matchable variant rather than a panic (rule 2). |
| `serde` / `serde_json` | Protocol envelope and on-disk state; JSON is the wire format the brief specifies in §5.1. |
| `tracing` | Structured logging with levels; the audit log is separate and deliberately not built on this. |
| `snow` | The Noise Protocol implementation. §4.1 locks it. Used with `default-features = false` — see the note below. |
| `ed25519-dalek` | Ed25519 device identity key mandated by §6.1. |
| `x25519-dalek` | The X25519 Noise static. Required because Ed25519 cannot key a DH handshake (amendment A4). |
| `rand_core` | CSPRNG trait plumbing for the dalek key generators; `getrandom` feature supplies the OS entropy source. |
| `sha2` | `routing_id = SHA-256(pairing_secret)` and key fingerprints. |
| `zeroize` | Wipes private key material from memory on drop; cheap and appropriate for a crate whose whole job is key custody. |

### Note on `snow` features

`snow` is pinned with `default-features = false` and only the pure-Rust
resolver features. Its default `std` feature declares `ring/std` **without** the
weak-dependency `?` syntax, which force-enables the optional `ring` C
dependency; `ring`'s build script shells out to `xcrun` and therefore cannot
cross-compile to Apple targets from a non-Mac host. The pure-Rust configuration
keeps the agent tree free of C code (verified: zero `ring` in `agent/Cargo.lock`)
and is what lets the identical crypto core build for iOS.
Evidence: `artifacts/P0-plan-evidence/ios-crossbuild.md`.

## Agent — `osprey-core`

| Crate | Why |
|---|---|
| `hex` | Key fingerprints and the QR payload's hex fields; the operator has to read these. |
| `time` | RFC 3339 timestamps for audit records, which must be machine-parsable after the fact. |
| `p256` | Verifies the phone's Secure Enclave cross-signature (amendment A20). Pinned to 0.13 rather than 0.14 on purpose: 0.14 pulls a second generation of the RustCrypto stack alongside the one `ed25519-dalek` already uses, giving the build two copies of the primitives the trust model rests on. Pure Rust, so the Apple cross-build stays free of C toolchains. |
| `windows` (cfg windows) | DPAPI `CryptProtectData`/`CryptUnprotectData` for the machine-scoped keystore (§6.1, amendment A12). Scoped to `cfg(windows)` so non-Windows builds never pull it. |
| `tempfile` (dev) | Isolated directories for keystore round-trip tests. |

A DPAPI wrapper crate was deliberately **not** used: the call is roughly thirty
lines of `unsafe`, and a thin third-party wrapper around it would not clear
rule 5's bar.

## Agent — `osprey-proto`

| Crate | Why |
|---|---|
| `uuid` | Envelope correlation ids (§5.1 specifies a UUID). |
| `base64` | Byte fields on the wire are base64, matching what Foundation's `JSONDecoder` produces on the Swift side; both ends are pinned explicitly rather than relying on a default. |

## Agent — `osprey-svc`

| Crate | Why |
|---|---|
| `clap` | Subcommand parsing for the P0 console entry point (`pair` / `run` / `unpair`, amendment A8). |
| `ctrlc` | Clean shutdown so a interrupted `pair` still tears down its listener and writes its audit record. |
| `tracing-subscriber` | Renders `tracing` output; the binary needs exactly one subscriber. |
| `qrcode` | Renders the pairing QR as Unicode half-blocks in the terminal. Encoding QR by hand is not a fifteen-line job. |
| `if-addrs` | Enumerates local interfaces to populate the QR's `lan_hints` and to bind the listener to private addresses only (amendment A6/A7). |
| `ureq` | Blocking HTTP client for the relay REST calls. Blocking suits a console binary with no async runtime; async arrives with the P1 service. |
| `mdns-sd` | Advertises `_osprey._tcp` for LAN discovery (amendment A6). Pure Rust with no async-runtime dependency, so it does not impose a runtime on a console binary that has none. |
| `hex` | Renders key fingerprints the operator reads off the screen to confirm a pin. |
| `uuid` | Device ids, shared with the protocol layer. |
| `base64` | Encodes key material in the QR payload and in relay requests, matching the protocol layer's encoding. |
| `tempfile` (dev) | Test isolation. |

## Agent — `osprey-ffi`

The Rust↔Swift bridge, so the iOS client runs the same Noise implementation as
the agent rather than a second, independently written one.

| Crate | Why |
|---|---|
| `uniffi` | Generates the Swift bindings from the Rust surface. `default-features = false` keeps the code generator out of the shipping library; the `bindgen-cli` feature enables it only for the `uniffi-bindgen` binary that emits the bindings at build time. |
| `osprey-core`, `osprey-proto` | The crate is a thin adapter over these; it holds no protocol logic of its own. |
| `tempfile` (dev) | Test isolation. |

## Relay (`relay/package.json`)

| Package | Why |
|---|---|
| `fastify` | The HTTP server §4.2 locks. |
| `@fastify/websocket` | The official Fastify WebSocket plugin, v11 line tracking Fastify 5; carries the agent and client attach routes. |
| `drizzle-orm` | The ORM §4.2 locks; its schema-level RLS support backs the defence-in-depth policies. |
| `postgres` | The Postgres driver Drizzle sits on. |
| `drizzle-kit` (dev) | Migration generation. |
| `eslint`, `typescript-eslint` (dev) | Host the repo-boundary rule that enforces the tenancy invariant. |
| `eslint-plugin-boundaries` (dev) | Resolver-based layer enforcement, so a relative-path import cannot evade the string-pattern rule. Two independent mechanisms guard the single highest-severity bug class (§6.7). |
| `typescript` (dev) | Type checking. |
| `vitest` (dev) | Test runner, including the cross-tenant isolation suite. |
| `ws`, `@types/ws` (dev) | WebSocket client used by the tests to attack the WS routes. |
| `@types/node` (dev) | Node 24 type definitions, matching the runtime pin. |

## Protocol codegen (`proto/package.json`)

| Package | Why |
|---|---|
| `smol-toml` | Parses `messages.toml`. Maintained and TOML 1.1-compliant; `@iarna/toml` has been unmaintained since ~2020. |
| `typescript`, `@types/node` (dev) | The generator is TypeScript and type-checks under `strict`. |
