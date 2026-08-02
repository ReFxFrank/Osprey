# Running Osprey today

What actually works right now, and the exact commands to run it. Everything here
was read out of the source — `agent/osprey-svc/src/cli.rs`, `relay/src/config.ts`,
`relay/.env.example`, `relay/docker-compose.yml` — not from memory. Where the
source and the older docs disagree, that is called out.

---

## Read this first: what is and is not possible today

**The iOS app has never been compiled.** There is no Apple toolchain in the
development environment, so no Swift compiler has ever read
`ios/Osprey/Osprey/**`. The Xcode project is generated from
`ios/Osprey/project.yml` and does not exist as a checked-in artifact.

**Therefore: you cannot pair a phone with a host yet.** Gate P0's headline
criterion — phone scans QR, pairs, exchanges an encrypted ping/pong — is
`NOT MEASURED`, and Gate P0's status is **FAIL** for that reason. Closing it
requires a cloud-Mac session; the ordered runbook is `docs/ios-build.md`.

**What *is* exercised today** is the identical protocol path with a Rust
controller standing in for the phone, over real TCP on loopback:

```bash
cd agent && cargo test -p osprey-svc --test pairing_e2e
```

Three tests: `pair_then_session_then_unpair_blocks_the_next_connection`,
`an_unknown_controller_is_refused_a_session`, and
`a_connection_accepted_before_an_unpair_is_refused_after_it`. That is a full
`IKpsk2` pairing, a steady-state `IK` session, encrypted ping/pong, and
revocation — the same `osprey-core` code the phone will drive. It is not the
gate criterion, because the gate criterion says "phone".

**Also not built yet:** the Windows service wrapper and the tray helper are P1.
`CLAUDE.md` lists `osprey-svc.exe install` / `uninstall` and `Get-Service Osprey`
— **those subcommands do not exist in this build.** The CLI has exactly three:
`pair`, `run`, `unpair` (amendment A8: pairing is a console command in P0 because
the tray it would otherwise live in is a P1 deliverable). Run the agent in a
terminal.

---

## 1. Prerequisites

| Component | Requirement | Notes |
|---|---|---|
| Rust | A current stable toolchain, `rustup` | Edition 2021. Build with `cargo`. |
| Node | **>= 24** | `relay/package.json` enforces `engines.node >= 24.0.0`; `relay/.nvmrc` pins `24`. Measured against 24.18.1. |
| pnpm | 10.x | `packageManager` pins `pnpm@10.33.0`. |
| Postgres | **16** | Retained deliberately (amendment A3); nothing in the relay needs newer. |
| Docker (optional) | Compose v2 | Only for the bundled local relay stack. |

The agent's target platform is Windows. It builds and its tests pass on Linux
too — the keystore there is an explicitly non-encrypting development backend,
which is why `OSPREY_DATA_DIR` is honoured off Windows and ignored on it.

Type-check the Windows target even when developing elsewhere:

```bash
cd agent && cargo clippy --workspace --all-targets --target x86_64-pc-windows-msvc -- -D warnings
```

---

## 2. The relay

The relay is a tenant-scoped signalling broker. It **never sees plaintext** — it
is assumed hostile by design — and the management plane does not depend on it
for LAN pairing. You can skip this entire section if you only want `--lan-only`
pairing (§4).

### 2.1 The easy path — docker compose

```bash
cd relay
cp .env.example .env
```

Fill in the three blank secrets in `.env`. They are blank on purpose: compose's
`${VAR:?…}` guard only fires on an *empty* value, so a placeholder would ship a
guessable credential that passes the guard.

```bash
openssl rand -base64 36    # -> POSTGRES_PASSWORD
openssl rand -base64 36    # -> OSPREY_APP_PASSWORD
openssl rand -base64 48    # -> OSPREY_ENROLLMENT_SECRET   (minimum 32 chars, enforced)
```

Then:

```bash
docker compose up --build
```

Four services come up in order: `postgres` (16-alpine) → `migrate` (one-shot) →
`relay` → `caddy`.

The relay port **is not published to the host**. Caddy on 443 is the only
ingress, so there is no plaintext port to accidentally point a phone at. The
default domain is `osprey.localhost`, which resolves to loopback on macOS and
most Linux distributions with no `/etc/hosts` entry. Caddy mints its own
certificate (`tls internal`), so to talk to it from a device you must trust that
CA once:

```bash
docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./caddy-root.crt
```

This exists because iOS App Transport Security blocks plaintext HTTP *and*
blocks connections to bare IP addresses — a dev relay reachable only at
`http://<lan-ip>` cannot be talked to by the real app without an ATS exception
that then has to be remembered and removed.

### 2.2 Running the relay directly

`relay/src/index.ts` reads `process.env` and **does not load a `.env` file**;
neither does the `dev` script (`node --watch src/index.ts`). Export the variables
yourself, or use Node's own loader:

```bash
cd relay
pnpm install
node --env-file=.env --watch src/index.ts
```

Migrations are separate, and deliberately run on a *different* connection:

```bash
cd relay
DATABASE_URL_MIGRATOR=postgres://osprey_owner:…@localhost:5432/osprey \
OSPREY_APP_PASSWORD=… \
  pnpm db:migrate
```

`pnpm db:generate` (drizzle-kit) regenerates migration SQL after a schema change.

### 2.3 Relay environment variables

Read off `relay/src/config.ts`. Anything without a default is fatal at startup —
the relay fails loudly rather than booting half-configured.

| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_URL` | **required** | Runtime connection. Must be the non-owner `osprey_app` role. |
| `OSPREY_ENROLLMENT_SECRET` | **required, >= 32 chars** | Deploy-time secret for `POST /v1/agents/enroll`. Per-account quotas structurally cannot bound *account creation*, so this is the only thing between a public relay and unlimited account minting (amendment A13). |
| `OSPREY_HOST` | `0.0.0.0` | Listen address. |
| `OSPREY_PORT` | `8080` | Listen port. |
| `OSPREY_ENROLL_RATE_LIMIT_PER_HOUR` | `10` | **Global** per-source-IP, not per account. |
| `OSPREY_REDEEM_RATE_LIMIT_PER_MINUTE` | `20` | Per source IP, and failed attempts per target account. `POST /v1/pairing/redeem` is unauthenticated and names its tenant in the body. |
| `OSPREY_PAIRING_TOKEN_TTL_SECONDS` | `120` | Brief §6.1 fixes the QR validity window at 120 s. |
| `OSPREY_DEFAULT_MAX_DEVICES` | `25` | Per-account quota default. |
| `OSPREY_DEFAULT_MAX_PAIRING_ATTEMPTS_PER_HOUR` | `20` | Per-account quota default. |
| `OSPREY_DEFAULT_TURN_BYTES_PER_MONTH` | `53687091200` (50 GiB) | Per-account quota default. |
| `OSPREY_LOG_LEVEL` | `info` | |

Compose-only, not read by the application: `POSTGRES_PASSWORD`,
`OSPREY_APP_PASSWORD`, `OSPREY_RELAY_DOMAIN`. Migration-only:
`DATABASE_URL_MIGRATOR`.

**The relay refuses to start as a privileged role.** Postgres row-level security
filters nothing for a superuser, a `BYPASSRLS` role, or a table's owner, so a
relay connecting with migration privileges would ship policies that merely look
protective. `relay/src/db/client.ts` checks the effective role at boot and exits
(amendment A14).

### 2.4 Relay tests

```bash
cd relay && pnpm test        # 70 tests, needs a live Postgres
cd relay && pnpm lint
cd relay && pnpm typecheck
```

The suite creates and drops its own database. It connects on **port 5433** by
default with the user `postgres` and no password, which means a local Postgres
configured for `trust` on that port. Override with:

`OSPREY_TEST_PG_HOST` (`localhost`), `OSPREY_TEST_PG_PORT` (`5433`),
`OSPREY_TEST_PG_OWNER` (`postgres`), `OSPREY_TEST_PG_DATABASE` (`osprey_test`).

---

## 3. Building the agent

```bash
cd agent
cargo build --workspace
cargo test --workspace                                   # 142 tests
cargo clippy --workspace --all-targets -- -D warnings
```

The debug binary lands at `agent/target/debug/osprey-svc` (`.exe` on Windows).
The examples below use `cargo run -p osprey-svc --` so they work from a source
checkout on either platform; substitute the binary path if you prefer.

Protocol types are generated. After any edit to `proto/messages.toml`:

```bash
cd proto && pnpm generate      # then `git diff` on the generated files must be intentional
```

Never hand-edit a generated file.

---

## 4. Pairing, sessions, and unpairing

Three subcommands. That is the entire surface.

### Global option

`--data-dir <DIR>` — override the data directory. **Ignored on Windows**, where
the path is fixed at `%ProgramData%\Osprey` and the ACL on that directory is the
only thing protecting the sealed keys. An environment variable that could
redirect the keystore somewhere world-writable would dissolve the only boundary
that exists. (DPAPI is at-rest obfuscation, not an access-control boundary —
amendment A12.)

Off Windows, the data directory is `$OSPREY_DATA_DIR`, else
`$XDG_STATE_HOME/osprey`, else `~/.local/state/osprey`.

### `osprey-svc pair`

Displays a pairing QR and enrols exactly one controller. **Requires physical
access to the host** — you must run this command at the machine. That is not a
UX convention; see §5.

```bash
# No relay at all. This is the simplest thing that works.
cargo run -p osprey-svc -- pair --lan-only

# Through a relay, first contact:
cargo run -p osprey-svc -- pair \
  --relay-url https://osprey.localhost \
  --enrollment-secret "$OSPREY_ENROLLMENT_SECRET"

# Through a relay, subsequently — the URL and token are remembered:
cargo run -p osprey-svc -- pair
```

| Flag | Default | Meaning |
|---|---|---|
| `--relay-url <URL>` | remembered after first enrolment | Relay base URL. |
| `--enrollment-secret <SECRET>` | also read from `OSPREY_ENROLLMENT_SECRET` | Needed only on first contact with a given relay. |
| `--lan-only` | off | Pair with no relay involved. Conflicts with the two flags above. |
| `--port <PORT>` | `47010` | TCP listen port. `0` asks the OS for an ephemeral port. |
| `--ttl <SECONDS>` | `120` | How long the QR stays valid. |
| `--no-mdns` | off (so mDNS **is** advertised) | Suppress the `_osprey._tcp` advertisement during the pairing window. |
| `--print-payload` | off | Also print the QR's decoded JSON. **This contains the pairing secret.** |

`--print-payload` exists for the case where a scan is impossible. Leave it off
otherwise: as text the secret survives shell redirection, terminal scrollback, a
tmux capture, and anything collecting stdout. The QR itself is transient pixels.

A failed pairing attempt does **not** close the window — only success or the TTL
does — so a fumbled scan does not mean re-running the command.

### `osprey-svc run`

Serves sessions to already-pinned controllers. Refuses to start if nothing is
paired.

```bash
cargo run -p osprey-svc -- run
```

| Flag | Default | Meaning |
|---|---|---|
| `--port <PORT>` | `47010` | TCP listen port. |
| `--no-mdns` | off (so mDNS **is** advertised) | Suppress `_osprey._tcp`. |

mDNS is on by default because it is the discovery path that survives the host
changing address (amendment A6). Without it a paired phone is limited to the
addresses frozen into its original QR scan.

Ctrl-C stops the accept loop cleanly: it hangs up live sessions and joins the
revocation watcher rather than terminating mid-write. Idle sessions are closed
after 5 minutes.

The agent listens only on private/link-local interfaces and, on Windows, should
be registered with the firewall's **Private** profile only. It is never
WAN-reachable; "outbound connections only" governs all relay and WAN traversal
(amendment A7).

### `osprey-svc unpair`

```bash
cargo run -p osprey-svc -- unpair all
cargo run -p osprey-svc -- unpair 3f9a2c…        # fingerprint prefix, as displayed by `pair`
cargo run -p osprey-svc -- unpair <relay-device-uuid>
```

The target is required — `all`, a relay device UUID, or a prefix of the
fingerprint `pair` printed.

The **order of operations is the security property** (amendment A18):

1. the pin is removed from the local store and the store is fsynced;
2. live sessions with that peer are hung up on;
3. the unpair is written to the audit log;
4. **only then** is the relay told, best-effort.

The local pin store is authoritative. The relay is never consulted and never
gets a veto — a LAN session does not involve it at all, and a compromised relay
that could stall a revocation could keep a device paired against your explicit
instruction. A relay failure at step 4 cannot undo steps 1–3.

If you run `unpair` as a separate process while `run` is serving, the running
agent's watcher notices the changed pin store and closes the sessions itself,
within one polling interval.

### Logging

`OSPREY_LOG` sets the tracing filter (default
`osprey_svc=info,osprey_core=info`). Diagnostics go to **stderr** so the QR and
the fingerprint on stdout stay clean enough to pipe or screenshot.

---

## 5. What the QR contains, and what you must verify

The QR payload is:

```
{ v, relay_url, account_id, device_id, agent_identity, lan_hints, pairing_secret }
```

- `pairing_secret` — >= 256 bits of CSPRNG output that **the relay never sees**.
  Rendezvous through the relay uses only `routing_id = SHA-256(pairing_secret)`.
  The secret is the Noise **PSK**: pairing runs
  `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`, so only the physical scanner of the
  QR can complete the handshake. This is what makes "physical access is required
  to enrol" a cryptographic property rather than a convention (amendment A5).
  Sessions *after* pairing run plain `Noise_IK` on the pinned statics.
- `agent_identity` — the host's Ed25519 identity public key plus the X25519
  Noise static it cross-signs. The phone verifies that cross-signature **before
  a single byte goes on the wire**; that check is the trust anchor.
- `lan_hints` — the agent's private addresses and port, valid by construction
  because you are standing at the machine (amendment A6).
- `relay_url` / `account_id` are **empty strings** for a `--lan-only` QR. The iOS
  decoder accepts that. `TODO(frank):` decide whether the empty-string encoding
  is the contract or whether the QR should gain an explicit `mode` field — both
  ends work today, but the decision should be made before the encoding is
  depended on.

### The fingerprint check is the operator's job

`pair` prints the **host identity fingerprint** before the scan, and the
**controller fingerprint** it just pinned after it:

```
Paired.
  controller fingerprint : <short form>
  full                   : <full form>
  noise static           : <hex>

Check this fingerprint against the one your phone is showing. If they
differ, run `osprey-svc unpair <short form>` now.
```

**Do this comparison.** It is the whole point of displaying the pin: a
fingerprint you do not recognise means you have just caught a pairing you did not
intend — a substituted key, or someone else's device — and you can revoke it
before it is ever used. Nothing else in the system will tell you.

---

## 6. The audit log

**Location:** `<data-dir>/audit/`, one append-only JSONL file per UTC day.

- Windows: `%ProgramData%\Osprey\audit\`
- Linux/macOS dev: `$OSPREY_DATA_DIR/audit/`, else `$XDG_STATE_HOME/osprey/audit/`,
  else `~/.local/state/osprey/audit/`

Alongside it: `keys/` (sealed private key material) and `state.json` (device id,
relay credentials, pinned-peer list).

**Recorded events** (amendment A16): `pairing_succeeded` — with the pinned peer's
identity fingerprint, its Noise static, device id, account id and timestamp;
`pairing_failed` — with a typed reason (PSK mismatch, expired or replayed token,
signature failure) and detail that **never contains the pairing secret**; and
`unpaired` — with the peer fingerprint and which side initiated it (`host` or
`peer`).

**Append-only is enforced by construction, not by policy.** The `AuditLog` type
exposes no truncate, no rewrite and no delete; every write opens the day's file
with `append(true)`. There is deliberately **no client-reachable path that
removes a line** — no protocol message, no remote command. A paired phone cannot
erase the record of its own pairing.

This is non-optional and not user-suppressible, along with the host session
indicator. That property is part of what separates Osprey from malware.

An audit-write failure during `unpair` does not abort the revocation: the pin is
already gone, so the command reports the failure and exits non-zero. Revocation
happened; the record of it did not. That is the honest outcome and it is
deliberate.

---

## 7. Getting to a phone

You cannot yet. Follow `docs/ios-build.md`, which is ordered to close Gate P0
criteria 1, 2 (app half) and 7 (swiftlint half) in one cloud-Mac session.

Two constraints worth knowing before you book the Mac:

- Cloud Macs have no USB passthrough, so there is no "Run on device" over a
  cable. Builds reach the iPhone over the air, or via an IPA you download to the
  Windows PC and install with Sideloadly.
- The iOS Simulator has **neither a camera nor a Secure Enclave**, so criteria 1
  and 2 cannot be satisfied in it at all. They require the physical iPhone.
