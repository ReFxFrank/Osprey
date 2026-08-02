# TETHER — P0 Execution Plan

*Planning deliverable. No implementation code written this session. Awaiting approval before building P0.*

Every crate version, API signature, and platform limit below was verified against current (2026-08-02) upstream sources or by a reproducible test run in this environment — not recalled. Where I ran code, the command is cited. Evidence lives in `artifacts/P0-plan-evidence/`.

---

## 1. What I understood

TETHER is a self-hosted, single-operator remote-access system — one product covering the useful half of TeamViewer (live screen + input injection) and the useful half of Pulseway (headless metrics, terminal, files, alerts) — driven from an iPhone against Windows hosts you own. It is split three ways because each piece has a hard constraint the others don't: the **agent** is split again into a SYSTEM service (`tether-svc`, Session 0, no desktop) and a per-session helper (`tether-helper`) because a Windows service physically cannot touch the desktop or inject input; the **relay** exists only to broker signaling and push when the two endpoints can't reach each other directly, and is treated as fully hostile so plaintext never crosses it; the **iOS client** is the console. The architecture is shaped by two non-negotiables that also make it distributable rather than malware: physical-access QR pairing as the *only* enrollment path, and a relay that is multi-tenant in its data model from day one even though 1.0 ships zero multi-tenant UX. P0 builds none of the actual remote-access features — it builds the trust spine (identity, pairing, an authenticated encrypted channel) and the tenant-scoped relay skeleton that everything else hangs off.

If any of that is wrong, this is the cheap moment to correct it.

---

## 2. What in the brief is wrong, underspecified, or contradictory

Ordered by how early it bites and how expensive it is to discover late. Each item cites brief line numbers and states the minimal fix. The genuinely load-bearing ones are the security cluster **#1, #2, #14, #15**: the crypto is incoherent as literally written (#1); a compromised relay can hijack pairing as written (#2); the audit log omits the highest-privilege event in the system (#14); and the gate never tests the hostile-relay property the whole design is premised on (#15). These four were driven out by an adversarial pre-implementation security walk (evidence: `artifacts/P0-plan-evidence/`, and the walk itself), not by reading — which is the point of doing it now rather than at the gate.

### #1 — "Noise IK keyed on pinned static keys" is not directly implementable with the mandated key types. *(DEFECT — verified, with a working fix)*

Brief line 241 says the E2E channel is a Noise IK handshake keyed on the pinned static keys. Lines 233–234 mandate **Ed25519 on the agent** and **P-256 in the iOS Secure Enclave**. Three facts make the literal reading impossible:

- **Ed25519 is a signature algorithm, not a DH function.** Noise needs a Diffie-Hellman key on each side. You cannot hand an Ed25519 key to a Noise handshake as a static.
- **Noise requires *both* parties on the *same* DH function.** Agent-on-25519 + phone-on-P256 cannot handshake with each other at all. Verified: `snow` 0.10.0 supports 25519 always and P-256 only behind a non-standard opt-in `use-p256` feature; the two cannot mix in one protocol string.
- **The iOS Secure Enclave key cannot *be* the Noise static.** `snow` requires the raw 32-byte private key (`Builder::local_private_key(&[u8])`). The Secure Enclave never exports a private key — that is its entire point. So an SE-resident key can never be a `snow` static, on any curve. (SE *can* do P-256 ECDH via `SecureEnclave.P256.KeyAgreement`, but only if you also hand-roll a Noise implementation over CryptoKit, which §14 and the audit-surface argument both reject — see §4.)

**The coherent, minimal design — and I verified it runs (`artifacts/P0-plan-evidence/`, both tests pass):**

- Each side keeps its mandated **hardware identity key** exactly as the brief says (Ed25519 in DPAPI on the agent; P-256 in the Secure Enclave on the phone). These sign, are pinned, and are the **durable root of trust**.
- Each side *additionally* generates an **X25519 "Noise static"** — a software key (agent: DPAPI-sealed alongside the Ed25519 key; phone: Curve25519 key in the Keychain, since SE can't hold X25519 — Apple's documented pattern is `kSecClassGenericPassword` with `rawRepresentation`).
- At generation, the identity key **cross-signs** its own Noise static (`Ed25519.sign(x25519_pub)` / `SE-P256.sign(x25519_pub)`). This binds the DH key to the hardware identity.
- Both sides run **Noise on 25519** — the standard, audited path — using their X25519 statics. `snow` on the agent; `snow` compiled into the iOS app as an XCFramework on the phone (§4, item B), so there is exactly **one** Noise implementation in the whole product.
- What gets **pinned** at pairing (exact byte strings): the phone pins `agent_Ed25519_identity_pub ‖ agent_X25519_static_pub`; the agent pins `phone_P256_identity_pub ‖ phone_X25519_static_pub`. Each static is accepted only if the cross-signature verifies under the pinned identity key.
- **Bootstrap vs steady state are cryptographically separated.** Pairing (the *first* time the phone key crosses the untrusted relay) uses `Noise_IKpsk2` with the QR secret as PSK (#2). Every session *after* pairing runs plain `Noise_IK` on the **pinned X25519 statics** — no PSK — because the pin is now the authentication. The identity key is the durable anchor; the X25519 static is **rotatable** by re-signing, which is the recovery path if the software key is ever extracted.

This is Signal's XEdDSA-style separation done conservatively. `ed25519-dalek` *can* convert Ed25519→X25519 (`to_montgomery`), but the crate's own docs advise against reusing a signing key for DH, and the conversion does nothing for the phone (SE P-256 can't convert to X25519 at all) — so the separate-signed-static design is both recommended and what I tested. Note DPAPI is at-rest obfuscation, not access control: the **service-account ACL** on `%ProgramData%\Tether\` is the actual boundary, and both agent keys get that treatment.

*Requires amending brief §4.1/§6.1 to name the X25519 Noise statics and the cross-signature. Recorded as a v1.1 amendment per line 735.*

### #2 — As written, a compromised relay can hijack QR pairing. *(DEFECT)*

The §6.1 (line 235) flow: the QR carries `{relay_url, account_id, device_id, agent_pubkey, one_time_token}`; the agent registers the token with the relay; the phone "posts its pubkey" **through the relay**; both sides pin. The threat model (line 241) says assume the relay is fully compromised. Walk it: the relay sees the token (the agent registered it) and sees the phone's posted pubkey (it's the broker). Nothing in the payload is secret *from the relay*. So a hostile relay can redeem the token with **its own** key before/instead of the phone, or swap the phone's pubkey for its own, and pair itself. The phone does get the authentic `agent_pubkey` from the QR (that direction is fine), but the agent has no relay-independent way to authenticate *which* pubkey is the real phone's.

**Minimal fix (verified to run — this is the `IKpsk2` test in the evidence dir).** The subtlety the adversarial walk exposed: "relay stores only a hash of the token" is **insufficient by itself**, because redemption still forces the phone to reveal the token to the relay. So split the secret into two roles:

- Add a high-entropy **`pairing_secret`** (≥128 bits, `ring` CSPRNG) to the QR. **The relay never sees it.**
- **Rendezvous** uses `routing_id = H(pairing_secret)` — the phone presents the *hash* to the relay to be matched to the pending pairing; preimage resistance means the relay cannot recover the secret. This replaces the old `one_time_token` entirely.
- **Authentication** uses `pairing_secret` as the **Noise PSK** (`Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`). Only the physical scanner holds it, so only it can complete the handshake; the relay, holding only `routing_id`, cannot redeem-as-itself nor substitute the phone key. The phone's real pubkey is learned *inside* the PSK-authenticated channel, never from a relay POST.

This preserves "physical access is required to enroll" (line 236) as a *cryptographic* property, not a UX convention, and needs no new pairing path (§6.6 respected). `snow`'s `Builder::psk(2, &key)` on the always-available 25519 path supports exactly this — no new dependency, no touching §4.1's locked `snow`/`ring` choice. Tested. (This also defends the plain-TCP P0 pairing leg against on-path attackers, not just the relay — see #12's note on F7.)

### #3 — The phone has no way to learn the agent's LAN address for the P0 gate. *(GAP)*

Gate P0 (line 361) requires authenticated ping/pong "over the local network" over "Noise IK over plain TCP" (line 357) — so the phone must open a TCP socket to the agent. But the QR payload (line 235) contains **no IP and no port**, and the only discovery mechanism named is mDNS (line 125), which is **not in the P0 build list** (lines 351–358). **Fix:** (a) add a `lan_hints` field to the QR (agent's current private IPv4/IPv6 + chosen port) — valid by construction because the phone is physically at the host during pairing; and (b) pull minimal mDNS forward into P0 (`_tether._tcp`, `mdns-sd` crate on the agent, `NWBrowser` on iOS) as the durable path. This is step 1 of the §3.1 ladder that P0's LAN requirement already implicitly needs, not new scope.

### #4 — "Agent makes outbound connections only" contradicts the P0 LAN listener. *(CONTRADICTION — wording)*

Line 243: "Agent makes outbound connections only. No listening WAN port." But the direct-LAN path (line 125) and the P0 gate (line 361) require the agent to **accept** a TCP connection on the LAN. The intent is clearly WAN-scoped (the second sentence says "WAN port"). **Fix:** one clarifying sentence — the agent MAY listen on private/link-local interfaces for the direct-LAN path, bound to RFC1918/link-local addresses and the Windows Firewall *Private* profile only, never WAN-reachable; outbound-only governs all relay/WAN traversal.

### #5 — The P0 pairing entry point (tray menu) doesn't exist until P1. *(GAP)*

§6.1 (line 235) starts pairing from the "agent tray menu." The tray lives in `tether-helper` (diagram line 89) and the service itself are both **P1** (lines 373–381). P0 predates all of it. **Fix:** the P0 agent is a **console binary** with subcommands (`tether-agent pair | run | unpair <id|all>`). The QR renders as Unicode half-blocks in the terminal (`qrcode` crate); all pairing logic lives in `tether-core` so the P1 tray is a thin caller. Record as a scheduled deviation in the gate report: tray UX lands at P1.

### #6 — `proto/messages.toml` has no pairing group and no `error` type. *(GAP)*

§5.2 (lines 192–215) lists ~70 message *names* and zero body schemas; line 190 promises every request maps to "exactly one response type or an `error`," but **`error` is not in the registry**, and there is **no pairing/enrollment group at all** — yet P0 must ship pairing end to end (line 356). **Fix — what P0's `messages.toml` must *fully* define** (bodies + codegen): the envelope `{v,id,t,ts,body}`; `error {code, message, retryable}`; the Session group (`hello`/`hello.ok` carrying protocol version + capability bits so the P10 "zero new messages" gate is achievable — `bye`, `ping`, `pong`); and a **new `pair.*` group** (`pair.request`, `pair.confirm`, `pair.revoke`). The remaining ~65 names ship as **name-only stubs** (group+name, bodies marked deferred) so the file stays the single source of truth without inventing speculative schemas. Amend the §5.2 table to add Pairing + `error`.

### #7 — The cross-tenant "every endpoint, 404" gate never lists the endpoints. *(GAP)*

Gate line 365 demands "two accounts, every endpoint, 404 on foreign resources — report the endpoint count," but no endpoint list exists anywhere. **Fix — the derived P0 relay surface (8 endpoints)**, which I'll write into the gate report and make the test suite enumerate programmatically (a new route with no tenant test fails CI):

1. `POST /v1/agents/enroll` — agent enroll + implicit account creation
2. `POST /v1/pairing/tokens` — agent-auth token issue (rate-limited per account)
3. `POST /v1/pairing/redeem` — phone redeems token (404, not 403, on a foreign/again token)
4. `GET /v1/devices` — list this account's devices
5. `DELETE /v1/pairings/:id` — unpair (phone side)
6. `DELETE /v1/devices/:id` — revoke (agent side)
7. `WS /v1/agent` — agent attach
8. `WS /v1/client` — phone attach

Explicitly **not** P0: TURN minting (P5), push tokens (P8), SDP exchange (P5).

### #8 — Dev relay is local Docker, but iOS ATS + the pairing token transiting plaintext bite in week one. *(GAP)*

P0 runs the relay "in Docker locally" (line 358) and the QR embeds `relay_url` (line 235), but Caddy-for-TLS is described only for the VPS (line 156). In dev, `relay_url` is a LAN IP; **iOS 17 ATS blocks plaintext and blocks IP-address connections by default** (verified against Apple docs). **Fix:** put Caddy in the local `docker-compose` from P0 (production parity is free) using Caddy's `internal` CA, **or** add the Debug-only ATS exception `NSAllowsLocalNetworking`. Prefer the Caddy-TLS option because the `pairing_secret`/token hop does transit this leg. Security posture is unaffected either way — Noise treats the relay as untrusted, so dev plaintext to the relay leaks no payload plaintext by design; TLS here only protects metadata.

### #9 — `devices` vs `pairings` schema shape is ambiguous, and it's the hardest P0 decision to reverse. *(GAP)*

Line 153 fixes the table list but never says whether a **phone** is a `device`. `push_tokens` must reference the phone, so it needs a first-class row. **Fix (keeps the fixed table list intact):** `devices` gets a `kind` column (`'agent' | 'client'`), `account_id` on every row; `pairings` is the join (`agent_device_id`, `client_device_id`, both pinned pubkeys + cross-signatures, `created_at`, `revoked_at`). Unpair = soft-revoke (preserves audit). Decide before the first Drizzle migration. **`pairing_tokens` needs three invariants the brief omits** (from the security walk): (a) **atomic single-use** — redemption is one transactional `UPDATE … WHERE routing_id=? AND used=false RETURNING …`, or a race/malicious relay creates two pins; (b) row carries `account_id` + `device_id` so a relay cannot route a phone's pairing into a *different* tenant's pending pairing (confused-deputy, §6.7); (c) stores `routing_id = H(pairing_secret)`, never the secret.

### #10 — DPAPI scope trap will strand P0 keys at the P1 service transition. *(GAP)*

Line 233 specifies machine-scoped DPAPI. In P0 the agent runs as the logged-in user (#5). If the implementer uses the DPAPI *default* (per-user scope), the sealed key becomes **undecryptable by the SYSTEM service in P1**, forcing silent re-enrollment. **Fix:** use `CRYPTPROTECT_LOCAL_MACHINE` from the first line (verified this constant + `CryptProtectData`/`CryptUnprotectData` resolve in `windows` 0.62 via cross-check from Linux). P0 needs elevation once to create `%ProgramData%\Tether\` with a tight ACL (Administrators+SYSTEM in P0; service-account-only ACL deferred to P1 when the account exists — note it in the gate report).

### #11 — Implicit account creation is an unbounded minting surface. *(GAP)*

§0.1 line 35: an account is created when the first agent enrolls, no signup. Quotas are **per-account** (line 37), so they are *structurally incapable* of limiting *account* creation — an attacker hitting `/enroll` gets a fresh account with a fresh quota every call (a Postgres/cost-amplification vector on a public relay). The security walk rates this a DEFECT, not just a gap. **Fix (P0-appropriate, respects "no signup/login/email in 1.0"):** enroll requires a deploy-time **enrollment secret** in the relay's config (single-operator 1.0 has exactly one, so this costs nothing) — note this does **not** conflict with §6.6's "physical access to enroll a *controller*," because enrolling an *agent* (installing on a Windows box you own) is a distinct act gated by whoever runs the relay. Add a **global** (not per-account) per-IP rate limit on `/enroll`, and optionally a hashcash proof-of-work. Public release later swaps the shared secret for per-tenant invite tokens — exactly the provisioning story §0.1 already defers, so no architecture change.

### #12 — Version pins are slightly stale (raise via the decision log, don't silently change). *(minor)*

- **Node 22** (line 48) went to *Maintenance* LTS on 2025-10-21; **Node 24** is Active LTS. Safe to keep for 1.0, but Node 24 is the better greenfield pin. Decision-log item.
- **Postgres 16** (line 151) is supported to ~Nov 2028; fine to keep. 17/18 exist if you want more runway. Nothing in the relay needs newer.
- **Drizzle RLS caveat:** RLS (line 278, "defence in depth") filters *nothing* if the app connects as the table owner/superuser. To make it real: a dedicated **non-owner** app role + per-request `SET LOCAL app.account_id` inside a transaction, with policies referencing `current_setting(...)`. The repo-layer `accountId`-first filtering stays the **primary** mechanism (as CLAUDE.md mandates); RLS is the backstop.

### #13 — Noise initiator/responder roles are never stated. *(GAP, minor)*

IK requires the initiator to know the responder's static in advance. The QR gives the **phone** the agent's key, so the **phone must be the IK initiator** and the agent the responder on the LAN path. State it — it fixes the shape of the handshake, the `pair.*` messages, and the tampered-byte test (line 364).

### #14 — The audit log omits the single highest-privilege event in the system: pairing. *(DEFECT)*

§6.4's audited-event list (lines 251–253) is commands, session start/stop, file transfers, failed auth. It does **not** include **successful pairing/enrollment** or **unpair** — yet pairing a new controller grants a device full control of the machine and is the most security-sensitive action TETHER performs. This is squarely a P0 concern because P0 is *where pairing is built*. **Fix — append to §6.4 and implement from P0:** pairing **success** (pinned peer key fingerprint, device id, account id, timestamp), pairing **failure** (PSK mismatch, expired/replayed token, signature failure), and **unpair** (which peer, which side initiated). The Gate P0 "tampered-byte → clean logged failure" (line 364) should be one of these audit entries, tying the gate to §6.4 rather than an ad-hoc log line. The agent also **displays** the new phone-key fingerprint in its pairing confirmation (tray at P1; console output at P0), so a human can catch an unexpected pin.

### #15 — Gate P0 tests only the happy path; the anti-MITM property the whole design rests on is never gated. *(GAP → add a criterion)*

Gate P0 (lines 361–367) verifies happy-path pairing, key survival, unpair, tampered-byte, and cross-tenant 404s — but has **no adversarial-relay criterion**, even though §6.2's "the relay is untrusted" is the entire justification for the architecture and the P9 threat model (line 528) names "replayed pairing token / hostile relay." The property is asserted at P0 and only tested at P9, which is exactly the "discovered late" failure the brief warns against. **Fix — add a Gate P0 criterion:** with a *deliberately malicious relay build*, verify that (a) substituting the posted phone key, (b) the relay redeeming the `routing_id` itself, and (c) replaying a used/expired token each cause pairing to **fail closed** — never a silent successful pin. This directly gates #1/#2 and should block P0 sign-off. I'll build this malicious-relay harness as part of P0, not P9.

---

## 3. P0 task breakdown (ordered, dependencies marked)

IDs are for the dependency notation. `→` = "depends on." Roughly sequenced; independent tracks can run in parallel.

**Track A — repo + protocol (unblocks everything)**
- **A1.** Cargo workspace: `tether-core`, `tether-proto`, `tether-svc`, `tether-helper` (empty stubs for the last two — P1 fills them). Node relay skeleton (Fastify 5, `@fastify/websocket` 11.x). Xcode project. Layout per §11. *(no deps)*
- **A2.** `proto/messages.toml` = envelope + `error` + Session group + **new `pair.*` group** with full bodies; remaining ~65 names as deferred stubs. *(→ A1)*
- **A3.** `proto/generate.ts` (`smol-toml` parser) → Rust types (`tether-proto`) + Swift types. Protocol round-trip test both languages. *(→ A2)* — **required test #1**

**Track B — identity & crypto (the trust spine)**
- **B1.** `tether-core` key model: Ed25519 identity + X25519 Noise static (agent), cross-signed at generation. DPAPI seal with `CRYPTPROTECT_LOCAL_MACHINE` (Win) behind a `cfg(windows)` trait; a file-with-0600 dev backend for Linux CI so `tether-core` tests run here. *(→ A1; design from §2 #1)*
- **B2.** Noise IK**psk2** channel over plain TCP in `tether-core`: length-prefixed framing (`snow` does none — 2-byte big-endian prefix, chunk payloads >65 519 B), initiator=phone/responder=agent, PSK = `pairing_secret`. *(→ B1)* — **required test #2** (handshake + **tampered-byte rejection returns a clean logged error, never a panic** — CLAUDE.md rule 2)
- **B3.** iOS identity: P-256 in Secure Enclave (`SecureEnclave.P256.Signing`) + Curve25519 Noise static in Keychain, cross-signed. `snow` compiled to an XCFramework via UniFFI (small synchronous byte-in/byte-out surface, wrapped in a Swift actor). *(→ B1, B2; needs macOS — see §6)*

**Track C — tenant-scoped relay**
- **C1.** Drizzle schema: `accounts, devices(kind), pairings, pairing_tokens, push_tokens, quotas, audit_relay` — all `account_id`. `enableRLS` + policies as backstop; non-owner app role. *(→ A1; shape from §2 #9)*
- **C2.** `src/repo/` layer: every fn takes `accountId` first. ESLint flat-config rule (`no-restricted-imports` per-dir + `eslint-plugin-boundaries`) failing any raw `db.` outside `repo/`. *(→ C1)* — CLAUDE.md rule 12
- **C3.** The 8 route handlers (§2 #7): enroll (+ implicit account, + enrollment-secret gate + global per-IP rate limit from #11), pairing token issue/redeem (**atomic single-use, tenant-bound, `routing_id`-only** per #9), device list, unpair×2, WS attach×2. *(→ C2, A3)*
- **C4.** Cross-tenant test suite: two accounts, **programmatically enumerate every route**, assert **404** on foreign resources; report the count. *(→ C3)* — **required test #5**
- **C5.** `docker-compose.yml` + Caddy (`internal` CA) for the local dev relay. *(→ C3)*

**Track D — pairing end-to-end (integrates A/B/C)**
- **D1.** Agent `pair` subcommand: generate `pairing_secret`, register its **hash** with the relay, render QR (`{relay_url, account_id, device_id, agent_identity_pubkey, lan_hints, pairing_secret}`), listen on LAN. *(→ B2, C3)*
- **D2.** iOS pairing UI: scan QR (physical device only), redeem, run PSK-authenticated Noise handshake, learn+pin agent identity key & verify its cross-signed static; pin own side. *(→ B3, D1)*
- **D3.** Unpair both directions. **Enforcement point = the agent's local pin store, which is authoritative** (the relay is untrusted and is not even on the path for a LAN session). Agent unpair: remove the peer pin, close the Noise session, and (P1+) signal the helper to stop capture/input. Phone unpair: delete local pins, stop connecting, and send a **signed `pair.revoke` over the authenticated Noise channel** so the agent removes the pin; if unreachable, the operator removes it locally at the host (physical access — consistent with §6.1). Relay carries the revocation best-effort only, can neither forge nor suppress it. Every unpair is audited (#14). *(→ D1, D2)*
- **D4.** mDNS (`_tether._tcp`) advertise (agent) + browse (iOS) as the durable LAN discovery path. *(→ D1)*

**Track E — gate**
- **E1.** Wire the P0 gate evidence: ping/pong over LAN, key survival across restart, unpair blocks traffic, tampered-byte clean failure (as an **audit entry**, #14), cross-tenant count, lint green, `cargo clippy -D warnings` + `swiftlint`. **Plus the #15 malicious-relay harness**: a deliberately hostile relay build proving key-substitution, self-redemption, and token-replay all **fail closed**. Write `artifacts/gate-P0.md` per §15. *(→ all)*

**What CI can run here vs. what needs real hardware** (§6): the relay (C*), protocol codegen + round-trip (A3), and `tether-core` crypto/Noise tests (B1, B2) all run in **this Linux environment now** — verified. Windows agent code **type-checks** here via `cargo clippy --target x86_64-pc-windows-msvc` (verified). The iOS app build, Secure Enclave, camera/QR scan, and true DPAPI round-trips require **macOS + a physical iPhone + a Windows box** respectively.

---

## 4. The riskiest thing in P0, and how I'll de-risk it early

**The risk: the entire crypto/identity/pairing design (§2 #1 + #2) is where P0 either holds up or collapses, and it's the one part that, if wrong, fails silently** — a handshake that "works" in the happy path but MITMs under a hostile relay, or an SE/curve mismatch discovered only when the iOS handshake won't complete against the Rust peer. It is also the part the brief specified without a compiler in the loop, and it turned out to be literally non-implementable as written.

**How I'm de-risking it — already started, this session, before writing any P0 code:**

1. **I built the crypto happy-path as a throwaway and ran it.** `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` completes with caller-supplied X25519 statics + the QR-secret PSK, and Ed25519 cross-signs the X25519 static — **both tests pass** (`artifacts/P0-plan-evidence/`, reproducible). The design in §2 #1/#2 is proven runnable, not asserted.
2. **The adversarial pairing walk** (compromised relay redeems the token / swaps the pubkey) drove the PSK-from-QR fix *before* implementation, not at the gate.
3. **snow↔snow on both ends** removes the entire class of cross-implementation handshake bugs (transcript-hash divergence, nonce encoding, PSK ordering) that snow↔hand-rolled-Swift would introduce. One audited implementation, not two.
4. **The tampered-byte gate (line 364) is written as a test in B2 from the start**, not retrofitted — a malformed handshake byte must produce a logged error, never a panic (CLAUDE.md rule 2).
5. **The one residual unknown is snow-in-Swift interop over the real FFI**, which needs a Mac. I'll stand up the XCFramework + a Swift-side vector test against the Rust peer as the *first* iOS task (B3), so if UniFFI/Swift-6-concurrency friction is worse than the research suggests, it surfaces in week one — with manual C FFI over ~6 functions as the tested fallback.

Runner-up risk: **cross-tenant leakage** (§6.7 calls it the highest-severity bug class). De-risked structurally by C2's lint wall + C4's programmatic 404 suite, so a leak fails CI rather than shipping.

---

## 5. TODO(frank) items that actually block P0

- **#4 (bundle identifier)** — **genuinely blocks P0**, partially. The Xcode project is a P0 deliverable and the gate needs the app on a *physical* device (camera QR scan, Keychain, Secure Enclave), which needs a provisioning profile, which needs a registered bundle ID. The **APNs `.p8` half is P8, not P0.** I need the bundle ID (or explicit OK to use a placeholder like `com.<yourname>.tether` now and rename later — noting a rename invalidates Keychain access groups and forces re-pairing, so a placeholder is not free). *Everything non-iOS in P0 proceeds without it.*
- **#11 (single host vs. device list)** — **does not block P0.** The schema in §2 #9 (`devices.kind` + `pairings` join) supports N agents per account without prejudging the UI. It affects P1 UI shape only. No decision needed now.
- **#5 (relay domain + which VPS)** — does not block P0; P0 uses the local Docker relay. Needed at P5.
- **#9 (session indicator style)** — P6. Not P0.
- **#10 (file-browser denylist)** — P3. Not P0.

Net: **only #4's bundle-ID half is a real P0 blocker**, and only for the on-device iOS gate steps.

---

## 6. What I need from you before I start

1. **Bundle identifier** (TODO #4) — or approval to use a placeholder and rename later, accepting the re-pairing cost. *Blocks the on-device iOS gate; nothing else.*
2. **Approval of the three brief amendments in §2**, since they change locked/spec'd decisions and CLAUDE.md forbids reopening §14 silently:
   - **#1** — X25519 Noise statics cross-signed by the Ed25519/SE-P256 identity keys (the identity keys stay exactly as §4.1 mandates; this *adds* the DH statics the brief's own "Noise IK" requirement needs).
   - **#2** — a `pairing_secret` in the QR used as the Noise PSK, relay stores only its hash. This is what makes physical-access pairing a cryptographic guarantee against the hostile relay rather than a UX convention.
   - **#3/#4** — QR gains `lan_hints`; `messages.toml` gains a `pair.*` group + `error` type; "outbound only" clarified as WAN-scoped.
   - **#14/#15** — §6.4's audited-event list gains pairing-success/failure and unpair; the Gate P0 criteria gain a hostile-relay fail-closed test.
   None of these weaken §6.6; all strengthen it. I'll record each as a v1.1 amendment in the brief.
3. **Hardware/access reality check** — the P0 gate as written ("phone scans QR, pairs, ping/pong over LAN") needs, at minimum, **a physical iPhone**, **a Windows host**, and **a Mac** (to build the iOS app + the Rust XCFramework — required under either iOS approach). This planning container is Linux; it can build and fully test the relay, the protocol codegen, and the `tether-core` crypto/Noise layer, and can type-check the Windows agent — but it cannot run the end-to-end gate. **Tell me what hardware you actually have**, so I split P0 into "what I finish and prove here" versus "what needs you at the keyboard on real devices" honestly, rather than reporting a hollow pass.
4. **Two small decision-log calls** (§2 #12): keep Node 22 / Postgres 16 as pinned, or bump to Node 24 / PG 17? Either is fine; I'll implement your call.

---

*Stopping here for your response. On approval I'll build P0 against this breakdown and produce `artifacts/gate-P0.md` in the §15 format — reporting the split between what's proven in CI and what requires your hardware, with no green checkmark over anything I couldn't measure.*
