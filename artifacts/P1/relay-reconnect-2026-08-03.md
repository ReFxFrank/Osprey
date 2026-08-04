# P1 evidence — relay reconnect after a network drop

Gate criterion: *"Service installs, starts on boot, reconnects to the relay
after a network drop without intervention."* This file covers the reconnect
half; registration and auto-restart are in `service-install-2026-08-03.md`.

Measured 2026-08-03 against a local relay (Node 24, Postgres 16 in Docker on
5433) at commit `1ace94a`.

## Reproduce

```powershell
docker start osprey-test-pg
powershell -ExecutionPolicy Bypass -File scripts/dev-relay.ps1 -Action start

cd agent
$env:OSPREY_TEST_RELAY_URL='http://127.0.0.1:8099'
$env:OSPREY_TEST_ENROLLMENT_SECRET='test-enrollment-secret-0123456789abcdef'
$env:OSPREY_TEST_RELAY_RESTART='powershell -ExecutionPolicy Bypass -File <repo>\scripts\dev-relay.ps1 -Action restart'
cargo test -p osprey-svc --test relay_reconnect -- --ignored --nocapture
```

## Result

```
attached to http://127.0.0.1:8099 (attachments=1)
restart command exited Some(0):
reattached without intervention (attachments=2)
test the_agent_reattaches_after_the_relay_goes_away ... ok
test result: ok. 1 passed; 0 failed; finished in 7.10s
```

The agent enrolled, attached, kept the link up, noticed the relay had gone,
and came back on its own — **7.1 s end to end**, with the reattachment driven
only by the supervisor's own backoff.

## What the numbers mean

`attachments` counts links established since start, which is what separates
"never dropped" from "dropped and recovered". Going 1 → 2 with no call into the
agent between them is the criterion.

Detecting the drop is the part that could have silently failed: the relay has
**no server-side heartbeat and never probes**, so a half-open socket after a
network drop is invisible to it and would sit in its hub until TCP gave up. The
agent's own `{"t":"ping"}` keepalive is what notices, and this run exercises it.

## A false pass avoided

The first attempt at this measurement used a "restart" command that only
*killed* the relay. The agent correctly never reattached — there was nothing to
attach to — and the test failed. Reported here because the fix was to the
harness, not the agent, and a stop-only command would have been an easy way to
make this criterion look measured while proving nothing.

## Not covered here

- **A real network drop** (interface down, cable out) rather than the relay
  process going away. Both present as a dead socket to the agent, but only the
  process case is automated.
- **Reconnect against the VPS relay over the internet.** Local loopback has no
  DNS, TLS handshake or NAT rebinding in the path.
- **Sessions carried over the relay.** The supervisor holds the link and logs
  relayed frames; feeding them into a Noise session is the next increment and is
  what the LTE criterion needs.
