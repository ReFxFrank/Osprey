# Gate P0 — physical-device evidence, 2026-08-03 (UTC)

Criteria 1 and 2 (app half), measured on the physical iPhone against the agent
on the Windows host, both on the same LAN. App build: development IPA exported
from the 2026-08-02 cloud-Mac session (commit `13015ce` plus comment-only
`5f2f569` divergence; style-only diff from the archived commit).

## Timeline (host clock, UTC)

| Time | Event |
|---|---|
| 00:52:54 | `pairing_succeeded` — QR scanned by the phone, PSK handshake completed, controller pinned |
| ~00:54 | App force-quit from the app switcher and relaunched; same device fingerprint and paired host shown — **criterion 2 app half** |
| 00:56:32 | `session established peer_addr=192.168.1.159:53858 fingerprint=18f9-b86c-b21d-0d87` — post-relaunch session, no re-pairing |
| 00:56:52 | Session ended (operator disconnect); logged as a read error — see discovered problem 14 |

## Audit log line (verbatim from `C:\ProgramData\Osprey\audit\2026-08-03.jsonl`)

```json
{"ts":"2026-08-03T00:52:54.1359477Z","event":"pairing_succeeded","account_id":"lan-only","device_id":"7c611dfc-fe50-41ed-8d0a-5fd81d77b55c","peer_fingerprint":"18f9b86cb21d0d8719d5d0072934611afc1db0fb71f5e37dfc0de76262f31d2d","peer_noise_static":"6d246c002af0267e677481f056048d1c3eb7e3642adb6709e8c45f969e75fe29"}
```

## Host `run` console (verbatim, ANSI stripped)

```
2026-08-03T00:54:25 INFO osprey_svc::discovery: advertising on the LAN service=osprey-7c611dfcfe50._osprey._tcp.local. addresses=3
Osprey agent listening for paired controllers on:
  192.168.1.204:47010
  192.168.240.1:47010
  [fe80::ef3b:db9a:9aba:7d27%45]:47010
  127.0.0.1:47010
  [::1]:47010
1 controller(s) pinned.
2026-08-03T00:56:32 INFO osprey_svc::commands::run: session established peer_addr=192.168.1.159:53858 fingerprint=18f9-b86c-b21d-0d87
2026-08-03T00:56:52 WARN osprey_svc::commands::run: session ended with an error peer_addr=192.168.1.159:53858 error=could not read from the noise session
```

## App session view (operator's screenshot, transcribed)

- Session `862B5467-28BD-4643-8F85-B45A4C1C5B62`
- Host build `0.1.0`
- **Last round trip: 14 ms** (encrypted ping over LAN)
- Pings sent: 2
- Addresses from the pairing code list the host's `lan_hints` verbatim

## Operator confirmations

- The controller fingerprint printed by the host at pairing matched the one
  displayed in the app (`18f9b86c…`).
- After force-quit and relaunch, the app showed the same device fingerprint and
  the same paired host, and opened the session above without re-scanning.

## Fixed environment prerequisites observed on the way

- iOS Developer Mode had to be enabled (Settings → Privacy & Security) for the
  development-signed install — expected, documented here for repeatability.
- The network profile on the Windows host had to be flipped from Public to
  Private for the A7 firewall posture.
