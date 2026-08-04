# P1 evidence — iOS device list and live metrics dashboard

Measured on the physical iPhone against the Windows service on `FRANKSPC`,
2026-08-04 (UTC), at commit `be4c396`. Amendment A23 (device list) and A24
(`hello.ok.display_name`) in the client.

## Build and verification on the cloud Mac

| Step | Result |
|---|---|
| First Apple-SDK compile of the P1 iOS work | **1 error** across ~900 lines written on Windows |
| XCTest suite | **46 passed, 0 failed** |
| `swiftlint --strict` | **0 violations** in 47 files, after fixing the 4 it found |
| Release archive + development IPA | succeeded; installed by Sideloadly over USB |

The single compile error was `ByteCountFormatter` as a shared `static let` —
a mutable class, so not concurrency-safe under Swift 6. Replaced with the
`ByteCountFormatStyle` value type.

## Device list

- Opens to the list (A23), showing the machine migrated from P0's single-record
  pin store. Fingerprint `6abe-43ab-fd2d-4a50`, unchanged across the migration —
  **no re-pairing was required**, which is the property the migration exists to
  preserve, since re-pairing needs physical access to the host.
- Before the first connection the row is labelled by fingerprint; after
  `hello.ok` it is labelled `FRANKSPC`.

## Dashboard, connected

Read off the device:

| Field | Value |
|---|---|
| Title | `FRANKSPC` — the machine name over the wire, **amendment A24 working** |
| Host build | `0.1.0` |
| Processor | live chart, `10%` current |
| Memory | live chart, `21.55 GB` in use of `63.59 GB` installed |
| Network | Down `1.5 MB/s`, Up `510 kB/s` |
| Storage | `C:` 752.33 GB of 1.82 TB · `D:` 713.21 GB of 930.64 GB · `E:` 826.43 GB of 931.5 GB |
| Fingerprint | `6abe-43ab-fd2d-4a50`, matching the pin |

The charts populate from the ring-buffer backfill and then append live at 1 Hz
from pushed `metrics.tick` frames.

### The network figure is the LWF fix, confirmed on real hardware

`Down 1.5 MB/s / Up 510 kB/s` are plausible rates for what the machine was
doing. Before the fix, `GetIfTable2`'s per-filter-driver pseudo-interfaces were
summed alongside the real adapter and throughput read **4.000× reality** —
this machine would have reported roughly 6 MB/s down for the same traffic,
above what the adapter was actually carrying. Unit tests pin the signature; this
is the end-to-end confirmation.

## A defect this run found, and the log that proved it

The session dropped 10–15 s after connecting. The host log settled it without
guesswork:

```
01:14:45 session established peer_addr=192.168.1.159:53106
01:14:50 peer ended the session reason=normal detail=None
01:14:50 session closed ... pings_answered=0 end=PeerSaidBye
01:15:07 session established peer_addr=192.168.1.159:53109
01:15:21 peer ended the session reason=normal detail=None
01:15:21 session closed ... pings_answered=1 end=PeerSaidBye
```

`PeerSaidBye` — the *phone* was hanging up cleanly, so this was never a network
or agent fault. `refreshAfterForeground` tore the session down unconditionally
whenever `scenePhase` returned to `.active`, and iOS reports that for
notification banners, Control Centre and the screenshot UI, not only for a real
return from suspension.

Fixed by probing with a ping and redialling only when that fails. A second
defect was sitting behind it: a failed ping called `disconnect()`, which cleared
the operator's intent to stay connected — so once a session *did* legitimately
die, the foreground refresh would never have brought it back. That one would
have been considerably harder to find later.

Confirmed by the operator after the fix: the connection holds.

## Not measured here

- **Live graphs over LTE**, the P1 gate's actual wording. This was LAN. The
  phone cannot yet reach the agent from outside the network, because
  relay-borne sessions are not served — the supervisor holds the relay link but
  does not yet feed frames into a Noise session. That plus the VPS deploy is
  what the LTE criterion needs.
- **Idle CPU and RSS** under an active subscription — a separate P1 criterion,
  deferred until the agent is feature-complete enough for the figure to mean
  something.
- **Foreground reconnect after a genuine suspension.** The fix was verified by
  the session no longer dropping; a real background-then-resume cycle with a
  dead socket has not been exercised.
