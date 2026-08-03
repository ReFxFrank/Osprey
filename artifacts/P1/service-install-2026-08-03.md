# P1 evidence — Windows service registration and lifecycle

Measured 2026-08-03 on the target machine, from an elevated PowerShell.
Binary under test: `agent/target/debug/osprey-svc.exe` at commit `0c2dec3`.

## Registration

```
> osprey-svc.exe install
Osprey is installed and will start automatically at boot.

> Get-Service Osprey
Name      : Osprey
Status    : Running
StartType : Automatic

> Get-CimInstance Win32_Service -Filter "Name='Osprey'"
ProcessId : 26492
PathName  : ...\osprey-svc.exe service --port 47010
StartName : LocalSystem
```

`StartName: LocalSystem` is the load-bearing one: the service holds no desktop
and runs in Session 0, per brief §9.1.

## Listener

All five bound addresses are private or loopback — the WAN-facing surface is
still nil, as amendment A7 requires:

```
fe80::ef3b:db9a:9aba:7d27%45:47010   pid=26492 (osprey-svc)
::1:47010
192.168.240.1:47010
192.168.1.204:47010
127.0.0.1:47010
```

## Data directory ACL

```
> (Get-Acl C:\ProgramData\Osprey).Sddl
O:BAG:S-1-5-21-...-1002D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)
```

`D:P` — inheritance severed. Exactly two allow entries, `SY` (SYSTEM) and `BA`
(Builtin Administrators), both `FA` (full access) with `OICI` (object and
container inherit). This is the boundary the keystore's own docs identify as the
real protection for sealed keys, since machine-scoped DPAPI is readable by any
local process.

## Firewall rule

```
DisplayName : Osprey LAN listener
Enabled     : True
Profile     : Private
Direction   : Inbound
Action      : Allow
```

**First execution of the COM write path.** API verification deliberately
exercised only `INetFwPolicy2` reads, so `INetFwRules::Add` was unmeasured until
this run. It works, and the rule is scoped to the Private profile alone.

## Auto-restart after an uncommanded kill

```
> Stop-Process -Id 26492 -Force ; sleep 6
KILL TEST: before=26492 after=23312 status=Running
```

A different process id with the service back in `Running` — the SCM applied the
first recovery action (1 s delay) registered by `update_failure_actions`.

## Graceful stop and start

```
> Restart-Service Osprey
GRACEFUL: status=Running
```

## Service log

`C:\ProgramData\Osprey\logs\osprey-svc.log`, verbatim:

```
2026-08-03T03:06:15Z INFO ...windows_impl: the Osprey service is running port=47010
2026-08-03T03:06:15Z INFO ...discovery: advertising on the LAN service=osprey-7c611dfcfe50._osprey._tcp.local. addresses=3
2026-08-03T03:06:32Z INFO ...commands::run: session established peer_addr=192.168.1.159:54285 fingerprint=18f9-b86c-b21d-0d87
2026-08-03T03:08:08Z INFO ...windows_impl: the Osprey service is running port=47010
2026-08-03T03:08:08Z INFO ...discovery: advertising on the LAN service=osprey-7c611dfcfe50._osprey._tcp.local. addresses=3
2026-08-03T03:08:13Z INFO ...windows_impl: the Osprey service is running port=47010
2026-08-03T03:08:13Z INFO ...discovery: advertising on the LAN service=osprey-7c611dfcfe50._osprey._tcp.local. addresses=3
```

Three clean startups across the kill and the graceful restart, no panic and no
repeated error line.

## The result that was not asked for

`session established peer_addr=192.168.1.159 fingerprint=18f9-b86c-b21d-0d87` is
the **physical iPhone**, holding the pin created at the P0 gate, completing a
`Noise_IK` session against the *service* rather than against a console process.

That is amendment A12 paying off exactly as predicted. The identity key was
generated and DPAPI-sealed by the P0 console agent running as the interactive
user; it was unsealed here by a LocalSystem service. Had the default per-user
DPAPI scope been used, this handoff would have silently stranded the device
identity and forced every paired device to re-pair at the P0→P1 boundary.

## Not measured here

- **Start on boot.** `StartType: Automatic` is registered, but no reboot has
  been performed; the P1 gate wants an actual boot.
- **Relay reconnect after a network drop.** No relay connection exists yet —
  that is P1 task 5.
- **Live 1 Hz graphs.** The metrics engine runs inside this service, but no
  client consumes it until the iOS dashboard lands.
- **Idle CPU and RSS.** A P1 gate criterion, deferred until the agent is
  feature-complete enough for the number to mean anything.
