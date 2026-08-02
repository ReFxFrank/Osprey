# iOS build runbook — cloud Mac session

From "nothing built" to "Gate P0 criteria 1, 2 and 7 measured on the physical
iPhone."

**The Mac is metered; almost none of this work needs it.** The Rust static
libraries *and* the UniFFI Swift bindings already build on Linux and Windows —
`scripts/build-xcframework.sh` proves this and says so in its own header.

- **No Mac needed:** `cargo build --target aarch64-apple-ios` (and `-sim`,
  `x86_64-apple-ios`) — a Rust `staticlib` is assembled by `ar`, not linked, so
  no Apple SDK and no `xcrun` are involved; and
  `uniffi-bindgen generate --language swift`, which reads UniFFI metadata
  straight out of the `.a`.
- **Mac only:** `lipo -create`, `xcodebuild -create-xcframework`, the Swift
  compile, code signing, IPA export, and upload.

Do §0 before you start the Mac clock. §2 and §3 can also be done in advance.

---

## §0 Pre-flight — do this on Linux/Windows first

### 0.1 Where the XCFramework lives — resolved, no action needed

An earlier draft of this runbook flagged a mismatch between the XcodeGen spec and
the build script. It has been fixed; the paths below are the settled answer.

| Step | Location |
|---|---|
| `scripts/build-xcframework.sh` writes | `agent/target/xcframework/Osprey.xcframework` and `agent/target/xcframework/bindings/osprey_ffi.swift` |
| the build then stages into | `ios/Osprey/Frameworks/` |
| `ios/Osprey/project.yml` references | `Frameworks/Osprey.xcframework` and `Frameworks/osprey_ffi.swift` |

`ios/Osprey/Frameworks/` is gitignored — it holds build output, not source.
`.github/workflows/ios.yml` performs the staging copy.

Two things worth knowing, because both fail quietly rather than loudly:

- The binding is staged into `Frameworks/`, **not** `Osprey/Generated/`.
  `proto/generate.ts` deletes every `.swift` in the generated directory it did
  not itself emit, so a UniFFI binding parked there would vanish on the next
  `pnpm generate` and break the build for a reason that looks unrelated.
- `project.yml` marks the binding source `optional: true`, so if the staging step
  is skipped XcodeGen still produces a project — one with no Rust bindings
  compiled in, yielding a wall of `cannot find type 'NoiseHandshake' in scope`.
  If you see that, the staging copy did not run.

Sanity check before booting the Mac:

```bash
cd /path/to/Osprey
scripts/build-xcframework.sh --partial   # prints exactly what it produced
ls -R agent/target/xcframework
grep -n "Frameworks/" ios/Osprey/project.yml
```

### 0.2 Build the Linux half and keep the output

```bash
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
scripts/build-xcframework.sh --partial
```

`--partial` makes the Linux half exit 0 instead of failing on the missing
`lipo`. Keep the resulting `.a` files and `bindings/` — if you copy them to the
Mac you can skip installing Rust there entirely (see §4.2).

Optional but cheap: with a Linux Swift toolchain,
`SWIFTC=/path/to/swiftc scripts/typecheck-bindings-linux.sh` type-checks the
generated bindings against a consumer that walks the whole pairing sequence. It
cannot prove linking or anything about CryptoKit/Security, but it catches
Rust-signature drift before the Mac clock starts.

### 0.3 swiftlint configuration — settled

Gate P0 criterion 7 requires `swiftlint` clean, which is meaningless without a
defined rule set. `.swiftlint.yml` now exists at the repo root, so "clean" has a
fixed meaning and cannot be quietly redefined by adding a config later.

It runs SwiftLint's default rules over `ios/` only, with two exclusions that are
deliberate rather than convenient: `ios/Osprey/Osprey/Generated/` (emitted by
`proto/generate.ts` — lint findings there are bugs in the *generator*, to be
fixed in `proto/lib/emit-swift.ts`, and hand-editing generated files is forbidden
by CLAUDE.md) and `ios/Osprey/Frameworks/` (UniFFI output, not our source).

Run it with `swiftlint --strict` so warnings fail too; otherwise "clean" quietly
means "no errors, warnings ignored".

---

## §1 Check the Mac's macOS and Xcode versions — first command of the session

Discovering the image is too old after an hour of setup wastes the whole
session. Run these before anything else:

```bash
sw_vers                                     # macOS product version
xcodebuild -version                         # Xcode + build number
xcode-select -p                             # which Xcode is active
xcrun --show-sdk-version --sdk iphoneos     # the iOS SDK you will actually link against
ls /Applications | grep -i xcode            # some images ship several Xcodes
```

**What you need and why:**

- **Xcode 26 / the iOS 26 SDK.** Since **2026-04-28**, App Store and TestFlight
  submissions must be built with the iOS 26 SDK. An older Xcode can still build
  and sideload for local testing, but it cannot upload — so if TestFlight is in
  your plan for this session, Xcode 26 is not optional.
- **Xcode 26.0 requires macOS Sequoia 15.6 or newer.**
- **Xcode 26.4 and newer require macOS Tahoe 26.2 or newer.** A cloud image
  still on Sequoia therefore caps you at an Xcode 26.0–26.3 line.

If the image is too old, reprovision with a newer one — do not `softwareupdate`
your way there on the meter. Ask the provider for an Xcode-26-preinstalled image
when you book. If several Xcodes are installed, pin one first:

```bash
sudo xcode-select -s /Applications/Xcode-26.app
sudo xcodebuild -license accept        # a fresh image often has an unaccepted licence
xcodebuild -runFirstLaunch             # installs the bundled toolchains/simulators
```

**Also check the phone.** `project.yml` sets a deployment target of **iOS 17.0**,
so the iPhone must be on iOS 17 or later (Settings → General → About). It costs
nothing to check and it is the other version mismatch that ends a session.

### 1.1 Tools to install on the Mac

```bash
brew install xcodegen swiftlint
xcodegen --version
swiftlint --version
```

Only install Rust on the Mac if you are *not* copying the prebuilt `.a` files
across (§4.2):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
```

---

## §2 Register the App ID — ✅ DONE 2026-08-02

**Already complete. Skip to §3.** Recorded here because the outcome matters and
the failure is worth not repeating.

| | |
|---|---|
| Bundle ID | `com.ospreyremote.app` (Explicit) |
| Description | Osprey Remote Manager |
| Team ID | `FM8Z8BA64H` — this is the `APPLE_TEAM_ID` CI secret |
| Capabilities | none enabled, which is correct for P0 |

**`com.osprey.app` was tried first and rejected as unavailable.** "Osprey" is a
common trade name, and a wildcard App ID of the form `com.osprey.*` blocks every
explicit identifier beneath it — so no `com.osprey.<anything>` variant would have
worked. Do not retry that prefix.

Doing this before any signing configuration existed is what made the collision
cheap. Per amendment A21, changing the bundle id after first pairing
**invalidates Keychain access groups and forces every paired device to
re-pair** — the identity key, the Noise static and the host pin all live in the
keychain under that identity.

The iPhone is also **registered under Devices** (done 2026-08-02), so the portal
side is complete. With an App ID and a registered device in place, Xcode's
automatic signing can mint the development certificate and provisioning profile
for you on the Mac — §3's manual certificate route is optional and only worth it
if you want signing artifacts that do not depend on the Mac.

Xcode's automatic signing *can* mint an App ID for you on first build. It was
done by hand anyway, because automatic creation surfaces a name collision as an
opaque signing error at the worst possible moment — and as it turned out, there
was a collision.

---

## §3 Certificates without a Mac (optional)

You do not need this. Xcode's automatic signing will mint an Apple Development
certificate on the Mac in about thirty seconds.

It becomes worth doing when the Mac is **ephemeral**: a certificate Xcode
creates on a cloud Mac has its private key in that VM's keychain, and the key
dies with the VM. Apple caps how many active certificates an account may hold,
so burning a fresh one per session eventually wedges you. Generating the key
yourself means you own the `.p12` forever and every future Mac just imports it.

### 3.1 Generate the key and CSR (Windows/Linux, no Apple tooling)

```bash
# 2048-bit RSA is what Apple's portal accepts for signing certificates.
openssl genrsa -out osprey-dev.key 2048

openssl req -new -key osprey-dev.key -out osprey-dev.csr \
  -subj "/emailAddress=you@example.com/CN=Osprey Development/C=US"
```

Keep `osprey-dev.key` somewhere durable and private — it cannot be regenerated.

### 3.2 Upload the CSR

Portal → **Certificates** → **+** → **Apple Development** → upload
`osprey-dev.csr` → download the issued `development.cer` (DER-encoded).

### 3.3 Convert to a `.p12` the Mac can import

```bash
openssl x509 -in development.cer -inform DER -out development.pem -outform PEM

openssl pkcs12 -legacy -export \
  -inkey osprey-dev.key \
  -in development.pem \
  -out osprey-dev.p12 \
  -name "Osprey Development"
```

> **`-legacy` is mandatory on OpenSSL 3.x.** OpenSSL 3 defaults the PKCS#12
> encryption to modern AES-256-CBC/PBKDF2 ciphers. Apple's Security framework
> does not read that container — and the failure is quiet and confusing:
> `openssl pkcs12 -info` parses the file perfectly, then Keychain Access or
> `security import` rejects it with a generic error, or appears to succeed while
> `codesign` cannot find the identity. `-legacy` loads the legacy provider and
> writes the older RC2/3DES container Apple expects. Check with
> `openssl version` — if it prints `OpenSSL 3.x`, you need the flag.

### 3.4 Import on the Mac

```bash
security import osprey-dev.p12 \
  -k ~/Library/Keychains/login.keychain-db \
  -P '<the p12 password>' \
  -T /usr/bin/codesign
security find-identity -v -p codesigning     # the identity must appear here
```

### 3.5 Full automation: the App Store Connect API

For a hands-off pipeline the same certificate can be issued over HTTP:
`POST https://api.appstoreconnect.apple.com/v1/certificates` with a body of
`{"data":{"type":"certificates","attributes":{"certificateType":"DEVELOPMENT","csrContent":"<PEM body of osprey-dev.csr>"}}}`.
Authentication is a short-lived ES256 JWT signed with an App Store Connect API
key (`.p8`), sent as `Authorization: Bearer <jwt>`; the response carries the
certificate as base64 DER in `attributes.certificateContent`. The same API
manages `/v1/devices`, `/v1/bundleIds` and `/v1/profiles`, so device
registration and profile issuance can be scripted end to end.

**Not verified here** — there is no Apple account or network path to Apple in
this environment. Check the field names against the current App Store Connect
API reference before scripting against them.

---

## §4 Build

### 4.1 Get the source onto the Mac

```bash
git clone <your remote> Osprey
cd Osprey
```

### 4.2 Produce the XCFramework

**If Rust is installed on the Mac**, one command does everything:

```bash
scripts/build-xcframework.sh
```

It rebuilds steps 1–3 (device slice, simulator slices, bindings) and then runs
the two Mac-only steps, printing the paths it produced.

**If you copied the Linux output across instead**, the two remaining steps are
exactly what the script does, and you can run them by hand. Adjust the paths to
match whatever §0.1 settled on:

```bash
OUT=agent/target/xcframework

lipo -create \
  agent/target/aarch64-apple-ios-sim/release/libosprey_ffi.a \
  agent/target/x86_64-apple-ios/release/libosprey_ffi.a \
  -output "$OUT/ios-arm64-simulator/libosprey_ffi.a"
lipo -info "$OUT/ios-arm64-simulator/libosprey_ffi.a"

xcodebuild -create-xcframework \
  -library "$OUT/ios-arm64/libosprey_ffi.a"           -headers "$OUT/headers" \
  -library "$OUT/ios-arm64-simulator/libosprey_ffi.a" -headers "$OUT/headers" \
  -output  "$OUT/Osprey.xcframework"
```

The device slice and the simulator slice must be separate `-library` arguments.
Fusing an `ios-arm64` device slice into the same fat archive as an
`ios-arm64-simulator` slice is rejected by `xcodebuild -create-xcframework`
(same architecture, different platform), and is the most common way this step
fails.

### 4.3 Generate the Xcode project

```bash
cd ios/Osprey
xcodegen generate
```

This writes `ios/Osprey/Osprey.xcodeproj`. It is generated output — do not edit
it in Xcode expecting the change to survive, and do not commit it. `project.yml`
is the source of truth.

Immediately sanity-check that the bindings actually made it in:

```bash
grep -c osprey_ffi.swift Osprey.xcodeproj/project.pbxproj
```

Zero means §0.1 is still unresolved and the build is about to fail in the
confusing way. Fix it before compiling.

### 4.4 First compile — the Simulator, because it is fast and free

Do this before touching signing. It separates "does the Swift compile and link
against the Rust core" from "is signing configured" — two entirely different
debugging sessions.

```bash
xcrun simctl list devices available          # pick a real device name from this output
cd /path/to/Osprey
xcodebuild -project ios/Osprey/Osprey.xcodeproj -scheme Osprey \
  -destination 'platform=iOS Simulator,name=<name from the list>' build
xcodebuild -project ios/Osprey/Osprey.xcodeproj -scheme Osprey \
  -destination 'platform=iOS Simulator,name=<name from the list>' test
```

`OspreyTests` is written against test doubles (`OspreyTests/TestDoubles.swift`)
rather than live hardware, so it should run here — but **whether every test
passes in the Simulator has never been observed**, on any machine. Treat a
failure as new information, not as a broken runbook.

The Simulator cannot satisfy gate criteria 1 or 2. See §6.

### 4.5 Device build and archive

```bash
cd /path/to/Osprey
xcodebuild \
  -project ios/Osprey/Osprey.xcodeproj \
  -scheme Osprey \
  -configuration Release \
  -destination 'generic/platform=iOS' \
  -archivePath build/Osprey.xcarchive \
  -allowProvisioningUpdates \
  archive
```

`-allowProvisioningUpdates` lets Xcode create/refresh the provisioning profile,
which is what `CODE_SIGN_STYLE: Automatic` in `project.yml` expects. It requires
the Mac to be signed in to your Apple ID (Xcode → Settings → Accounts), **or**
App Store Connect API credentials supplied on the command line:

```bash
  -authenticationKeyPath /path/to/AuthKey_XXXXXXXXXX.p8 \
  -authenticationKeyID XXXXXXXXXX \
  -authenticationKeyIssuerID xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

Then export an IPA. Write an `ExportOptions.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>method</key>
  <string>development</string>
  <key>teamID</key>
  <string>YOURTEAMID</string>
  <key>signingStyle</key>
  <string>automatic</string>
</dict>
</plist>
```

```bash
xcodebuild -exportArchive \
  -archivePath build/Osprey.xcarchive \
  -exportOptionsPlist ExportOptions.plist \
  -exportPath build/ipa \
  -allowProvisioningUpdates
```

> **On the `method` value.** Recent Xcode renamed the export methods:
> `development` → `debugging`, `ad-hoc` → `release-testing`, `app-store` →
> `app-store-connect`. The older names have been accepted as aliases, but I
> cannot verify which spellings Xcode 26 still takes. If the export fails
> complaining about the method, try the other name — the error message from
> `xcodebuild -help` / the failure itself lists the values that version accepts.
> Do not guess a third spelling.

---

## §5 Getting the build onto the iPhone

### Why there is no cable

The iPhone is physically beside the Windows PC. The Mac is in a datacentre.
**Cloud Mac providers do not offer USB device passthrough**, so Xcode's "Run on
device" — which is a USB operation — is unavailable. Xcode's wireless device
pairing does not rescue this either: it requires the Mac and the iPhone to be on
the same local network, and a rented Mac is not on your LAN.

So the artifact travels: Mac → your Windows PC (or TestFlight) → phone.

### 5.1 Path A — development IPA + Sideloadly over USB (use this for the pairing loop)

**Seconds per install once set up.** This is what you want while iterating on
criterion 1, because a failed pairing attempt should cost a minute, not half an
hour.

Prerequisites:

1. **Register the phone's UDID** in the portal (§2). To read the UDID from
   Windows: install the **Apple Devices** app (or iTunes), connect the iPhone,
   open the device page, and click the serial number field until it cycles to
   the UDID; copy it.
2. The development provisioning profile must include that device. If you
   registered the device *before* the archive in §4.5, `-allowProvisioningUpdates`
   will have picked it up. If you registered it after, re-archive.

Then:

1. Download `build/ipa/Osprey.ipa` from the Mac to Windows — `scp`, the
   provider's file browser, or any file-drop the provider gives you.
2. Install **Sideloadly** on Windows (it requires the Apple Devices/iTunes
   drivers to talk to the phone).
3. Connect the iPhone over USB, drop the IPA into Sideloadly, install.
4. On the phone: **Settings → General → VPN & Device Management** → trust the
   developer certificate. Required on first install of a given signing identity.

With a **paid** Apple Developer Program membership the signature is good for a
**year**, so you install once and iterate. (A free Apple ID gives 7 days and a
3-app limit — that is the constraint you are paying to avoid.)

### 5.2 Path B — TestFlight (use this for release candidates)

Add `<key>destination</key><string>upload</string>` to `ExportOptions.plist`
with `method` set to the App Store method, and `xcodebuild -exportArchive` will
upload the build to App Store Connect directly rather than writing an IPA. Apple
also ships the **Transporter** app and the `xcrun altool` / `iTMSTransporter`
command-line uploaders; *which of those remains supported under Xcode 26 is
something I could not verify here*, so prefer the `-exportArchive` upload path
and fall back only if it errors.

Trade-offs, and why this is not the iteration loop:

- **Internal testers require no App Review.** Up to 100, each of whom must be a
  user on your App Store Connect team. This is what makes TestFlight usable at
  all for a private tool.
- **Processing takes roughly 10–30 minutes** after upload before the build is
  installable. That is the killer for a debug loop.
- **Builds expire after 90 days.**
- Every upload needs a **unique `CFBundleVersion`**, currently hardcoded to `1`
  in both `Info.plist` and `project.yml`. Bump it before the second upload.
- Export compliance is already answered: `ITSAppUsesNonExemptEncryption` is
  `false` in `Info.plist`, so the encryption question is not asked per upload.

---

## §6 Closing the open Gate P0 criteria

Gate P0 is currently **FAIL**. Three half-criteria are open, all of them iOS.
This is the exact action that closes each.

> **The Simulator cannot satisfy criterion 1 or criterion 2.** It has no camera,
> so there is nothing to scan a QR code with; and Apple DTS states the Simulator
> "acts like an iOS device that has no SE", so `SecureEnclave.P256.Signing.PrivateKey`
> — which `DeviceIdentity` is built on — cannot be created there at all. Both
> criteria require the physical iPhone. This is recorded as amendment A19.

### Criterion 1 — "Phone scans QR, pairs, exchanges an authenticated encrypted `ping`/`pong` over the local network."

Put the iPhone and the Windows PC on the **same Wi-Fi network**. The relay is not
involved; `--lan-only` skips it entirely, and the iOS `QRPayload` decoder
explicitly accepts the empty `relay_url` / `account_id` that a LAN-only QR
carries.

1. On the Windows PC, in the repo:

   ```powershell
   cargo run -p osprey-svc -- pair --lan-only
   ```

   It renders the QR as Unicode half-blocks, lists the addresses it is listening
   on (default port **47010**), and prints the **host identity fingerprint**. The
   pairing window is **120 seconds** by default; `--ttl <SECONDS>` widens it, and
   a fumbled scan does not close the window — only success or expiry does.

2. On the iPhone, launch Osprey and scan. Grant the camera prompt **and** the
   local-network prompt; iOS raises the second one on any connection to a private
   address, and denying it makes the TCP connect silently never become ready.

3. When pairing completes, the host prints the newly pinned **controller
   fingerprint** and tells you to compare it against the one the phone is
   showing. **Compare them.** A mismatch means you have just pinned something you
   did not intend, and `osprey-svc unpair <fingerprint-prefix>` undoes it.

4. Leave `pair` and start the session server, then exercise ping/pong from the
   app:

   ```powershell
   cargo run -p osprey-svc -- run
   ```

**Evidence for the gate report:** host console output showing the pinned
fingerprint, the phone's screen showing the same fingerprint, the `ping`/`pong`
round trip in the app, and the `pairing_succeeded` line from
`%ProgramData%\Osprey\audit\<UTC-date>.jsonl`.

### Criterion 2, app half — "Keys survive … app restart."

The agent half already passes. For the app half, on the physical iPhone, after
pairing:

1. Note the phone's own identity fingerprint and the paired-host record shown in
   the UI.
2. **Force-quit** the app from the app switcher — swipe it away. Do not merely
   background it, and do **not** delete and reinstall (that is a different, much
   stronger claim, and deleting an app can clear its keychain items).
3. Relaunch. The app must show the **same** device fingerprint and the **same**
   paired host, and must be able to open a session without re-pairing.

This exercises `DeviceIdentityStore.loadOrCreate` reloading the Secure Enclave
key blob, the X25519 Noise scalar and the device id from the keychain under
service `com.ospreyremote.app.identity`, plus `PinStore` reloading the host pin.
**Evidence:** the fingerprint before and after, plus a successful post-restart
session.

### Criterion 7, swiftlint half — "`cargo clippy -- -D warnings` and `swiftlint` clean."

clippy already passes on both the host and `x86_64-pc-windows-msvc`. On the Mac:

```bash
cd /path/to/Osprey
swiftlint --strict          # non-zero exit on warnings as well as errors
```

Record the exit code and the violation count. See §0.3 — there is no
`.swiftlint.yml`, so this measures against swiftlint's defaults, and the report
should say so rather than implying a curated rule set.

### Everything else

Criterion 2's agent half, criteria 3–6 and the A17 hostile-relay criterion are
already **PASS**, measured on Linux. Nothing on the Mac changes them.

---

## §7 Troubleshooting the first compile

Ordered by how likely you are to hit it.

**`cannot find type 'NoiseHandshake' / 'ScannedQr' / 'PeerIdentity' in scope`**
(hundreds of them) — the UniFFI-generated `osprey_ffi.swift` was not added to the
target. It is `optional: true` in `project.yml`, so a wrong path fails silently.
See §0.1; confirm with
`grep -c osprey_ffi.swift ios/Osprey/Osprey.xcodeproj/project.pbxproj`.

**`framework not found OspreyFFI`** — same root cause, the XCFramework half.
Check the name too: the script writes `Osprey.xcframework`, the spec asks for
`OspreyFFI.xcframework`.

**`building for iOS Simulator, but linking in object file built for iOS`** — the
XCFramework is missing its simulator slice, or the device and simulator slices
were fused into one archive. Rebuild per §4.2 with separate `-library`
arguments.

**Missing x86_64 simulator slice** — the build script warns rather than failing
when `x86_64-apple-ios` is not installed. Harmless on an Apple Silicon Mac;
breaks the Simulator on an Intel Mac. `rustup target add x86_64-apple-ios`.

**Swift 6 strict-concurrency errors inside the generated bindings** —
`project.yml` sets `SWIFT_STRICT_CONCURRENCY: complete` and compiles the
generated file into the app module, so UniFFI's output is held to the same bar
as hand-written code. If this bites, the fix belongs on the Rust/UniFFI side or
in the generated file's isolation annotations; do **not** relax
`SWIFT_STRICT_CONCURRENCY` for the whole app to make it go away.

**`No profiles for 'com.ospreyremote.app' were found`** — the App ID is not registered
(§2), or the Apple ID on the Mac is not on the team, or you archived without
`-allowProvisioningUpdates`.

**App installs but will not launch, or dies instantly** — the device UDID is not
in the provisioning profile (register it, then re-archive), or the developer
certificate has not been trusted on the phone (§5.1 step 4).

**App crashes the instant the scanner opens** — a missing
`NSCameraUsageDescription`. It is present in `Info.plist` today; the failure
mode appears if the plist is ever regenerated by Xcode instead of used from the
file, which `GENERATE_INFOPLIST_FILE: NO` in `project.yml` prevents.

**Pairing hangs with no error; the phone never connects** — the local-network
permission was denied, or `NSLocalNetworkUsageDescription` /
`NSBonjourServices` are missing. iOS gives you no error for this; the connection
simply never becomes ready. Also check Windows Firewall is allowing inbound TCP
47010 on the **Private** profile.

**Miscellaneous** — `xcodegen: command not found` → `brew install xcodegen`.
`xcodebuild` prompting about a licence → `sudo xcodebuild -license accept` then
`xcodebuild -runFirstLaunch`. "Requires a newer version of iOS" on install → the
phone is below the iOS 17.0 deployment target. Second TestFlight upload rejected
→ duplicate `CFBundleVersion`, hardcoded to `1` (§5.2).
