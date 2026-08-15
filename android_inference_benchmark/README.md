# VisionForge Mobile

VisionForge Mobile is the Android half of the two-machine local inference path.
It is not a remote-control client for the Windows host.

The product UI uses native Android Views so state remains accessible and adapts
to the physical screen. The header keeps the logo, product name and settings
action on one horizontal line, including narrow phones and enlarged font scales.

The application shell has three persistent destinations: Card, Inference and
Control. Link health and inference telemetry share the Inference destination;
the top-right settings action directly exports the single append-only redacted
runtime log. Screens consume one immutable `MobileUiState`
and return user intent through `MobileAppActions`; they never parse JNI reports
or own QNN, decoder or USB objects directly. There is no manual inference
start/stop action: verified Host video automatically opens formal usage, and
Host loss closes billing and rearms the application.

Formal start and lifecycle stop are race-safe. Before the potentially billed
start request is sent, the app creates one immutable, dual-signed cancellation
for that exact start ID. A stop closes the local video/inference/control gate
first, then retries the same cancellation until the server confirms a terminal
result. Delayed executor work is generation-bound, so an old cancellation can
never close or cancel a later Host generation. Any response-validation or
installation failure after start dispatch remains in STOPPING and retains the
exact cancellation; it cannot fall back to idle or create a second session.

## Responsibility boundary

```text
Windows Host: DXGI capture -> NVENC H.264 -> UDP video
Android:      UDP reassembly -> MediaCodec -> inference router (QNN HTP / NNAPI / CPU)
              -> post-process -> USB MAKCU
```

The Windows host never receives, interprets, or sends mouse/keyboard control.
Control, when hardware is connected, originates on Android and is sent only to
the authorised MAKCU USB device.

## Production transport

- The foreground service automatically prefers the dedicated CAT6 link. Its
  fixed contract remains `eth0`, Android `10.57.23.2/24`, Host
  `10.57.23.1/24`, with video on UDP `5000`.
- When the CAT6 contract is unavailable, the service automatically selects a
  usable Wi-Fi LAN network. It announces readiness to multicast group
  `239.57.23.57:5003`; the Host route-selects its LAN address, sends two real
  fixed-size probes to the phone on UDP `5004`, and the phone records the
  validated probe requester as the unicast Host endpoint. There is no manual
  interface picker or address entry.
- Both paths use the same bounded UDP data plane: video `5000`, IDR recovery
  `5001`, probe acknowledgement `5004`, and mouse-button observation `5005`.
  `VF_CAT6_READY_V1` remains the versioned readiness wire message for backward
  compatibility; runtime state identifies the selected path as `cat6` or
  `wireless_lan_udp`.
- The host sends each newly available captured frame without a software FPS
  scheduler. Android keeps compressed H.264 access units in a four-slot ordered
  handoff because predictive frames cannot safely replace their references; on
  overflow it rejects the newest unit, requests IDR recovery, and rejects later
  predictive units until an IDR is actually admitted. After decode,
  the inference stage remains latest-frame-first and supersedes obsolete frames
  instead of creating an unbounded latency queue.

## Build

The repository includes the Gradle Wrapper. Set the QNN SDK root and build the
release APK from this directory:

```powershell
$env:QNN_SDK_ROOT = "$PWD\qnn_sdk\qairt\2.37.1.250807"
.\gradlew.bat :app:assembleRelease --offline
```

Output:

```text
app\build\outputs\apk\release\app-release.apk
```

When one authorised phone is connected and a production signing identity is
configured, build, install, and launch the product app with:

```powershell
.\tools\install_mobile_release.ps1 -Build -Launch
```

`-Build` uses an explicitly configured `QNN_SDK_ROOT` when present and otherwise
falls back to the repository's current QAIRT `2.37.1.250807`. A newer SDK is not
accepted merely because it contains additional HTP architectures: its
`sdk.yaml` identity and all four rebuilt model libraries must pass the shared
SDK/model release gate.

Before the production signing identity exists, the explicit local-device path
is:

```powershell
.\tools\install_mobile_release.ps1 -Build -Launch -AllowDevelopmentSigning
```

The development-signing switch never turns that APK into a distribution
artifact, and it still uses the release build type. The release installer always
requires APK Signature Scheme v2 before installation. Unless
`-AllowDevelopmentSigning` is explicitly passed for local acceptance, it also
requires v1=false, v3=true, exactly one current signer and a non-debug
certificate. The installer also refuses
obvious debug APK paths, stale APKs older than the current four-model migration
inputs, and APKs that do not contain all four 416 QNN model libraries:

```text
lib/arm64-v8a/libvalorant_416_v11s_no_flash_w8a16.so
lib/arm64-v8a/libow2_416_w8a16.so
lib/arm64-v8a/libdelta_416_v8s_w8a16.so
lib/arm64-v8a/libcs2_vombit_416_v8s_w8a16.so
```

After installation it checks `dumpsys package` and fails if the installed
package is `DEBUGGABLE`; a debuggable package cannot be used as formal CAT6
acceptance evidence.

To exercise persistent navigation, verify the unified link/inference page,
confirm that the removed control-lock prompt card is absent, and validate the
model-specific control targets, run after unlocking the phone normally:

```powershell
.\tools\install_mobile_release.ps1 -VerifyUi
```

UI evidence is written under `output/device-acceptance/<timestamp>/`. The
verifier fails rather than claiming success when the PIN keyguard obscures the
application. It also switches the Control page through Valorant, OW2 and Delta
Force and verifies that each model exposes only its supported aim target
buttons: Valorant body/head, OW2 body/head, and Delta Force body/head/teammate/
AI/crosshair.

`--offline` is intentional for the configured local SDK/toolchain. A physical
phone test still requires an authorised ADB device. QNN certification additionally
requires a compatible Qualcomm runtime; a successful APK build or portable
NNAPI/CPU fallback is not proof of HTP execution.

## Continuous portable model-graph simulation

After installing the Debug app and AndroidTest APK on the dedicated x86_64
emulator, keep all four portable model graphs cycling through both reference
backends with:

```powershell
.\tools\run_portable_backend_probe_loop.ps1 `
    -Serial emulator-5554 `
    -IterationsPerBackend 16
```

Each backend pass performs 64 complete model lifecycles: hash-pinned asset
installation, backend preparation, one real graph execution, readiness/report
validation and release. The runner has no fixed inter-pass delay and does not
insert a frame-rate ceiling. It retains only each backend's latest raw report
plus an append-only `probe-summary.jsonl` under
`output/portable-backend-continuous/`. Create the reported session's `STOP`
file to request a clean stop between backend passes. This emulator lane proves
portable CPU/NNAPI graph compatibility only; it is not physical-device QNN HTP
evidence.

A transient ADB or instrumentation failure is preserved in the raw output and
summary, followed by an exponentially bounded failure-only recovery delay and
an indefinite retry until the `STOP` file exists. The recovery delay is never
used after a successful pass, so it cannot cap model throughput.

After a portable NNAPI/CPU session has passed initialisation and one real graph
execution, one live-frame `Ort::Run` exception or non-finite output rejects that
frame and closes control through the existing execution-health gate, but does
not permanently retire the proven session. The next incoming frame is attempted
immediately, without a fixed frame period, sleep or FPS ceiling; a later success
records an execution recovery and reopens control through the normal health
contract. Sustained no-progress still reaches the existing formal-stop and
billing fail-close path. Immutable model, asset and graph-contract failures
remain terminal for that backend candidate during preparation.

## Pairing identity verification

The release contract runs the framework-independent P-256 SPKI, fingerprint and
signature codec gate:

```powershell
.\gradlew.bat :app:verifyDualMachinePairingIdentityCodec --offline
```

The AndroidKeyStore contract must also be exercised on an unlocked, authorised
physical device:

```powershell
$env:QNN_SDK_ROOT = "$PWD\qnn_sdk\qairt\2.37.1.250807"
.\gradlew.bat :app:assembleDebug :app:assembleDebugAndroidTest --offline
adb -s <serial> install -r -t app\build\outputs\apk\debug\app-debug.apk
adb -s <serial> install -r -t `
    app\build\outputs\apk\androidTest\debug\app-debug-androidTest.apk
adb -s <serial> shell am instrument -w `
    com.visionforge.mobile.test/com.visionforge.inferencebenchmark.PairingIdentityTestInstrumentation
```

The runner is a custom `Instrumentation`, not a JUnit test class. Some Android
Gradle Plugin/UTP versions report `Starting 0 tests` for
`connectedDebugAndroidTest` without invoking its `onStart()` method. A zero-test
Gradle result is not evidence; the direct `am instrument` output must contain
all markers below. The manually installed debug packages can be removed after
capture with `adb uninstall com.visionforge.mobile.test` and
`adb uninstall com.visionforge.mobile`.

The custom instrumentation runner reports
`ANDROID_AUTHENTICATED_PEER_HANDSHAKE_V1_INSTRUMENTATION_OK api_level=<SDK_INT>` and
`ANDROID_BOUND_PEER_SESSION_INSTRUMENTATION_OK api_level=<SDK_INT> hardware_backed=<true|false>` and
`ANDROID_PAIRING_IDENTITY_INSTRUMENTATION_OK` with
`INSTRUMENTATION_CODE: -1` in the connected test log. It verifies P-256
creation, non-exportability, SHA-256 sign-only `KeyInfo`, reopen stability,
signature tamper rejection, deletion/recreation, concurrent in-process
creation, the real SharedPreferences entitlement round-trip/corrupt-type
fail-closed path, and that any selected public authentication network is
validated Wi-Fi/cellular rather than the isolated Ethernet link. It also runs
two fresh API-29-or-newer provider-backed P-256 ECDH sessions through canonical transcript,
HKDF, role-bound Finished confirmation and channel-binding derivation. That
probe uses only the production public API; fixed scalars remain in the local
JVM self-test source set and cannot enter the release DEX.

The bound-session probe additionally creates a temporary JCA Host identity and
a fresh real AndroidKeyStore identity, locally rebuilds the entitlement-bound
typed transcript, verifies the Host signature through the public
`bindExpectedPair` path, completes both Finished proofs, and compares the
channel binding and every directional key-material output. It also proves that
an alias mismatch and an entitlement fingerprint mismatch destroy the fresh
Android ephemeral before derivation can be retried. The probe performs no
socket, runtime-service or production data-plane wiring.

The marker records the runtime API level but does not prove that the target is
a physical device. `hardware_backed=false` is expected and accepted for the
API-29 emulator compatibility lane, but it is never formal evidence. Formal
evidence must report `hardware_backed=true` and bind an authorised physical
serial, device fingerprint, API level, production APK identity and server-side
attestation result outside the app. The primitive provider marker assumes that
caller-side long-term identity verification already succeeded; the newer bound
marker exercises the Android public binding path but still uses a temporary
test Host, not a Windows TPM identity. None of these markers proves public-server
reachability, Windows Host interoperability, persistent generation allocation,
authenticated control records, raw-lease installation, or production data-plane
wiring.

The current `setUnlockedDeviceRequired(true)` policy applies when a new alias is
generated. An alias created by an older build can be reopened under its legacy
policy; this probe deliberately uses a fresh unique alias and therefore does not
prove legacy-key migration. Formal rollout still requires a versioned alias,
server-mediated rebind/revocation and recovery procedure that rotates the old
pair without silently deleting user state. That migration is an open release
blocker and is not claimed as solved here.
