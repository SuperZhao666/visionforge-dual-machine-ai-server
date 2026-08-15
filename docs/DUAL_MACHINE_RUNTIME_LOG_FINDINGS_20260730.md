# Dual-machine runtime log findings (2026-07-30)

This report records the evidence extracted from the five user-supplied
VF Mobile and Host JSONL files. It distinguishes a logged symptom, a current
code fix, a release gate and physical-device evidence; those are not
interchangeable.

## Evidence set

| File | JSONL rows | JSON parse failures | Distinct traces |
|---|---:|---:|---:|
| `VFMobile-runtime-log.jsonl (1)` | 132,078 | 0 | 34 |
| `host-events (2).jsonl` | 709 | 0 | 6 |
| `VFMobile-runtime-log.jsonl` | 3,014 | 0 | 5 |
| `VFMobile-runtime-log.ndjson` | 24,402 | 0 | 12 |
| `host-events (3).jsonl` | 4,926 | 0 | 1 |

The combined set contains 165,129 valid structured events. Counts below are
from the supplied files and therefore describe the affected builds, not an
assumption about the current source tree.

## Root-cause and fix matrix

### 1. “Wireless LAN did not discover VF Mobile” was not one failure

The visible Host message covered two distinct failure stages:

1. `host-events (2).jsonl` contains 15 failed bootstrap attempts. Twelve
   report `reason=ambiguous_same_name_rule`. The managed firewall rule still
   pointed at a versioned `VisionForgeHost_1.0.8.exe`, while the running image
   had a different canonical path. Discovery was intentionally not attempted
   when firewall ownership could not be proved.
2. Other attempts reached discovery but selected an unusable address and
   reported multicast membership failure with WinSock 10049
   (`WSAEADDRNOTAVAIL`). No ready messages or probes were exchanged.

Current code addresses both stages:

- `host_firewall_provisioner.cpp` accepts only strict three-segment
  `VisionForgeHost_<n>.<n>.<n>.exe` and `VFHost_<n>.<n>.<n>.exe` migration
  identities, while continuing to reject suffixes, path disguises, empty or
  overlong segments and arbitrary prefix matches. All other narrow rule fields
  must still match before a rule is migrated.
- `host_cat6_session.cpp` enumerates preferred private IPv4 interfaces, joins
  multicast by Windows interface index first, falls back to the legacy IPv4
  membership form, and also sends directed-broadcast probes. One broken or
  multicast-hostile interface no longer prevents discovery on another LAN.
- `streamer_desktop_app.cpp` maps firewall ownership conflict before the
  generic discovery message, so the UI does not mislabel a firewall failure as
  “phone not found”.

Physical A/B evidence on 2026-07-30 then proved the corrected path:
`192.168.1.18 -> 192.168.1.42`, `wireless_lan_udp`, about 150 FPS, with automatic
formal start and a confirmed stop. This proves the tested Xiaomi/V75 route; it
does not certify every AP, Windows adapter or phone.

### 2. Three independent observability storms obscured real failures

The largest Mobile file contains:

- 94,621 `dual_machine_automatic_usage_reservation_unchanged` no-op events;
- 2,180 `running -> running` phase “changes”;
- 374 repeated host-video preflight failures while no valid Host stream was
  available.

The Host long run contains 3,577 preferred-CAT6 diagnostic rows from only 82
probe starts because every warm-up diagnostic was emitted separately.

Current code now:

- logs an unchanged automatic-usage reservation on transition and then once
  per five-minute heartbeat;
- emits `mobile_runtime_phase_changed` only when the phase actually changes;
- requires a discovered wireless requester before entering the billed-start
  preflight and reports one discovery timeout per network handle;
- summarizes a complete Host bootstrap diagnostic vector as
  `count=<n> final={<last>}`.

These changes preserve state transitions and failure context while removing
the high-frequency duplicates that made the 76 MB Mobile log difficult to
triage.

### 3. A rejected automatic start retried the whole preparation every second

One Mobile trace (`6696a5e5-8038-4c2d-bbf9-b5ac38856159`) received 21 definite
HTTP 409 rejections between sequence 71 and sequence 503, over about 25 seconds.
Each attempt repeated video validation, local QNN/decoder preparation and
data-plane close. Sequence 527 finally succeeded when the server conflict
cleared.

`AutomaticFormalStartRetryPolicy` now applies bounded rejection backoff:
1, 2, 4, 8, 16 and then 30 seconds. The wait is checked before another full
automatic start. It resets after a successful start, a confirmed new Host
stream, or a successful status path that ends only in “Host video not yet
observed”. The structured rejection event includes the bounded server error
token, consecutive count and selected delay. This keeps transient 409 recovery
automatic without hammering the server or rebuilding the local pipeline every
second.

### 4. Output-route failures were safe, but mostly hardware absence

The supplied files contain 1,871 `control_output_reconnect_failed` events and
6,013 `control_output_auto_locked` events in the largest Mobile file. The
selected MAKCU route was not connected. The retry cadence backs off to 30
seconds and every failure keeps delivery disabled. This is correct fail-closed
behaviour, not evidence that inference failed. MAKCU and Bluetooth HID cursor
delivery remain separate physical-hardware acceptance items.

### 5. Capture loss recovered; phone foreground loss intentionally stopped billing

The long Host trace records 22 stream-recovery schedules, 13 successful
recoveries and seven failed intermediate attempts, mainly around capture access
loss/denial. Recovery therefore worked, although secure-desktop or display
ownership changes can still interrupt capture.

In the locality-first A/B run, VF Mobile closed the data plane when
`display_interactive=false` and `activity_foreground=false`, about 65 seconds
before the Host was manually stopped. The formal stop was locally closed and
server-confirmed. Host metrics after that Mobile timestamp are Host-only and
must not be represented as receive/decode/QNN evidence.

## QNN performance and multi-Snapdragon boundary

The supplied Mobile files contain 1,975 `mobile_pipeline_metrics` rows. Their
maximum cumulative `qnn_failures` value is zero. Mature trace FPS varies with
Host production rate, display state and run conditions; several traces sustain
about 149–150 FPS, while others are materially lower. Therefore “QNN failures
are absent in this evidence” is supported, but “every phone always runs at 150
FPS” is not.

The current package closure is generated from actual paired SDK artifacts:
V68, V69, V73, V75 and V79 for local QAIRT 2.37.1. Known SoCs are rejected early
only when their required HTP architecture is absent. Unknown/OEM variants still
probe backend, device, context and graph finalisation instead of being rejected
by a phone-model allow-list.

The customer iQOO 15 is treated as an SM8850/V81 target. Local QAIRT 2.37.1 has
no V81 stub/skeleton pair, so the current APK is not a V81-capable artifact.
Release gates additionally bind `sdk.yaml` (`version` plus `build_id`) to the
approved model manifest and to the full embedded SDK identity of the Valorant,
OW2 and Delta model libraries. A newer V81 runtime cannot be mixed with the
three older model libraries.

V81 completion requires all of the following external evidence:

1. A legally supplied QAIRT SDK containing a real V81 stub/skeleton pair.
2. All four 416x416 W8A16 models rebuilt and reapproved with that exact SDK.
3. QNN backend/device/context/graph finalisation on the customer phone.
4. At least 300 warm executions, the labelled 484-frame replay, and a
   30-minute end-to-end thermal run with P50/P95 and failure counters.

Until those exist, V81 is intentionally a release blocker rather than a
marketing claim.

## Verification commands

The relevant release evidence is produced by:

```powershell
cd android_inference_benchmark
./gradlew.bat --no-daemon :app:verifyMobileReleaseContracts `
  "-PqnnSdkRoot=<approved QAIRT root>"
cd ..
python tools/verify_dual_machine_release_readiness.py --json
```

Host firewall/discovery changes additionally require the Host CTest suite and
a real Host/Mobile wireless run. Unit and static contracts validate policy
shape; they do not replace the physical run.
