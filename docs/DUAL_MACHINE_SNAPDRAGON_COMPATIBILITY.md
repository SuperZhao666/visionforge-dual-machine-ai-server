# Dual-machine Snapdragon HTP compatibility contract

This document separates **packaged compatibility**, **real HTP execution** and
**product certification**. They are not interchangeable.

## Current runtime closure

The Android product is built with QAIRT `2.37.1.250807`. Its APK stages the HTP
stub and unsigned skeleton pairs listed below, restores all skeletons to the
application-owned runtime directory, and exposes that directory through
`ADSP_LIBRARY_PATH` before QNN backend creation.

| HTP architecture | Stub in APK | Skeleton in APK | Current evidence tier |
|---|---:|---:|---|
| V68 | yes | yes | build/package integration; physical device required |
| V69 | yes | yes | build/package integration; physical device required |
| V73 | yes | yes | build/package integration; physical device required |
| V75 | yes | yes | build/package integration plus real execution on the authorised Snapdragon 8 Gen 3 phone |
| V79 | yes | yes | build/package integration; physical device required |
| V81 | no in QAIRT 2.37.1 | no in QAIRT 2.37.1 | required by iQOO 15 / SM8850; SDK upgrade and physical certification required |

The local SDK does not contain a V81 stub/skeleton pair. Current Qualcomm
documentation lists V81 as a newer HTP architecture, so V81 is an explicit
future SDK-upgrade gate rather than an unsupported library name fabricated by
the application.

The build no longer maintains a second hard-coded candidate list. It scans the
selected QAIRT SDK for strict
`libQnnHtpV<digits>Stub.so`/`libQnnHtpV<digits>Skel.so` pairs and packages their
intersection in numeric architecture order. A release can set
`VISIONFORGE_REQUIRED_QNN_HTP_ARCHITECTURES`; any required architecture missing
either half of the pair fails the release contract. For example, the iQOO 15
gate is:

```powershell
$env:VISIONFORGE_REQUIRED_QNN_HTP_ARCHITECTURES = 'v68,v69,v73,v75,v79,v81'
./gradlew.bat verifyMobileReleaseContracts `
  "-PqnnSdkRoot=C:\Qualcomm\AIStack\QAIRT\<V81-capable-version>"
```

With the repository's current QAIRT 2.37.1 this command must fail on V81. That
is intentional: it prevents publishing an APK that advertises SM8850 support
without the required Qualcomm binaries.

Architecture discovery does not authorize mixing a newer runtime with older
model libraries. The build reads `version` and `build_id` from the selected
SDK's `sdk.yaml`, normalizes the current SDK to an identity such as
`2.37.1.250807`, and requires it to match the toolchain identity in the approved
model manifest. It also verifies the full embedded `QNN_SDK_VERSION` identity
in each of the Valorant, OW2, Delta and CS2 model libraries. A synthetic V81 SDK with
a different identity is a mandatory negative release test. Adding V81 therefore
requires rebuilding and reapproving all four model libraries with that same SDK;
copying only its runtime, stub and skeleton files is rejected.

Marketing chipset names are not used as the runtime switch. Android vendor
firmware and the QNN HTP backend select the matching architecture from the
packaged closure. This avoids hard-coding an incomplete phone-model list and
also covers OEM variants that share an HTP architecture.

For early diagnostics only, public Android `Build.SOC_MODEL` values are mapped
to known HTP generations. Known examples are SM8350→V68, SM8450/SM8475→V69,
SM8550→V73, SM8650→V75, SM8750→V79 and SM8845/SM8850→V81. A known device's
QNN candidate is rejected early only when its required architecture is absent
from the packaged manifest. That rejection does not masquerade as HTP success:
the explicitly separate portable NNAPI and CPU candidates may continue only
after their own real initialisation and graph-execution proof. Unknown or empty
SoC identities are routed through runtime capability probes and are never
rejected merely for being absent from this diagnostic table.

## Fail-closed NPU evidence

VisionForge Mobile routes known HTP-capable Snapdragon devices through QNN first,
then through the portable NNAPI and CPU candidates if QNN cannot be prepared.
Other physical Android SoC families route through NNAPI and then CPU; the
emulator uses CPU only. Every selected backend must initialise and execute the
real selected graph once before it becomes ready. The UI may show `QNN HTP
ready` only after backend, device, context, graph composition and graph
finalisation succeed. Execution counters and latency samples must then advance
on decoded frames.

The optional Turbo+ performance vote is an optimisation, not a correctness
dependency. If an older driver does not implement that vote, the graph remains
on HTP with the device default power mode and records the fallback. A failed
HTP backend/graph preparation is recorded as a failed QNN candidate. A later
portable candidate is labelled explicitly as `ONNX Runtime / NNAPI` or `ONNX
Runtime / CPU`; it is never silently relabelled as HTP inference and does not
inherit an HTP frame-rate or certification claim.

## Per-device certification gate

Each physical phone/firmware combination must pass all of the following before
it becomes a certified device profile:

1. Clean install and cold start without missing stub/skeleton or linker errors.
2. QNN backend/device/context/graph creation and finalisation evidence.
3. At least 300 warm inference executions with advancing QNN counters and no
   hidden CPU/NNAPI provider path.
4. The 484-frame labelled dataset replay with complete trace coverage and the
   recorded precision, recall, F1, AP50 and mAP50-95 values.
5. Thirty-minute sustained video decode + QNN run with P50/P95, thermal state,
   failure count and latest-frame drop behaviour recorded.
6. App stop/start and host encoder/link recovery without a stale control-frame
   monotonic gate.

Packaging V68/V69/V73/V79 makes those devices build-compatible candidates; it
does not replace this physical certification. The absence of the MAKCU and
final Ethernet hardware also keeps physical control and wired failover outside
the current evidence boundary.

## Upgrade rule

When QAIRT is upgraded, the dynamic manifest automatically adopts complete
stub/skeleton pairs, but the release remains blocked until all four W8A16
split-output models are rebuilt and their manifests are reapproved with that
same SDK identity. Rerun the current V75 reference phone, then run at least one
device for every newly added HTP generation. An SDK version change without
those gates is not a compatibility release.
