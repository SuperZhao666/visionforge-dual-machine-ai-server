# VisionForge Mobile Architecture

This document is the implementation guide for the Android side of the
two-machine runtime. It complements `DUAL_MACHINE_RUNTIME_ACCEPTANCE.md`: the
acceptance document defines product ownership and physical evidence, while this
document defines code ownership and change rules.

## Module boundaries

```text
MainActivity (Android view/lifecycle only)
    |
    +-- MobileRuntimeSnapshot (native diagnostic text -> immutable UI state)
    |
    +-- MobileControlRuntime (process-scoped composition root)
            |
            +-- InferenceProfile (validated QNN post-process policy)
            |
            +-- ControlOutputCoordinator (automatic fail-closed health gate)
            |
            +-- MakcuSerialController (the sole USB serial owner)

MobileRuntimeService (foreground runtime owner)
    |
    +-- MobilePipelineCoordinator (ordered video/inference lifecycle)
    |       |
    |       +-- NativeVideoInferencePipeline (small port)
    |               |
    |               +-- QnnNativeVideoInferencePipeline (JNI adapter)
    |
    +-- MobileControlRuntime.reconcileRuntimeHealth(...)
```

`MainActivity` must not directly prepare QNN, configure MediaCodec, bind the
video socket, own MAKCU writes, or decide whether physical output is safe. Its
responsibility is limited to activity lifetime, user interaction and rendering.
The foreground service continues to own the runtime when the Activity is in the
background.

## Video and inference lifecycle

`MobileRuntimeService` keeps the pipeline armed but closed. A valid automatic
start first observes real Host video without billing, prepares QNN with the
data plane closed, observes a fresh Host packet again, and only then asks for
the first short lease. `MobilePipelineCoordinator` owns the lease-authorized
data-plane sequence:

1. Stop a possible previous receiver and decoder.
2. Prepare the QNN/HTP graph.
3. Configure the decoder output for the selected model contract (currently
   320×320 or 416×416).
4. Bind UDP video port 5000.

The APK stages Qualcomm HTP skeletons for V68, V69, V73, V75 and V79. Runtime
selection remains a device-driver decision: packaging those generations is a
compatibility prerequisite, not proof that every Snapdragon SKU has executed
the graph. An optional HTP performance vote may improve sustained latency on a
supporting driver, but an unsupported vote must fall back to the device default
power mode without failing graph preparation.

If a step fails, later steps must not run. The coordinator writes a structured
event for the request, successful startup, failure, and stop. A future runtime
can replace `QnnNativeVideoInferencePipeline` without changing the GUI or
control code, provided it preserves `NativeVideoInferencePipeline` semantics.

## Inference policy ownership

`InferenceProfile` owns only persisted, validated detector post-process
settings. Its default confidence is `0.84` and its current NMS IoU is `0.45`.
Confidence is represented on an exact `0.01` product grid and is clamped to
the documented bounds before persistence or JNI configuration.
The profile calls a narrow JNI function which updates the native QNN runtime's
`YoloPostprocessConfig`; it neither starts QNN nor controls USB output.

Every application of the policy records the selected confidence, IoU and the
native-call result in the single append-only
`visionforge-mobile-runtime.jsonl`. This makes a UI setting
independently auditable without mixing inference policy into the video
lifecycle or MAKCU control code.

## Control ownership

Control has a separate lifecycle. `ControlOutputCoordinator` is the only owner
of the automatic fail-closed output gate and uses `MakcuSerialController` for
physical transport. `MobileRuntimeService` supplies the gate with independently
verified health facts: the current short formal-use permit is inside its
monotonic time window, the selected CAT6/Wi-Fi data-plane route is present,
receiver/decoder/QNN are live, QNN has a recent successful execution with no
consecutive failure, and MAKCU is connected.
Only the conjunction of all facts enables `km.move`; loss of any fact disables
native output and USB delivery immediately. Recovery is automatic after every
fact becomes healthy again.

Each physical move is a transaction. Native assigns one ticket and permits only
one command in flight; Java returning from `offerNativeMove` is not a commit.
Only a matching firmware echo plus prompt completes the ticket. A mismatched
ticket, failed ACK or ACK older than 100 ms fail-closes and resets control state.
After a valid ACK, the next plan still requires a newer source frame observed
at least 8 ms later. This visibility barrier prevents an unchanged old image
from causing a duplicate move; it is deliberately conservative and is not
reported as learned game-camera response.

The coordinator depends only on three narrow ports: `MakcuConnection` for USB
readiness and a connection request, `ControlProfilePort` for validated native
parameters, and `MobileRuntimeEventSink` for an append-only event. This makes
the output gate testable without Android, a serial device, or QNN libraries.
The Android implementations remain `MakcuSerialController`, `ControlProfile`,
and `MobileEventLogger` respectively.

Activity visibility is not a health fact and therefore must not stop a valid
foreground-service runtime. Raw video startup alone is also insufficient to
enable output. No code may introduce a Windows input fallback, an
Android-to-host control socket, clicks, automatic fire, recoil compensation,
backflash macros, wheel output, or any control command other than `km.move`.

The control-frame monotonic sequence is generated locally by the mobile
receiver. Host `frame_id` remains diagnostic metadata only because encoder
recovery and network-path replacement may restart the host counter. A host
counter reset must therefore never freeze the mobile freshness gate.

## Presentation state

Native reports are diagnostic strings, not a UI API. Only
`MobileRuntimeSnapshot` interprets them for the screen. A live desktop-video
status requires both a running receiver and a completed access unit no older
than the documented freshness threshold. Binding UDP alone is not proof that
video is reaching the phone.

`MobileThroughputTracker` derives receiver, decoder and QNN FPS from successive
monotonic counter samples. These are display-only observed rates: they never
configure encoder timing, inference scheduling, queue depth or a frame cap.

When native metrics change, first update the snapshot contract and its test;
do not add ad-hoc string parsing to a view or control class.

## Test and build gates

`MobileRuntimeSnapshotSelfTest` is deliberately dependency-free and runs with
the build JDK through:

```powershell
./gradlew.bat :app:verifyMobileRuntimeSnapshot --offline
```

It covers stale/live link rendering and the ordered `MobilePipelineCoordinator`
contract with a fake native pipeline. The release assembly remains the native
integration gate:

```powershell
./gradlew.bat :app:assembleRelease --offline
```

Neither gate proves QNN execution, Ethernet delivery or MAKCU output. Those
remain physical-device acceptance checks documented in
`DUAL_MACHINE_RUNTIME_ACCEPTANCE.md`.

## Extension rules

- Add a new inference backend by implementing the native pipeline port, not by
  branching in `MainActivity`.
- Add a user-visible metric by extending the snapshot and its test first.
- Add a new control transport behind the control coordinator; it must retain
  the automatic fail-closed health contract and may expose only `km.move`.
- Preserve latest-frame-first behavior. Do not add a user-facing FPS cap or an
  unbounded work queue as a congestion workaround.
