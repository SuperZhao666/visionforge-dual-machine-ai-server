# VF dual-machine runtime

The production boundary is asymmetric and automatically selects its transport:

```text
Windows VFHost.exe
  auto-selected game-display center 320x320 DXGI capture
  -> D3D11 bridge -> H.264 -> UDP video:5000

transport preference
  1. isolated CAT6: 10.57.23.1/24 <-> 10.57.23.2/24
  2. local LAN UDP: automatic multicast/broadcast discovery -> validated unicast peer

VisionForge Mobile
  UDP reassembly -> MediaCodec -> preprocess -> QNN/HTP
  -> post-process -> optional USB serial -> MAKCU
```

The Windows Host owns capture, encoding, and UDP video publication only. Link
readiness, bounded quality probes, and `IDR1` are transport-recovery metadata;
they never carry detections or input commands. The Host does not link an input
driver, accept control commands, or call `SendInput`.

The Host and Android service both prefer the fixed CAT6 contract. If that link
cannot be provisioned and validated, they automatically fall back to the same
local network without requiring an interface picker or manual IP configuration.
The Windows computer may use Wi-Fi or wired Ethernet to reach a phone connected
through the same router; firewall scope remains limited to on-link `LAN` and
`Wireless` interfaces and never includes `RemoteAccess`/VPN interfaces.
Wireless discovery uses `239.57.23.57:5003`; the Host also sends bounded active
probes pinned to each selected interface's directed broadcast address so Windows can
discover a phone when one-way multicast or limited broadcast is filtered. Two
1200-byte token-preserving probe acknowledgements on UDP `5004` establish the
unicast peer before video, IDR, or mouse-button observation endpoints are
activated.

On a multi-homed Windows host, discovery joins the multicast group explicitly
on every operational, multicast-capable, preferred RFC1918 or `100.64.0.0/10`
IPv4 interface. It
does not depend on Windows choosing the correct route for an `INADDR_ANY`
membership. The fallback to `INADDR_ANY` is retained only for compatibility
when no explicit membership succeeds. Structured discovery diagnostics record
the candidate/joined interface addresses, per-interface directed-broadcast
targets, send/receive failures with Winsock codes, route retries, and first
validated packet sources so a timeout can be attributed without guesswork.

Android owns inference, post-processing, and the authorised MAKCU path.
Physical output is off by default and is not persisted across app launches.
Stopping the pipeline or hiding the activity closes the output gate and clears
queued moves before decoder teardown.

## Windows Host

Build the actual product executable with:

```bat
host\windows\build_host_application.bat
```

Output:

```text
out\VFHost.exe
```

The wrapper delegates to the repository CMake target instead of maintaining a
second source-file list. Release optimisation and the static MSVC runtime stay
enabled. The formal one-EXE wrapper disables linker PDB generation so the
distributed image cannot retain a CodeView/PDB locator or a build-machine path.
Ordinary local CMake builds keep `VFDUAL_ENABLE_PRIVATE_HOST_SYMBOLS=ON` by
default and archive their development PDB under
`private_symbols\<exe-sha256>.pdb`; those symbols are private development
material and must never be copied beside or distributed with `VFHost.exe`.

The application selects the output covered by the topmost eligible full-screen
or large borderless external window and captures only its centered 320x320
physical-pixel ROI. It falls back to the Windows system-primary output when no
eligible game surface exists. Recovery retains the exact selected display while
it remains attached, so Alt-Tab or a notification cannot silently move the
stream; only removal of that output triggers a fresh automatic selection.

The production encoder policy is:

1. NVIDIA capture uses same-adapter NVENC.
2. Intel/AMD capture uses cross-adapter NVENC when a usable NVIDIA adapter is
   present.
3. If NVENC is unavailable, use the built-in Microsoft software H.264 MFT.
4. If the first real NVENC frame fails during registration, mapping, or encode,
   the current Host run permanently trips its circuit breaker to Microsoft
   software H.264.

Intel/AMD hardware MFT is diagnostics-only. Its current input path is not truly
zero-copy and teardown has a crash risk, so it is not a production candidate.
See `host/windows/include/vfdual/host_encoder_policy.hpp` and
`host/windows/src/host_runtime_service.cpp`.

The capture/publish loop has no configured FPS scheduler or sleep ceiling.
`frames_per_second` and `encoder_timing_fps` are H.264 timestamp/keyframe
metadata, not a capture or publication limit. A 144 Hz desktop currently
provides about 144 independent new frames.

Current hot-path evidence:

- NVENC, 2000 frames: P50 capture 1676 us, bridge 2250 us, encode 2646 us,
  total 6819 us (`146.649 FPS` from total time).
- Microsoft software H.264, 1000 frames: a requested 240 Hz metadata rate was
  negotiated to 120 Hz; P50 total 6782 us (`147.449 FPS`). The 120 Hz value is
  still metadata, not a scheduler cap.

Raw Host evidence is written to:

- `%LOCALAPPDATA%\VisionForge\DualMachine\host-metrics.csv`
- `%LOCALAPPDATA%\VisionForge\DualMachine\host-events.jsonl`

## Android runtime

Android owns MediaCodec output, preprocessing, QNN/HTP graph execution,
post-processing, and the optional MAKCU serial queue. A measured QNN stage of
about 2.08 ms is stage-only evidence; it is not end-to-end 500 FPS. Display
capture cadence, encode, network, decode, preprocessing, post-processing,
queues, and optional physical output remain outside that number.

## Current release identity

The only current release identity is the repository manifest at
`../release/release-manifest.json`. It binds the Server, Android and Host
versions, protocol versions, compatibility range, release ID and the
content-addressed artifact fields. This checkout intentionally carries an
unpublished source manifest: no APK or Host hash is claimed as a current
publishable artifact until a release build fills and signs that manifest.

### Historical acceptance (SUPERSEDED)

The following evidence was valid for an earlier physical acceptance and is
retained for audit history only. It must not be copied into a current release
manifest:

`releases/android/cat6-wireless-lan-production-latest/VisionForgeMobile_1.0.1_20260728_190441.apk`
with SHA256
`3B985E864DF66B9EB9B460D763EF3F0FE4068FC3FB22FDB3C52A800C493D4C97`.
It is package `com.visionforge.mobile`, version `1.0.1` (code `4`), signed by
the production certificate, and is not debuggable. The matching product Host is
`out/VFHost.exe` with SHA256
`F0512994A78F2667C7A815F32BCDACDC4BCA5C301E301D3EF8713FBD69D77876`.

Physical acceptance on 2026-07-28 first exercised bidirectional switching with
the preceding Host build:

- CAT6 was automatically selected at `10.57.23.1 <-> 10.57.23.2` while both
  wired and wireless links were available.
- Disabling only the Windows wired adapter during an active stream recovered
  automatically to `wireless_lan_udp` at
  `192.168.1.18 <-> 192.168.1.42` without restarting the Host.
- Restoring the wired link caused the background preference probe to upgrade
  automatically from wireless LAN UDP back to CAT6 without restarting the Host.
- The CAT6 baseline, wireless fallback, and CAT6 failback events share Host
  trace `vfhost-1785238155228-4280`; the stream epoch advanced from `2` to `3`
  and then to `4`.
- A separate final live-state window covered the later loss of the mobile
  `eth0` interface. With CAT6 genuinely unavailable, the same Host correctly
  remained on wireless LAN UDP at epoch `5` and published 2,304 additional
  frames in 30 seconds.

That acceptance did not cover a fresh Host start with CAT6 already unavailable.
The omitted case exposed a real Windows multicast-interface defect: an
`INADDR_ANY` membership followed the Ethernet route and missed announcements
arriving on Wi-Fi. The current canonical Host fixes that defect and was then
accepted twice with the Windows Ethernet adapter disabled:

- An acceptance-autostart run joined `192.168.1.18`, discovered mobile
  `192.168.1.42`, validated two probe acknowledgements, and increased the
  published frame count from 574 to 20,902 with no runtime fault or recovery.
- A separate no-argument product launch followed by the visible Start Streaming
  button joined the same WLAN, reached wireless readiness in 6.363 seconds,
  started video in 8.244 seconds, and increased the published frame count from
  680 to 22,618. Every quality sample reported the mobile reachable, with zero
  recovery and zero runtime faults.
- The full native suite passed 40/40 against the exact release build. After the
  run, the Host exited cleanly and the temporarily disabled Ethernet adapter was
  restored to its enabled state; Ethernet and WLAN both reported `Up` after link
  negotiation.

Machine-readable evidence, release gates, screenshots, and artifact signatures
are in
`releases/android/cat6-wireless-lan-production-latest/transport_acceptance_evidence.json`.
The cold-start defect isolation, exact Host hash, discovery diagnostics, two
physical no-cable runs, and final adapter restoration are recorded separately
in
`releases/android/cat6-wireless-lan-production-latest/wireless_no_cable_cold_start_acceptance.json`.
The authorization and physical-output gates remain fail-closed: a valid
production card/lease and explicit output enable are required. No development
credential, test-only switch, or authorization bypass is enabled in the release.

Additional GPU, display, DPI, and MAKCU hardware combinations are compatibility
matrix expansion. Their runtime paths remain compiled and enabled; qualification
of another hardware topology must not be represented as acceptance evidence for
hardware that was not physically present.
