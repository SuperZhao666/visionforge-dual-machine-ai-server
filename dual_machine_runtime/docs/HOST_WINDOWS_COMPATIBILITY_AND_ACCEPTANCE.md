# VF Host Windows compatibility and acceptance contract

## Formal security status

The current Host runtime is a development transport and is not formally
release-eligible. The video publisher has a fail-closed lease gate, but no
production control coordinator can yet install a confirmed peer and the same
raw verified lease. The UDP video/control formats are not fully authenticated,
and the Android application can still simulate the Host authorization identity
locally. Those facts are release blockers, not accepted compatibility behavior.

Every formal Host candidate must additionally satisfy all of the following:

- `Get-AuthenticodeSignature` reports `Valid`, a trusted timestamp is present,
  and the signer certificate SHA-256 matches the explicit release allowlist.
- The Host owns an independent, non-exportable CNG/TPM P-256 identity and the
  server has registered/verified that identity; Android cannot generate or
  substitute the Host private key.
- Host and Android mutually authenticate the frozen fresh signed P-256 ECDHE
  control channel, derive channel binding from its transcript/exporter, and
  independently verify the same raw short lease.
- Video, presence probes, IDR requests and mouse-button packets share an AEAD
  v2 session with direction/type/epoch-separated keys, unique nonces and a
  sliding anti-replay window. Authentication is checked before parsing or
  allocating from untrusted packet metadata.
- Lease expiry, revocation, route change, control-channel loss or key-epoch
  failure closes the Host publish gate. A pair that has completed v2 never
  falls back to plaintext automatically.
- `python tools/verify_dual_machine_release_readiness.py --mode formal` and the
  physical security acceptance both pass for the exact signed `VFHost.exe`
  hash. Static string contracts are only a preflight and do not replace packet
  mutation/replay tests, Wireshark inspection or real TPM/device testing.

Until these conditions are met, use `--mode diagnostic` only and
do not describe the Host as reverse-resistant or secure against a hostile LAN.

The checked-in Host identity implementation now selects the Microsoft Platform
Crypto Provider in formal builds, requires a machine-scoped signing-only P-256
key, rejects software/exportable metadata, persists a protected DACL containing
only `LOCAL_SYSTEM`, Builtin Administrators and the current interactive user,
and validates every ACE after reading the descriptor back from CNG. Existing
formal keys are re-applied and re-audited on open; any unsupported provider,
write failure, broad/extra ACE or read-back mismatch fails closed. Development
builds retain their separately named current-user software key and cannot claim
formal ACL assurance. `VFHost.exe --host-device-identity-probe` exercises the
same production composition without opening the GUI or emitting key material.
A passing development probe does not replace the final real-TPM formal probe.

## Supported operating-system boundary

- Windows 10 version 1703 or newer, x64.
- Windows 11, x64.
- A local, unlocked, interactive desktop session with a D3D11 feature-level 11
  display adapter and DXGI Desktop Duplication support.
- Windows Media Foundation H.264 must be present. Windows N/KN editions need
  Microsoft's Media Feature Pack.

RDP-only, locked, headless, Microsoft Basic Display Adapter, Windows 7/8,
Linux and macOS are outside this executable's support contract. The Host now
records OS build, session type, precise startup stage, native error and stack
addresses so these environments fail diagnostically rather than as error `1`.

## Encoder selection and runtime failover

| Capture hardware | Initial path | Runtime failover |
|---|---|---|
| NVIDIA | same-adapter NVENC | hardware MFT, then Microsoft software H.264 |
| Intel/AMD with NVIDIA also installed | cross-adapter NVENC | bridge failure trips the per-run NVENC breaker; hardware MFT, then software |
| Intel/AMD without usable NVIDIA | adapter-bound hardware MFT | Microsoft software H.264 |
| Hardware encoder unavailable | Microsoft software H.264 | startup reports exact Media Foundation stage and HRESULT |

The capture loop remains presentation-driven. Encoder timing metadata follows
the detected display refresh rate; no artificial FPS ceiling is introduced.

## Release artifact contract

- Exactly one distributable `VFHost.exe`; `VisionForgeHost.exe` is accepted only as a legacy migration identity.
- x64 PE, Windows GUI subsystem, statically linked MSVC/UCRT.
- Only Windows system DLL imports; no sidecar runtime DLLs.
- Embedded Windows 10/11 compatibility, per-monitor-v2 DPI and long-path
  manifest.
- A SHA-256 keyed PDB and JSON manifest are archived privately under the build
  directory and must never be shipped.
- Unsigned internal builds are development-only. Formal distribution requires
  a valid timestamped Authenticode signature whose signer certificate SHA-256
  is in the versioned release allowlist; a development bypass can never produce
  a formal-eligible report.
- The GUI process owns a global named mutex. Renaming the EXE therefore cannot
  start a second Host that races DHCP, firewall or direct-link restoration.

## Physical acceptance evidence

Every system acceptance must use the final EXE hash and require all of:

1. `host_process_start` with the expected hash and real OS build.
2. A selected transport with matching evidence: `host_cat6_ready` on
   `10.57.23.2`, or `host_wireless_lan_ready` with RFC1918 Host and phone
   addresses after `host_wireless_lan_fallback_started`.
3. `host_encoder_selected` with a named candidate and initialization stage.
4. `host_stream_started`.
5. At least ten `host_cat6_quality` samples carrying the selected `transport`,
   at least 1,000 published frames,
   strictly increasing frame counters over the quality window, a fresh healthy
   final link sample, and no hard initialization/worker failure.
6. Clean `host_stream_stopped`; CAT6 runs also require direct-link restoration
   on exit.
7. For CAT6 runs, the physical Ethernet address, DHCP, gateway, DNS and metric
   state after shutdown must equal the pre-run snapshot. A run that provisioned
   the link must report `restored`; `not_required` is accepted only when startup
   did not provision it.

Release acceptance includes two core physical cases. With CAT6 and Wi-Fi
both available, the selected transport must be `cat6`. With only the wired
adapter disabled and Wi-Fi retained, startup must first record the CAT6 failure,
then automatically select `wireless_lan_udp`, publish increasing frame counters,
and stop cleanly. Neither case permits manual endpoint entry.

Local-network compatibility acceptance additionally requires a Windows Host
connected to the router by wired Ethernet while VF Mobile remains on that
router's Wi-Fi. Discovery must show an interface-pinned directed-broadcast
target for the LAN ifIndex, receive two probe acknowledgements, select
`wireless_lan_udp`, and complete the same publish/stop evidence contract. The
installed inbound rule must cover `LAN,Wireless` with `LocalSubnet` remotes and
must not include `RemoteAccess`.

`host/windows/tools/run_e_system_acceptance.ps1` implements this same evidence
contract for the secondary Windows installation. Each result directory keeps an
immutable filtered JSONL trace, metrics tail, network snapshots and any crash or
emergency evidence. It is a test tool, not a second product executable.

`host/windows/tools/invoke_e_system_acceptance_once.ps1` is the narrow RunOnce
wrapper. It reads the expected content identity from `expected_sha256.txt`,
persists a minimal fallback result when preflight fails, and schedules return to
the default Windows installation after the harness finishes. RunOnce fires only
after an interactive user login: a secondary installation without verified
auto-login therefore requires one manual Administrator login. Use BCD
`/bootsequence` for the one-time E-system boot; never change the default loader.
