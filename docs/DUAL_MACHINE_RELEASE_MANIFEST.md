# Dual-machine release manifest contract

`release/release-manifest.json` is the single source for the current
dual-machine release identity. `dual_machine_runtime/release_version.txt`
remains the native build input, but the consistency gate requires it to agree
with the manifest; Android reads both and fails on drift. The server version
API returns the same `release_id` and `release_version`.

The checked-in manifest is an `unpublished` source manifest. Its commit and
artifact fields are explicit placeholders because this repository checkout
does not contain the production APK or Host binary. A release machine must
create a new manifest with the exact Git commit, content-addressed URLs,
positive sizes, lowercase SHA-256 values, and an Ed25519 signature. A
published manifest is immutable: corrections require a new `release_id`, not
an in-place edit.

Run the source consistency gate from the repository root:

```powershell
python tools/verify_release_manifest_consistency.py --json
```

The publish gate is deliberately fail-closed until real artifacts and an
external signing key are supplied:

```powershell
python tools/verify_release_manifest_consistency.py --require-published --json
```

Historical APK/Host hashes remain in their original acceptance documents but
are marked `SUPERSEDED`; they are evidence, not a current release manifest.
