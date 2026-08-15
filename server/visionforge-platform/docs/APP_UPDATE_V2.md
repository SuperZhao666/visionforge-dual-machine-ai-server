# VisionForge EXE update protocol v2

This update path uses only the existing VisionForge server and domain. Full EXE files and delta files are served from `app/static/releases/`; no CDN, object storage, or paid third-party service is required.

The first migration from an already installed legacy EXE requires one full delivery through the legacy Inno installer or a manual replacement of a new client built with the updater and `--onefile-as-archive`. A legacy client cannot acquire updater support through a delta or signed-v2 onefile it does not yet understand, and a legacy non-archive onefile is not a reusable archive baseline. Releases after that bootstrap version prefer deltas selected by the installed EXE's content SHA256. Later self-updates request native Windows UAC only when the installed target is in a protected directory such as `Program Files`; the elevated helper only replaces or rolls back protected files, while a verified normal-user token owns health checks, restart, and all user-writable paths.

## Storage and URLs

- The release builder uses content-addressed names `<target_sha256>.exe` and `<patch_sha256>.vfdiff`.
- `--base` may be repeated for up to 64 installed EXE baselines. Bases are deduplicated by content SHA256, and an oversized delta is skipped independently without suppressing useful deltas for other versions.
- Before signing, the builder requires a protected `.verify.json` from `verify_protected_onefile_release.py --publish`. The report must match the target SHA256 and embedded version and must include a passing binary-protection proof; unsigned `--self-test` fallback is not accepted for release signing.
- Signed artifact URLs must resolve to `/static/releases/` on this server. Both relative URLs and same-origin HTTPS forms are accepted; third-party and other same-origin paths are rejected.
- Signed v2 publication verifies every local `/static/releases/` file against its declared size and SHA256 before committing the release.
- The full target and every delta must fit the client's 512 MiB safety limit.
- Successful content-hash static responses use `Cache-Control: public, max-age=31536000, immutable`. Update manifests use `Cache-Control: no-store`.

## Signed payload

The server reuses `RUNTIME_CATALOG_PUBLIC_KEY` or `RUNTIME_CATALOG_PUBLIC_KEY_PATH` only as the Ed25519 verification key. The private key remains offline and must never be copied to the server.

Signed `(channel, version)` releases are immutable. A rollback is published by rebuilding the prior code with a new, higher version and signing that new manifest; the server refuses to reactivate an old signed envelope or to overwrite it through the legacy editor.
Each new signed release on a channel must have both a strictly higher dotted numeric version and a strictly later `published_at`; publication and clients reject timestamps more than 15 minutes in the future, and clients persist the last accepted value to reject older replayed envelopes.

`payload_b64` is the Base64 encoding of the exact UTF-8 JSON bytes covered by `signature_b64`. Its top-level fields are fixed:

```json
{
  "schema_version": 2,
  "channel": "stable",
  "version": "v20.0.0",
  "min_supported_version": "v19.0.0",
  "mandatory": false,
  "published_at": "2026-07-15T12:00:00Z",
  "target": {
    "url": "/static/releases/<sha256>.exe",
    "sha256": "<64 lowercase hex characters>",
    "size": 201962496,
    "kind": "onefile_exe"
  },
  "deltas": [
    {
      "base_sha256": "<old EXE SHA256>",
      "url": "/static/releases/<patch_sha256>.vfdiff",
      "sha256": "<delta file SHA256>",
      "size": 10485760,
      "algorithm": "visionforge-exe-delta-v1"
    }
  ],
  "notes": "Release notes"
}
```

Publish the envelope to `POST /api/admin/releases/v2`:

```json
{
  "channel": "stable",
  "algorithm": "Ed25519",
  "key_id": "release-key-2026",
  "payload_b64": "...",
  "signature_b64": "..."
}
```

For a signed release, `GET /update/stable.json` keeps the legacy download fields and also returns `target`, `deltas`, `min_supported_version`, `algorithm`, `key_id`, `payload_b64`, and `signature_b64`. Legacy unsigned releases omit all envelope-only fields so older clients remain readable and new clients cannot mistake empty fields for a signature.

## Integrity identity

The executable identity is its content, not its filename. New clients report `executable_sha256` and use `path: "@executable", role: "executable"`; users may rename the EXE without changing its identity. Legacy clients are accepted through file-list fallback only when the list contains exactly one valid `.exe` entry, preventing an official helper EXE from hiding a modified main executable.
