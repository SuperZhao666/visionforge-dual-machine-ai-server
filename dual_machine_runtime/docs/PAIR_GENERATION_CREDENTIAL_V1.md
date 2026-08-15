# Pair-generation credential v1 and server issuance

## 1. Status and security boundary

This document specifies the isolated RS256 cryptographic boundary in
`server/visionforge-platform/dual_machine_service/pair_generation_credential_v1.py`.
The production Sidecar now composes that boundary with double-PoP
authorization, atomic persistence, and public challenge/credential routes.
Its current evidence flags are intentionally:

```text
cryptographic_foundation_present=true
transactional_issuance_service_present=true
strict_public_verifier_present=true
authoritative_service_wired=true
immutable_issuance_journal_wired=true
public_route_registered=true
host_operation_boundary_verifier_wired=false
android_operation_boundary_verifier_wired=false
formal_security_implemented=false
```

The cryptographic module does not read settings, access either database, register an HTTP
route, activate a pair, bill usage, issue a runtime lease, or change a formal
release flag. Its only proposal claim is an already-authoritative
`transcript_proposal_sha256` value. Proposal parsing and live authorization
belong to the orchestration layer rather than this primitive.

The cryptographic module alone must not be described as a production
credential issuer. The signing source, signer, and signed issuance result are
module-private. The public surface contains only a constructible expected
verification context, a strict verifier, an immutable verified owner,
constants, and sanitized errors.

`pair_generation_credential_service.py` now contains the only trusted
`PairGenerationCredentialService` permitted to mint the private source from
authoritative state. It atomically joins the repository allocation transaction
to the separate immutable journal. `pair_generation_authorization_service.py`
requires Host and Android P-256 signatures for both the pre-proposal challenge
and the final credential proof, reparses the canonical proposal, derives the
server nonce/connection authority, and rechecks the live tuple inside the same
write transaction. `pair_generation_composition.py` loads the dedicated
production RSA keyring, and `routes.py` publishes the two strict endpoints.
Those server facts do not make Host/Android consumption or formal capability
complete.

## 2. Dedicated key contract

The credential uses only RSA PKCS#1 v1.5 with SHA-256 (`RS256`). Every current
or previous public key must satisfy all of these requirements:

- RSA modulus size is at least 3072 bits;
- public exponent is exactly 65537;
- the current private key resolves to exactly the configured current public
  key;
- the online verification ring contains one to three keys total, including
  current and at most two previous keys;
- the journal replay archive may add at most 13 verification-only public keys,
  for an overall current/previous/archive closure of at most 16 keys;
- canonical public material is DER SubjectPublicKeyInfo;
- caller-provided RSA objects are never retained as verification authorities:
  their strictly typed `RSAPublicNumbers` are used to build a fresh
  provider-owned public key, and all subsequent SPKI, `kid`, separation, and
  signature operations use only that rebuilt object;
- `kid` is the first 16 lowercase hexadecimal characters of
  `SHA-256(canonical DER SPKI)`;
- duplicate SPKI bytes and duplicate `kid` values are rejected;
- pair-credential SPKI SHA-256 values must be disjoint from every passed
  usage-lease, runtime-ticket, release, or other-purpose RSA key ring.

Only the current private key may sign. Previous and archived keys are
verification-only. Archived keys are never accepted as an online signing
fallback; they exist solely so an immutable historical journal row can be
verified and returned byte-for-byte after an older online key leaves rotation.
The private signer likewise rebuilds a provider-owned private key from strict
`RSAPrivateNumbers`; a caller-defined subclass cannot replace `sign()` or
`public_key()` with a permissive implementation. Immediate post-verification
uses the independently rebuilt public key even if a future provider adapter is
changed.

The composition layer is responsible for passing all other-purpose public
keys to the separation check; this module deliberately does not read settings
or discover those rings itself. Reusing a usage/runtime signing key as the
pair-generation key is a configuration failure, not a supported fallback.

## 3. Compact JWT and canonical encoding

The credential is an ASCII compact JWT with exactly three non-empty segments
and at most 8192 characters. Each segment uses unpadded base64url. Decoding a
segment and encoding it again must reproduce the original segment byte for
byte, so padding and alternate encodings are rejected.

Header JSON has exactly these keys and values:

```json
{"alg":"RS256","kid":"<derived-16-lowerhex>","typ":"JWT"}
```

Header and payload JSON use:

```python
json.dumps(
    value,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=True,
    allow_nan=False,
)
```

The input bytes must exactly equal the re-encoded canonical bytes. Duplicate,
extra, and missing JSON members are rejected. `NaN`, infinity, non-ASCII JSON,
whitespace variants, and reordered objects are not accepted as equivalent.

## 4. Exact signed claims

The payload contains exactly the following claims; there is no extensible
claim bag and no caller-provided nonce, token, header, digest, or dictionary:

| Claim | Contract |
|---|---|
| `typ` | `vf-dual-machine-pair-generation-credential-v1` |
| `iss` | `visionforge-dual-machine-service` |
| `aud` | `visionforge-dual-machine-peer-handshake-v1` |
| `allocation_request_id` | 1–128 ASCII characters from `[A-Za-z0-9._:-]`; immutable journal key |
| `pair_id` | exactly 32 lowercase hexadecimal characters |
| `entitlement_id` | exactly 32 lowercase hexadecimal characters |
| `binding_id` | exactly 32 lowercase hexadecimal characters |
| `binding_revision` | JSON integer, `1..INT64_MAX`; booleans, strings, and floats are rejected |
| `revocation_version` | same strict signed-64 contract |
| `generation` | same strict signed-64 contract |
| `connection_id` | same strict signed-64 contract |
| `host_identity_spki_sha256` | exactly 64 lowercase hexadecimal characters |
| `android_identity_spki_sha256` | exactly 64 lowercase hexadecimal characters and different from Host |
| `transcript_proposal_sha256` | exactly 64 lowercase hexadecimal characters |
| `credential_nonce` | 32 bytes generated internally with `secrets.token_bytes`, encoded as 64 lowercase hex |
| `iat` | strict signed-64 JSON integer |
| `nbf` | strict signed-64 JSON integer and exactly equal to `iat` |
| `exp` | strict signed-64 JSON integer, greater than `iat` |

`allocation_request_id` is signed because it is the unique immutable issuance
journal key. It prevents a credential for one allocation request from being
accepted under a different expected request even when all other fields happen
to match.

`allocated_at_epoch` is not a peer claim. It is private authoritative server
metadata used only to authorize signing: issuance must occur at or after the
allocation timestamp and no more than five seconds later. The issuance service
obtains it from the allocation created in the open write transaction; it never
accepts it from a request or reconstructs it from client time.

## 5. Time contract

- Default credential lifetime is 15 seconds.
- Configured and received lifetime must be at least one second and no more
  than 30 seconds.
- `nbf == iat` and `exp > iat` are mandatory.
- Verification tolerates `iat` at most two seconds in the future.
- Expiration grace is zero: a credential is invalid when `now >= exp`.
- All epoch inputs are real Python/JSON integers in `1..INT64_MAX`; `bool`,
  string, and float coercion is forbidden.
- Issuance rejects arithmetic that could overflow the signed-64 contract.

## 6. Issuance and verification sequence

The private foundation signing sequence is fail closed:

1. require the exact module-private authoritative source type;
2. validate its public expected fields and private allocation timestamp;
3. enforce the five-second allocation-to-issuance window;
4. generate a fresh internal 32-byte credential nonce;
5. construct the exact canonical payload and header;
6. sign using the dedicated current RSA key;
7. immediately run the public verifier with the corresponding key and the
same expected allocation context;
8. require the verified `kid` to equal the current signing `kid`;
9. only then return the private immutable result containing token bytes,
   token SHA-256, `kid`, and typed verified claims.

The public verification sequence validates the expected context first, then
the compact/canonical envelope, exact header, bounded known `kid`, RS256
signature, exact claims and types, time rules, and every expected committed
field. It returns only `VerifiedPairGenerationCredentialV1`. The verified
owner does not store mutable claim fields. Its properties read an immutable
snapshot from two closure-owned `WeakKeyDictionary` stores protected by one
`RLock`. No registry, write-side registration callback, or owner factory is
left on the module surface after the verifier method is installed. The object
contains only minimal canonical-token identity slots; every property checks
that those slots still reference the registered bytes and digest, recomputes
the token SHA-256, and reparses and reverifies the signature, original expected
context, and verification epoch. The reconstructed claims must also equal the
registered snapshot. Merely importing the module-private constructor sentinel
cannot create a registered owner, and ordinary module callers cannot register
an attacker-selected key or expected context for a forged owner.

This misuse-resistant Python owner is not a language-level authorization
capability against arbitrary code execution inside the Sidecar process.
Python code with process compromise can inspect closures, monkeypatch module
globals, or modify interpreter memory. A future security-sensitive consumer
must receive the compact token plus authoritative expected context and invoke
a build-pinned verifier at the operation boundary; it must never authorize an
operation from the Python owner type alone. Process isolation and OS access
control, not private Python names, define the hostile-code boundary.
`object.__setattr__` cannot add or replace a claim property, and modifying an
identity slot makes all later access fail closed with a sanitized owner error.

All outward failures use `PairGenerationCredentialError` and stable,
non-sensitive error codes. Provider exceptions are consumed before the public
error is created; errors do not retain a provider cause, token, claim object,
key, identity, or proposal digest.

## 7. Transactional issuance journal and remaining hard blockers

RS256 PKCS#1 v1.5 is deterministic for a fixed message, but
`credential_nonce` is intentionally random. Calling the private signer twice
for the same allocation therefore creates two credentials for the same
generation. `PairGenerationCredentialService` prevents that by implementing
all of the following in one `BEGIN IMMEDIATE` transaction:

1. reserve `allocation_request_id` and generation by compare-and-swap in a
   transaction;
2. revalidate the live entitlement, pair, binding revision, revocation
   version, identity hashes, connection ID, and proposal SHA-256;
3. permit exactly one mint operation for the allocation;
4. persist the exact token bytes, token SHA-256, `kid`, nonce commitment, and
   issuance timestamps in an append-only/immutable issuance journal before
   returning any response;
5. on concurrent, delayed, or post-crash exact retry, return the same persisted
   token bytes instead of signing again;
6. reject a reused allocation request with any conflicting expected field;
7. make journal/state rollback and credential replacement fail closed;
8. expose no generic signing endpoint and never accept caller-produced claims,
   nonce, `allocated_at_epoch`, or proposal digest as authoritative.

The journal is a separate `dm_pair_generation_credentials` table keyed by the
immutable allocation request. It stores the exact compact-token ASCII bytes as
a SQLite BLOB, token SHA-256, signing `kid`, SHA-256 commitment of the random
credential nonce, and exact `iat`/`nbf`/`exp`. Update and delete triggers are
reinstalled on initialization. An insert trigger requires issuance within the
five-second authoritative allocation window. The service then reads the row
back and independently verifies its signature, expected claims, hashes,
commitments, and times before the transaction may commit.

The v7 token/hash columns formerly embedded in the allocation table are not
trusted and are never imported. The v8 migration continues to remove them;
v10 creates the independent journal only after allocation migration is
complete. A pre-existing allocation without a journal row is treated as an
unrecoverable half-state and is never adopted or signed later.

Exact retries revalidate the live active entitlement, current binding,
binding revision, revocation version, both identity hashes, allocation tuple,
and proposal hash. They verify the stored credential at its immutable issuance
epoch and return the same bytes even if the credential has since expired.
This does not make an expired credential usable: Host and Android must verify
against current time and start a fresh challenge/generation when it is no
longer valid. It only guarantees that a retry cannot create a second nonce or
credential for one allocation.

The service issue DTO accepts a strict `VerifiedPairGenerationProposalV1`
owner rather than raw `pair_id`, identity hashes, `connection_id`, or proposal
digest fields. Pair ID, both identity hashes, connection ID, and proposal
SHA-256 are derived inside the service from that immutable owner and then
matched to live server state. The still-missing network-attempt coordinator
must separately prove that the proposal endpoint tuple came from the actual
socket/direct-link context; validated proposal bytes alone do not prove that
physical authority.

Production composition and the public server routes are now implemented. The
bootstrap generates a dedicated RSA-3072 pair-credential keypair independently
from the usage-ticket keypair, installs both with `0600` ownership, and writes
the current/previous/archive/TTL settings. Startup rejects private/public
mismatch, weak RSA, exponent mismatch, duplicate key material, wrong passwords,
oversized rings, or actual SPKI reuse across the two purposes.

The remaining blockers are both consumers and the physical connection binding.
There is still no Host or Android operation-boundary credential verifier wired
into the authenticated handshake. The network-attempt coordinator also still
must prove that the signed proposal endpoint tuple belongs to the actual
socket/direct-link attempt. Fresh card activation, reactivation, and
device-binding confirmations perform the proof-verifying pair-state bootstrap:
both P-256 signatures are rechecked inside the write transaction before a
private proof capability may create/advance an `active` state. Old consumed
confirmations are not retroactively upgraded; a `legacy_blocked` pair needs a
fresh signed reactivation or binding proof. Therefore
`authoritative_service_wired=true`, `public_route_registered=true`, and
`formal_security_implemented=false` are the required evidence values. No
route, lease, billing, pairing activation, data-plane operation, or formal
release gate may treat server issuance alone as a completed trust chain.

## 8. Current test evidence

`dual_machine_service/tests/test_pair_generation_credential_v1.py` generates
temporary RSA keys at test time and covers:

- exact canonical token bytes and immediate post-verification;
- one-to-three-key rotation and canonical SPKI-derived `kid`;
- RSA 2048, exponent mismatch, current-key mismatch, duplicate rings, and
  cross-purpose SPKI reuse;
- malicious RSA public/private subclasses with no-op `verify()`/`sign()`;
- wrong algorithm, type, issuer, audience, key ID, and signature key;
- noncanonical JSON/base64url, padding, duplicate/extra/missing members, and
  compact-token bounds;
- every integer type and signed-64 boundary, identifier/hash syntax, identity
  separation, expected-field mismatch, TTL/future/expiration boundaries, and
  private allocation freshness;
- absence of a public signing oracle, immutable verified/result objects,
  unregistered sentinel construction, identity-slot tampering, absence of any
  module-visible registry or write-side anchor-registration callback,
  fail-closed post-verification, and sanitized provider failures.

The tests create no production key and add no owner or release private key to
the repository.

`dual_machine_service/tests/test_pair_generation_credential_service.py`
additionally covers:

- first allocation/sign/post-verify/persist/read-back in one transaction;
- concurrent exact retries producing one stored token and nonce commitment;
- restart and delayed/expired exact replay returning identical bytes;
- one-winner semantics for the same challenge and conflict rejection for a
  reused allocation request with a changed payload or tuple;
- signer failure, immediate post-verification failure, and journal insert
  failure rolling back challenge consumption, allocation, and high-water;
- refusal to adopt an allocation committed without a journal row;
- current/previous key rotation and failure when the signing key is no longer
  in the verification ring;
- stored token, SHA-256, `kid`, nonce commitment, and live assurance/binding/
  revocation drift failing closed;
- immutable journal triggers, weak-trigger replacement, v8/v9/v10/v11 migration
  history, and downgrade/operator-recovery boundaries.

`dual_machine_service/tests/test_pair_generation_authorization_service.py`
covers both registered P-256 signatures, server-nonce and connection-ID
derivation, canonical proposal ownership, live rechecks under the issuance
transaction, rollback when success audit persistence fails, strict public wire
types, concurrent exact retry, and both public routes.

`dual_machine_service/tests/test_pair_generation_composition.py` and
`test_deployment_contract.py` cover dedicated current/previous/archive loading,
RSA/private-public/password failures, cross-purpose SPKI separation, 16-key
journal-verifier bounds, strict environment JSON, TTL limits, independent
RSA-3072 bootstrap generation, `0600` permissions, and the production
environment-variable closure.
