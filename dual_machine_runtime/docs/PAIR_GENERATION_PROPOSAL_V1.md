# Pair generation proposal v1

## Status and boundary

`visionforge-peer-generation-proposal-v1` is a frozen, cross-language cryptographic foundation for the values that must exist before the server allocates a pair-session generation. It is implemented independently in Python, C++20/BCrypt and Java 8/JCA.

It is not a production pairing protocol. It does not authenticate a first pairing, prove an entitlement, allocate or sign a generation, register a route, install a lease, charge usage, derive traffic keys, or enable Host/Android runtime services. `VFDUAL_FORMAL_SECURITY_IMPLEMENTED` and `formalSecureDataPlaneImplemented` remain false.

The proposal deliberately does not contain `entitlement_id`, `binding_id`, `binding_revision`, revocation state, or a credential. Those belong to the later server-authoritative generation-allocation credential. Adding them informally to proposal v1 would create two competing sources of authority.

## Canonical encoding

The encoding is exactly 17 TLVs in ascending tag order. Every TLV is:

```text
[tag: u8][length: u32 big-endian][value: exact length bytes]
```

| Tag | Value | Contract |
|---:|---|---|
| 0 | domain | exact ASCII `visionforge-peer-generation-proposal-v1` |
| 1 | version | exact u32 big-endian `1` |
| 2 | Host identity SPKI hash | SHA-256, exactly 32 bytes |
| 3 | Android identity SPKI hash | SHA-256, exactly 32 bytes; both identity hashes are non-zero and different |
| 4 | Host ephemeral public key | valid P-256 SEC1 uncompressed point, exactly 65 bytes |
| 5 | Android ephemeral public key | valid P-256 SEC1 uncompressed point, exactly 65 bytes; both points are different |
| 6 | Host nonce | exactly 32 bytes, non-zero |
| 7 | Android nonce | exactly 32 bytes, non-zero and different from the Host nonce |
| 8 | connection ID | u64 big-endian representation restricted to `1..INT64_MAX` |
| 9 | transport | u8: CAT6 `1`, WLAN `2` |
| 10 | Host IPv4 | exactly 4 bytes |
| 11 | Android IPv4 | exactly 4 bytes |
| 12 | video port | non-zero u16 big-endian |
| 13 | control port | non-zero u16 big-endian and different from the video port |
| 14 | pair ID | exactly 32 lowercase hexadecimal ASCII bytes |
| 15 | Host runtime version | strict ASCII stable SemVer `x.y.z`, 1–32 bytes, no leading zero, prerelease or build suffix |
| 16 | Android runtime version | same contract as tag 15 |

The maximum accepted container is exactly 503 bytes. Parsers reject oversized input before copying it, then reject missing, extra, duplicate, unknown, out-of-order, truncated, trailing, wrong-length and non-canonical encodings. Builders and parsers compute SHA-256 themselves; there is no caller-supplied digest API. Validated owners are immutable and copy peer-controlled byte arrays defensively.

Python byte-like inputs are first converted to their exact immutable byte representation and only then checked by actual byte length. Typed, multidimensional and non-contiguous `memoryview` values therefore cannot exploit element-count versus byte-count differences. Security scalar inputs require the exact built-in `int` type; `bool` and behavior-overriding `int` subclasses are rejected before comparisons or `to_bytes` calls.

The Python verified owner does not retain a replaceable field bag. Its canonical bytes, SHA-256 and normalized fields are registered in an external weak identity registry. Every accessor verifies the registered slot identities and recomputed digest; the proposal-to-final transition additionally reparses the registered canonical bytes and compares the canonical bytes, hash and every normalized field before using them. Direct `object.__setattr__` replacement of private slots, including coordinated canonical/hash replacement, therefore fails closed.

Public errors contain only an enumerated reason and, where useful, a tag number. They do not include raw identity, nonce, endpoint, pair/version text or a crypto-provider cause.

## Required field authority and attempt lifecycle

The foundation validates bytes, not their authority. A later production coordinator must enforce all of the following before it may submit or accept this proposal:

1. Load `pair_id` from the server-verified active entitlement/binding record. A caller-provided JSON pair ID is not authoritative. The later signed generation credential must separately bind entitlement, binding ID, binding revision, revocation version, proposal hash and generation.
2. Create fresh Host and Android P-256 ephemeral keys and fresh 32-byte nonces for one attempt. Neither key nor nonce may be recycled after any rejection or network change.
3. Produce `connection_id` either from an unbiased non-zero 63-bit CSPRNG value or from a domain-separated controlled derivation that includes both fresh nonces and a fresh server challenge. It must never be a timestamp, PID, counter supplied by one peer, or arbitrary request field.
4. Source transport, both IPv4 addresses and both ports from the actual direct-link/socket context used by this attempt. Configuration text, DHCP intent, UI state and caller JSON do not prove the endpoint tuple.
5. Canonicalize and hash the 17 fields on each verifying side. Only an identical verified proposal may advance to server generation allocation.
6. Allocate a new positive signed-64 generation through the server high-water transaction and bind it to this exact proposal hash in the later signed credential.
7. Use the restricted proposal-to-final helper to insert that generation as final transcript tag 9. The helper copies and revalidates every other field; callers cannot replace an authorized field subset or supply a transcript hash.

If the route, DHCP lease, address, port, transport, socket or direct-link identity changes at any point, the attempt is burned. Both peers must discard their ephemeral key/nonces, obtain a new server challenge, create a new proposal and—if a generation was already allocated—consume a new higher generation. An old immutable allocation must never be edited or re-signed for the replacement tuple.

## Restricted transition to the final handshake transcript

The final `visionforge-peer-handshake-v1` transcript has 18 fields. Tags 0 and 1 switch to the final domain/version contract; proposal tags 2–8 remain final tags 2–8; the server generation is inserted at final tag 9; proposal tags 9–16 become final tags 10–17 unchanged.

The only public transition APIs accept a verified proposal owner plus a positive signed-64 generation:

- Python: `build_final_handshake_transcript_v1(...)`
- C++: `build_final_peer_handshake_transcript_from_proposal_v1(...)`
- Java: `PairGenerationProposalV1.buildFinalHandshakeTranscript(...)`

Python returns a restricted mirror used for server-side cross-language evidence. C++ and Java delegate to the existing strict 18-field transcript builders. None accepts a field bag or digest during this transition.

## Frozen cross-language vector

Vector values use Host identity bytes `00..1f`, Android identity bytes `20..3f`, Host nonce bytes `40..5f`, Android nonce bytes `60..7f`, P-256 public points for private scalars 1 and 2, connection `0x1020304050607080`, CAT6, `192.168.55.1` / `192.168.55.2`, ports `45678` / `45679`, pair ID `0123456789abcdef0123456789abcdef`, and runtime versions `17.8.47`. The final generation is `0x0102030405060708`.

Proposal canonical length: `453` bytes.

Proposal canonical bytes (hex):

```text
0000000027766973696f6e666f7267652d706565722d67656e65726174696f6e2d70726f706f73616c2d76310100000004000000010200000020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0300000020202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f0400000041046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f50500000041047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d10600000020404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f0700000020606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f080000000810203040506070800900000001010a00000004c0a837010b00000004c0a837020c00000002b26e0d00000002b26f0e0000002030313233343536373839616263646566303132333435363738396162636465660f0000000731372e382e3437100000000731372e382e3437
```

Proposal SHA-256:

```text
89669a6d4e73b4ae9e9e44e042c75426a520f611009077d5caa5a8fafad9732d
```

Final transcript canonical length: `456` bytes.

Final transcript SHA-256:

```text
ea8f01700d0921665958fcb8dc0f9abf657499cc7423ff37dd6efbd233025098
```

The Python, C++ and Java tests freeze the same canonical proposal bytes, proposal hash and final transcript hash. This is interoperability evidence for the pure contract, not evidence of a production identity exchange, signed generation credential, physical device, TPM/TEE or complete dual-machine security closure.
