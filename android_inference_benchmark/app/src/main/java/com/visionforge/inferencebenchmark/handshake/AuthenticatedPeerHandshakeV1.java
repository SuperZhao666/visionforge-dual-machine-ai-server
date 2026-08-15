package com.visionforge.inferencebenchmark.handshake;

/**
 * Public entry point for the dependency-free Android/JCA peer-handshake v1 foundation.
 *
 * <p>This package provides the frozen transcript, fresh ephemeral P-256 ECDH, HKDF-SHA256,
 * Finished, and channel-binding primitives. It does not perform first-pairing authentication,
 * verify long-term identity signatures, install a lease, or enable a production data path. A
 * caller must verify both transcript identity signatures against an already trusted pairing
 * record before invoking key derivation. Derivation returns an unconfirmed owner that exposes
 * only the fixed local Finished proof and peer-Finished confirmation; traffic material is
 * available only through the confirmed type returned after both proofs exist.
 *
 * <p>The only public ephemeral-key factory generates a fresh key internally. There is no public
 * API for a caller-selected private scalar, ECDH secret, HKDF label, or successful crypto-provider
 * seam.
 */
public final class AuthenticatedPeerHandshakeV1 {
    public static final int PROTOCOL_VERSION = 1;
    public static final int SHA256_BYTES = 32;
    public static final int P256_SEC1_UNCOMPRESSED_BYTES = 65;
    public static final int NONCE_BYTES = 32;
    public static final int CONTROL_MATERIAL_BYTES = 36;
    public static final int DATA_PLANE_MATERIAL_BYTES = 36;
    public static final int FINISHED_MAC_BYTES = 32;
    public static final int CHANNEL_BINDING_BYTES = 32;

    private AuthenticatedPeerHandshakeV1() {}

    public static HandshakeTranscriptV1.Builder newTranscriptBuilder() {
        return new HandshakeTranscriptV1.Builder();
    }

    /** Parses one complete, canonical, attacker-controlled 18-field transcript. */
    public static HandshakeTranscriptV1 parseTranscript(byte[] encoded)
            throws AuthenticatedPeerHandshakeV1Exception {
        return HandshakeTranscriptV1.parse(encoded);
    }

    /** Generates a fresh, one-session P-256 ephemeral key through the installed JCA provider. */
    public static FreshP256KeyAgreement generateFreshEphemeralKeyAgreement()
            throws AuthenticatedPeerHandshakeV1Exception {
        return FreshP256KeyAgreement.generate();
    }

    public enum Role {
        HOST(1),
        ANDROID(2);

        private final int wireCode;

        Role(int wireCode) {
            this.wireCode = wireCode;
        }

        int wireCode() {
            return wireCode;
        }
    }

    public enum TransportKind {
        CAT6(1),
        WLAN(2);

        private final int wireCode;

        TransportKind(int wireCode) {
            this.wireCode = wireCode;
        }

        int wireCode() {
            return wireCode;
        }

        static TransportKind fromWireCode(int wireCode) {
            for (TransportKind kind : values()) {
                if (kind.wireCode == wireCode) return kind;
            }
            return null;
        }
    }
}
