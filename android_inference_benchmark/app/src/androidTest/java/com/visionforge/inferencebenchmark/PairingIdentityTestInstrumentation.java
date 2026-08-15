package com.visionforge.inferencebenchmark;

import com.visionforge.inferencebenchmark.dataplane.AuthenticatedDataPlaneV2InstrumentationProbe;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.Context;
import android.content.SharedPreferences;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Bundle;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * Dependency-free physical-device gate for AndroidKeyStore pairing identity.
 *
 * Run through the generated test APK with connectedDebugAndroidTest or
 * `adb shell am instrument -w <test-package>/<this-class>`.
 */
public final class PairingIdentityTestInstrumentation extends Instrumentation {
    private static final String ARG_MODE = "mode";
    private static final String MODE_QNN_BENCHMARK = "qnn_benchmark";
    private static final String MODE_PORTABLE_BACKEND_PROBE =
            "portable_backend_probe";
    private static final String ENTITLEMENT_STORE =
            "visionforge_dual_machine_entitlement_migration_test_v1";
    private static final String HOST_PUBLIC_KEY_BASE64 =
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaxfR8uEsQkf4vOblY6RA8ncDfYEt"
                    + "6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9Q==";
    private static final String HOST_KEY_SHA256 =
            "5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3";

    private String alias;
    private String pendingActivationAlias;
    private Bundle arguments = Bundle.EMPTY;

    @Override
    public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        this.arguments = arguments == null ? Bundle.EMPTY : new Bundle(arguments);
        start();
    }

    @Override
    public void onStart() {
        Bundle result = new Bundle();
        try {
            if (MODE_QNN_BENCHMARK.equals(arguments.getString(ARG_MODE))) {
                result.putString("stream",
                        MobileQnnBenchmarkRunner.run(getTargetContext(), arguments));
                finish(Activity.RESULT_OK, result);
                return;
            }
            if (MODE_PORTABLE_BACKEND_PROBE.equals(
                    arguments.getString(ARG_MODE))) {
                result.putString(
                        "stream",
                        MobilePortableBackendProbeRunner.run(
                                getTargetContext(), arguments));
                finish(Activity.RESULT_OK, result);
                return;
            }
            alias = "vf-pairing-test-" + Long.toHexString(System.nanoTime());
            deleteFixture();
            verifyIdentityLifecycleAndPolicy();
            deleteFixture();
            verifyConcurrentStoreInstances();
            verifyEntitlementPersistenceFailsClosed();
            verifyPendingActivationRecoveryIsSealedAndFailClosed();
            verifyPublicAuthenticationRouteHonorsActiveVpn();
            AuthenticatedDataPlaneV2InstrumentationProbe.verify();
            int handshakeApiLevel =
                    AuthenticatedPeerHandshakeV1InstrumentationProbe.verify();
            AndroidBoundPeerHandshakeSessionInstrumentationProbe.Result
                    boundPeerResult =
                    AndroidBoundPeerHandshakeSessionInstrumentationProbe.verify();
            result.putString(
                    "stream",
                    "ANDROID_AUTHENTICATED_PEER_HANDSHAKE_V1_INSTRUMENTATION_OK"
                            + " api_level=" + handshakeApiLevel + "\n"
                            + "ANDROID_BOUND_PEER_SESSION_INSTRUMENTATION_OK"
                            + " api_level=" + boundPeerResult.apiLevel
                            + " hardware_backed="
                            + boundPeerResult.hardwareBacked + "\n"
                            + "ANDROID_PAIRING_IDENTITY_INSTRUMENTATION_OK\n");
            finish(Activity.RESULT_OK, result);
        } catch (Throwable failure) {
            result.putString("stream", stackTrace(failure));
            finish(Activity.RESULT_CANCELED, result);
        } finally {
            try {
                deleteFixture();
            } catch (Exception ignoredCleanupFailure) {
                // The primary failure, including its stack, remains authoritative.
            }
        }
    }

    private void verifyPendingActivationRecoveryIsSealedAndFailClosed()
            throws Exception {
        Context context = getTargetContext();
        pendingActivationAlias =
                "vf-pending-test-" + Long.toHexString(System.nanoTime());
        SharedPreferences preferences = context.getSharedPreferences(
                AndroidPendingActivationStore.STORE,
                Context.MODE_PRIVATE);
        require(preferences.edit().clear().commit(),
                "pending activation fixture clear must succeed");
        AndroidPendingActivationStore store =
                new AndroidPendingActivationStore(
                        context, pendingActivationAlias);
        String signature = Base64.getEncoder().encodeToString(
                new byte[64]);
        DualMachineCardAuthorizationCoordinator.PendingActivation expected =
                new DualMachineCardAuthorizationCoordinator
                        .PendingActivation(
                        repeated('1', 32),
                        repeated('2', 32),
                        repeated('3', 32),
                        repeated('A', 43),
                         4_000_000_000L,
                         signature,
                         signature,
                         repeated('4', 64),
                         repeated('5', 64),
                         "visionforge-dual-machine-pairing-identity",
                         DualMachineUsageAuthorizationContract
                                 .ACTIVATION_MODE_REACTIVATE,
                         repeated('6', 32));
        store.save(expected);
        String sealed = preferences.getString(
                AndroidPendingActivationStore.VALUE_KEY, "");
        require(!sealed.isEmpty(),
                "pending activation must be persisted");
        require(!sealed.contains(expected.challengeToken),
                "challenge token must not appear in sealed storage");
        require(!sealed.contains(expected.requestId),
                "request id must not appear in sealed storage");
        require(!sealed.contains(expected.targetEntitlementId),
                "reactivation target must not appear in sealed storage");
        DualMachineCardAuthorizationCoordinator.PendingActivation loaded =
                store.load();
        require(loaded != null,
                "pending activation must round-trip");
        require(loaded.requestId.equals(expected.requestId)
                        && loaded.pairId.equals(expected.pairId)
                        && loaded.challengeId.equals(expected.challengeId)
                        && loaded.challengeToken.equals(
                        expected.challengeToken)
                         && loaded.hostSignatureBase64.equals(signature)
                         && loaded.androidSignatureBase64.equals(signature)
                         && loaded.hostKeyFingerprintSha256.equals(
                         expected.hostKeyFingerprintSha256)
                         && loaded.androidKeyFingerprintSha256.equals(
                         expected.androidKeyFingerprintSha256)
                         && loaded.androidIdentityAlias.equals(
                         expected.androidIdentityAlias)
                         && loaded.activationMode.equals(
                         expected.activationMode)
                         && loaded.targetEntitlementId.equals(
                         expected.targetEntitlementId),
                "pending activation round-trip must be exact");

        byte[] corrupted = Base64.getDecoder().decode(sealed);
        corrupted[corrupted.length - 1] ^= 1;
        require(preferences.edit().putString(
                        AndroidPendingActivationStore.VALUE_KEY,
                        Base64.getEncoder().encodeToString(corrupted))
                        .commit(),
                "corrupt pending activation fixture write must succeed");
        try {
            store.load();
            throw new AssertionError(
                    "tampered pending activation must fail closed");
        } catch (java.security.GeneralSecurityException expectedFailure) {
            // Expected AEAD authentication failure.
        }
        store.clear();
        require(store.load() == null,
                "cleared pending activation must be absent");
    }

    private void verifyIdentityLifecycleAndPolicy() throws Exception {
        AndroidPairingIdentityStore store = new AndroidPairingIdentityStore(alias);
        require(!store.hasIdentity(), "identity must start absent");

        ECPublicKey publicKey = store.getOrCreateIdentity();
        String firstFingerprint = store.fingerprintHex();
        require(store.hasIdentity(), "identity must exist after creation");
        require(
                publicKey.getParams().getCurve().getField().getFieldSize() == 256,
                "identity must use P-256");

        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        Key storedKey = keyStore.getKey(alias, null);
        require(storedKey instanceof PrivateKey, "identity must hold a private key");
        PrivateKey privateKey = (PrivateKey) storedKey;
        require(privateKey.getEncoded() == null, "private key must not be exportable");
        require(privateKey.getFormat() == null, "private key format must not be exportable");

        KeyFactory keyFactory = KeyFactory.getInstance(
                privateKey.getAlgorithm(), "AndroidKeyStore");
        KeyInfo keyInfo = keyFactory.getKeySpec(privateKey, KeyInfo.class);
        require(
                keyInfo.getPurposes() == KeyProperties.PURPOSE_SIGN,
                "identity must be sign-only");
        require(
                Arrays.asList(keyInfo.getDigests()).contains(
                        KeyProperties.DIGEST_SHA256),
                "identity must permit SHA-256");

        byte[] payload = "visionforge-device-pairing-pop"
                .getBytes(StandardCharsets.UTF_8);
        byte[] signature = store.sign(payload);
        require(
                DualMachinePairingIdentityCodec.verify(
                        store.publicKeySpkiDer(), payload, signature),
                "valid device signature must verify");
        payload[0] ^= 1;
        require(
                !DualMachinePairingIdentityCodec.verify(
                        store.publicKeySpkiDer(), payload, signature),
                "tampered payload must fail verification");

        AndroidPairingIdentityStore reopened =
                new AndroidPairingIdentityStore(alias);
        require(
                firstFingerprint.equals(reopened.fingerprintHex()),
                "reopened identity must remain stable");

        reopened.deleteIdentity();
        require(!store.hasIdentity(), "deleted local identity must be absent");
        String replacementFingerprint = store.fingerprintHex();
        require(
                !firstFingerprint.equals(replacementFingerprint),
                "explicit deletion must create a fresh replacement identity");
    }

    private void verifyConcurrentStoreInstances() throws Exception {
        deleteFixture();
        int workerCount = 8;
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(workerCount);
        try {
            @SuppressWarnings("unchecked")
            Future<String>[] futures = new Future[workerCount];
            for (int index = 0; index < workerCount; index++) {
                futures[index] = executor.submit(() -> {
                    start.await();
                    return new AndroidPairingIdentityStore(alias).fingerprintHex();
                });
            }
            start.countDown();
            Set<String> fingerprints = new HashSet<>();
            for (Future<String> future : futures) {
                fingerprints.add(future.get());
            }
            require(
                    fingerprints.size() == 1,
                    "concurrent store instances must share one identity");
        } finally {
            executor.shutdownNow();
        }
    }

    private void verifyEntitlementPersistenceFailsClosed() throws Exception {
        Context context = getTargetContext();
        SharedPreferences preferences = context.getSharedPreferences(
                ENTITLEMENT_STORE, Context.MODE_PRIVATE);
        require(preferences.edit().clear().commit(),
                "entitlement fixture clear must succeed");
        AndroidPairingIdentityStore identity =
                new AndroidPairingIdentityStore(alias);
        DualMachineEntitlementRecord expected =
                new DualMachineEntitlementRecord(
                        repeated('a', 32),
                        repeated('b', 32),
                        2,
                        7L,
                        HOST_KEY_SHA256,
                        HOST_PUBLIC_KEY_BASE64,
                        identity.fingerprintHex(),
                        alias);
        SharedPreferencesDualMachineEntitlementStore store =
                new SharedPreferencesDualMachineEntitlementStore(preferences);
        store.save(expected);
        require(expected.equals(store.load()),
                "entitlement binding must round-trip");

        DualMachineEntitlementRecord legacyBalance =
                new DualMachineEntitlementRecord(
                        repeated('c', 32),
                        repeated('d', 32),
                        2,
                        8L,
                        HOST_KEY_SHA256,
                        HOST_PUBLIC_KEY_BASE64,
                        identity.fingerprintHex(),
                        alias,
                        "legacy_balance",
                        "legacy_balance",
                        false,
                        false);
        writeLegacyEntitlementFixture(
                preferences, legacyBalance, 2, false, false);
        require(legacyBalance.equals(store.load()),
                "schema-2 balance entitlement must survive migration");
        require(preferences.getInt("schema_version", -1) == 4,
                "schema-2 entitlement migration must commit the current schema");

        DualMachineEntitlementRecord revokedLegacyBalance =
                new DualMachineEntitlementRecord(
                        repeated('e', 32),
                        repeated('f', 32),
                        2,
                        10L,
                        HOST_KEY_SHA256,
                        HOST_PUBLIC_KEY_BASE64,
                        identity.fingerprintHex(),
                        alias,
                        "legacy_balance",
                        "legacy_balance",
                        false,
                        true);
        writeLegacyEntitlementFixture(
                preferences, revokedLegacyBalance, 3, false, true);
        require(revokedLegacyBalance.equals(store.load()),
                "schema-3 revoked balance entitlement must survive migration");
        require(preferences.getInt("schema_version", -1) == 4,
                "schema-3 entitlement migration must commit the current schema");

        writeLegacyEntitlementFixture(
                preferences, revokedLegacyBalance, 3, false, false);
        Map<String, ?> missingRevokedSnapshot = preferences.getAll();
        try {
            store.load();
            throw new AssertionError(
                    "schema-3 entitlement without revoked marker must fail closed");
        } catch (SecurityException expectedFailure) {
            require(missingRevokedSnapshot.equals(preferences.getAll()),
                    "incomplete schema-3 entitlement must not erase user binding");
        }

        DualMachineEntitlementRecord legacyPermanent =
                new DualMachineEntitlementRecord(
                        repeated('1', 32),
                        repeated('2', 32),
                        2,
                        9L,
                        HOST_KEY_SHA256,
                        HOST_PUBLIC_KEY_BASE64,
                        identity.fingerprintHex(),
                        alias,
                        "permanent",
                        "permanent",
                        true,
                        false);
        for (int schemaVersion : new int[] {2, 3}) {
            writeLegacyEntitlementFixture(
                    preferences,
                    legacyPermanent,
                    schemaVersion,
                    true,
                    schemaVersion >= 3);
            require(legacyPermanent.equals(store.load()),
                    "legacy permanent entitlement must survive migration");
            require(preferences.getInt("schema_version", -1) == 4,
                    "legacy permanent migration must commit current schema");
        }

        require(preferences.edit().putInt("schema_version", 99).commit(),
                "unsupported entitlement fixture write must succeed");
        Map<String, ?> unsupportedSnapshot = preferences.getAll();
        try {
            store.load();
            throw new AssertionError(
                    "unsupported entitlement schema must fail closed");
        } catch (SecurityException expectedFailure) {
            require(unsupportedSnapshot.equals(preferences.getAll()),
                    "unsupported entitlement schema must not erase user binding");
        }
        store.save(expected);
        DualMachineEntitlementRecord revoked =
                expected.withRevocationVersion(8L);
        store.save(revoked);
        require(revoked.equals(store.load()) && store.load().revoked,
                "revoked entitlement marker must round-trip");
        require(preferences.edit()
                        .putString("schema_version", "corrupt-type")
                        .commit(),
                "corrupt entitlement fixture write must succeed");
        try {
            store.load();
            throw new AssertionError(
                    "corrupt entitlement schema type must fail closed");
        } catch (SecurityException expectedFailure) {
            // Expected.
        } finally {
            store.clear();
        }
    }

    private static void writeLegacyEntitlementFixture(
            SharedPreferences preferences,
            DualMachineEntitlementRecord record,
            int schemaVersion,
            boolean includeAuthorization,
            boolean includeRevoked) {
        SharedPreferences.Editor editor = preferences.edit().clear()
                .putInt("schema_version", schemaVersion)
                .putString("entitlement_id", record.entitlementId)
                .putString("pair_id", record.pairId)
                .putInt("protocol_version", record.protocolVersion)
                .putLong("revocation_version", record.revocationVersion)
                .putString("host_key_sha256", record.hostKeySha256)
                .putString(
                        "host_identity_public_key_base64",
                        record.hostIdentityPublicKeyBase64)
                .putString("android_key_sha256", record.androidKeySha256)
                .putString(
                        "android_identity_alias",
                        record.androidIdentityAlias);
        if (includeAuthorization) {
            editor.putString("authorization_kind", record.authorizationKind)
                    .putString("product_key", record.productKey)
                    .putBoolean("permanent", record.permanent);
        }
        if (includeRevoked) editor.putBoolean("revoked", record.revoked);
        require(editor.commit(),
                "legacy entitlement fixture write must succeed");
    }

    private void verifyPublicAuthenticationRouteHonorsActiveVpn()
            throws Exception {
        Context context = getTargetContext();
        AndroidValidatedInternetNetworkProvider provider =
                new AndroidValidatedInternetNetworkProvider(context);
        final Network selected;
        try {
            selected = provider.requireValidatedInternetNetwork();
        } catch (IOException unavailable) {
            require(
                    "no validated VPN, Wi-Fi or cellular authentication route"
                            .equals(unavailable.getMessage()),
                    "unavailable public route must fail with bounded reason");
            return;
        }
        ConnectivityManager manager = (ConnectivityManager)
                context.getSystemService(Context.CONNECTIVITY_SERVICE);
        require(manager != null,
                "ConnectivityManager must exist for a selected route");
        NetworkCapabilities capabilities =
                manager.getNetworkCapabilities(selected);
        LinkProperties properties = manager.getLinkProperties(selected);
        Network activeNetwork = manager.getActiveNetwork();
        require(capabilities != null,
                "selected public route capabilities must remain available");
        DualMachineInternetRoutePolicy.Candidate candidate =
                new DualMachineInternetRoutePolicy.Candidate(
                        capabilities.hasCapability(
                                NetworkCapabilities.NET_CAPABILITY_INTERNET),
                        capabilities.hasCapability(
                                NetworkCapabilities.NET_CAPABILITY_VALIDATED),
                        capabilities.hasTransport(
                                NetworkCapabilities.TRANSPORT_ETHERNET),
                        capabilities.hasTransport(
                                NetworkCapabilities.TRANSPORT_WIFI),
                        capabilities.hasTransport(
                                NetworkCapabilities.TRANSPORT_CELLULAR),
                        capabilities.hasTransport(
                                NetworkCapabilities.TRANSPORT_VPN),
                        selected.equals(activeNetwork),
                        properties == null
                                ? "" : properties.getInterfaceName());
        require(DualMachineInternetRoutePolicy.eligible(candidate),
                "selected public route must remain validated and eligible");
        if (candidate.vpn) {
            require(candidate.active,
                    "selected VPN must remain Android's active network");
        } else {
            require(!candidate.ethernet
                            && !DualMachineInternetRoutePolicy
                            .ISOLATED_CAT6_INTERFACE.equals(
                            candidate.interfaceName),
                    "isolated Ethernet must never carry sidecar authentication");
        }
    }

    private void deleteFixture() throws Exception {
        if (alias != null) {
            new AndroidPairingIdentityStore(alias).deleteIdentity();
        }
        Context context = getTargetContext();
        context.getSharedPreferences(
                AndroidPendingActivationStore.STORE,
                Context.MODE_PRIVATE).edit().clear().commit();
        if (pendingActivationAlias != null) {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            if (keyStore.containsAlias(pendingActivationAlias)) {
                keyStore.deleteEntry(pendingActivationAlias);
            }
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private static String repeated(char character, int count) {
        StringBuilder value = new StringBuilder(count);
        for (int index = 0; index < count; index++) {
            value.append(character);
        }
        return value.toString();
    }

    private static String stackTrace(Throwable failure) {
        StringWriter buffer = new StringWriter();
        failure.printStackTrace(new PrintWriter(buffer));
        return "ANDROID_PAIRING_IDENTITY_INSTRUMENTATION_FAILED\n" + buffer;
    }

}
