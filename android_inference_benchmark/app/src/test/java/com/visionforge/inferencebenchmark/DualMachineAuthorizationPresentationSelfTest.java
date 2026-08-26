package com.visionforge.inferencebenchmark;

import com.visionforge.inferencebenchmark.ui.DualMachineAuthorizationUiState;
import com.visionforge.inferencebenchmark.ui.DualMachineAuthorizationUiMapper;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Locale;

/** Dependency-free card input and authorization capability regression checks. */
public final class DualMachineAuthorizationPresentationSelfTest {
    private static final String ISSUED_CARD =
            "VFD2-9FW4B-TVHCV-B7EKW-YHVHR-E77GF-Z5MYW";

    private DualMachineAuthorizationPresentationSelfTest() {
    }

    public static void main(String[] arguments) throws Exception {
        require(ISSUED_CARD.equals(
                DualMachineCardCode.normalizeAndValidate(ISSUED_CARD)));
        require(ISSUED_CARD.equals(
                DualMachineCardCode.normalizeAndValidate(
                        ISSUED_CARD.toLowerCase(Locale.ROOT)
                                .replace("-", " "))));
        expectInvalid(ISSUED_CARD.substring(0, ISSUED_CARD.length() - 1) + "X");
        expectInvalid(ISSUED_CARD.replaceFirst("-", "_"));
        expectInvalid(ISSUED_CARD.replace('9', '0'));
        expectInvalid("");

        DualMachineAuthorizationUiState fresh =
                DualMachineAuthorizationUiState.readyForActivation();
        require(!fresh.balanceKnown);
        require(fresh.canActivateCard());
        require(!fresh.canStartFormalUse());
        require(!fresh.canStopFormalUse());
        require(fresh.isActivationCardVisible());
        require(fresh.canEnterCardCode());

        DualMachineAuthorizationUiState ready =
                DualMachineAuthorizationUiState.readyForActivation();
        require(ready.canActivateCard());
        require(!ready.canStartFormalUse());
        require(ready.isActivationCardVisible());
        require(ready.canEnterCardCode());

        DualMachineAuthorizationUiState queued =
                state(DualMachineAuthorizationUiState.Status
                                .CARD_SAVED_WAITING_FOR_HOST,
                        false, 0L);
        require(!queued.canActivateCard());
        require(!queued.isActivationCardVisible());
        require(!queued.canEnterCardCode());

        DualMachineAuthorizationUiState idle =
                state(DualMachineAuthorizationUiState.Status.ACTIVE_IDLE,
                        true, 3_600L);
        require(idle.entitlementBound());
        require(!idle.canActivateCard());
        require(idle.canRefreshStatus());
        require(idle.canStartFormalUse());
        require(!idle.canStopFormalUse());
        require(!idle.isActivationCardVisible());
        require(!idle.canEnterCardCode());

        DualMachineAuthorizationUiState unknownIdle =
                new DualMachineAuthorizationUiState(
                        DualMachineAuthorizationUiState.Status.ACTIVE_IDLE,
                        true,
                        0L,
                        0L,
                        false,
                        false,
                        "");
        require(!unknownIdle.balanceKnown);
        require(!unknownIdle.canStartFormalUse());

        DualMachineAuthorizationUiState permanentIdle =
                new DualMachineAuthorizationUiState(
                        DualMachineAuthorizationUiState.Status.ACTIVE_IDLE,
                        true,
                        0L,
                        0L,
                        true,
                        true,
                        "");
        require(permanentIdle.balanceKnown);
        require(permanentIdle.permanent);
        require(permanentIdle.canStartFormalUse());

        DualMachineAuthorizationUiState permanentPending =
                new DualMachineAuthorizationUiState(
                        DualMachineAuthorizationUiState.Status.ACTIVE_IDLE,
                        true,
                        0L,
                        0L,
                        false,
                        true,
                        "");
        require(!permanentPending.balanceKnown);
        require(permanentPending.permanent);
        require(!permanentPending.canStartFormalUse());
        require(!permanentIdle.equals(permanentPending));

        DualMachineAuthorizationUiState inUse =
                state(DualMachineAuthorizationUiState.Status.IN_USE,
                        true, 3_595L);
        require(!inUse.canActivateCard());
        require(!inUse.canRefreshStatus());
        require(!inUse.canStartFormalUse());
        require(inUse.canStopFormalUse());
        require(!inUse.canEnterCardCode());

        DualMachineAuthorizationUiState exhausted =
                state(DualMachineAuthorizationUiState.Status.EXHAUSTED,
                        true, 0L);
        require(!exhausted.canActivateCard());
        require(!exhausted.canStartFormalUse());
        require(!exhausted.isActivationCardVisible());

        DualMachineAuthorizationUiState releasedAfterExhaustion =
                DualMachineAuthorizationUiState.readyForActivation();
        require(releasedAfterExhaustion.isActivationCardVisible());
        require(releasedAfterExhaustion.canActivateCard());

        DualMachineAuthorizationUiState revoked =
                state(DualMachineAuthorizationUiState.Status.REVOKED,
                        true, 0L);
        require(!revoked.canActivateCard());
        require(!revoked.canRefreshStatus());
        require(!revoked.canStartFormalUse());
        require(!revoked.canStopFormalUse());

        verifyDomainStateMapping();
        verifyRestartUsesCachedBalanceForDisplayOnly();
    }

    private static void verifyRestartUsesCachedBalanceForDisplayOnly()
            throws Exception {
        DualMachineEntitlementRecord entitlement = entitlement("11".repeat(16));
        DualMachineFormalUsageStateMachine restored =
                new DualMachineFormalUsageStateMachine();
        restored.restoreBoundEntitlement(entitlement);
        DualMachinePresentationBalance cached =
                DualMachinePresentationBalance.fromAuthoritativeSnapshot(
                        entitlement,
                        86_367L,
                        33L,
                        1_787_540_332L);

        DualMachineAuthorizationUiState mapped =
                DualMachineAuthorizationUiMapper.map(
                        restored.snapshot(),
                        false,
                        false,
                        false,
                        "",
                        cached);
        require(!mapped.balanceKnown);
        require(mapped.displayBalanceKnown);
        require(mapped.balanceStale);
        require(mapped.remainingSeconds == 86_367L);
        require(mapped.totalConsumedSeconds == 33L);
        require(mapped.balanceSynchronizedAtEpochSeconds == 1_787_540_332L);
        require(!mapped.canStartFormalUse());

        DualMachinePresentationBalance wrongEntitlement =
                DualMachinePresentationBalance.fromAuthoritativeSnapshot(
                        entitlement("22".repeat(16)),
                        1L,
                        86_399L,
                        1_787_540_333L);
        DualMachineAuthorizationUiState mismatch =
                DualMachineAuthorizationUiMapper.map(
                        restored.snapshot(),
                        false,
                        false,
                        false,
                        "",
                        wrongEntitlement);
        require(!mismatch.displayBalanceKnown);
        require(!mismatch.balanceStale);
        require(mismatch.remainingSeconds == 0L);
    }

    private static DualMachineEntitlementRecord entitlement(String entitlementId)
            throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair host = generator.generateKeyPair();
        String hostPublicKey = DualMachinePairingIdentityCodec
                .encodePublicKeyBase64(host.getPublic().getEncoded());
        return new DualMachineEntitlementRecord(
                entitlementId,
                "33".repeat(16),
                "44".repeat(16),
                1L,
                "active",
                DualMachineEntitlementRecord.PROTOCOL_VERSION,
                1L,
                DualMachinePairingIdentityCodec.fingerprintHex(
                        host.getPublic().getEncoded()),
                hostPublicKey,
                "55".repeat(32),
                "visionforge-dual-machine-pairing-identity",
                "day",
                "day",
                false,
                false);
    }

    private static void verifyDomainStateMapping() {
        DualMachineFormalUsageStateMachine stateMachine =
                new DualMachineFormalUsageStateMachine();
        DualMachineAuthorizationUiState unmapped =
                DualMachineAuthorizationUiMapper.map(
                        stateMachine.snapshot(), false, false, "");
        require(unmapped.status
                == DualMachineAuthorizationUiState.Status
                .WAITING_FOR_HOST);
        require(!unmapped.balanceKnown);
        require(!unmapped.authorizationReady);
        require(!unmapped.activationReady);
        require(!unmapped.canActivateCard());
        require(unmapped.isActivationCardVisible());
        require(unmapped.canEnterCardCode());

        DualMachineAuthorizationUiState firstPairReady =
                DualMachineAuthorizationUiMapper.map(
                        stateMachine.snapshot(), false, true, false, "");
        require(firstPairReady.status
                == DualMachineAuthorizationUiState.Status
                .READY_FOR_ACTIVATION);
        require(!firstPairReady.authorizationReady);
        require(firstPairReady.activationReady);
        require(firstPairReady.canActivateCard());
        require(firstPairReady.canEnterCardCode());
        require(!firstPairReady.canRefreshStatus());
        require(!firstPairReady.canStartFormalUse());

        DualMachineAuthorizationUiState ready =
                DualMachineAuthorizationUiMapper.map(
                        stateMachine.snapshot(), true, false, "");
        require(ready.status
                == DualMachineAuthorizationUiState.Status
                .READY_FOR_ACTIVATION);
        require(!ready.balanceKnown);
        stateMachine.beginCardActivation();
        DualMachineAuthorizationUiState activating =
                DualMachineAuthorizationUiMapper.map(
                        stateMachine.snapshot(), true, false, "");
        require(activating.status
                == DualMachineAuthorizationUiState.Status.ACTIVATING);
        require(!activating.balanceKnown);
        require(!activating.isActivationCardVisible());
        stateMachine.markCardActivationPending();
        DualMachineAuthorizationUiState pending =
                DualMachineAuthorizationUiMapper.map(
                        stateMachine.snapshot(), true, false, "");
        require(pending.status
                == DualMachineAuthorizationUiState.Status
                .ACTIVATION_PENDING);
        require(!pending.canActivateCard());
        require(pending.canResumeActivation());
        require(!pending.canEnterCardCode());
        require(!pending.balanceKnown);
        require(!pending.isActivationCardVisible());

        DualMachineAuthorizationUiState fatal =
                DualMachineAuthorizationUiMapper.map(
                        stateMachine.snapshot(), true, true,
                        "security_configuration_unavailable");
        require(fatal.status
                == DualMachineAuthorizationUiState.Status
                .SECURITY_CONFIGURATION_ERROR);
        require(!fatal.balanceKnown);
        require(!fatal.displayBalanceKnown);
        require(!fatal.authorizationReady);
        require(!fatal.activationReady);
        require(!fatal.canActivateCard());
    }

    private static DualMachineAuthorizationUiState state(
            DualMachineAuthorizationUiState.Status status,
            boolean hostReady,
            long remainingSeconds) {
        return new DualMachineAuthorizationUiState(
                status,
                hostReady,
                remainingSeconds,
                5L,
                true,
                false,
                "");
    }

    private static void expectInvalid(String value) {
        try {
            DualMachineCardCode.normalizeAndValidate(value);
            throw new AssertionError("invalid card code was accepted");
        } catch (IllegalArgumentException expected) {
            // Expected.
        }
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("condition failed");
    }
}
