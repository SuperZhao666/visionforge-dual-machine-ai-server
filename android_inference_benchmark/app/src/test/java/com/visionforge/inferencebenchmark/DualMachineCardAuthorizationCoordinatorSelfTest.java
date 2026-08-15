package com.visionforge.inferencebenchmark;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayDeque;
import java.util.Base64;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/** Zero-cost activation, canonical double-proof and no-auto-start contract. */
public final class DualMachineCardAuthorizationCoordinatorSelfTest {
    private static final String CARD =
            "VFD2-AAAAA-AAAAA-AAAAA-AAAAA-AAAAA-AAAT3";
    private static final String REQUEST_ID = "11".repeat(16);
    private static final String PAIR_ID = "22".repeat(16);
    private static final String STATUS_NONCE = "33".repeat(16);
    private static final String CHALLENGE_ID = "44".repeat(16);
    private static final String ENTITLEMENT_ID = "55".repeat(16);
    private static final String OTHER_ENTITLEMENT_ID = "88".repeat(16);
    private static final String CHALLENGE_TOKEN = "A".repeat(43);
    private static final long DAY_SECONDS = 86_400L;
    private static final long WEEK_SECONDS = 604_800L;
    private static final long MONTH_SECONDS = 2_592_000L;

    private DualMachineCardAuthorizationCoordinatorSelfTest() {
    }

    public static void main(String[] arguments) throws Exception {
        verifiesActivationAndStatusStayIdleAndZeroCost();
        verifiesLostConfirmationResponseResumesSameChallenge();
        rejectsSecondCardAfterActivation();
        verifiesAuthenticatedNewerRevocationFailsClosed();
        rejectsOpaqueServerPayloadBeforeEitherDeviceSigns();
        rejectsBillingAndBalanceContractViolations();
        rejectsActivationWhileFormalUseIsRunning();
        rejectsPendingActivationAfterIdentityBindingChanges();
        restoredEntitlementNeverAcceptsAnotherCard();
        inFlightStatusBlocksFormalStartAndAccounting();
        statusFailureAndErrorReleaseReservation();
        authenticatedRevocationStoreErrorStaysTerminal();
        reactivationResumePreservesTargetAndCreditsNewTerm();
        bindDeviceResumePreservesTargetAndAddsNoCredit();
        rejectsBindDeviceConfirmationContractChanges();
        authoritativeInvalidChallengeClearsPendingActivation();
        finiteProductMetadataCoversDayWeekAndMonth();
        permanentActivationStaysUsableAtZeroBalance();
        legacyBalanceStatusRefreshMigratesAuthoritativeMetadata();
        exhaustedBindingIsReleasedOnlyAfterUsageSessionEnds();
        exhaustedBindingClearFailureStaysFailClosed();
        System.out.println("DUAL_MACHINE_CARD_AUTHORIZATION_COORDINATOR_OK");
    }

    private static void exhaustedBindingIsReleasedOnlyAfterUsageSessionEnds()
            throws Exception {
        Fixture fixture = new Fixture();
        fixture.coordinator.activateCard(CARD);
        fixture.sidecar.status = "exhausted";
        fixture.sidecar.statusRemaining = 0L;
        fixture.sidecar.statusConsumed = DAY_SECONDS;
        fixture.sidecar.usageSessionStatus = "active";
        DualMachineFormalUsageStateMachine.Snapshot activeFinalLease =
                fixture.coordinator.refreshStatus();
        check(activeFinalLease.state
                == DualMachineFormalUsageStateMachine.State.EXHAUSTED);
        check(fixture.saved.get() != null);

        fixture.sidecar.usageSessionStatus = "ended";
        DualMachineFormalUsageStateMachine.Snapshot released =
                fixture.coordinator.refreshStatus();
        check(released.state
                == DualMachineFormalUsageStateMachine.State.UNACTIVATED);
        check(released.entitlement == null);
        check(released.canActivate());
        check(fixture.saved.get() == null);
    }

    private static void exhaustedBindingClearFailureStaysFailClosed()
            throws Exception {
        Fixture fixture = new Fixture();
        fixture.coordinator.activateCard(CARD);
        fixture.sidecar.status = "exhausted";
        fixture.sidecar.statusRemaining = 0L;
        fixture.sidecar.statusConsumed = DAY_SECONDS;
        fixture.sidecar.usageSessionStatus = "ended";
        fixture.entitlementClearError =
                new AssertionError("injected entitlement clear error");
        expectError(fixture.coordinator::refreshStatus,
                fixture.entitlementClearError);
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.EXHAUSTED);
        check(fixture.state.snapshot().entitlement != null);
        check(!fixture.state.snapshot().canActivate());
    }

    private static void permanentActivationStaysUsableAtZeroBalance()
            throws Exception {
        Fixture fixture = new Fixture();
        fixture.sidecar.permanent = true;
        fixture.sidecar.statusRemaining = 0L;
        DualMachineEntitlementRecord entitlement =
                fixture.coordinator.activateCard(CARD);
        check(entitlement.permanent);
        check(entitlement.authorizationKind.equals("permanent"));
        check(entitlement.productKey.equals("permanent"));
        check(fixture.state.snapshot().remainingSeconds == 0L);
        check(fixture.state.snapshot().canFormalStart());
        check(fixture.coordinator.refreshStatus().canFormalStart());
    }

    private static void
            legacyBalanceStatusRefreshMigratesAuthoritativeMetadata()
            throws Exception {
        Fixture fixture = new Fixture();
        String hostPublicKey = DualMachinePairingIdentityCodec
                .encodePublicKeyBase64(fixture.host.getPublic().getEncoded());
        String androidPublicKey = DualMachinePairingIdentityCodec
                .encodePublicKeyBase64(fixture.android.getPublic().getEncoded());
        DualMachineEntitlementRecord legacy =
                new DualMachineEntitlementRecord(
                        ENTITLEMENT_ID,
                        PAIR_ID,
                        DualMachineEntitlementRecord.PROTOCOL_VERSION,
                        1L,
                        fingerprint(hostPublicKey),
                        hostPublicKey,
                        fingerprint(androidPublicKey),
                        "visionforge-dual-machine-pairing-identity",
                        "legacy_balance",
                        "legacy_balance",
                        false,
                        false);
        fixture.saved.set(legacy);
        fixture.state.restoreBoundEntitlement(legacy);
        fixture.sidecar.permanent = true;
        fixture.sidecar.statusRemaining = 0L;

        DualMachineFormalUsageStateMachine.Snapshot migrated =
                fixture.coordinator.refreshStatus();
        check(migrated.entitlement.authorizationKind.equals("permanent"));
        check(migrated.entitlement.productKey.equals("permanent"));
        check(migrated.entitlement.permanent);
        check(fixture.saved.get().equals(migrated.entitlement));
        check(migrated.canFormalStart());

        Fixture revokedLegacyFixture = new Fixture();
        String revokedHostPublicKey = DualMachinePairingIdentityCodec
                .encodePublicKeyBase64(
                        revokedLegacyFixture.host.getPublic().getEncoded());
        String revokedAndroidPublicKey = DualMachinePairingIdentityCodec
                .encodePublicKeyBase64(
                        revokedLegacyFixture.android.getPublic().getEncoded());
        DualMachineEntitlementRecord revokedLegacy =
                new DualMachineEntitlementRecord(
                        ENTITLEMENT_ID,
                        PAIR_ID,
                        DualMachineEntitlementRecord.PROTOCOL_VERSION,
                        1L,
                        fingerprint(revokedHostPublicKey),
                        revokedHostPublicKey,
                        fingerprint(revokedAndroidPublicKey),
                        "visionforge-dual-machine-pairing-identity",
                        "legacy_balance",
                        "legacy_balance",
                        false,
                        true);
        revokedLegacyFixture.saved.set(revokedLegacy);
        revokedLegacyFixture.state.restoreBoundEntitlement(revokedLegacy);
        revokedLegacyFixture.sidecar.permanent = true;
        revokedLegacyFixture.sidecar.statusRemaining = 0L;
        revokedLegacyFixture.sidecar.status = "active";
        expectSecurity(revokedLegacyFixture.coordinator::refreshStatus);
        check(revokedLegacyFixture.saved.get().equals(revokedLegacy));
        check(revokedLegacyFixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.REVOKED);

        Fixture modern = new Fixture();
        modern.coordinator.activateCard(CARD);
        modern.sidecar.authorizationKind = "week";
        modern.sidecar.statusRemaining = WEEK_SECONDS;
        expectSecurity(modern.coordinator::refreshStatus);
        check(modern.saved.get().authorizationKind.equals("day"));
    }

    private static void bindDeviceResumePreservesTargetAndAddsNoCredit()
            throws Exception {
        Fixture fixture = new Fixture();
        fixture.sidecar.challengeActivationMode = "bind_device";
        fixture.sidecar.challengeTargetEntitlementId = ENTITLEMENT_ID;
        fixture.sidecar.responseBindingUpdated = true;
        fixture.sidecar.failFirstConfirmationAfterCommit = true;
        expectIo(() -> fixture.coordinator.activateCard(CARD));
        DualMachineCardAuthorizationCoordinator.PendingActivation pending =
                fixture.pending.get();
        check(pending != null);
        check(pending.activationMode.equals("bind_device"));
        check(pending.targetEntitlementId.equals(ENTITLEMENT_ID));
        DualMachineEntitlementRecord rebound =
                fixture.coordinator.resumePendingActivation();
        check(rebound.entitlementId.equals(ENTITLEMENT_ID));
        check(fixture.state.snapshot().remainingSeconds == DAY_SECONDS);
        check(fixture.state.snapshot().totalConsumedSeconds == 0L);
        check(!fixture.state.snapshot().billingStarted);
        check(fixture.sidecar.activationChallenges == 1);
        check(fixture.sidecar.activationConfirmations == 2);
    }

    private static void
            reactivationResumePreservesTargetAndCreditsNewTerm()
            throws Exception {
        Fixture fixture = new Fixture();
        fixture.sidecar.challengeActivationMode = "reactivate";
        fixture.sidecar.challengeTargetEntitlementId = ENTITLEMENT_ID;
        fixture.sidecar.failFirstConfirmationAfterCommit = true;
        expectIo(() -> fixture.coordinator.activateCard(CARD));

        DualMachineCardAuthorizationCoordinator.PendingActivation pending =
                fixture.pending.get();
        check(pending != null);
        check(pending.activationMode.equals("reactivate"));
        check(pending.targetEntitlementId.equals(ENTITLEMENT_ID));

        DualMachineEntitlementRecord reactivated =
                fixture.coordinator.resumePendingActivation();
        check(reactivated.entitlementId.equals(ENTITLEMENT_ID));
        check(fixture.state.snapshot().remainingSeconds == DAY_SECONDS);
        check(fixture.state.snapshot().totalConsumedSeconds == 0L);
        check(!fixture.state.snapshot().billingStarted);
        check(fixture.sidecar.activationChallenges == 1);
        check(fixture.sidecar.activationConfirmations == 2);
    }

    private static void rejectsBindDeviceConfirmationContractChanges()
            throws Exception {
        Fixture wrongTarget = new Fixture();
        wrongTarget.sidecar.challengeActivationMode = "bind_device";
        wrongTarget.sidecar.challengeTargetEntitlementId = ENTITLEMENT_ID;
        wrongTarget.sidecar.responseBindingUpdated = true;
        wrongTarget.sidecar.responseEntitlementId = OTHER_ENTITLEMENT_ID;
        expectSecurity(() -> wrongTarget.coordinator.activateCard(CARD));
        check(wrongTarget.saved.get() == null);
        check(wrongTarget.pending.get() != null);

        Fixture wrongMode = new Fixture();
        wrongMode.sidecar.challengeActivationMode = "bind_device";
        wrongMode.sidecar.challengeTargetEntitlementId = ENTITLEMENT_ID;
        wrongMode.sidecar.responseActivationMode = "activate";
        wrongMode.sidecar.responseBindingUpdated = false;
        expectSecurity(() -> wrongMode.coordinator.activateCard(CARD));
        check(wrongMode.saved.get() == null);
    }

    private static void finiteProductMetadataCoversDayWeekAndMonth()
            throws Exception {
        for (String product : new String[] {"day", "week", "month"}) {
            Fixture fixture = new Fixture();
            fixture.sidecar.authorizationKind = product;
            fixture.sidecar.statusRemaining = termSeconds(product);
            DualMachineEntitlementRecord entitlement =
                    fixture.coordinator.activateCard(CARD);
            check(entitlement.authorizationKind.equals(product));
            check(entitlement.productKey.equals(product));
            check(!entitlement.permanent);
            check(fixture.coordinator.refreshStatus().canFormalStart());
        }
    }

    private static void authoritativeInvalidChallengeClearsPendingActivation()
            throws Exception {
        Fixture fixture = new Fixture();
        fixture.sidecar.rejectActivationChallengeInvalid = true;
        expectIo(() -> fixture.coordinator.activateCard(CARD));
        check(fixture.pending.get() == null);
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.UNACTIVATED);
        fixture.sidecar.rejectActivationChallengeInvalid = false;
        DualMachineEntitlementRecord recovered =
                fixture.coordinator.activateCard(CARD);
        check(recovered.authorizationKind.equals("day"));
    }

    private static void verifiesAuthenticatedNewerRevocationFailsClosed()
            throws Exception {
        Fixture fixture = new Fixture();
        fixture.coordinator.activateCard(CARD);
        fixture.sidecar.status = "revoked";
        fixture.sidecar.statusRevision = 2L;
        DualMachineFormalUsageStateMachine.Snapshot revoked =
                fixture.coordinator.refreshStatus();
        check(revoked.state
                == DualMachineFormalUsageStateMachine.State.REVOKED);
        check(revoked.entitlement.revoked);
        check(revoked.entitlement.revocationVersion == 2L);
        check(fixture.saved.get().revoked);
        check(fixture.saved.get().revocationVersion == 2L);
        check(!revoked.permitsDataPlane);
        check(!revoked.billingStarted);

        fixture.sidecar.status = "active";
        expectSecurity(fixture.coordinator::refreshStatus);
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.REVOKED);

        fixture.state.restoreBoundEntitlement(fixture.saved.get());
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.REVOKED);
        expectSecurity(fixture.coordinator::refreshStatus);
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.REVOKED);
    }

    private static void verifiesLostConfirmationResponseResumesSameChallenge()
            throws Exception {
        Fixture fixture = new Fixture();
        fixture.sidecar.failFirstConfirmationAfterCommit = true;
        expectIo(() -> fixture.coordinator.activateCard(CARD));
        check(fixture.pending.get() != null);
        check(fixture.saved.get() == null);
        DualMachineEntitlementRecord resumed =
                fixture.coordinator.resumePendingActivation();
        check(resumed.entitlementId.equals(ENTITLEMENT_ID));
        check(fixture.pending.get() == null);
        check(fixture.sidecar.activationChallenges == 1);
        check(fixture.sidecar.activationConfirmations == 2);
        check(fixture.state.snapshot().remainingSeconds == DAY_SECONDS);
    }

    private static void rejectsSecondCardAfterActivation()
            throws Exception {
        Fixture fixture = new Fixture();
        fixture.coordinator.activateCard(CARD);
        expectState(() -> fixture.coordinator.activateCard(CARD));
        check(fixture.sidecar.activationChallenges == 1);
        check(fixture.state.snapshot().remainingSeconds == DAY_SECONDS);
        check(fixture.state.snapshot().totalConsumedSeconds == 0L);
        check(!fixture.state.snapshot().billingStarted);
        check(fixture.sidecar.starts == 0);
    }

    private static void verifiesActivationAndStatusStayIdleAndZeroCost()
            throws Exception {
        Fixture fixture = new Fixture();
        DualMachineEntitlementRecord entitlement =
                fixture.coordinator.activateCard(CARD);
        check(entitlement.entitlementId.equals(ENTITLEMENT_ID));
        check(fixture.saved.get().equals(entitlement));
        check(fixture.sidecar.activationChallenges == 1);
        check(fixture.sidecar.activationConfirmations == 1);
        check(fixture.sidecar.starts == 0);
        check(fixture.sidecar.heartbeats == 0);
        DualMachineFormalUsageStateMachine.Snapshot activated =
                fixture.state.snapshot();
        check(activated.state
                == DualMachineFormalUsageStateMachine.State.ACTIVATED_IDLE);
        check(!activated.billingStarted);
        check(!activated.permitsDataPlane);
        check(activated.remainingSeconds == DAY_SECONDS);

        DualMachineFormalUsageStateMachine.Snapshot status =
                fixture.coordinator.refreshStatus();
        check(status.state
                == DualMachineFormalUsageStateMachine.State.ACTIVATED_IDLE);
        check(!status.billingStarted);
        check(!status.permitsDataPlane);
        String firstStatusNonce = fixture.sidecar.lastStatusNonce;
        DualMachineFormalUsageStateMachine.Snapshot repeatedStatus =
                fixture.coordinator.refreshStatus();
        check(repeatedStatus.state
                == DualMachineFormalUsageStateMachine.State.ACTIVATED_IDLE);
        String secondStatusNonce = fixture.sidecar.lastStatusNonce;
        check(!firstStatusNonce.equals(secondStatusNonce));
        check(fixture.sidecar.statusRequests == 2);
        check(fixture.sidecar.starts == 0);
        check(fixture.sidecar.heartbeats == 0);
    }

    private static void rejectsOpaqueServerPayloadBeforeEitherDeviceSigns()
            throws Exception {
        Fixture fixture = new Fixture();
        fixture.sidecar.corruptActivationProofPayload = true;
        expectSecurity(() -> fixture.coordinator.activateCard(CARD));
        check(fixture.hostSignCalls.get() == 0);
        check(fixture.androidSignCalls.get() == 0);
        check(fixture.sidecar.activationConfirmations == 0);
        check(fixture.saved.get() == null);
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.UNACTIVATED);
    }

    private static void rejectsBillingAndBalanceContractViolations()
            throws Exception {
        Fixture billing = new Fixture();
        billing.sidecar.activationBillingStarted = true;
        expectSecurity(() -> billing.coordinator.activateCard(CARD));
        check(billing.saved.get() == null);
        check(billing.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.ACTIVATING);
        check(billing.pending.get() != null);

        Fixture status = new Fixture();
        status.coordinator.activateCard(CARD);
        status.sidecar.statusRemaining = DAY_SECONDS + 1L;
        expectSecurity(status.coordinator::refreshStatus);
        check(status.state.snapshot().remainingSeconds == DAY_SECONDS);
        check(status.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.ACTIVATED_IDLE);
        check(!status.state.snapshot().billingStarted);

        Fixture wrongTermCredit = new Fixture();
        wrongTermCredit.sidecar.wrongInitialTermAmount = true;
        expectSecurity(() -> wrongTermCredit.coordinator.activateCard(CARD));
        check(wrongTermCredit.saved.get() == null);
    }

    private static void rejectsActivationWhileFormalUseIsRunning()
            throws Exception {
        Fixture fixture = new Fixture();
        fixture.coordinator.activateCard(CARD);
        fixture.state.runtimeRequestedFormalStart(true);
        expectState(() -> fixture.coordinator.activateCard(CARD));
        expectState(fixture.coordinator::refreshStatus);
        check(fixture.sidecar.activationChallenges == 1);
        check(fixture.sidecar.statusRequests == 0);
    }

    private static void rejectsPendingActivationAfterIdentityBindingChanges()
            throws Exception {
        Fixture fixture = new Fixture();
        fixture.sidecar.failFirstConfirmationAfterCommit = true;
        expectIo(() -> fixture.coordinator.activateCard(CARD));
        DualMachineCardAuthorizationCoordinator.PendingActivation original =
                fixture.pending.get();
        check(original != null);
        fixture.pending.set(new DualMachineCardAuthorizationCoordinator
                .PendingActivation(
                original.requestId,
                original.pairId,
                original.challengeId,
                original.challengeToken,
                original.challengeExpiresAtEpoch,
                original.hostSignatureBase64,
                original.androidSignatureBase64,
                "f".repeat(64),
                original.androidKeyFingerprintSha256,
                original.androidIdentityAlias,
                original.activationMode,
                original.targetEntitlementId));
        int confirmationsBefore = fixture.sidecar.activationConfirmations;
        expectSecurity(fixture.coordinator::resumePendingActivation);
        check(fixture.sidecar.activationConfirmations
                == confirmationsBefore);
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.ACTIVATING);
    }

    private static void restoredEntitlementNeverAcceptsAnotherCard()
            throws Exception {
        Fixture fixture = new Fixture();
        fixture.coordinator.activateCard(CARD);
        DualMachineEntitlementRecord stored = fixture.saved.get();
        fixture.state.restoreBoundEntitlement(stored);
        int challengesBefore = fixture.sidecar.activationChallenges;
        expectState(() -> fixture.coordinator.activateCard(CARD));
        check(fixture.sidecar.activationChallenges == challengesBefore);
        fixture.coordinator.refreshStatus();
        expectState(() -> fixture.coordinator.activateCard(CARD));
        check(fixture.sidecar.activationChallenges == challengesBefore);
        check(fixture.state.snapshot().remainingSeconds == DAY_SECONDS);
    }

    private static void inFlightStatusBlocksFormalStartAndAccounting()
            throws Exception {
        Fixture fixture = new Fixture();
        fixture.coordinator.activateCard(CARD);
        fixture.sidecar.statusEntered = new CountDownLatch(1);
        fixture.sidecar.statusRelease = new CountDownLatch(1);
        AtomicReference<Throwable> backgroundFailure =
                new AtomicReference<>();
        Thread refresh = new Thread(() -> {
            try {
                fixture.coordinator.refreshStatus();
            } catch (Throwable failure) {
                backgroundFailure.set(failure);
            }
        }, "dual-machine-status-race-test");
        refresh.start();
        check(fixture.sidecar.statusEntered.await(5L, TimeUnit.SECONDS));
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.STATUS_REFRESHING);
        expectState(() -> fixture.state.runtimeRequestedFormalStart(true));
        expectState(() -> fixture.state.verifiedRenewalInstalled(
                1L, 5L, 95L, 5L));
        fixture.sidecar.statusRelease.countDown();
        refresh.join(5_000L);
        check(!refresh.isAlive());
        check(backgroundFailure.get() == null);
        check(fixture.state.snapshot().remainingSeconds == DAY_SECONDS);
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.ACTIVATED_IDLE);
        check(fixture.sidecar.starts == 0);
    }

    private static void statusFailureAndErrorReleaseReservation()
            throws Exception {
        Fixture fixture = new Fixture();
        fixture.coordinator.activateCard(CARD);
        fixture.sidecar.statusRemaining = DAY_SECONDS + 1L;
        expectSecurity(fixture.coordinator::refreshStatus);
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.ACTIVATED_IDLE);

        fixture.sidecar.statusRemaining = DAY_SECONDS;
        Error injected = new AssertionError("injected status error");
        fixture.sidecar.statusError = injected;
        expectError(fixture.coordinator::refreshStatus, injected);
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.ACTIVATED_IDLE);
        check(fixture.coordinator.refreshStatus().canFormalStart());
    }

    private static void authenticatedRevocationStoreErrorStaysTerminal()
            throws Exception {
        Fixture fixture = new Fixture();
        fixture.coordinator.activateCard(CARD);
        fixture.sidecar.status = "revoked";
        fixture.sidecar.statusRevision = 2L;
        Error injected = new AssertionError("committed entitlement save error");
        fixture.entitlementSaveErrorAfterCommit = injected;
        expectError(fixture.coordinator::refreshStatus, injected);
        check(fixture.saved.get().revoked);
        check(fixture.saved.get().revocationVersion == 2L);
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.REVOKED);
        check(!fixture.state.snapshot().canFormalStart());
    }

    private static final class Fixture {
        final KeyPair host = keyPair();
        final KeyPair android = keyPair();
        final AtomicInteger hostSignCalls = new AtomicInteger();
        final AtomicInteger androidSignCalls = new AtomicInteger();
        final AtomicReference<DualMachineEntitlementRecord> saved =
                new AtomicReference<>();
        final AtomicReference<
                DualMachineCardAuthorizationCoordinator.PendingActivation>
                pending = new AtomicReference<>();
        volatile Error entitlementSaveErrorAfterCommit;
        volatile Error entitlementClearError;
        final DualMachineFormalUsageStateMachine state =
                new DualMachineFormalUsageStateMachine();
        final FakeSidecar sidecar = new FakeSidecar(
                host.getPublic().getEncoded(),
                android.getPublic().getEncoded());
        final DualMachineCardAuthorizationCoordinator coordinator;

        Fixture() throws Exception {
            ArrayDeque<String> identifiers = new ArrayDeque<>();
            identifiers.add(REQUEST_ID);
            identifiers.add(PAIR_ID);
            identifiers.add(STATUS_NONCE);
            identifiers.add("66".repeat(16));
            identifiers.add("77".repeat(16));
            DualMachineCardAuthorizationCoordinator.IdentityBinding hostBinding =
                    identity(
                            "HOST-DEVICE",
                            "17.8.81",
                            host,
                            hostSignCalls);
            DualMachineCardAuthorizationCoordinator.IdentityBinding
                    androidBinding = identity(
                    "ANDROID-DEVICE",
                    "1.0.0",
                    android,
                    androidSignCalls);
            coordinator = new DualMachineCardAuthorizationCoordinator(
                    sidecar,
                    state,
                    new DualMachineEntitlementStore() {
                        @Override
                        public DualMachineEntitlementRecord load() {
                            return saved.get();
                        }

                        @Override
                        public void save(
                                DualMachineEntitlementRecord value) {
                            saved.set(value);
                            Error failure = entitlementSaveErrorAfterCommit;
                            if (failure != null) throw failure;
                        }

                        @Override
                        public void clear() {
                            Error failure = entitlementClearError;
                            if (failure != null) throw failure;
                            saved.set(null);
                        }
                    },
                    new DualMachineCardAuthorizationCoordinator
                            .PendingActivationStore() {
                        @Override
                        public DualMachineCardAuthorizationCoordinator
                                .PendingActivation load() {
                            return pending.get();
                        }

                        @Override
                        public void save(
                                DualMachineCardAuthorizationCoordinator
                                        .PendingActivation value) {
                            pending.set(value);
                        }

                        @Override
                        public void clear() {
                            pending.set(null);
                        }
                    },
                    hostBinding,
                    androidBinding,
                    "visionforge-dual-machine-pairing-identity",
                    identifiers::remove,
                    () -> 100L);
        }
    }

    private static DualMachineCardAuthorizationCoordinator.IdentityBinding
            identity(
            String deviceCode,
            String version,
            KeyPair keyPair,
            AtomicInteger calls) throws GeneralSecurityException {
        return new DualMachineCardAuthorizationCoordinator.IdentityBinding(
                deviceCode,
                version,
                DualMachinePairingIdentityCodec.encodePublicKeyBase64(
                        keyPair.getPublic().getEncoded()),
                payload -> {
                    calls.incrementAndGet();
                    return DualMachinePairingIdentityCodec.sign(
                            keyPair.getPrivate(), payload);
                });
    }

    private static final class FakeSidecar
            implements DualMachineSidecarPort {
        private final byte[] hostKey;
        private final byte[] androidKey;
        private ActivationChallengeRequest activationRequest;
        private byte[] activationProof;
        int activationChallenges;
        int activationConfirmations;
        int statusRequests;
        int starts;
        int heartbeats;
        boolean corruptActivationProofPayload;
        boolean activationBillingStarted;
        boolean failFirstConfirmationAfterCommit;
        boolean confirmationResponseLost;
        boolean permanent;
        boolean responseBindingUpdated;
        boolean wrongInitialTermAmount;
        boolean rejectActivationChallengeInvalid;
        long statusRemaining = DAY_SECONDS;
        long statusConsumed;
        long statusRevision = 1L;
        String status = "active";
        String usageSessionStatus = "";
        String lastActivationPairId = "";
        String lastStatusNonce = "";
        String challengeActivationMode = "activate";
        String challengeTargetEntitlementId = "";
        String responseActivationMode = "";
        String responseEntitlementId = ENTITLEMENT_ID;
        String authorizationKind = "day";
        volatile CountDownLatch statusEntered;
        volatile CountDownLatch statusRelease;
        volatile Error statusError;

        FakeSidecar(byte[] hostKey, byte[] androidKey) {
            this.hostKey = hostKey.clone();
            this.androidKey = androidKey.clone();
        }

        @Override
        public ActivationChallengeResponse createActivationChallenge(
                ActivationChallengeRequest request)
                throws IOException {
            activationChallenges++;
            activationRequest = request;
            lastActivationPairId = request.pairId;
            try {
                activationProof = activationPayload(
                        request,
                        challengeActivationMode,
                        challengeTargetEntitlementId);
                byte[] returned = activationProof.clone();
                if (corruptActivationProofPayload) returned[0] ^= 1;
                return new ActivationChallengeResponse(
                        CHALLENGE_ID,
                        CHALLENGE_TOKEN,
                        200L,
                        challengeActivationMode,
                        challengeTargetEntitlementId,
                        profileSha256(request),
                        returned);
            } catch (GeneralSecurityException exception) {
                throw new IOException(exception);
            }
        }

        @Override
        public ActivationResponse confirmActivation(
                ActivationConfirmationRequest request)
                throws IOException {
            activationConfirmations++;
            if (rejectActivationChallengeInvalid) {
                throw new DualMachineSidecarPort
                        .RejectedException(
                        409, "activation_challenge_invalid");
            }
            try {
                check(request.challengeId.equals(CHALLENGE_ID));
                check(request.challengeToken.equals(CHALLENGE_TOKEN));
                check(DualMachinePairingIdentityCodec.verify(
                        hostKey,
                        activationProof,
                        Base64.getDecoder().decode(
                                request.hostSignatureBase64)));
                check(DualMachinePairingIdentityCodec.verify(
                        androidKey,
                        activationProof,
                        Base64.getDecoder().decode(
                                request.androidSignatureBase64)));
            } catch (GeneralSecurityException exception) {
                throw new IOException(exception);
            }
            if (failFirstConfirmationAfterCommit
                    && !confirmationResponseLost) {
                confirmationResponseLost = true;
                throw new IOException("simulated response loss after commit");
            }
            String mode = responseActivationMode.isEmpty()
                    ? challengeActivationMode : responseActivationMode;
            String product = permanent ? "permanent" : authorizationKind;
            long productSeconds = permanent ? 0L : termSeconds(product);
            if (wrongInitialTermAmount) productSeconds--;
            return new ActivationResponse(
                    responseEntitlementId,
                    activationRequest.pairId,
                    1L,
                    permanent || DualMachineUsageAuthorizationContract
                    .ACTIVATION_MODE_BIND_DEVICE.equals(mode)
                            ? 0L : productSeconds,
                    productSeconds,
                    productSeconds,
                    0L,
                    activationBillingStarted,
                    mode,
                    responseBindingUpdated,
                    product,
                    product,
                    permanent);
        }

        @Override
        public EntitlementStatusResponse fetchEntitlementStatus(
                EntitlementStatusRequest request)
                throws IOException {
            statusRequests++;
            lastStatusNonce = request.requestNonce;
            CountDownLatch entered = statusEntered;
            CountDownLatch release = statusRelease;
            if (entered != null && release != null) {
                entered.countDown();
                try {
                    if (!release.await(5L, TimeUnit.SECONDS)) {
                        throw new IOException(
                                "status race fixture timed out");
                    }
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw new IOException(
                            "status race fixture interrupted",
                            interrupted);
                }
            }
            Error failure = statusError;
            statusError = null;
            if (failure != null) throw failure;
            DualMachineUsageAuthorizationContract.EntitlementStatus value =
                    new DualMachineUsageAuthorizationContract
                            .EntitlementStatus();
            value.entitlementId = request.proof.entitlementId;
            value.pairId = request.proof.pairId;
            value.requestNonce = request.requestNonce;
            value.revocationVersion = request.proof.revocationVersion;
            byte[] payload = DualMachineUsageAuthorizationContract
                    .entitlementStatus(value);
            try {
                check(DualMachinePairingIdentityCodec.verify(
                        hostKey,
                        payload,
                        Base64.getDecoder().decode(
                                request.proof.hostSignatureBase64)));
                check(DualMachinePairingIdentityCodec.verify(
                        androidKey,
                        payload,
                        Base64.getDecoder().decode(
                                request.proof.androidSignatureBase64)));
            } catch (GeneralSecurityException exception) {
                throw new IOException(exception);
            }
            return new EntitlementStatusResponse(
                    status,
                    statusRevision,
                    statusRemaining,
                    permanent ? 0L : termSeconds(authorizationKind),
                    permanent ? 0L : statusConsumed,
                    usageSessionStatus,
                    permanent ? "permanent" : authorizationKind,
                    permanent ? "permanent" : authorizationKind,
                    permanent);
        }

        @Override
        public StartChallengeResponse createStartChallenge(
                StartChallengeRequest request) {
            throw new AssertionError("activation must not start usage");
        }

        @Override
        public UsageLeaseResponse startUsage(StartUsageRequest request) {
            starts++;
            throw new AssertionError("activation must not start usage");
        }

        @Override
        public StartCancellationResponse cancelStart(
                StartCancellationRequest request) {
            throw new AssertionError("activation must not cancel usage start");
        }

        @Override
        public UsageLeaseResponse heartbeat(HeartbeatRequest request) {
            heartbeats++;
            throw new AssertionError("activation must not heartbeat");
        }

        @Override
        public StopResponse stop(StopRequest request) {
            throw new AssertionError("activation must not stop usage");
        }

        private static byte[] activationPayload(
                ActivationChallengeRequest request,
                String activationMode,
                String targetEntitlementId)
                throws GeneralSecurityException {
            DualMachineUsageAuthorizationContract.ActivationConfirmation
                    value = new DualMachineUsageAuthorizationContract
                    .ActivationConfirmation();
            value.activationMode = activationMode;
            value.androidClientVersion = request.android.clientVersion;
            value.androidDeviceCode = request.android.deviceCode;
            value.androidDeviceProfileSha256 = profileSha256(request);
            value.androidKeySha256 = fingerprint(
                    request.android.identityPublicKeyBase64);
            value.challengeId = CHALLENGE_ID;
            value.challengeTokenSha256 = sha256Hex(
                    CHALLENGE_TOKEN.getBytes(StandardCharsets.US_ASCII));
            value.hostClientVersion = request.host.clientVersion;
            value.hostDeviceCode = request.host.deviceCode;
            value.hostKeySha256 = fingerprint(
                    request.host.identityPublicKeyBase64);
            value.pairId = request.pairId;
            value.requestId = request.requestId;
            value.targetEntitlementId = targetEntitlementId;
            return DualMachineUsageAuthorizationContract
                    .activationConfirmation(value);
        }

        private static String profileSha256(
                ActivationChallengeRequest request)
                throws GeneralSecurityException {
            byte[] profile = request.android.deviceProfile == null
                    ? "{}".getBytes(StandardCharsets.UTF_8)
                    : request.android.deviceProfile.canonicalJson();
            return sha256Hex(profile);
        }
    }

    private static String fingerprint(String publicKeyBase64)
            throws GeneralSecurityException {
        return DualMachinePairingIdentityCodec.fingerprintHex(
                DualMachinePairingIdentityCodec.decodePublicKeyBase64(
                        publicKeyBase64));
    }

    private static long termSeconds(String product) {
        if ("day".equals(product)) return DAY_SECONDS;
        if ("week".equals(product)) return WEEK_SECONDS;
        if ("month".equals(product)) return MONTH_SECONDS;
        throw new IllegalArgumentException("unsupported test product");
    }

    private static String sha256Hex(byte[] value)
            throws GeneralSecurityException {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(value);
        StringBuilder result = new StringBuilder(64);
        for (byte current : digest) {
            result.append(String.format(
                    java.util.Locale.ROOT, "%02x", current & 0xff));
        }
        return result.toString();
    }

    private static KeyPair keyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec(
                    DualMachinePairingIdentityCodec.CURVE_NAME));
            return generator.generateKeyPair();
        } catch (GeneralSecurityException exception) {
            throw new AssertionError(exception);
        }
    }

    private static void expectSecurity(Action action) throws Exception {
        try {
            action.run();
            throw new AssertionError("expected security rejection");
        } catch (GeneralSecurityException | SecurityException expected) {
            // Expected.
        }
    }

    private static void expectState(Action action) throws Exception {
        try {
            action.run();
            throw new AssertionError("expected state rejection");
        } catch (IllegalStateException expected) {
            // Expected.
        }
    }

    private static void expectIo(Action action) throws Exception {
        try {
            action.run();
            throw new AssertionError("expected transport failure");
        } catch (IOException expected) {
            // Expected.
        }
    }

    private static void expectError(Action action, Error expected)
            throws Exception {
        try {
            action.run();
        } catch (Error failure) {
            check(failure == expected);
            return;
        }
        throw new AssertionError("expected injected Error");
    }

    private static void check(boolean condition) {
        if (!condition) {
            throw new AssertionError("card authorization check failed");
        }
    }

    @FunctionalInterface
    private interface Action {
        void run() throws Exception;
    }
}
