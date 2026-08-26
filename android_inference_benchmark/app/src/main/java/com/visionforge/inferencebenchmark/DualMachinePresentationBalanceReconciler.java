package com.visionforge.inferencebenchmark;

/**
 * Maintains the non-authorizing last-confirmed balance used by the UI.
 *
 * <p>This cache can improve presentation after a process restart, but it never
 * restores a formal-use lease or opens the data plane.</p>
 */
final class DualMachinePresentationBalanceReconciler {
    private final SharedPreferencesDualMachinePresentationBalanceStore store;
    private final MobileRuntimeEventSink events;

    DualMachinePresentationBalanceReconciler(
            SharedPreferencesDualMachinePresentationBalanceStore store,
            MobileRuntimeEventSink events) {
        if (store == null || events == null) {
            throw new IllegalArgumentException(
                    "presentation balance dependencies are required");
        }
        this.store = store;
        this.events = events;
    }

    DualMachinePresentationBalance reconcile(
            DualMachineFormalUsageStateMachine.Snapshot snapshot,
            boolean previousBalanceKnown) {
        if (snapshot == null) return null;
        try {
            DualMachinePresentationBalance stored = store.load();
            if (snapshot.entitlement == null) {
                if (stored != null) store.clear();
                return null;
            }
            if (snapshot.balanceKnown) {
                DualMachinePresentationBalance confirmed =
                        DualMachinePresentationBalance
                                .fromAuthoritativeSnapshot(
                                        snapshot.entitlement,
                                        snapshot.remainingSeconds,
                                        snapshot.totalConsumedSeconds,
                                        Math.max(
                                                1L,
                                                System.currentTimeMillis()
                                                        / 1_000L));
                if (stored == null || !stored.sameBalance(confirmed)
                        || !previousBalanceKnown) {
                    store.save(confirmed);
                    events.write(
                            "dual_machine_presentation_balance_saved",
                            "authoritative=true formal_authority_restored=false");
                }
                return null;
            }
            if (stored != null && stored.matches(snapshot.entitlement)) {
                return stored;
            }
            if (stored != null) store.clear();
        } catch (RuntimeException failure) {
            events.write(
                    "dual_machine_presentation_balance_rejected",
                    "formal_authority_restored=false failure_type="
                            + failure.getClass().getSimpleName());
            try {
                store.clear();
            } catch (RuntimeException ignored) {
                // Presentation state is non-authorizing; keep the domain
                // runtime available even when its optional cache cannot clear.
            }
        }
        return null;
    }
}
