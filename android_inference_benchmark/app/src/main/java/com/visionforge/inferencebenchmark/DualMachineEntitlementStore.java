package com.visionforge.inferencebenchmark;

/**
 * Minimal persistence boundary for an activated card binding.
 *
 * <p>Implementations must never persist card codes, challenge material,
 * signatures, compact usage leases or session keys.</p>
 */
public interface DualMachineEntitlementStore {
    DualMachineEntitlementRecord load();

    void save(DualMachineEntitlementRecord record);

    void clear();
}
