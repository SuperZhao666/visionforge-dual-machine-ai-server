package com.visionforge.inferencebenchmark.runtime;

/**
 * Public same-process boundary implemented by the concrete Android Binder.
 *
 * <p>UI code depends only on this interface. The Service may change its Binder,
 * coordinators or process layout without forcing an Activity rewrite.</p>
 */
public interface MobileRuntimeBinding
        extends MobileRuntimeCommandPort, MobileRuntimeStatePort {}
