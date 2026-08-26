package com.visionforge.inferencebenchmark;

/** Immutable cross-executor owner for one authorization/pipeline pair. */
final class FormalPipelineOwnerReceipt {
    final DualMachineAuthorizationRuntime runtime;
    final DualMachineAuthorizationRuntime.CurrentGenerationReceipt
            authorizationReceipt;
    final long pipelineGeneration;
    final MobileTransportEndpoint endpoint;

    FormalPipelineOwnerReceipt(
            DualMachineAuthorizationRuntime runtime,
            DualMachineAuthorizationRuntime.CurrentGenerationReceipt
                    authorizationReceipt,
            long pipelineGeneration,
            MobileTransportEndpoint endpoint) {
        this.runtime = runtime;
        this.authorizationReceipt = authorizationReceipt;
        this.pipelineGeneration = pipelineGeneration;
        this.endpoint = endpoint;
    }

    boolean owns(long generation, MobileTransportEndpoint candidate) {
        if (pipelineGeneration != generation) return false;
        if (endpoint == null || candidate == null) {
            return endpoint == candidate;
        }
        return endpoint.hasSameDataPlaneRoute(candidate);
    }
}
