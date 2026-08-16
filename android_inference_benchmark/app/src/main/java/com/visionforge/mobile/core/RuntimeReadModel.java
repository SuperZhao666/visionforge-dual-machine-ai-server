package com.visionforge.mobile.core;

/** Read-only state boundary for presentation code. */
@FunctionalInterface
public interface RuntimeReadModel {
    RuntimeSnapshot snapshot();
}
