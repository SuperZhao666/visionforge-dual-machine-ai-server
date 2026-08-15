package com.visionforge.inferencebenchmark;

final class PersonalTrajectoryProfileSelfTest {
    static void run() {
        String json = "{"
                + "\"profile_id\":\"profile-1\","
                + "\"quality\":{\"valid_for_auto_apply\":true},"
                + "\"aggregate\":{"
                + "\"median_movement_duration_ms\":540,"
                + "\"median_peak_time_fraction\":0.39,"
                + "\"median_bell_correlation\":0.44,"
                + "\"median_mid_perpendicular_rms_px\":11.68,"
                + "\"median_high_freq_energy_ratio\":0.01069,"
                + "\"median_endpoint_sign_flips\":0,"
                + "\"fitts_law_grouped\":{\"intercept_ms\":-77.5,"
                + "\"slope_ms_per_bit\":163.4}},"
                + "\"recommendations\":{\"control\":{"
                + "\"personal_trajectory_jitter_amp_px\":0.85,"
                + "\"personal_trajectory_jitter_max_px\":3.5}},"
                + "\"trajectory_model\":{"
                + "\"model_type\":\"empirical_envelope_v1\","
                + "\"speed_envelope_16\":[0.17,0.24,0.40,0.65,0.97,1.0,0.92,0.86,"
                + "0.62,0.48,0.37,0.23,0.19,0.13,0.14,0.21],"
                + "\"duration_bins\":[{\"id\":3.5,\"median_ms\":435,\"n\":22}],"
                + "\"holdout_similarity\":{\"overall_score\":0.836}}}";
        PersonalTrajectoryProfile profile = PersonalTrajectoryProfile.parse(json);
        assert profile.enabled;
        assert "profile-1".equals(profile.profileId);
        assert profile.speedEnvelope.length == 16;
        assert profile.durationBinIds.length == 1;
        assert Math.abs(profile.recommendedSpeedScale - 1.223f) < 0.002f;
        assert Math.abs(profile.recommendedStabilityScale - 1.266f) < 0.002f;
        assert Math.abs(profile.recommendedVariationScale - 0.679f) < 0.002f;
        assert Math.abs(profile.jitterAmplitudePixels - 0.85f) < 0.001f;

        boolean rejected = false;
        try {
            PersonalTrajectoryProfile.parse(json.replace(
                    "\"valid_for_auto_apply\":true", "\"valid_for_auto_apply\":false"));
        } catch (IllegalArgumentException expected) {
            rejected = true;
        }
        assert rejected;
    }

    private PersonalTrajectoryProfileSelfTest() {
    }
}
