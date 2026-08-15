package com.visionforge.inferencebenchmark;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Validated, portable subset of the desktop personal-trajectory profile. */
final class PersonalTrajectoryProfile {
    private static final int EXPECTED_ENVELOPE_POINTS = 16;
    private static final int MAXIMUM_DURATION_BINS = 32;

    final boolean enabled;
    final String profileId;
    final String modelType;
    final float medianMovementDurationMillis;
    final float peakTimeFraction;
    final float bellCorrelation;
    final float curveRmsPixels;
    final float highFrequencyEnergyRatio;
    final float holdoutSimilarity;
    final float fittsInterceptMillis;
    final float fittsSlopeMillisPerBit;
    final float jitterAmplitudePixels;
    final float jitterMaximumPixels;
    final float recommendedSpeedScale;
    final float recommendedStabilityScale;
    final float recommendedVariationScale;
    final float[] speedEnvelope;
    final float[] durationBinIds;
    final float[] durationBinMedianMillis;
    final String sourceJson;

    private PersonalTrajectoryProfile(
            boolean enabled,
            String profileId,
            String modelType,
            float medianMovementDurationMillis,
            float peakTimeFraction,
            float bellCorrelation,
            float curveRmsPixels,
            float highFrequencyEnergyRatio,
            float holdoutSimilarity,
            float fittsInterceptMillis,
            float fittsSlopeMillisPerBit,
            float jitterAmplitudePixels,
            float jitterMaximumPixels,
            float recommendedSpeedScale,
            float recommendedStabilityScale,
            float recommendedVariationScale,
            float[] speedEnvelope,
            float[] durationBinIds,
            float[] durationBinMedianMillis,
            String sourceJson) {
        this.enabled = enabled;
        this.profileId = profileId;
        this.modelType = modelType;
        this.medianMovementDurationMillis = medianMovementDurationMillis;
        this.peakTimeFraction = peakTimeFraction;
        this.bellCorrelation = bellCorrelation;
        this.curveRmsPixels = curveRmsPixels;
        this.highFrequencyEnergyRatio = highFrequencyEnergyRatio;
        this.holdoutSimilarity = holdoutSimilarity;
        this.fittsInterceptMillis = fittsInterceptMillis;
        this.fittsSlopeMillisPerBit = fittsSlopeMillisPerBit;
        this.jitterAmplitudePixels = jitterAmplitudePixels;
        this.jitterMaximumPixels = jitterMaximumPixels;
        this.recommendedSpeedScale = recommendedSpeedScale;
        this.recommendedStabilityScale = recommendedStabilityScale;
        this.recommendedVariationScale = recommendedVariationScale;
        this.speedEnvelope = speedEnvelope;
        this.durationBinIds = durationBinIds;
        this.durationBinMedianMillis = durationBinMedianMillis;
        this.sourceJson = sourceJson;
    }

    static PersonalTrajectoryProfile disabled() {
        return new PersonalTrajectoryProfile(
                false, "", "", 480.0f, 0.42f, 0.75f, 2.0f, 0.01f,
                0.75f, 0.0f, 0.0f, 0.20f, 1.0f,
                1.0f, 1.0f, 1.0f, new float[0], new float[0], new float[0], "");
    }

    static PersonalTrajectoryProfile parse(String json) {
        if (json == null || json.isBlank()) throw new IllegalArgumentException("empty_profile");
        try {
            JSONObject root = new JSONObject(json);
            String profileId = root.optString("profile_id", "").trim();
            JSONObject quality = root.optJSONObject("quality");
            JSONObject aggregate = root.optJSONObject("aggregate");
            JSONObject model = root.optJSONObject("trajectory_model");
            if (profileId.isEmpty()) throw new IllegalArgumentException("profile_id_missing");
            if (quality == null || !quality.optBoolean("valid_for_auto_apply", false)) {
                throw new IllegalArgumentException("profile_quality_not_usable");
            }
            if (aggregate == null || model == null) {
                throw new IllegalArgumentException("profile_sections_missing");
            }
            String modelType = model.optString("model_type", "");
            if (!"empirical_envelope_v1".equals(modelType)) {
                throw new IllegalArgumentException("unsupported_model_type");
            }
            float[] envelope = parseEnvelope(model.optJSONArray("speed_envelope_16"));
            float[][] durationBins = parseDurationBins(model.optJSONArray("duration_bins"));
            JSONObject holdout = model.optJSONObject("holdout_similarity");
            float similarity = clamp(number(holdout, "overall_score",
                    number(quality, "holdout_similarity_score", 0.75f)), 0.0f, 1.0f);
            float medianDuration = clamp(number(
                    aggregate, "median_movement_duration_ms", 480.0f), 120.0f, 1_200.0f);
            float curveRms = clamp(number(
                    aggregate, "median_mid_perpendicular_rms_px", 2.0f), 0.0f, 64.0f);
            float frequencyNoise = clamp(number(
                    aggregate, "median_high_freq_energy_ratio", 0.01f), 0.0f, 1.0f);
            float endpointFlips = clamp(number(
                    aggregate, "median_endpoint_sign_flips", 0.0f), 0.0f, 16.0f);
            float[] recommendedScales = recommendedScales(
                    medianDuration, curveRms, frequencyNoise, endpointFlips, similarity);
            JSONObject recommendations = root.optJSONObject("recommendations");
            JSONObject control = recommendations == null
                    ? null : recommendations.optJSONObject("control");
            JSONObject fitts = aggregate.optJSONObject("fitts_law_grouped");
            if (fitts == null) fitts = aggregate.optJSONObject("fitts_law");
            return new PersonalTrajectoryProfile(
                    true,
                    profileId,
                    modelType,
                    medianDuration,
                    clamp(number(aggregate, "median_peak_time_fraction", 0.42f), 0.10f, 0.90f),
                    clamp(number(aggregate, "median_bell_correlation", 0.75f), 0.0f, 1.0f),
                    curveRms,
                    frequencyNoise,
                    similarity,
                    clamp(number(fitts, "intercept_ms", 0.0f), -500.0f, 1_500.0f),
                    clamp(number(fitts, "slope_ms_per_bit", 0.0f), 0.0f, 1_000.0f),
                    clamp(number(control, "personal_trajectory_jitter_amp_px", 0.20f),
                            0.0f, 1.2f),
                    clamp(number(control, "personal_trajectory_jitter_max_px", 1.0f),
                            0.0f, 4.5f),
                    recommendedScales[0],
                    recommendedScales[1],
                    recommendedScales[2],
                    envelope,
                    durationBins[0],
                    durationBins[1],
                    json);
        } catch (JSONException exception) {
            throw new IllegalArgumentException("profile_json_invalid", exception);
        }
    }

    String auditDetail() {
        return String.format(Locale.US,
                "personal_enabled=%s personal_profile_id=%s personal_model=%s "
                        + "personal_envelope_points=%d personal_duration_bins=%d",
                enabled, reportToken(profileId), reportToken(modelType),
                speedEnvelope.length, durationBinIds.length);
    }

    private static float[] parseEnvelope(JSONArray source) throws JSONException {
        if (source == null || source.length() != EXPECTED_ENVELOPE_POINTS) {
            throw new IllegalArgumentException("speed_envelope_must_have_16_points");
        }
        float[] values = new float[EXPECTED_ENVELOPE_POINTS];
        float maximum = 0.0f;
        for (int index = 0; index < values.length; index++) {
            values[index] = finiteFloat(source.getDouble(index), "speed_envelope_non_finite");
            if (values[index] < 0.0f || values[index] > 2.0f) {
                throw new IllegalArgumentException("speed_envelope_out_of_range");
            }
            maximum = Math.max(maximum, values[index]);
        }
        if (maximum <= 0.0f) throw new IllegalArgumentException("speed_envelope_zero");
        return values;
    }

    private static float[][] parseDurationBins(JSONArray source) throws JSONException {
        if (source == null || source.length() == 0) return new float[][]{new float[0], new float[0]};
        List<Float> ids = new ArrayList<>();
        List<Float> medians = new ArrayList<>();
        int count = Math.min(source.length(), MAXIMUM_DURATION_BINS);
        for (int index = 0; index < count; index++) {
            JSONObject row = source.optJSONObject(index);
            if (row == null) continue;
            float id = number(row, "id", -1.0f);
            float median = number(row, "median_ms", -1.0f);
            if (!Float.isFinite(id) || !Float.isFinite(median)
                    || id < 0.0f || median < 40.0f || median > 2_000.0f) {
                continue;
            }
            ids.add(id);
            medians.add(median);
        }
        float[] idValues = new float[ids.size()];
        float[] medianValues = new float[medians.size()];
        for (int index = 0; index < ids.size(); index++) {
            idValues[index] = ids.get(index);
            medianValues[index] = medians.get(index);
        }
        return new float[][]{idValues, medianValues};
    }

    private static float[] recommendedScales(
            float durationMillis,
            float curveRmsPixels,
            float frequencyEnergy,
            float endpointFlips,
            float similarity) {
        float curveNoise = clamp(curveRmsPixels / 8.0f, 0.0f, 1.0f);
        float frequencyNoise = clamp(frequencyEnergy / 0.10f, 0.0f, 1.0f);
        float endpointNoise = clamp(endpointFlips / 4.0f, 0.0f, 1.0f);
        float uncertainty = 1.0f - similarity;
        float noise = clamp(0.55f * curveNoise + 0.20f * frequencyNoise
                + 0.15f * endpointNoise + 0.10f * uncertainty, 0.0f, 1.0f);
        float durationScore = clamp((durationMillis - 350.0f) / 500.0f, 0.0f, 1.0f);
        return new float[]{
                round3(clamp(1.18f + 0.05f * durationScore + 0.02f * similarity,
                        1.15f, 1.25f)),
                round3(clamp(1.18f + 0.14f * noise + 0.04f * uncertainty,
                        1.15f, 1.32f)),
                round3(clamp(0.82f - 0.22f * noise - 0.12f * uncertainty,
                        0.55f, 0.85f))
        };
    }

    private static float number(JSONObject object, String key, float fallback) {
        if (object == null) return fallback;
        double value = object.optDouble(key, fallback);
        return Double.isFinite(value) ? (float) value : fallback;
    }

    private static float finiteFloat(double value, String error) {
        if (!Double.isFinite(value)) throw new IllegalArgumentException(error);
        return (float) value;
    }

    private static float round3(float value) {
        return Math.round(value * 1_000.0f) / 1_000.0f;
    }

    private static float clamp(float value, float minimum, float maximum) {
        return Math.max(minimum, Math.min(maximum, value));
    }

    private static String reportToken(String value) {
        return value == null || value.isBlank() ? "none"
                : value.replace(' ', '_').replace('\r', '_').replace('\n', '_');
    }
}
