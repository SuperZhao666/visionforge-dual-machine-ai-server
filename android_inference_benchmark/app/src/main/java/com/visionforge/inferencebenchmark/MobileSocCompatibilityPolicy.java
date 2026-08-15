package com.visionforge.inferencebenchmark;

import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Pure policy that classifies Android SoCs without loading a vendor runtime.
 *
 * <p>The result is a routing contract, not proof that a vendor accelerator is
 * usable.  Backend initialisation and one real graph execution remain the
 * authoritative readiness checks.</p>
 */
final class MobileSocCompatibilityPolicy {
    enum Family {
        SNAPDRAGON,
        DIMENSITY,
        KIRIN,
        EXYNOS,
        TENSOR,
        ANDROID_EMULATOR,
        UNKNOWN
    }

    enum Era {
        LEGACY_2018_AND_EARLIER,
        GENERATION_2019_2021,
        GENERATION_2022_2023,
        GENERATION_2024_PLUS,
        UNKNOWN
    }

    enum RequiredBackend {
        QNN_HTP,
        PORTABLE_NNAPI,
        EMULATOR_REFERENCE,
        RUNTIME_PROBE
    }

    private static final Pattern SNAPDRAGON_TOKEN = Pattern.compile(
            "(?i)(?:^|[^A-Z0-9])((?:SM|SDM|MSM|APQ|QCM|QCS)[0-9]{3,4})"
                    + "(?:[A-Z])?(?:$|[^A-Z0-9])");
    private static final Pattern MEDIATEK_TOKEN = Pattern.compile(
            "(?i)(?:^|[^A-Z0-9])(MT[0-9]{4})"
                    + "(?:[A-Z])?(?:$|[^A-Z0-9])");
    private static final Pattern KIRIN_TOKEN = Pattern.compile(
            "(?i)(?:KIRIN[ _-]*([0-9]{3,4}[A-Z0-9]*))|(?:^|[^A-Z0-9])(HI[0-9]{4})(?:$|[^A-Z0-9])");
    private static final Pattern EXYNOS_TOKEN = Pattern.compile(
            "(?i)(?:EXYNOS[ _-]*([0-9]{3,4}))|(?:^|[^A-Z0-9])(S5E[0-9]{3,4})(?:$|[^A-Z0-9])");
    private static final Pattern TENSOR_HARDWARE_TOKEN = Pattern.compile(
            "(?i)(?:^|[^A-Z0-9])(GS[0-9]{3})(?:$|[^A-Z0-9])");
    private static final Pattern TENSOR_MARKETING_GENERATION = Pattern.compile(
            "(?i)(?:^|[^A-Z0-9])(?:GOOGLE[ _-]+)?TENSOR[ _-]*G?([1-9])"
                    + "(?:$|[^0-9])");
    private static final Pattern SNAPDRAGON_888_MARKETING = Pattern.compile(
            "(?i)(?:^|[^A-Z0-9])SNAPDRAGON[ _-]+888"
                    + "(?:[ _-]*(?:\\+|PLUS))?(?:$|[^A-Z0-9])");
    private static final Pattern SNAPDRAGON_8_PLUS_GEN_1_MARKETING = Pattern.compile(
            "(?i)(?:^|[^A-Z0-9])SNAPDRAGON[ _-]+8[ _-]*(?:\\+|PLUS)"
                    + "[ _-]*GEN[ _-]*1(?:$|[^A-Z0-9])");
    private static final Pattern SNAPDRAGON_8_GEN_1_MARKETING = Pattern.compile(
            "(?i)(?:^|[^A-Z0-9])SNAPDRAGON[ _-]+8[ _-]+GEN[ _-]*1"
                    + "(?:$|[^A-Z0-9])");
    private static final Pattern SNAPDRAGON_8_GEN_2_MARKETING = Pattern.compile(
            "(?i)(?:^|[^A-Z0-9])SNAPDRAGON[ _-]+8[ _-]+GEN[ _-]*2"
                    + "(?:$|[^A-Z0-9])");
    private static final Pattern SNAPDRAGON_8_GEN_3_MARKETING = Pattern.compile(
            "(?i)(?:^|[^A-Z0-9])SNAPDRAGON[ _-]+8[ _-]+GEN[ _-]*3"
                    + "(?:$|[^A-Z0-9])");
    private static final Pattern SNAPDRAGON_8_ELITE_GEN_5_MARKETING = Pattern.compile(
            "(?i)(?:^|[^A-Z0-9])SNAPDRAGON[ _-]+8[ _-]+ELITE"
                    + "[ _-]+GEN[ _-]*5(?:$|[^A-Z0-9])");
    private static final Pattern SNAPDRAGON_8_ELITE_MARKETING = Pattern.compile(
            "(?i)(?:^|[^A-Z0-9])SNAPDRAGON[ _-]+8[ _-]+ELITE"
                    + "(?![ _-]+GEN[ _-]+[0-9])(?:$|[^A-Z0-9])");
    private static final Pattern DIMENSITY_MARKETING_MODEL = Pattern.compile(
            "(?i)(?:^|[^A-Z0-9])DIMENSITY[ _-]+"
                    + "(9000|9200|9300|9400|9500)"
                    + "(?:[ _-]*(?:\\+|PLUS))?(?:$|[^A-Z0-9])");

    private static final Map<String, String> SNAPDRAGON_HTP_ARCHITECTURES = Map.ofEntries(
            Map.entry("SM8350", "v68"),
            Map.entry("QCM6490", "v68"),
            Map.entry("SM8450", "v69"),
            Map.entry("SM8475", "v69"),
            Map.entry("SM8550", "v73"),
            Map.entry("SM8650", "v75"),
            Map.entry("SM8750", "v79"),
            Map.entry("SM8845", "v81"),
            Map.entry("SM8850", "v81"));
    private static final Map<String, String> SNAPDRAGON_PLATFORM_MODELS = Map.ofEntries(
            Map.entry("LAHAINA", "SM8350"),
            Map.entry("TARO", "SM8450"),
            Map.entry("WAIPIO", "SM8450"),
            Map.entry("CAPE", "SM8475"),
            Map.entry("KALAMA", "SM8550"),
            Map.entry("PINEAPPLE", "SM8650"),
            Map.entry("SUN", "SM8750"));
    private static final Map<String, String> DIMENSITY_MARKETING_MODELS = Map.of(
            "9000", "MT6983",
            "9200", "MT6985",
            "9300", "MT6989",
            "9400", "MT6991",
            "9500", "MT6993");
    private static final Set<String> LEGACY_SOCS = Set.of(
            "MSM8996", "MSM8998", "APQ8084", "APQ8096",
            "SDM660", "SDM710", "SDM845",
            "KIRIN970", "KIRIN980", "HI3660", "HI3670",
            "KIRIN710", "MT6763", "MT6771", "MT6797",
            "EXYNOS8895", "EXYNOS9810", "S5E8895", "S5E9810");
    private static final Set<String> GENERATION_2019_2021_SOCS = Set.of(
            "SDM855", "SM8150", "SDM865", "SM8250", "SM7250", "SM8350",
            "QCM6490",
            "MT6873", "MT6885", "MT6889", "MT6891", "MT6893", "MT6983",
            "KIRIN710A", "KIRIN810", "KIRIN820", "KIRIN985", "KIRIN990",
            "KIRIN9000", "KIRIN9000E", "KIRIN9000L",
            "EXYNOS980", "EXYNOS9820", "EXYNOS9825", "EXYNOS990",
            "EXYNOS1080", "EXYNOS2100",
            "S5E9820", "S5E9825", "S5E9830", "S5E9840",
            "GS101");
    private static final Set<String> GENERATION_2022_2023_SOCS = Set.of(
            "SM8450", "SM8475", "SM8550", "SM8650",
            "MT6895", "MT6897", "MT6985", "MT6989",
            "KIRIN9000S", "EXYNOS1280", "EXYNOS1380", "EXYNOS2200",
            "S5E8825", "S5E8835", "S5E9925", "GS201", "GS301");
    private static final Set<String> GENERATION_2024_PLUS_SOCS = Set.of(
            "SM8750", "SM8845", "SM8850", "MT6991", "MT6993",
            "KIRIN9000S1", "KIRIN9010", "KIRIN9020",
            "EXYNOS1480", "EXYNOS2400", "EXYNOS2500",
            "S5E8845", "S5E9945", "S5E9955",
            "GS401", "GS501");

    private MobileSocCompatibilityPolicy() {}

    static Result evaluate(
            String reportedSocModel,
            String reportedSocManufacturer,
            String reportedHardware) {
        String socModel = normalized(reportedSocModel);
        String socManufacturer = normalized(reportedSocManufacturer);
        String hardware = normalized(reportedHardware);
        String combined = socModel + " " + socManufacturer + " " + hardware;
        if (containsAny(combined, "RANCHU", "GOLDFISH", "CUTTLEFISH")) {
            return result(
                    Family.ANDROID_EMULATOR, Era.UNKNOWN,
                    "android-emulator", RequiredBackend.EMULATOR_REFERENCE,
                    "none");
        }

        Result direct = directTokenResult(socModel);
        if (direct != null) return direct;
        direct = directTokenResult(hardware);
        if (direct != null) return direct;
        direct = directTokenResult(socManufacturer);
        if (direct != null) return direct;

        boolean qualcommMarker = containsAny(
                combined, "QUALCOMM", "SNAPDRAGON", "QCOM", "QTI");
        boolean nonQualcommVendorMarker = containsAny(
                combined,
                "MEDIATEK", "DIMENSITY", "MTK",
                "HISILICON", "KIRIN", "EXYNOS", "GOOGLE TENSOR");
        String platformModel = snapdragonPlatformModel(hardware);
        if (!platformModel.isEmpty()
                && (qualcommMarker || !nonQualcommVendorMarker)) {
            return snapdragonResult(platformModel);
        }
        if (qualcommMarker) return snapdragonResult("");
        if (containsAny(combined, "MEDIATEK", "DIMENSITY", "MTK")) {
            return portableResult(Family.DIMENSITY, "", "unknown-dimensity");
        }
        if (containsAny(combined, "HISILICON", "KIRIN")) {
            return portableResult(Family.KIRIN, "", "unknown-kirin");
        }
        if (combined.contains("EXYNOS")) {
            return portableResult(Family.EXYNOS, "", "unknown-exynos");
        }
        if (combined.contains("GOOGLE TENSOR")) {
            return portableResult(Family.TENSOR, "", "unknown-tensor");
        }

        return result(
                Family.UNKNOWN, Era.UNKNOWN, "unknown",
                RequiredBackend.RUNTIME_PROBE, "none");
    }

    private static Result directTokenResult(String value) {
        String token = extract(SNAPDRAGON_TOKEN, value);
        if (!token.isEmpty()) return snapdragonResult(token);
        token = extract(MEDIATEK_TOKEN, value);
        if (!token.isEmpty()) {
            return portableResult(Family.DIMENSITY, token, "unknown-dimensity");
        }
        token = extractKirin(value);
        if (!token.isEmpty()) {
            return portableResult(Family.KIRIN, token, "unknown-kirin");
        }
        token = extractPrefixed(EXYNOS_TOKEN, value, "EXYNOS");
        if (!token.isEmpty()) {
            return portableResult(Family.EXYNOS, token, "unknown-exynos");
        }
        token = extractTensor(value);
        if (!token.isEmpty()) {
            return portableResult(Family.TENSOR, token, "unknown-tensor");
        }
        token = snapdragonMarketingModel(value);
        if (!token.isEmpty()) return snapdragonResult(token);
        token = dimensityMarketingModel(value);
        if (!token.isEmpty()) {
            return portableResult(Family.DIMENSITY, token, "unknown-dimensity");
        }
        return null;
    }

    private static String snapdragonMarketingModel(String value) {
        if (SNAPDRAGON_8_ELITE_GEN_5_MARKETING.matcher(value).find()) return "SM8850";
        if (SNAPDRAGON_8_ELITE_MARKETING.matcher(value).find()) return "SM8750";
        if (SNAPDRAGON_8_GEN_3_MARKETING.matcher(value).find()) return "SM8650";
        if (SNAPDRAGON_8_GEN_2_MARKETING.matcher(value).find()) return "SM8550";
        if (SNAPDRAGON_8_PLUS_GEN_1_MARKETING.matcher(value).find()) return "SM8475";
        if (SNAPDRAGON_8_GEN_1_MARKETING.matcher(value).find()) return "SM8450";
        if (SNAPDRAGON_888_MARKETING.matcher(value).find()) return "SM8350";
        return "";
    }

    private static String dimensityMarketingModel(String value) {
        Matcher matcher = DIMENSITY_MARKETING_MODEL.matcher(value);
        if (!matcher.find()) return "";
        String model = DIMENSITY_MARKETING_MODELS.get(normalized(matcher.group(1)));
        return model == null ? "" : model;
    }

    private static Result snapdragonResult(String token) {
        String canonical = token.isEmpty() ? "unknown-snapdragon" : token;
        String htpArchitecture = SNAPDRAGON_HTP_ARCHITECTURES.get(canonical);
        if (htpArchitecture != null) {
            return result(
                    Family.SNAPDRAGON, era(canonical), canonical,
                    RequiredBackend.QNN_HTP, htpArchitecture);
        }
        return result(
                Family.SNAPDRAGON, era(canonical), canonical,
                RequiredBackend.PORTABLE_NNAPI, "none");
    }

    private static Result portableResult(
            Family family, String token, String unknownToken) {
        String canonical = token.isEmpty() ? unknownToken : token;
        return result(
                family, era(canonical), canonical,
                RequiredBackend.PORTABLE_NNAPI, "none");
    }

    private static String snapdragonPlatformModel(String hardwareEvidence) {
        for (String token : normalized(hardwareEvidence).split("[\\s,;]+")) {
            String model = SNAPDRAGON_PLATFORM_MODELS.get(token);
            if (model != null) return model;
        }
        return "";
    }

    static String expectedHtpArchitecture(String canonicalSocModel) {
        return SNAPDRAGON_HTP_ARCHITECTURES.get(
                normalized(canonicalSocModel));
    }

    private static Result result(
            Family family,
            Era era,
            String canonicalSocModel,
            RequiredBackend requiredBackend,
            String htpArchitecture) {
        return new Result(
                family, era, canonicalSocModel,
                requiredBackend, htpArchitecture);
    }

    private static Era era(String canonicalSocModel) {
        if (LEGACY_SOCS.contains(canonicalSocModel)) {
            return Era.LEGACY_2018_AND_EARLIER;
        }
        if (GENERATION_2019_2021_SOCS.contains(canonicalSocModel)) {
            return Era.GENERATION_2019_2021;
        }
        if (GENERATION_2022_2023_SOCS.contains(canonicalSocModel)) {
            return Era.GENERATION_2022_2023;
        }
        if (GENERATION_2024_PLUS_SOCS.contains(canonicalSocModel)) {
            return Era.GENERATION_2024_PLUS;
        }
        return Era.UNKNOWN;
    }

    private static String extract(Pattern pattern, String value) {
        Matcher matcher = pattern.matcher(value);
        return matcher.find() ? normalized(matcher.group(1)) : "";
    }

    private static String extractKirin(String value) {
        Matcher matcher = KIRIN_TOKEN.matcher(value);
        if (!matcher.find()) return "";
        if (matcher.group(1) != null) {
            return "KIRIN" + normalized(matcher.group(1));
        }
        return normalized(matcher.group(2));
    }

    private static String extractPrefixed(
            Pattern pattern,
            String value,
            String prefix) {
        Matcher matcher = pattern.matcher(value);
        if (!matcher.find()) return "";
        String first = matcher.group(1);
        String second = matcher.groupCount() >= 2 ? matcher.group(2) : null;
        if (first != null) return prefix + normalized(first);
        return normalized(second);
    }

    private static String extractTensor(String value) {
        String hardwareToken = extract(TENSOR_HARDWARE_TOKEN, value);
        if (!hardwareToken.isEmpty()) return hardwareToken;
        Matcher marketing = TENSOR_MARKETING_GENERATION.matcher(value);
        if (!marketing.find()) return "";
        int generation = Integer.parseInt(marketing.group(1));
        return "GS" + generation + "01";
    }

    private static boolean containsAny(String value, String... tokens) {
        for (String token : tokens) {
            if (value.contains(token)) return true;
        }
        return false;
    }

    private static String normalized(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }

    static final class Result {
        final Family family;
        final Era era;
        final String canonicalSocModel;
        final RequiredBackend requiredBackend;
        final String expectedHtpArchitecture;

        Result(
                Family family,
                Era era,
                String canonicalSocModel,
                RequiredBackend requiredBackend,
                String expectedHtpArchitecture) {
            this.family = family;
            this.era = era;
            this.canonicalSocModel = canonicalSocModel;
            this.requiredBackend = requiredBackend;
            this.expectedHtpArchitecture = expectedHtpArchitecture;
        }

        String detail() {
            return "soc_family=" + family.name().toLowerCase(Locale.ROOT)
                    + " soc_era=" + era.name().toLowerCase(Locale.ROOT)
                    + " soc_model=" + canonicalSocModel
                    + " required_backend="
                    + requiredBackend.name().toLowerCase(Locale.ROOT)
                    + " expected_htp_architecture="
                    + expectedHtpArchitecture
                    + " readiness_proof=backend_init_and_real_graph_execution";
        }
    }
}
