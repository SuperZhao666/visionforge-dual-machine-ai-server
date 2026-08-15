package com.visionforge.inferencebenchmark;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * Non-sensitive Android hardware summary carried only for owner audit.
 *
 * <p>The profile is not an authorization key. In particular, it never carries
 * raw ANDROID_ID, IMEI, phone number or device serial values.</p>
 */
public final class DualMachineAndroidDeviceProfile {
    private static final int MAX_TEXT_CHARACTERS = 128;
    private static final int MAX_ABIS = 16;

    public final String manufacturer;
    public final String brand;
    public final String model;
    public final String device;
    public final String product;
    public final String hardware;
    public final String osRelease;
    public final int sdkInt;
    public final List<String> supportedAbis;
    public final String deviceFingerprint;

    public DualMachineAndroidDeviceProfile(
            String manufacturer,
            String brand,
            String model,
            String device,
            String product,
            String hardware,
            String osRelease,
            int sdkInt,
            List<String> supportedAbis,
            String deviceFingerprint) {
        this.manufacturer = boundedText(manufacturer, "manufacturer");
        this.brand = boundedText(brand, "brand");
        this.model = boundedText(model, "model");
        this.device = boundedText(device, "device");
        this.product = boundedText(product, "product");
        this.hardware = boundedText(hardware, "hardware");
        this.osRelease = boundedText(osRelease, "osRelease");
        if (sdkInt <= 0 || sdkInt > 10_000) {
            throw new IllegalArgumentException("sdkInt is invalid");
        }
        this.sdkInt = sdkInt;
        if (supportedAbis == null || supportedAbis.isEmpty()
                || supportedAbis.size() > MAX_ABIS) {
            throw new IllegalArgumentException("supportedAbis is invalid");
        }
        ArrayList<String> abis = new ArrayList<>(supportedAbis.size());
        for (String abi : supportedAbis) {
            String normalized = boundedText(abi, "supportedAbi");
            if (abis.contains(normalized)) {
                throw new IllegalArgumentException(
                        "supportedAbis contains a duplicate");
            }
            abis.add(normalized);
        }
        this.supportedAbis = Collections.unmodifiableList(abis);
        this.deviceFingerprint = DualMachineSidecarValues.sha256(
                deviceFingerprint, "deviceFingerprint");
    }

    /** Canonical UTF-8 JSON; keys intentionally match the server normalizer. */
    public byte[] canonicalJson() {
        StringBuilder json = new StringBuilder(768).append('{');
        stringField(json, "brand", brand, true);
        stringField(json, "device", device, false);
        stringField(json, "device_fingerprint", deviceFingerprint, false);
        stringField(json, "hardware", hardware, false);
        stringField(json, "manufacturer", manufacturer, false);
        stringField(json, "model", model, false);
        stringField(json, "os_release", osRelease, false);
        stringField(json, "product", product, false);
        json.append(",\"sdk_int\":").append(sdkInt);
        json.append(",\"supported_abis\":[");
        for (int index = 0; index < supportedAbis.size(); index++) {
            if (index > 0) json.append(',');
            quote(json, supportedAbis.get(index));
        }
        json.append("]}");
        return json.toString().getBytes(StandardCharsets.UTF_8);
    }

    public String canonicalSha256() {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(canonicalJson());
            StringBuilder value = new StringBuilder(64);
            for (byte octet : digest) {
                value.append(String.format(
                        Locale.ROOT, "%02x", octet & 0xff));
            }
            return value.toString();
        } catch (NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException(
                    "SHA-256 is unavailable", unavailable);
        }
    }

    private static String boundedText(String value, String name) {
        String normalized = value == null ? "" : value.trim();
        if (normalized.isEmpty()
                || normalized.length() > MAX_TEXT_CHARACTERS) {
            throw new IllegalArgumentException(name + " is invalid");
        }
        for (int index = 0; index < normalized.length(); index++) {
            char character = normalized.charAt(index);
            if (Character.isISOControl(character)) {
                throw new IllegalArgumentException(name + " is invalid");
            }
        }
        return normalized;
    }

    private static void stringField(
            StringBuilder destination,
            String name,
            String value,
            boolean first) {
        if (!first) destination.append(',');
        quote(destination, name);
        destination.append(':');
        quote(destination, value);
    }

    private static void quote(StringBuilder destination, String value) {
        destination.append('"');
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '"':
                    destination.append("\\\"");
                    break;
                case '\\':
                    destination.append("\\\\");
                    break;
                case '\b':
                    destination.append("\\b");
                    break;
                case '\f':
                    destination.append("\\f");
                    break;
                case '\n':
                    destination.append("\\n");
                    break;
                case '\r':
                    destination.append("\\r");
                    break;
                case '\t':
                    destination.append("\\t");
                    break;
                default:
                    if (character < 0x20) {
                        destination.append(String.format(
                                Locale.ROOT, "\\u%04x", (int) character));
                    } else {
                        destination.append(character);
                    }
                    break;
            }
        }
        destination.append('"');
    }
}
