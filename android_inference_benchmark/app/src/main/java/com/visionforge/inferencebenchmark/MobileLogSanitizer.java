package com.visionforge.inferencebenchmark;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Central privacy boundary for every value written to the mobile event log. */
final class MobileLogSanitizer {
    static final String REDACTED = "[REDACTED]";

    private static final int PATTERN_FLAGS = Pattern.CASE_INSENSITIVE
            | Pattern.UNICODE_CASE;
    private static final String SENSITIVE_LABEL =
            "(?:card[-_ ]?(?:code|secret|key)(?:[-_ ]?(?:hash|sha256|digest))?"
                    + "|(?:activation|redeem|license)[-_ ]?(?:code|key)"
                    + "|(?:access|refresh|auth|identity|client|challenge|session"
                    + "|device)?[-_ ]?token"
                    + "|api[-_ ]?key|client[-_ ]?secret|password|passwd|secret"
                    + "|(?:(?:usage|activation|pending)[-_ ]?)?ticket"
                    + "(?:[-_ ]?(?:id|token|key|base64|jwt))?"
                    + "|(?:(?:usage|formal|active)[-_ ]?)?lease"
                    + "(?:[-_ ]?(?:id|token|key|signature|sha256|digest|jwt))?"
                    + "|(?:device|host|android|peer)?[-_ ]?proof"
                    + "(?:[-_ ]?(?:id|signature|base64))?"
                    + "|(?:host|android|device|request|response|client|server"
                    + "|pairing)?[-_ ]?signature(?:[-_ ]?(?:base64|der|hex))?"
                    + "|(?:request|response|client|server|session|device"
                    + "|pairing)?[-_ ]?nonce(?:[-_ ]?(?:base64|hex))?"
                    + "|(?:usage[-_ ]?)?session"
                    + "(?:[-_ ]?(?:id|token|key|secret))?"
                    + "|(?:(?:(?:device|host|android|peer)(?:[-_ ]?key)?"
                    + "|local[-_ ]?host)[-_ ]?)?fingerprint"
                    + "(?:[-_ ]?sha256)?"
                    + "|(?:android[-_ ]?)?device[-_ ]?(?:id|code)"
                    + "|channel[-_ ]?binding|(?:request|challenge|pair|entitlement)"
                    + "[-_ ]?id"
                    + "|csrf(?:[-_ ]?token)?|jwt|authorization|\u5361\u5bc6)";
    private static final String QUOTED_OR_TOKEN_VALUE =
            "(?:\"(?:\\\\.|[^\"\\\\])*\""
                    + "|'(?:\\\\.|[^'\\\\])*'"
                    + "|[^\\s,;&}]+)";

    private static final Pattern CARD_CODE_PATTERN = Pattern.compile(
            "(\\bVFD2)(?:[-\\s]?[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]){30}\\b",
            PATTERN_FLAGS);
    private static final Pattern JWT_PATTERN = Pattern.compile(
            "(^|[^A-Za-z0-9_-])(?:[A-Za-z0-9_-]{8,}\\.){2}"
                    + "[A-Za-z0-9_-]{8,}(?=$|[^A-Za-z0-9_-])");
    private static final Pattern COOKIE_HEADER_PATTERN = Pattern.compile(
            "(\\b(?:set-cookie|cookie)\\b[\"']?\\s*[:=]\\s*)[^\\r\\n]*",
            PATTERN_FLAGS);
    private static final Pattern AUTHORIZATION_PATTERN = Pattern.compile(
            "(\\bauthorization\\b[\"']?\\s*[:=]\\s*)"
                    + "(?:(?:bearer|basic|digest|token|api[-_ ]?key)\\s+)?"
                    + QUOTED_OR_TOKEN_VALUE,
            PATTERN_FLAGS);
    private static final Pattern BEARER_PATTERN = Pattern.compile(
            "(\\bbearer\\s+)" + QUOTED_OR_TOKEN_VALUE,
            PATTERN_FLAGS);
    private static final Pattern SENSITIVE_PATH_PATTERN = Pattern.compile(
            "(/(?:usage-)?(?:sessions?|tickets?|leases?|proofs?)/)"
                    + "[^/?#\\s]+",
            PATTERN_FLAGS);
    private static final Pattern SENSITIVE_KEY_VALUE_PATTERN = Pattern.compile(
            "((?:\\b" + SENSITIVE_LABEL + "\\b|\u5361\u5bc6)[\"']?\\s*[:=]\\s*)"
                    + QUOTED_OR_TOKEN_VALUE,
            PATTERN_FLAGS);
    private static final Pattern SENSITIVE_LABELED_TOKEN_PATTERN = Pattern.compile(
            "((?:\\b" + SENSITIVE_LABEL + "\\b|\u5361\u5bc6)\\s+(?:is\\s+)?)"
                    + "(?=[A-Za-z0-9+/_=.:-]*[0-9+/_=.:-])"
                    + "[A-Za-z0-9][A-Za-z0-9+/_=.:-]{7,}",
            PATTERN_FLAGS);

    private MobileLogSanitizer() {
    }

    static String sanitize(String value) {
        if (value == null || value.isEmpty()) return "";
        String sanitized = redact(CARD_CODE_PATTERN, value);
        sanitized = redact(JWT_PATTERN, sanitized);
        sanitized = redact(COOKIE_HEADER_PATTERN, sanitized);
        sanitized = redact(AUTHORIZATION_PATTERN, sanitized);
        sanitized = redact(BEARER_PATTERN, sanitized);
        sanitized = redact(SENSITIVE_PATH_PATTERN, sanitized);
        sanitized = redact(SENSITIVE_KEY_VALUE_PATTERN, sanitized);
        return redact(SENSITIVE_LABELED_TOKEN_PATTERN, sanitized);
    }

    private static String redact(Pattern pattern, String value) {
        return pattern.matcher(value).replaceAll(
                "$1" + Matcher.quoteReplacement(REDACTED));
    }
}
