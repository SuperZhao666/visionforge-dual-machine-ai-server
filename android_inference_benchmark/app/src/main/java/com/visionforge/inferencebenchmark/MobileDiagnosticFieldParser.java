package com.visionforge.inferencebenchmark;

/** Exact parser for whitespace/braced key-value fields in native reports. */
final class MobileDiagnosticFieldParser {
    private MobileDiagnosticFieldParser() {}

    static boolean hasField(String report, String field) {
        return fieldStart(report, key(field)) >= 0;
    }

    static boolean isTrue(String report, String field) {
        String parsed = value(report, field);
        return "1".equals(parsed) || "true".equalsIgnoreCase(parsed);
    }

    static String valueOr(String report, String field, String fallback) {
        String parsed = value(report, field);
        return parsed == null ? fallback : parsed;
    }

    private static String value(String report, String field) {
        String key = key(field);
        int start = fieldStart(report, key);
        if (start < 0) return null;
        start += key.length();
        int end = start;
        while (end < report.length() && !isValueBoundary(report.charAt(end))) {
            end++;
        }
        return end == start ? null : report.substring(start, end);
    }

    private static int fieldStart(String report, String key) {
        if (report == null || report.isEmpty() || key == null) return -1;
        int searchFrom = 0;
        while (searchFrom < report.length()) {
            int start = report.indexOf(key, searchFrom);
            if (start < 0) return -1;
            if (start == 0 || isFieldBoundary(report.charAt(start - 1))) {
                return start;
            }
            searchFrom = start + key.length();
        }
        return -1;
    }

    private static String key(String field) {
        if (field == null || field.isEmpty() || field.indexOf('=') >= 0) {
            throw new IllegalArgumentException("diagnostic field name is invalid");
        }
        return field + "=";
    }

    private static boolean isFieldBoundary(char character) {
        return Character.isWhitespace(character)
                || character == '{'
                || character == ','
                || character == ';';
    }

    private static boolean isValueBoundary(char character) {
        return Character.isWhitespace(character)
                || character == '}'
                || character == ','
                || character == ';';
    }
}
