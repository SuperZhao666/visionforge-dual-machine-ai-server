package com.visionforge.inferencebenchmark;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Minimal strict JSON support for flat dual-machine sidecar responses.
 *
 * <p>This intentionally does not implement arrays, nested response objects,
 * floating-point numbers or null. None are part of the public sidecar
 * contract, and accepting them would enlarge the parser's attack surface.</p>
 */
final class DualMachineStrictJson {
    private static final int MAXIMUM_RESPONSE_BYTES = 128 * 1024;
    private static final int MAXIMUM_STRING_CHARACTERS = 16 * 1024;
    private static final String CONTRACT_ERROR =
            "dual-machine sidecar response violates contract";

    private DualMachineStrictJson() {
    }

    static Fields parseObject(byte[] encoded) throws IOException {
        if (encoded == null || encoded.length < 2
                || encoded.length > MAXIMUM_RESPONSE_BYTES) {
            throw contractError();
        }
        String text = decodeUtf8(encoded);
        return new Parser(text).parse();
    }

    static byte[] utf8(StringBuilder json) {
        return json.toString().getBytes(StandardCharsets.UTF_8);
    }

    static void quoted(StringBuilder destination, String value) {
        if (value == null) {
            throw new IllegalArgumentException("JSON string is required");
        }
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
                        appendUnicodeEscape(destination, character);
                    } else if (Character.isHighSurrogate(character)) {
                        if (index + 1 >= value.length()
                                || !Character.isLowSurrogate(
                                value.charAt(index + 1))) {
                            throw new IllegalArgumentException(
                                    "JSON string has invalid Unicode");
                        }
                        destination.append(character);
                        destination.append(value.charAt(++index));
                    } else if (Character.isLowSurrogate(character)) {
                        throw new IllegalArgumentException(
                                "JSON string has invalid Unicode");
                    } else {
                        destination.append(character);
                    }
                    break;
            }
        }
        destination.append('"');
    }

    static IOException contractError() {
        return new IOException(CONTRACT_ERROR);
    }

    private static String decodeUtf8(byte[] encoded) throws IOException {
        try {
            CharBuffer decoded = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(encoded));
            return decoded.toString();
        } catch (CharacterCodingException exception) {
            throw contractError();
        }
    }

    private static void appendUnicodeEscape(
            StringBuilder destination,
            char value) {
        destination.append("\\u");
        for (int shift = 12; shift >= 0; shift -= 4) {
            destination.append(Character.forDigit(
                    (value >>> shift) & 0x0f, 16));
        }
    }

    static final class Fields {
        private final Map<String, Object> values;

        Fields(Map<String, Object> values) {
            this.values = values;
        }

        void requireExactly(String... names) throws IOException {
            if (names == null || values.size() != names.length) {
                throw contractError();
            }
            for (String name : names) {
                if (!values.containsKey(name)) {
                    throw contractError();
                }
            }
        }

        String string(String name, int minimum, int maximum)
                throws IOException {
            Object value = values.get(name);
            if (!(value instanceof String)) {
                throw contractError();
            }
            String text = (String) value;
            if (text.length() < minimum || text.length() > maximum) {
                throw contractError();
            }
            return text;
        }

        boolean bool(String name) throws IOException {
            Object value = values.get(name);
            if (!(value instanceof Boolean)) {
                throw contractError();
            }
            return (Boolean) value;
        }

        long integer(String name, long minimum, long maximum)
                throws IOException {
            Object value = values.get(name);
            if (!(value instanceof Long)) {
                throw contractError();
            }
            long number = (Long) value;
            if (number < minimum || number > maximum) {
                throw contractError();
            }
            return number;
        }
    }

    private static final class Parser {
        private final String text;
        private int offset;

        Parser(String text) {
            this.text = text;
        }

        Fields parse() throws IOException {
            skipWhitespace();
            require('{');
            skipWhitespace();
            Map<String, Object> fields = new LinkedHashMap<>();
            if (consume('}')) {
                finish();
                return new Fields(fields);
            }
            while (true) {
                String name = parseString();
                if (fields.containsKey(name)) {
                    throw contractError();
                }
                skipWhitespace();
                require(':');
                skipWhitespace();
                fields.put(name, parseValue());
                skipWhitespace();
                if (consume('}')) {
                    finish();
                    return new Fields(fields);
                }
                require(',');
                skipWhitespace();
            }
        }

        private Object parseValue() throws IOException {
            if (peek('"')) {
                return parseString();
            }
            if (peek('t')) {
                requireLiteral("true");
                return Boolean.TRUE;
            }
            if (peek('f')) {
                requireLiteral("false");
                return Boolean.FALSE;
            }
            return parseInteger();
        }

        private String parseString() throws IOException {
            require('"');
            StringBuilder value = new StringBuilder();
            while (offset < text.length()) {
                char character = text.charAt(offset++);
                if (character == '"') {
                    if (value.length() > MAXIMUM_STRING_CHARACTERS) {
                        throw contractError();
                    }
                    return value.toString();
                }
                if (character == '\\') {
                    appendEscape(value);
                } else if (character < 0x20) {
                    throw contractError();
                } else if (Character.isHighSurrogate(character)) {
                    if (offset >= text.length()
                            || !Character.isLowSurrogate(
                            text.charAt(offset))) {
                        throw contractError();
                    }
                    value.append(character);
                    value.append(text.charAt(offset++));
                } else if (Character.isLowSurrogate(character)) {
                    throw contractError();
                } else {
                    value.append(character);
                }
                if (value.length() > MAXIMUM_STRING_CHARACTERS) {
                    throw contractError();
                }
            }
            throw contractError();
        }

        private void appendEscape(StringBuilder value) throws IOException {
            if (offset >= text.length()) {
                throw contractError();
            }
            char escaped = text.charAt(offset++);
            switch (escaped) {
                case '"':
                case '\\':
                case '/':
                    value.append(escaped);
                    return;
                case 'b':
                    value.append('\b');
                    return;
                case 'f':
                    value.append('\f');
                    return;
                case 'n':
                    value.append('\n');
                    return;
                case 'r':
                    value.append('\r');
                    return;
                case 't':
                    value.append('\t');
                    return;
                case 'u':
                    appendUnicode(value);
                    return;
                default:
                    throw contractError();
            }
        }

        private void appendUnicode(StringBuilder value) throws IOException {
            char first = parseHexCodeUnit();
            if (Character.isHighSurrogate(first)) {
                if (offset + 2 > text.length()
                        || text.charAt(offset) != '\\'
                        || text.charAt(offset + 1) != 'u') {
                    throw contractError();
                }
                offset += 2;
                char second = parseHexCodeUnit();
                if (!Character.isLowSurrogate(second)) {
                    throw contractError();
                }
                value.append(first).append(second);
            } else if (Character.isLowSurrogate(first)) {
                throw contractError();
            } else {
                value.append(first);
            }
        }

        private char parseHexCodeUnit() throws IOException {
            if (offset + 4 > text.length()) {
                throw contractError();
            }
            int result = 0;
            for (int count = 0; count < 4; count++) {
                int digit = Character.digit(text.charAt(offset++), 16);
                if (digit < 0) {
                    throw contractError();
                }
                result = (result << 4) | digit;
            }
            return (char) result;
        }

        private Long parseInteger() throws IOException {
            int start = offset;
            boolean negative = consume('-');
            if (negative && offset >= text.length()) {
                throw contractError();
            }
            if (consume('0')) {
                if (negative) {
                    throw contractError();
                }
                if (offset < text.length()
                        && isDigit(text.charAt(offset))) {
                    throw contractError();
                }
            } else {
                if (offset >= text.length()
                        || text.charAt(offset) < '1'
                        || text.charAt(offset) > '9') {
                    throw contractError();
                }
                while (offset < text.length()
                        && isDigit(text.charAt(offset))) {
                    offset++;
                }
            }
            if (offset < text.length()) {
                char suffix = text.charAt(offset);
                if (suffix == '.' || suffix == 'e' || suffix == 'E'
                        || suffix == '+') {
                    throw contractError();
                }
            }
            try {
                return Long.parseLong(text.substring(start, offset));
            } catch (NumberFormatException exception) {
                throw contractError();
            }
        }

        private void requireLiteral(String literal) throws IOException {
            if (!text.regionMatches(offset, literal, 0, literal.length())) {
                throw contractError();
            }
            offset += literal.length();
        }

        private void finish() throws IOException {
            skipWhitespace();
            if (offset != text.length()) {
                throw contractError();
            }
        }

        private void skipWhitespace() {
            while (offset < text.length()) {
                char character = text.charAt(offset);
                if (character != ' ' && character != '\t'
                        && character != '\r' && character != '\n') {
                    return;
                }
                offset++;
            }
        }

        private void require(char expected) throws IOException {
            if (!consume(expected)) {
                throw contractError();
            }
        }

        private boolean consume(char expected) {
            if (offset < text.length() && text.charAt(offset) == expected) {
                offset++;
                return true;
            }
            return false;
        }

        private boolean peek(char expected) {
            return offset < text.length() && text.charAt(offset) == expected;
        }

        private static boolean isDigit(char value) {
            return value >= '0' && value <= '9';
        }
    }
}
