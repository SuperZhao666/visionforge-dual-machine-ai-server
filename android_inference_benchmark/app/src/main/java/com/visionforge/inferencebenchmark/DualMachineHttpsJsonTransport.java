package com.visionforge.inferencebenchmark;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Locale;

import javax.net.ssl.HttpsURLConnection;

/**
 * Bounded HTTPS/JSON transport for the independent card sidecar.
 *
 * <p>The TLS handshake and SPKI pin validation complete before the request
 * body is opened, so a card code is not sent to an unpinned peer. Redirects,
 * cleartext fallback and process-wide network binding are forbidden.</p>
 */
public final class DualMachineHttpsJsonTransport {
    public interface ConnectionFactory {
        URLConnection open(URL url) throws IOException;
    }

    private static final int CONNECT_TIMEOUT_MILLIS = 5_000;
    private static final int READ_TIMEOUT_MILLIS = 8_000;
    private static final int MAXIMUM_REQUEST_BYTES = 64 * 1024;
    private static final int MAXIMUM_RESPONSE_BYTES = 128 * 1024;
    private static final String JSON_CONTENT_TYPE = "application/json";

    private final URI baseUri;
    private final ConnectionFactory connectionFactory;
    private final DualMachineTlsPinPolicy pinPolicy;
    private final String userAgent;

    public DualMachineHttpsJsonTransport(
            String baseUrl,
            ConnectionFactory connectionFactory,
            DualMachineTlsPinPolicy pinPolicy,
            String clientVersion) {
        baseUri = requireBaseUri(baseUrl);
        if (connectionFactory == null || pinPolicy == null) {
            throw new IllegalArgumentException(
                    "connectionFactory and pinPolicy are required");
        }
        this.connectionFactory = connectionFactory;
        this.pinPolicy = pinPolicy;
        userAgent = "VisionForge-Mobile/" + requireClientVersion(clientVersion);
    }

    public byte[] postJson(String apiPath, byte[] canonicalJson)
            throws IOException {
        String path = requireApiPath(apiPath);
        if (canonicalJson == null || canonicalJson.length < 2
                || canonicalJson.length > MAXIMUM_REQUEST_BYTES
                || canonicalJson[0] != '{'
                || canonicalJson[canonicalJson.length - 1] != '}') {
            throw new IOException("request JSON is invalid or oversized");
        }
        URL destination = destination(path);
        URLConnection opened = connectionFactory.open(destination);
        if (!(opened instanceof HttpsURLConnection)) {
            throw new IOException("authentication route is not HTTPS");
        }
        HttpsURLConnection connection = (HttpsURLConnection) opened;
        configure(connection, canonicalJson.length);
        boolean reusableSuccess = false;
        try {
            // connect() performs TLS/hostname validation. Pinning is checked
            // before getOutputStream() can expose the sensitive request body.
            connection.connect();
            verifyPins(connection);
            try (OutputStream output = connection.getOutputStream()) {
                output.write(canonicalJson);
                output.flush();
            }
            int status = connection.getResponseCode();
            byte[] response = readResponse(connection, status);
            if (status < 200 || status >= 300) {
                throw new SidecarHttpException(status, response);
            }
            requireJsonContentType(connection.getContentType());
            // Both streams are closed and the bounded response is completely
            // consumed. Do not call disconnect() on this successful path:
            // Android can return the already pinned TLS socket to its
            // keep-alive pool, which keeps five-second lease renewals inside
            // their signed window without weakening the lease deadline.
            reusableSuccess = true;
            return response;
        } finally {
            if (!reusableSuccess) {
                connection.disconnect();
            }
        }
    }

    private URL destination(String path) throws IOException {
        try {
            URI resolved = baseUri.resolve(path);
            if (!baseUri.getScheme().equalsIgnoreCase(resolved.getScheme())
                    || !baseUri.getHost().equalsIgnoreCase(resolved.getHost())
                    || effectivePort(baseUri) != effectivePort(resolved)
                    || resolved.getUserInfo() != null
                    || resolved.getFragment() != null
                    || resolved.getRawQuery() != null) {
                throw new IOException("sidecar destination escaped base origin");
            }
            return resolved.toURL();
        } catch (IllegalArgumentException exception) {
            throw new IOException("sidecar destination is invalid", exception);
        }
    }

    private void configure(
            HttpsURLConnection connection,
            int contentLength) throws IOException {
        connection.setInstanceFollowRedirects(false);
        connection.setConnectTimeout(CONNECT_TIMEOUT_MILLIS);
        connection.setReadTimeout(READ_TIMEOUT_MILLIS);
        connection.setUseCaches(false);
        connection.setDoInput(true);
        connection.setDoOutput(true);
        connection.setRequestMethod("POST");
        connection.setFixedLengthStreamingMode(contentLength);
        connection.setRequestProperty("Accept", JSON_CONTENT_TYPE);
        connection.setRequestProperty(
                "Content-Type", JSON_CONTENT_TYPE + "; charset=utf-8");
        connection.setRequestProperty("User-Agent", userAgent);
        connection.setRequestProperty("Cache-Control", "no-store");
    }

    private void verifyPins(HttpsURLConnection connection) throws IOException {
        try {
            pinPolicy.verify(connection.getServerCertificates());
        } catch (GeneralSecurityException exception) {
            throw new IOException("sidecar TLS peer rejected", exception);
        }
    }

    private static byte[] readResponse(
            HttpURLConnection connection,
            int status) throws IOException {
        InputStream selected = status >= 200 && status < 300
                ? connection.getInputStream() : connection.getErrorStream();
        if (selected == null) return new byte[0];
        try (InputStream input = selected;
             ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096];
            int total = 0;
            while (true) {
                int count = input.read(buffer);
                if (count < 0) break;
                total += count;
                if (total > MAXIMUM_RESPONSE_BYTES) {
                    throw new IOException("sidecar response is oversized");
                }
                output.write(buffer, 0, count);
            }
            return output.toByteArray();
        }
    }

    private static void requireJsonContentType(String value)
            throws IOException {
        String normalized = value == null
                ? "" : value.toLowerCase(Locale.ROOT);
        if (!normalized.equals(JSON_CONTENT_TYPE)
                && !normalized.startsWith(JSON_CONTENT_TYPE + ";")) {
            throw new IOException("sidecar response is not JSON");
        }
    }

    private static URI requireBaseUri(String value) {
        try {
            URI uri = new URI(value == null ? "" : value);
            String path = uri.getRawPath();
            if (!"https".equalsIgnoreCase(uri.getScheme())
                    || uri.getHost() == null || uri.getHost().isEmpty()
                    || uri.getUserInfo() != null
                    || uri.getRawQuery() != null
                    || uri.getFragment() != null
                    || (path != null && !path.isEmpty() && !"/".equals(path))) {
                throw new IllegalArgumentException(
                        "baseUrl must be an HTTPS origin");
            }
            return new URI(
                    "https",
                    null,
                    uri.getHost(),
                    uri.getPort(),
                    "/",
                    null,
                    null);
        } catch (URISyntaxException exception) {
            throw new IllegalArgumentException(
                    "baseUrl must be an HTTPS origin", exception);
        }
    }

    private static String requireApiPath(String value) {
        if (value == null || value.length() < 2 || value.length() > 256
                || !value.startsWith("/api/dual-machine/v1/")
                || value.contains("..") || value.indexOf('?') >= 0
                || value.indexOf('#') >= 0 || value.indexOf('\\') >= 0) {
            throw new IllegalArgumentException("apiPath is invalid");
        }
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (!((character >= 'a' && character <= 'z')
                    || (character >= '0' && character <= '9')
                    || character == '/' || character == '-')) {
                throw new IllegalArgumentException(
                        "apiPath has invalid characters");
            }
        }
        return value;
    }

    private static String requireClientVersion(String value) {
        if (value == null || value.isEmpty() || value.length() > 80) {
            throw new IllegalArgumentException("clientVersion is invalid");
        }
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (!((character >= 'A' && character <= 'Z')
                    || (character >= 'a' && character <= 'z')
                    || (character >= '0' && character <= '9')
                    || character == '.' || character == '-'
                    || character == '_' || character == '+')) {
                throw new IllegalArgumentException(
                        "clientVersion has invalid characters");
            }
        }
        return value;
    }

    private static int effectivePort(URI uri) {
        return uri.getPort() < 0 ? 443 : uri.getPort();
    }

    /**
     * Error bodies stay bounded and are intentionally not converted to log
     * messages by this transport.
     */
    public static final class SidecarHttpException extends IOException {
        public final int statusCode;
        private final byte[] responseBody;

        SidecarHttpException(int statusCode, byte[] responseBody) {
            super("dual-machine sidecar returned HTTP " + statusCode);
            this.statusCode = statusCode;
            this.responseBody = responseBody == null
                    ? new byte[0] : responseBody.clone();
        }

        public byte[] responseBody() {
            return responseBody.clone();
        }
    }
}
