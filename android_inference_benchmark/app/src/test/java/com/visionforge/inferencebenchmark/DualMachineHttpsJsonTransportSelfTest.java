package com.visionforge.inferencebenchmark;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;

/**
 * Dependency-free JVM contract for the pinned HTTPS/JSON sidecar transport.
 *
 * <p>A recording fake {@link HttpsURLConnection} proves the sensitive request
 * body can only be written after {@code connect()} and SPKI pin validation,
 * that redirects are never followed, that origin/path escape and request or
 * response size bounds are enforced, and that every accepted connection is
 * disconnected on success and on every failure path.</p>
 *
 * <p>Note: the non-HTTPS rejection branch runs before the transport accepts
 * the connection (the rejected object may not even be an
 * {@link HttpURLConnection}, so the transport has no disconnect handle on it);
 * disconnect assertions therefore cover every connection the transport
 * actually accepted, on every failure path after acceptance.</p>
 */
public final class DualMachineHttpsJsonTransportSelfTest {
    private static final String BASE_URL = "https://sidecar.example";
    private static final String API_PATH = "/api/dual-machine/v1/card/authorize";
    private static final String CLIENT_VERSION = "1.0.0-rc1";
    private static final int MAXIMUM_REQUEST_BYTES = 64 * 1024;
    private static final int MAXIMUM_RESPONSE_BYTES = 128 * 1024;

    private DualMachineHttpsJsonTransportSelfTest() {
    }

    public static void main(String[] arguments) throws Exception {
        KeyPair pinned = rsa();
        KeyPair attacker = rsa();
        DualMachineTlsPinPolicy matchingPolicy = policyFor(pinned);
        DualMachineTlsPinPolicy mismatchingPolicy = policyFor(attacker);

        happyPathOrderHeadersAndBody(matchingPolicy, pinned);
        pinMismatchWritesNoSensitiveByte(mismatchingPolicy, pinned);
        redirectDisabledAndNotFollowed(matchingPolicy, pinned);
        apiPathAndBaseUrlEscapeRejected(matchingPolicy);
        requestLengthBoundaryEnforced(matchingPolicy, pinned);
        responseLimitEnforced(matchingPolicy, pinned);
        nonHttpsConnectionRejected(matchingPolicy);
        failurePathsAlwaysDisconnect(matchingPolicy, pinned);
        System.out.println("ANDROID_HTTPS_JSON_TRANSPORT_OK");
    }

    private static void happyPathOrderHeadersAndBody(
            DualMachineTlsPinPolicy policy,
            KeyPair pinned) throws Exception {
        FakeHttpsConnection connection = new FakeHttpsConnection(pinned);
        connection.responseBody = "{\"ok\":true}".getBytes(StandardCharsets.UTF_8);
        FakeConnectionFactory factory = new FakeConnectionFactory(connection);
        DualMachineHttpsJsonTransport transport = newTransport(factory, policy);
        byte[] payload = "{\"card\":\"demo\"}".getBytes(StandardCharsets.UTF_8);

        byte[] response = transport.postJson(API_PATH, payload);

        check(factory.openCount == 1, "factory must open exactly one connection");
        check((BASE_URL + API_PATH).equals(factory.lastUrl.toString()),
                "destination URL mismatch: " + factory.lastUrl);
        int connectAt = connection.events.indexOf("connect");
        int pinAt = connection.events.indexOf("getServerCertificates");
        int bodyAt = connection.events.indexOf("getOutputStream");
        check(connectAt == 0,
                "connect() must be the first connection call: " + connection.events);
        check(pinAt > connectAt,
                "SPKI pin must be validated after connect: " + connection.events);
        check(bodyAt > pinAt,
                "request body must not open before SPKI pin validation: "
                        + connection.events);
        check(connection.events.indexOf("getResponseCode") > bodyAt,
                "response must be read after the body: " + connection.events);
        check(Arrays.equals(payload, connection.requestBody.toByteArray()),
                "request body bytes mismatch");
        check(Arrays.equals(connection.responseBody, response),
                "response bytes mismatch");
        check(!connection.getInstanceFollowRedirects(),
                "instance redirects must be disabled");
        check("POST".equals(connection.getRequestMethod()),
                "request method must be POST");
        check(connection.getConnectTimeout() == 5_000,
                "connect timeout mismatch");
        check(connection.getReadTimeout() == 8_000,
                "read timeout mismatch");
        check(!connection.getUseCaches(), "caches must be disabled");
        check(connection.getDoInput() && connection.getDoOutput(),
                "connection must be bidirectional");
        check(connection.fixedLength == payload.length,
                "fixed-length streaming mode must match the payload length");
        check("application/json".equals(connection.getRequestProperty("Accept")),
                "Accept header mismatch");
        check("application/json; charset=utf-8".equals(
                connection.getRequestProperty("Content-Type")),
                "Content-Type header mismatch");
        check(("VisionForge-Mobile/" + CLIENT_VERSION).equals(
                connection.getRequestProperty("User-Agent")),
                "User-Agent header mismatch");
        check("no-store".equals(connection.getRequestProperty("Cache-Control")),
                "Cache-Control header mismatch");
        check(connection.disconnectCount == 1,
                "connection must be disconnected exactly once");
    }

    private static void pinMismatchWritesNoSensitiveByte(
            DualMachineTlsPinPolicy mismatchingPolicy,
            KeyPair pinned) throws Exception {
        FakeHttpsConnection connection = new FakeHttpsConnection(pinned);
        FakeConnectionFactory factory = new FakeConnectionFactory(connection);
        DualMachineHttpsJsonTransport transport =
                newTransport(factory, mismatchingPolicy);
        byte[] payload = "{\"card\":\"secret\"}".getBytes(StandardCharsets.UTF_8);

        IOException failure = expectIOException("unpinned peer",
                () -> transport.postJson(API_PATH, payload));
        check(!(failure instanceof DualMachineHttpsJsonTransport.SidecarHttpException),
                "pin failure must not surface as an HTTP status error");
        check(connection.events.contains("connect"),
                "pin check requires an established connection");
        check(connection.events.contains("getServerCertificates"),
                "pin check must read the peer chain");
        check(!connection.events.contains("getOutputStream"),
                "sensitive body stream must never open when the pin fails");
        check(connection.requestBody.size() == 0,
                "sensitive body bytes written must be zero when the pin fails");
        check(connection.disconnectCount == 1,
                "rejected pin path must still disconnect");
    }

    private static void redirectDisabledAndNotFollowed(
            DualMachineTlsPinPolicy policy,
            KeyPair pinned) throws Exception {
        FakeHttpsConnection connection = new FakeHttpsConnection(pinned);
        connection.setFakeResponseCode(302);
        connection.errorBody = "{\"error\":\"redirect\"}"
                .getBytes(StandardCharsets.UTF_8);
        FakeConnectionFactory factory = new FakeConnectionFactory(connection);
        DualMachineHttpsJsonTransport transport = newTransport(factory, policy);

        DualMachineHttpsJsonTransport.SidecarHttpException failure =
                expectSidecarHttp("302 redirect",
                        () -> transport.postJson(API_PATH, jsonPayload(16)));
        check(failure.statusCode == 302,
                "redirect status must surface, not be followed");
        check(Arrays.equals(connection.errorBody, failure.responseBody()),
                "redirect error body mismatch");
        check(factory.openCount == 1,
                "a 3xx response must not open a second connection");
        check(!connection.getInstanceFollowRedirects(),
                "instance redirects must be disabled");
        check(!connection.events.contains("getInputStream"),
                "3xx must read the error stream, not the input stream");
        check(connection.events.contains("getErrorStream"),
                "3xx must bound the error body via the error stream");
        check(connection.disconnectCount == 1,
                "redirect path must still disconnect");
    }

    private static void apiPathAndBaseUrlEscapeRejected(
            DualMachineTlsPinPolicy policy) throws Exception {
        String[] badPaths = {
                null,
                "",
                "/",
                "/api",
                "/api/dual-machine/v2/card",
                "/API/dual-machine/v1/card",
                "/api/dual-machine/v1/../card",
                "/api/dual-machine/v1/card?x=1",
                "/api/dual-machine/v1/card#fragment",
                "/api/dual-machine/v1/card\\escape",
                "/api/dual-machine/v1/Card",
                "/api/dual-machine/v1/card_authorize",
                "/api/dual-machine/v1/" + repeat('a', 300),
        };
        for (String badPath : badPaths) {
            FakeHttpsConnection connection = new FakeHttpsConnection(rsa());
            FakeConnectionFactory factory = new FakeConnectionFactory(connection);
            DualMachineHttpsJsonTransport transport = newTransport(factory, policy);
            expectIllegalArgument("apiPath " + printable(badPath),
                    () -> transport.postJson(badPath, jsonPayload(16)));
            check(factory.openCount == 0,
                    "rejected apiPath must not open a connection: "
                            + printable(badPath));
        }

        String[] badBaseUrls = {
                null,
                "",
                "http://sidecar.example",
                "ftp://sidecar.example/",
                "https://user@sidecar.example/",
                "https://sidecar.example/path",
                "https://sidecar.example/?q=1",
                "https://sidecar.example/#fragment",
                "not a uri",
        };
        for (String badBaseUrl : badBaseUrls) {
            expectIllegalArgument("baseUrl " + printable(badBaseUrl),
                    () -> new DualMachineHttpsJsonTransport(
                            badBaseUrl, new FakeConnectionFactory(null),
                            policy, CLIENT_VERSION));
        }

        String[] badClientVersions = {null, "", repeat('v', 81), "1.0/bad"};
        for (String badClientVersion : badClientVersions) {
            expectIllegalArgument("clientVersion " + printable(badClientVersion),
                    () -> new DualMachineHttpsJsonTransport(
                            BASE_URL, new FakeConnectionFactory(null),
                            policy, badClientVersion));
        }
        expectIllegalArgument("null connectionFactory",
                () -> new DualMachineHttpsJsonTransport(
                        BASE_URL, null, policy, CLIENT_VERSION));
        expectIllegalArgument("null pinPolicy",
                () -> new DualMachineHttpsJsonTransport(
                        BASE_URL, new FakeConnectionFactory(null), null,
                        CLIENT_VERSION));
    }

    private static void requestLengthBoundaryEnforced(
            DualMachineTlsPinPolicy policy,
            KeyPair pinned) throws Exception {
        FakeHttpsConnection connection = new FakeHttpsConnection(pinned);
        FakeConnectionFactory factory = new FakeConnectionFactory(connection);
        DualMachineHttpsJsonTransport transport = newTransport(factory, policy);

        byte[] exact = jsonPayload(MAXIMUM_REQUEST_BYTES);
        transport.postJson(API_PATH, exact);
        check(connection.fixedLength == MAXIMUM_REQUEST_BYTES,
                "exactly-maximum request must use fixed-length streaming");
        check(connection.requestBody.size() == MAXIMUM_REQUEST_BYTES,
                "exactly-maximum request body must be fully written");
        check(connection.disconnectCount == 1,
                "exactly-maximum request must disconnect");

        byte[][] invalidPayloads = {
                null,
                new byte[0],
                new byte[1],
                "[]".getBytes(StandardCharsets.UTF_8),
                "{}x".getBytes(StandardCharsets.UTF_8),
                jsonPayload(MAXIMUM_REQUEST_BYTES + 1),
        };
        for (byte[] invalid : invalidPayloads) {
            FakeConnectionFactory rejectingFactory =
                    new FakeConnectionFactory(new FakeHttpsConnection(pinned));
            DualMachineHttpsJsonTransport rejectingTransport =
                    newTransport(rejectingFactory, policy);
            expectIOException("request payload " + describe(invalid),
                    () -> rejectingTransport.postJson(API_PATH, invalid));
            check(rejectingFactory.openCount == 0,
                    "invalid request must be rejected before opening: "
                            + describe(invalid));
        }
    }

    private static void responseLimitEnforced(
            DualMachineTlsPinPolicy policy,
            KeyPair pinned) throws Exception {
        FakeHttpsConnection exactConnection = new FakeHttpsConnection(pinned);
        byte[] exactBody = new byte[MAXIMUM_RESPONSE_BYTES];
        Arrays.fill(exactBody, (byte) 'x');
        exactConnection.responseBody = exactBody;
        DualMachineHttpsJsonTransport exactTransport = newTransport(
                new FakeConnectionFactory(exactConnection), policy);
        byte[] response = exactTransport.postJson(API_PATH, jsonPayload(16));
        check(response.length == MAXIMUM_RESPONSE_BYTES,
                "exactly-maximum response must be accepted");
        check(exactConnection.disconnectCount == 1,
                "exactly-maximum response path must disconnect");

        FakeHttpsConnection overConnection = new FakeHttpsConnection(pinned);
        overConnection.responseBody = new byte[MAXIMUM_RESPONSE_BYTES + 1];
        DualMachineHttpsJsonTransport overTransport = newTransport(
                new FakeConnectionFactory(overConnection), policy);
        IOException failure = expectIOException("oversized response",
                () -> overTransport.postJson(API_PATH, jsonPayload(16)));
        check(String.valueOf(failure.getMessage()).contains("oversized"),
                "oversized response must fail with the bound message: "
                        + failure.getMessage());
        check(overConnection.disconnectCount == 1,
                "oversized response path must disconnect");
    }

    private static void nonHttpsConnectionRejected(
            DualMachineTlsPinPolicy policy) throws Exception {
        FakePlainConnection plain = new FakePlainConnection();
        FakeConnectionFactory factory = new FakeConnectionFactory(plain);
        DualMachineHttpsJsonTransport transport = newTransport(factory, policy);

        IOException failure = expectIOException("non-HTTPS connection",
                () -> transport.postJson(API_PATH, jsonPayload(16)));
        check(String.valueOf(failure.getMessage()).contains("HTTPS"),
                "non-HTTPS rejection must name the route: " + failure.getMessage());
        check(factory.openCount == 1, "factory must have been consulted");
        check(!plain.connectCalled,
                "rejected non-HTTPS connection must never be connected");
    }

    private static void failurePathsAlwaysDisconnect(
            DualMachineTlsPinPolicy policy,
            KeyPair pinned) throws Exception {
        // HTTP 5xx with a bounded error body.
        FakeHttpsConnection errorConnection = new FakeHttpsConnection(pinned);
        errorConnection.setFakeResponseCode(500);
        errorConnection.errorBody = "{\"error\":\"boom\"}"
                .getBytes(StandardCharsets.UTF_8);
        DualMachineHttpsJsonTransport errorTransport = newTransport(
                new FakeConnectionFactory(errorConnection), policy);
        DualMachineHttpsJsonTransport.SidecarHttpException statusFailure =
                expectSidecarHttp("HTTP 500",
                        () -> errorTransport.postJson(API_PATH, jsonPayload(16)));
        check(statusFailure.statusCode == 500, "status code mismatch");
        check(Arrays.equals(errorConnection.errorBody,
                statusFailure.responseBody()), "error body mismatch");
        check(errorConnection.disconnectCount == 1,
                "HTTP error path must disconnect");

        // 2xx with a non-JSON content type.
        FakeHttpsConnection typeConnection = new FakeHttpsConnection(pinned);
        typeConnection.contentType = "text/plain";
        DualMachineHttpsJsonTransport typeTransport = newTransport(
                new FakeConnectionFactory(typeConnection), policy);
        expectIOException("non-JSON content type",
                () -> typeTransport.postJson(API_PATH, jsonPayload(16)));
        check(typeConnection.disconnectCount == 1,
                "content-type rejection path must disconnect");

        // Output stream cannot be opened at all.
        FakeHttpsConnection openConnection = new FakeHttpsConnection(pinned);
        openConnection.failOnGetOutputStream = true;
        DualMachineHttpsJsonTransport openTransport = newTransport(
                new FakeConnectionFactory(openConnection), policy);
        expectIOException("output open failure",
                () -> openTransport.postJson(API_PATH, jsonPayload(16)));
        check(openConnection.disconnectCount == 1,
                "output-open failure path must disconnect");

        // Output stream fails mid-write.
        FakeHttpsConnection writeConnection = new FakeHttpsConnection(pinned);
        writeConnection.failOnWrite = true;
        DualMachineHttpsJsonTransport writeTransport = newTransport(
                new FakeConnectionFactory(writeConnection), policy);
        expectIOException("write failure",
                () -> writeTransport.postJson(API_PATH, jsonPayload(16)));
        check(writeConnection.disconnectCount == 1,
                "write failure path must disconnect");

        // connect() itself fails before any pin or body work.
        FakeHttpsConnection connectConnection = new FakeHttpsConnection(pinned);
        connectConnection.failOnConnect = true;
        DualMachineHttpsJsonTransport connectTransport = newTransport(
                new FakeConnectionFactory(connectConnection), policy);
        expectIOException("connect failure",
                () -> connectTransport.postJson(API_PATH, jsonPayload(16)));
        check(!connectConnection.events.contains("getOutputStream"),
                "connect failure must never open the body stream");
        check(connectConnection.disconnectCount == 1,
                "connect failure path must disconnect");
    }

    private static DualMachineHttpsJsonTransport newTransport(
            FakeConnectionFactory factory,
            DualMachineTlsPinPolicy policy) {
        return new DualMachineHttpsJsonTransport(
                BASE_URL, factory, policy, CLIENT_VERSION);
    }

    private static DualMachineTlsPinPolicy policyFor(KeyPair key)
            throws GeneralSecurityException {
        return new DualMachineTlsPinPolicy(Collections.singletonList(
                DualMachineTlsPinPolicy.pinForEncodedPublicKey(
                        key.getPublic().getEncoded())));
    }

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static Certificate certificate(KeyPair pair) {
        return new Certificate("TEST") {
            @Override
            public byte[] getEncoded() {
                return pair.getPublic().getEncoded();
            }

            @Override
            public void verify(java.security.PublicKey key) {
            }

            @Override
            public void verify(java.security.PublicKey key, String provider) {
            }

            @Override
            public String toString() {
                return "test-certificate";
            }

            @Override
            public java.security.PublicKey getPublicKey() {
                return pair.getPublic();
            }
        };
    }

    private static byte[] jsonPayload(int size) {
        byte[] payload = new byte[size];
        Arrays.fill(payload, (byte) ' ');
        payload[0] = (byte) '{';
        payload[size - 1] = (byte) '}';
        return payload;
    }

    private static String repeat(char character, int count) {
        char[] data = new char[count];
        Arrays.fill(data, character);
        return new String(data);
    }

    private static String printable(String value) {
        return value == null ? "<null>"
                : value.length() > 60 ? value.substring(0, 60) + "..." : value;
    }

    private static String describe(byte[] payload) {
        return payload == null ? "<null>" : payload.length + " bytes";
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static IOException expectIOException(
            String label, CheckedRunnable action) throws Exception {
        try {
            action.run();
            throw new AssertionError(label + " must fail with IOException");
        } catch (IOException expected) {
            return expected;
        }
    }

    private static DualMachineHttpsJsonTransport.SidecarHttpException
            expectSidecarHttp(String label, CheckedRunnable action)
            throws Exception {
        IOException failure = expectIOException(label, action);
        if (!(failure instanceof DualMachineHttpsJsonTransport.SidecarHttpException)) {
            throw new AssertionError(
                    label + " must fail with SidecarHttpException, got: "
                            + failure);
        }
        return (DualMachineHttpsJsonTransport.SidecarHttpException) failure;
    }

    private static void expectIllegalArgument(
            String label, CheckedRunnable action) throws Exception {
        try {
            action.run();
            throw new AssertionError(
                    label + " must fail with IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            // Expected.
        }
    }

    private interface CheckedRunnable {
        void run() throws Exception;
    }

    private static final class FakeConnectionFactory
            implements DualMachineHttpsJsonTransport.ConnectionFactory {
        private final URLConnection next;
        private URL lastUrl;
        private int openCount;

        FakeConnectionFactory(URLConnection next) {
            this.next = next;
        }

        @Override
        public URLConnection open(URL url) {
            openCount++;
            lastUrl = url;
            return next;
        }
    }

    private static final class FakePlainConnection extends HttpURLConnection {
        private boolean connectCalled;

        FakePlainConnection() throws Exception {
            super(new URL("http://insecure.example/"));
        }

        @Override
        public void connect() {
            connectCalled = true;
        }

        @Override
        public void disconnect() {
            // The transport must never accept this connection.
        }

        @Override
        public boolean usingProxy() {
            return false;
        }
    }

    private static final class FakeHttpsConnection extends HttpsURLConnection {
        private final List<String> events = new ArrayList<>();
        private final ByteArrayOutputStream requestBody = new ByteArrayOutputStream();
        private final Certificate[] chain;
        private byte[] responseBody = "{}".getBytes(StandardCharsets.UTF_8);
        private byte[] errorBody = new byte[0];
        private String contentType = "application/json";
        private int fixedLength = -1;
        private int disconnectCount;
        private boolean failOnConnect;
        private boolean failOnGetOutputStream;
        private boolean failOnWrite;

        FakeHttpsConnection(KeyPair peerKey) throws Exception {
            super(new URL("https://sidecar.example/"));
            chain = new Certificate[]{certificate(peerKey)};
            setFakeResponseCode(200);
        }

        @Override
        public String getCipherSuite() {
            return "TLS_FAKE_SUITE";
        }

        @Override
        public Certificate[] getServerCertificates() {
            events.add("getServerCertificates");
            return chain;
        }

        @Override
        public Certificate[] getLocalCertificates() {
            return null;
        }

        private void setFakeResponseCode(int code) {
            responseCode = code;
        }

        @Override
        public void connect() throws IOException {
            events.add("connect");
            if (failOnConnect) throw new IOException("connect failure");
        }

        @Override
        public void disconnect() {
            disconnectCount++;
            events.add("disconnect");
        }

        @Override
        public boolean usingProxy() {
            return false;
        }

        @Override
        public void setFixedLengthStreamingMode(int contentLength) {
            fixedLength = contentLength;
        }

        @Override
        public OutputStream getOutputStream() throws IOException {
            events.add("getOutputStream");
            if (failOnGetOutputStream) {
                throw new IOException("output open failure");
            }
            return new OutputStream() {
                @Override
                public void write(int value) throws IOException {
                    if (failOnWrite) throw new IOException("write failure");
                    requestBody.write(value);
                }

                @Override
                public void write(byte[] data, int offset, int length)
                        throws IOException {
                    if (failOnWrite) throw new IOException("write failure");
                    requestBody.write(data, offset, length);
                }
            };
        }

        @Override
        public int getResponseCode() {
            events.add("getResponseCode");
            return responseCode;
        }

        @Override
        public InputStream getInputStream() {
            events.add("getInputStream");
            return new ByteArrayInputStream(responseBody);
        }

        @Override
        public InputStream getErrorStream() {
            events.add("getErrorStream");
            return new ByteArrayInputStream(errorBody);
        }

        @Override
        public String getContentType() {
            return contentType;
        }
    }
}
