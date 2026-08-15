package com.visionforge.inferencebenchmark;

import android.app.Activity;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.os.Bundle;
import android.util.Log;

import java.io.FileOutputStream;
import java.net.Inet4Address;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;

/** Debug-only, control-output-free validation of Ethernet, AVC decode and QNN HTP. */
public final class QnnVideoPipelineSelfTestActivity extends Activity {
    private static final String TAG = "VisionForgeVideoSelfTest";
    private static final String RESULT_FILE = "qnn_video_pipeline_self_test.txt";
    private static final long TEST_WINDOW_MILLIS = 90_000L;
    private static final long SNAPSHOT_INTERVAL_MILLIS = 1_000L;
    private static final int TRACE_FRAME_LIMIT = 600;
    private static final String WIFI_MODE = "wifi";
    private static final String EXTRA_TRANSPORT = "transport";
    private static final String EXTRA_HOST_IPV4 = "host_ipv4";

    private final AtomicBoolean pipelineStartClaimed = new AtomicBoolean(false);
    private final AtomicBoolean stopped = new AtomicBoolean(false);
    private final StringBuilder events = new StringBuilder();

    private ConnectivityManager connectivityManager;
    private ConnectivityManager.NetworkCallback networkCallback;
    private QnnNativeVideoInferencePipeline pipeline;
    private MobilePipelineCoordinator pipelineCoordinator;
    private boolean wifiValidation;
    private String receiverLocalIpv4 = EthernetTransportContract.MOBILE_IPV4;
    private String expectedSourceIpv4 = EthernetTransportContract.HOST_IPV4;
    private volatile Network ethernetNetwork;
    private volatile String stage = "created";
    private volatile String networkDetail = "unavailable";
    private volatile String terminalFailure = "none";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        wifiValidation = WIFI_MODE.equalsIgnoreCase(
                getIntent().getStringExtra(EXTRA_TRANSPORT));
        if (wifiValidation) {
            expectedSourceIpv4 = getIntent().getStringExtra(EXTRA_HOST_IPV4);
            if (expectedSourceIpv4 == null || expectedSourceIpv4.isBlank()) {
                expectedSourceIpv4 = "192.168.1.18";
            }
        }
        pipeline = new QnnNativeVideoInferencePipeline();
        pipelineCoordinator = new MobilePipelineCoordinator(
                pipeline, this::recordEvent);
        connectivityManager = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
        if (connectivityManager == null) {
            fail("ConnectivityManager unavailable", null);
            return;
        }
        requestValidationNetwork();
    }

    private void requestValidationNetwork() {
        stage = wifiValidation ? "requesting_debug_wifi" : "requesting_ethernet";
        persistSnapshot();
        networkCallback = new ConnectivityManager.NetworkCallback() {
            @Override
            public void onAvailable(Network network) {
                evaluateNetwork(network, connectivityManager.getLinkProperties(network),
                        "onAvailable");
            }

            @Override
            public void onLinkPropertiesChanged(Network network, LinkProperties properties) {
                evaluateNetwork(network, properties, "onLinkPropertiesChanged");
            }

            @Override
            public void onLost(Network network) {
                if (network.equals(ethernetNetwork)) {
                    networkDetail = "ethernet_lost handle=" + network.getNetworkHandle();
                    stage = "ethernet_lost";
                    persistSnapshot();
                }
            }

            @Override
            public void onUnavailable() {
                fail((wifiValidation ? "Wi-Fi" : "Ethernet")
                        + " network request timed out", null);
            }
        };
        int transport = wifiValidation
                ? NetworkCapabilities.TRANSPORT_WIFI
                : NetworkCapabilities.TRANSPORT_ETHERNET;
        NetworkRequest request = new NetworkRequest.Builder()
                .addTransportType(transport)
                .build();
        try {
            connectivityManager.requestNetwork(request, networkCallback, 60_000);
        } catch (RuntimeException failure) {
            fail((wifiValidation ? "Wi-Fi" : "Ethernet")
                    + " request failed", failure);
        }
    }

    private void evaluateNetwork(Network network, LinkProperties properties, String source) {
        if (wifiValidation) {
            evaluateWifiNetwork(network, properties, source);
            return;
        }
        EthernetNetworkDiagnostics.Evaluation evaluation =
                EthernetNetworkDiagnostics.evaluate(connectivityManager, network, properties);
        networkDetail = "source=" + source + " " + evaluation.detail();
        stage = evaluation.accepted ? "ethernet_ready" : "waiting_for_required_ipv4";
        persistSnapshot();
        if (!evaluation.accepted || !pipelineStartClaimed.compareAndSet(false, true)) {
            return;
        }
        ethernetNetwork = network;
        Thread worker = new Thread(
                () -> startPipeline(network), "vf-qnn-video-self-test");
        worker.start();
    }

    private void evaluateWifiNetwork(
            Network network, LinkProperties properties, String source) {
        NetworkCapabilities capabilities = connectivityManager.getNetworkCapabilities(network);
        String ipv4 = firstIpv4(properties);
        boolean accepted = capabilities != null
                && capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
                && !ipv4.isBlank();
        networkDetail = "source=" + source
                + " debug_transport=wifi accepted=" + accepted
                + " interface=" + (properties == null ? "missing" : properties.getInterfaceName())
                + " local_ipv4=" + (ipv4.isBlank() ? "missing" : ipv4)
                + " expected_source_ipv4=" + expectedSourceIpv4
                + " network_handle=" + network.getNetworkHandle();
        stage = accepted ? "debug_wifi_ready" : "waiting_for_wifi_ipv4";
        persistSnapshot();
        if (!accepted || !pipelineStartClaimed.compareAndSet(false, true)) return;
        receiverLocalIpv4 = ipv4;
        ethernetNetwork = network;
        Thread worker = new Thread(
                () -> startPipeline(network), "vf-qnn-video-self-test");
        worker.start();
    }

    private static String firstIpv4(LinkProperties properties) {
        if (properties == null) return "";
        for (LinkAddress address : properties.getLinkAddresses()) {
            if (address.getAddress() instanceof Inet4Address) {
                return address.getAddress().getHostAddress();
            }
        }
        return "";
    }

    private void startPipeline(Network network) {
        try {
            stage = "installing_qnn_assets";
            persistSnapshot();
            QnnAssetBundleInstaller.Result install = QnnAssetBundleInstaller.ensureInstalled(
                    getFilesDir(),
                    name -> getAssets().open(QnnAssetBundleInstaller.DIRECTORY_NAME + "/" + name));
            if (!install.ready || install.directory == null) {
                throw new IllegalStateException(
                        "QNN asset installation failed: " + install.detail, install.failure);
            }
            recordEvent("qnn_asset_install", install.detail);

            stage = "preparing_decoder_and_qnn";
            persistSnapshot();
            if (wifiValidation) {
                prepareDebugWifiPipeline(install, network);
            } else {
                prepareProductionEthernetPipeline(install, network);
            }
            stage = wifiValidation ? "receiving_video_debug_wifi" : "receiving_video";
            persistSnapshot();
            captureSnapshotsUntilDeadline();
        } catch (Throwable failure) {
            fail("Pipeline self-test failed", failure);
        }
    }

    private void prepareProductionEthernetPipeline(
            QnnAssetBundleInstaller.Result install, Network network) {
        MobilePipelineCoordinator.PrepareResult prepare =
                pipelineCoordinator.prepareDataPlaneClosed(
                        getApplicationInfo().nativeLibraryDir,
                        install.directory.getAbsolutePath(),
                        MobileModelCatalog.DEFAULT);
        if (!prepare.prepared) throw new IllegalStateException(prepare.message);
        QnnHtpBridge.beginNativeH264DetectionTrace(TRACE_FRAME_LIMIT);
        MobilePipelineCoordinator.StartResult start =
                pipelineCoordinator.openPreparedDataPlane(
                        MobileTransportEndpoint.cat6(network),
                        MobileModelCatalog.DEFAULT);
        if (!start.started) throw new IllegalStateException(start.message);
    }

    private void prepareDebugWifiPipeline(
            QnnAssetBundleInstaller.Result install, Network network) {
        pipeline.stop();
        if (!pipeline.prepareQnn(
                getApplicationInfo().nativeLibraryDir,
                install.directory.getAbsolutePath(),
                MobileModelCatalog.DEFAULT.token)) {
            throw new IllegalStateException("qnn_graph_load_failed: " + pipeline.qnnReport());
        }
        if (!pipeline.configureInferenceDecoder(
                MobileModelCatalog.DEFAULT.inputWidth,
                MobileModelCatalog.DEFAULT.inputHeight)) {
            throw new IllegalStateException("mediacodec_configuration_failed");
        }
        QnnHtpBridge.beginNativeH264DetectionTrace(TRACE_FRAME_LIMIT);
        if (!pipeline.startVideoReceiver(
                receiverLocalIpv4,
                expectedSourceIpv4,
                MobilePipelineCoordinator.VIDEO_PORT,
                network.getNetworkHandle())) {
            throw new IllegalStateException(
                    "debug_wifi_udp_bind_failed receiver={"
                            + pipeline.videoReceiverReport() + "}");
        }
        recordEvent("debug_wifi_pipeline_opened",
                "control_output=false local_ipv4=" + receiverLocalIpv4
                        + " expected_source_ipv4=" + expectedSourceIpv4);
    }

    private void captureSnapshotsUntilDeadline() throws InterruptedException {
        long deadline = System.nanoTime() + TEST_WINDOW_MILLIS * 1_000_000L;
        while (!stopped.get() && System.nanoTime() < deadline) {
            persistSnapshot();
            Thread.sleep(SNAPSHOT_INTERVAL_MILLIS);
        }
        if (!stopped.get()) {
            stage = "capture_window_complete";
            persistSnapshot();
            stopResources();
            runOnUiThread(this::finish);
        }
    }

    private synchronized void recordEvent(String event, String detail) {
        events.append(event).append(" {").append(detail).append("}\n");
        Log.i(TAG, event + " detail={" + detail + "}");
    }

    private void fail(String message, Throwable failure) {
        terminalFailure = failure == null
                ? message
                : message + " stack={" + MobileThrowableDiagnostics.format(failure) + "}";
        stage = "failed";
        Log.e(TAG, terminalFailure, failure);
        persistSnapshot();
        stopResources();
        runOnUiThread(this::finish);
    }

    private void persistSnapshot() {
        String report = buildSnapshot();
        try (FileOutputStream output = openFileOutput(RESULT_FILE, MODE_PRIVATE)) {
            output.write(report.getBytes(StandardCharsets.UTF_8));
            output.getFD().sync();
        } catch (Exception failure) {
            Log.e(TAG, "Unable to persist video pipeline self-test", failure);
        }
    }

    private synchronized String buildSnapshot() {
        String qnnReport = safeNativeReport(QnnHtpBridge::getNativeQnnRealtimeReport);
        String receiverReport = safeNativeReport(QnnHtpBridge::getNativeVideoReceiverReport);
        String decoderReport = safeNativeReport(QnnHtpBridge::getNativeH264DecoderReport);
        String metrics = safeNativeReport(QnnHtpBridge::getNativePipelineMetricsCsv);
        String detections = safeNativeReport(QnnHtpBridge::getNativeH264DetectionTraceCsv);
        return "stage=" + stage + '\n'
                + "model=" + MobileModelCatalog.DEFAULT.token + '\n'
                + "input=" + MobileModelCatalog.DEFAULT.inputWidth + "x"
                + MobileModelCatalog.DEFAULT.inputHeight + '\n'
                + "network={" + networkDetail + "}\n"
                + "terminal_failure={" + terminalFailure + "}\n"
                + "events:\n" + events
                + "qnn_report:\n" + qnnReport + '\n'
                + "receiver_report:\n" + receiverReport + '\n'
                + "decoder_report:\n" + decoderReport + '\n'
                + "pipeline_metrics_csv:\n" + metrics + '\n'
                + "detection_trace_csv:\n" + detections + '\n';
    }

    private static String safeNativeReport(NativeReportSupplier supplier) {
        try {
            String value = supplier.get();
            return value == null ? "null" : value;
        } catch (Throwable failure) {
            return "unavailable stack={" + MobileThrowableDiagnostics.format(failure) + "}";
        }
    }

    private void stopResources() {
        if (!stopped.compareAndSet(false, true)) return;
        if (pipelineCoordinator != null) pipelineCoordinator.stop();
        if (connectivityManager != null && networkCallback != null) {
            try {
                connectivityManager.unregisterNetworkCallback(networkCallback);
            } catch (RuntimeException failure) {
                Log.w(TAG, "Ethernet callback cleanup failed", failure);
            }
        }
    }

    @Override
    protected void onDestroy() {
        stopResources();
        super.onDestroy();
    }

    @FunctionalInterface
    private interface NativeReportSupplier {
        String get();
    }
}
