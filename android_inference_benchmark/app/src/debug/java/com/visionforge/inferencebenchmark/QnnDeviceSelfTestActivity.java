package com.visionforge.inferencebenchmark;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;

/** Debug-only device entry point that executes the packaged model through QNN HTP. */
public final class QnnDeviceSelfTestActivity extends Activity {
    private static final String TAG = "VisionForgeQnnSelfTest";
    private static final String RESULT_FILE = "qnn_device_self_test.txt";
    private static final String MODEL_TOKEN_EXTRA = "model_token";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Thread worker = new Thread(this::runSelfTest, "vf-qnn-device-self-test");
        worker.start();
    }

    private void runSelfTest() {
        String report;
        try {
            String requestedToken = getIntent().getStringExtra(MODEL_TOKEN_EXTRA);
            MobileModelCatalog.Profile model = requestedToken == null
                    ? MobileModelCatalog.DEFAULT
                    : MobileModelCatalog.forToken(requestedToken);
            if (requestedToken != null && !model.token.equals(requestedToken)) {
                throw new IllegalArgumentException("unsupported model token");
            }
            QnnAssetBundleInstaller.Result install = QnnAssetBundleInstaller.ensureInstalled(
                    getFilesDir(),
                    name -> getAssets().open(QnnAssetBundleInstaller.DIRECTORY_NAME + "/" + name));
            if (!install.ready || install.directory == null) {
                throw new IllegalStateException(
                        "QNN asset installation failed: " + install.detail, install.failure);
            }
            report = "asset_install={" + install.detail + "}\n"
                    + QnnHtpBridge.runBenchmark(
                            getApplicationInfo().nativeLibraryDir,
                            install.directory.getAbsolutePath(),
                            model.token);
            Log.i(TAG, report);
        } catch (Throwable failure) {
            report = "QNN_DEVICE_SELF_TEST_FAILED " +
                    MobileThrowableDiagnostics.format(failure);
            Log.e(TAG, report, failure);
        }
        try (FileOutputStream output = openFileOutput(RESULT_FILE, MODE_PRIVATE)) {
            output.write(report.getBytes(StandardCharsets.UTF_8));
            output.getFD().sync();
        } catch (Exception failure) {
            Log.e(TAG, "Unable to persist QNN device self-test result", failure);
        }
        runOnUiThread(this::finish);
    }
}
