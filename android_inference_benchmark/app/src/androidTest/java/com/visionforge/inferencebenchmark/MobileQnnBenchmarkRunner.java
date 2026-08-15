package com.visionforge.inferencebenchmark;

import android.content.Context;
import android.os.Bundle;

import java.io.File;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;

final class MobileQnnBenchmarkRunner {
    private static final String ARG_MODEL_TOKEN = "modelToken";
    private static final String RESULT_PREFIX = "MOBILE_QNN_BENCHMARK";

    private MobileQnnBenchmarkRunner() {}

    static String run(Context context, Bundle arguments) {
        try {
            return runChecked(context, arguments);
        } catch (Throwable failure) {
            return RESULT_PREFIX + "_FAILED\n" + stackTrace(failure);
        }
    }

    private static String runChecked(Context context, Bundle arguments) {
        if (context == null) {
            throw new IllegalStateException("target context is unavailable");
        }
        QnnAssetBundleInstaller.Result installed = QnnAssetBundleInstaller.ensureInstalled(
                context.getFilesDir(),
                name -> openQnnAsset(context, name));
        if (!installed.ready || installed.directory == null) {
            throw new IllegalStateException("QNN asset install failed: " + installed.detail,
                    installed.failure);
        }
        String requestedToken = arguments == null ? null : arguments.getString(ARG_MODEL_TOKEN);
        String nativeLibraryDirectory = context.getApplicationInfo().nativeLibraryDir;
        String skeletonDirectory = installed.directory.getAbsolutePath();
        StringBuilder stream = new StringBuilder(RESULT_PREFIX).append("_START\n")
                .append("native_library_directory=").append(nativeLibraryDirectory).append('\n')
                .append("skeleton_directory=").append(skeletonDirectory).append('\n')
                .append("asset_install=").append(installed.detail).append('\n');
        int executed = 0;
        for (MobileModelCatalog.Profile profile : MobileModelCatalog.ALL) {
            if (requestedToken != null && !requestedToken.isBlank()
                    && !profile.token.equals(requestedToken)) {
                continue;
            }
            executed++;
            stream.append("model=").append(profile.token)
                    .append(" qnn_library=").append(profile.qnnLibrary)
                    .append(" input=").append(profile.inputWidth).append('x')
                    .append(profile.inputHeight)
                    .append(" anchors=").append(profile.anchorCount)
                    .append(" classes=").append(profile.classCount)
                    .append('\n');
            stream.append(QnnHtpBridge.runBenchmark(
                    nativeLibraryDirectory, skeletonDirectory, profile.token)).append('\n');
        }
        if (executed == 0) {
            throw new IllegalArgumentException("unknown modelToken: " + requestedToken);
        }
        return stream.append(RESULT_PREFIX).append("_OK models=").append(executed).append('\n')
                .toString();
    }

    private static InputStream openQnnAsset(Context context, String name) throws java.io.IOException {
        return context.getAssets().open("qnn" + File.separator + name);
    }

    private static String stackTrace(Throwable failure) {
        StringWriter buffer = new StringWriter();
        failure.printStackTrace(new PrintWriter(buffer));
        return buffer.toString();
    }
}
