package com.visionforge.inferencebenchmark;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Enforces automatic Host-driven startup, verified billing and live reload.
 */
final class MobileRuntimeServiceCommandContractSelfTest {
    private static final String PROJECT_DIRECTORY_PROPERTY =
            "visionforge.android.project.dir";

    static void run() throws Exception {
        String projectDirectory = System.getProperty(PROJECT_DIRECTORY_PROPERTY, "");
        require(!projectDirectory.isEmpty());
        Path servicePath = Paths.get(projectDirectory, "src", "main", "java", "com",
                "visionforge", "inferencebenchmark", "MobileRuntimeService.java");
        String source = new String(Files.readAllBytes(servicePath), StandardCharsets.UTF_8)
                .replace("\r\n", "\n");
        Path gradlePath = Paths.get(projectDirectory, "build.gradle");
        String gradleSource = new String(
                Files.readAllBytes(gradlePath), StandardCharsets.UTF_8);
        String compactGradleSource = gradleSource.replaceAll("\\s+", "");
        Path formalCapabilityLoaderPath = Paths.get(
                projectDirectory, "formal-security-loader.gradle");
        String formalCapabilityLoaderSource = new String(
                Files.readAllBytes(formalCapabilityLoaderPath), StandardCharsets.UTF_8);
        String compactFormalCapabilityLoaderSource =
                formalCapabilityLoaderSource.replaceAll("\\s+", "");
        Path formalCapabilityPath = Paths.get(
                projectDirectory, "formal-security-capability.properties");
        String formalCapabilitySource = new String(
                Files.readAllBytes(formalCapabilityPath), StandardCharsets.US_ASCII)
                .replace("\r\n", "\n");
        require(gradleSource.contains(
                "apply from: 'formal-security-loader.gradle'"));
        require(compactGradleSource.contains(
                "if(task.namein['packageRelease','bundleRelease'])"));
        require(compactGradleSource.contains(
                "task.dependsOn(tasks.named('verifyMobileReleaseContracts'))"));
        require(formalCapabilityLoaderSource.contains(
                "def formalSecurityCapabilityFile = "
                        + "file('formal-security-capability.properties')"));
        require(formalCapabilityLoaderSource.contains(
                "if (!formalSecurityCapabilityFile.isFile())"));
        require(formalCapabilityLoaderSource.contains(
                "Formal security capability file is missing:"));
        require(formalCapabilityLoaderSource.contains(
                "def formalSecurityCapabilityProperties = new Properties()"));
        require(formalCapabilityLoaderSource.contains(
                "formalSecurityCapabilityFile.withInputStream {"));
        require(formalCapabilityLoaderSource.contains(
                "formalSecurityCapabilityProperties.load(it)"));
        require(formalCapabilityLoaderSource.contains(
                ".getProperty('formalSecureDataPlaneImplemented')"));
        require(formalCapabilityLoaderSource.contains(
                "if (!(formalSecurityCapabilityValue in ['true', 'false']))"));
        require(formalCapabilityLoaderSource.contains(
                "formalSecureDataPlaneImplemented must be exactly true or false"));
        require(formalCapabilityLoaderSource.contains(
                "ext.formalSecureDataPlaneImplemented = Boolean.parseBoolean("));
        require(!formalCapabilityLoaderSource.contains(
                "ext.formalSecureDataPlaneImplemented = false"));
        require(formalCapabilityLoaderSource.contains(
                ".gradleProperty('visionforgeFormalSecureDataPlaneOnly')"));
        int formalVerificationTaskIndex = formalCapabilityLoaderSource.indexOf(
                "tasks.register('verifyFormalSecureDataPlaneImplemented')");
        int formalOnlyGateIndex = formalCapabilityLoaderSource.indexOf(
                "if (!formalSecureDataPlaneOnly)", formalVerificationTaskIndex);
        int implementationGateIndex = formalCapabilityLoaderSource.indexOf(
                "if (!formalSecureDataPlaneImplemented)", formalOnlyGateIndex);
        int formalLoaderSuccessMarkerIndex = formalCapabilityLoaderSource.indexOf(
                "VFDUAL_FORMAL_SECURITY_LOADER_CONTRACT=v1:",
                implementationGateIndex);
        require(formalVerificationTaskIndex >= 0);
        require(formalOnlyGateIndex > formalVerificationTaskIndex);
        require(implementationGateIndex > formalOnlyGateIndex);
        require(formalLoaderSuccessMarkerIndex > implementationGateIndex);
        require(formalCapabilityLoaderSource.contains(
                "Formal release must set "
                        + "-PvisionforgeFormalSecureDataPlaneOnly=true"));
        require(formalCapabilityLoaderSource.contains(
                "Formal secure data plane is not implemented; refusing release APK"));
        require(compactFormalCapabilityLoaderSource.contains(
                "defformalReleaseArtifactTaskNames="
                        + "['packageRelease','bundleRelease']"));
        require(compactFormalCapabilityLoaderSource.contains(
                "tasks.configureEach{task->"
                        + "if(task.nameinformalReleaseArtifactTaskNames){"
                        + "task.dependsOn(tasks.named("
                        + "'verifyFormalSecureDataPlaneImplemented'))"));
        require(formalCapabilityLoaderSource.contains(
                "tasks.register('probeFormalSecurityReleaseGraphContract')"));
        require(formalCapabilityLoaderSource.contains(
                ".getDependencies(releaseTask)"));
        require(formalCapabilityLoaderSource.contains(
                "if (!dependencies.contains(formalTask))"));
        require(formalCapabilityLoaderSource.contains(
                "VFDUAL_FORMAL_SECURITY_RELEASE_GRAPH=v1:"));
        require(formalCapabilityLoaderSource.contains(
                "+ 'packageRelease,bundleRelease'"));
        require(formalCapabilityLoaderSource.contains(
                "+ '->verifyFormalSecureDataPlaneImplemented'"));
        require(formalCapabilitySource.equals(
                "formalSecureDataPlaneImplemented=false\n")
                || formalCapabilitySource.equals(
                "formalSecureDataPlaneImplemented=true\n"));
        require(source.contains(
                "WIRELESS_HOST_DISCOVERY_TIMEOUT_MILLIS = 4_000L"));
        require(source.contains(
                "HOST_VIDEO_PREFLIGHT_TIMEOUT_MILLIS = 8_000L"));
        require(source.contains(
                "HOST_VIDEO_REVALIDATION_TIMEOUT_MILLIS = 2_000L"));
        Path ethernetDiagnosticsPath = Paths.get(projectDirectory, "src", "main", "java",
                "com", "visionforge", "inferencebenchmark",
                "EthernetNetworkDiagnostics.java");
        String ethernetDiagnostics = new String(
                Files.readAllBytes(ethernetDiagnosticsPath), StandardCharsets.UTF_8);
        Path mobileTransportEndpointPath = Paths.get(projectDirectory, "src", "main", "java",
                "com", "visionforge", "inferencebenchmark", "MobileTransportEndpoint.java");
        String mobileTransportEndpoint = new String(
                Files.readAllBytes(mobileTransportEndpointPath), StandardCharsets.UTF_8);
        Path mobileTransportCatalogPath = Paths.get(projectDirectory, "src", "main", "java",
                "com", "visionforge", "inferencebenchmark", "MobileTransportCatalog.java");
        String mobileTransportCatalog = new String(
                Files.readAllBytes(mobileTransportCatalogPath), StandardCharsets.UTF_8);
        Path hostVideoPresenceProbePath = Paths.get(projectDirectory, "src", "main", "java",
                "com", "visionforge", "inferencebenchmark", "HostVideoPresenceProbe.java");
        String hostVideoPresenceProbeSource = new String(
                Files.readAllBytes(hostVideoPresenceProbePath), StandardCharsets.UTF_8)
                .replace("\r\n", "\n");
        Path nativeReadyAgentPath = Paths.get(projectDirectory, "src", "main", "java",
                "com", "visionforge", "inferencebenchmark", "NativeCat6ReadyAgent.java");
        String nativeReadyAgent = new String(
                Files.readAllBytes(nativeReadyAgentPath), StandardCharsets.UTF_8);
        Path activityPath = Paths.get(projectDirectory, "src", "main", "java", "com",
                "visionforge", "inferencebenchmark", "MainActivity.java");
        String activity = new String(
                Files.readAllBytes(activityPath), StandardCharsets.UTF_8)
                .replace("\r\n", "\n");
        Path runtimePresentationPolicyPath = Paths.get(
                projectDirectory, "src", "main", "java", "com",
                "visionforge", "inferencebenchmark",
                "MobileRuntimePresentationUpdatePolicy.java");
        String runtimePresentationPolicy = new String(
                Files.readAllBytes(runtimePresentationPolicyPath),
                StandardCharsets.UTF_8);
        Path checkpointPolicyPath = Paths.get(
                projectDirectory, "src", "main", "java", "com",
                "visionforge", "inferencebenchmark",
                "AutomaticUsageGuardCheckpointPolicy.java");
        String checkpointPolicy = new String(
                Files.readAllBytes(checkpointPolicyPath),
                StandardCharsets.UTF_8);
        Path authorizationRuntimePath = Paths.get(projectDirectory, "src",
                "main", "java", "com", "visionforge", "inferencebenchmark",
                "DualMachineAuthorizationRuntime.java");
        String authorizationRuntime = new String(
                Files.readAllBytes(authorizationRuntimePath), StandardCharsets.UTF_8);
        Path formalCoordinatorPath = Paths.get(projectDirectory, "src",
                "main", "java", "com", "visionforge", "inferencebenchmark",
                "DualMachineFormalUsageCoordinator.java");
        String formalCoordinator = new String(
                Files.readAllBytes(formalCoordinatorPath), StandardCharsets.UTF_8);
        Path qnnBridgePath = Paths.get(projectDirectory, "src", "main", "cpp",
                "QnnHtpBridge.cpp");
        String qnnBridge = new String(
                Files.readAllBytes(qnnBridgePath), StandardCharsets.UTF_8);
        Path dualMachineReceiverPath = Paths.get(projectDirectory, "src", "main", "cpp",
                "DualMachineReceiver.cpp");
        String dualMachineReceiver = new String(
                Files.readAllBytes(dualMachineReceiverPath), StandardCharsets.UTF_8)
                .replace("\r\n", "\n");
        Path controlRuntimePath = Paths.get(projectDirectory, "src", "main", "java", "com",
                "visionforge", "inferencebenchmark", "MobileControlRuntime.java");
        String controlRuntime = new String(
                Files.readAllBytes(controlRuntimePath), StandardCharsets.UTF_8);
        Path cat6MouseButtonInputPath = Paths.get(
                projectDirectory, "src", "main", "java", "com",
                "visionforge", "inferencebenchmark",
                "Cat6MouseButtonInput.java");
        String cat6MouseButtonInput = new String(
                Files.readAllBytes(cat6MouseButtonInputPath),
                StandardCharsets.UTF_8);
        Path inferenceProfilePath = Paths.get(projectDirectory, "src", "main", "java", "com",
                "visionforge", "inferencebenchmark", "InferenceProfile.java");
        String inferenceProfile = new String(
                Files.readAllBytes(inferenceProfilePath), StandardCharsets.UTF_8);
        Path controlProfilePath = Paths.get(projectDirectory, "src", "main", "java", "com",
                "visionforge", "inferencebenchmark", "ControlProfile.java");
        String controlProfile = new String(
                Files.readAllBytes(controlProfilePath), StandardCharsets.UTF_8);
        Path makcuMoveBridgePath = Paths.get(projectDirectory, "src", "main", "cpp",
                "MakcuMoveBridge.cpp");
        String makcuMoveBridge = new String(
                Files.readAllBytes(makcuMoveBridgePath), StandardCharsets.UTF_8);
        Path makcuControllerPath = Paths.get(projectDirectory, "src", "main", "java", "com",
                "visionforge", "inferencebenchmark", "MakcuSerialController.java");
        String makcuController = new String(
                Files.readAllBytes(makcuControllerPath), StandardCharsets.UTF_8);
        Path projectRootPath = Paths.get(projectDirectory).getParent();
        require(projectRootPath != null);
        Path repositoryRootPath = projectRootPath.getParent();
        require(repositoryRootPath != null);
        Path sharedModelContractPath = repositoryRootPath.resolve("dual_machine_runtime")
                .resolve("shared").resolve("include").resolve("vfdual")
                .resolve("model_contract.hpp");
        String sharedModelContract = new String(
                Files.readAllBytes(sharedModelContractPath), StandardCharsets.UTF_8);
        Path installScriptPath = projectRootPath.resolve("tools")
                .resolve("install_mobile_release.ps1");
        String installScript = new String(
                Files.readAllBytes(installScriptPath), StandardCharsets.UTF_8);
        Path portableProbeLoopPath = projectRootPath.resolve("tools")
                .resolve("run_portable_backend_probe_loop.ps1");
        String portableProbeLoop = new String(
                Files.readAllBytes(portableProbeLoopPath),
                StandardCharsets.UTF_8);
        Path controlScreenPath = Paths.get(projectDirectory, "src", "main", "java", "com",
                "visionforge", "inferencebenchmark", "ui", "ControlScreen.java");
        String controlScreen = new String(
                Files.readAllBytes(controlScreenPath), StandardCharsets.UTF_8);
        Path ionFieldPath = Paths.get(projectDirectory, "src", "main", "java", "com",
                "visionforge", "inferencebenchmark", "ui", "FxIonFieldView.java");
        String ionField = new String(
                Files.readAllBytes(ionFieldPath), StandardCharsets.UTF_8);
        Path appShellPath = Paths.get(projectDirectory, "src", "main", "java", "com",
                "visionforge", "inferencebenchmark", "ui", "MobileAppShell.java");
        String appShell = new String(
                Files.readAllBytes(appShellPath), StandardCharsets.UTF_8);
        Path mobileUiStatePath = Paths.get(projectDirectory, "src", "main", "java", "com",
                "visionforge", "inferencebenchmark", "ui", "MobileUiState.java");
        String mobileUiState = new String(
                Files.readAllBytes(mobileUiStatePath), StandardCharsets.UTF_8);
        Path mobileUiStateMapperPath = Paths.get(projectDirectory, "src", "main", "java",
                "com", "visionforge", "inferencebenchmark", "ui",
                "MobileUiStateMapper.java");
        String mobileUiStateMapper = new String(
                Files.readAllBytes(mobileUiStateMapperPath), StandardCharsets.UTF_8);
        Path mobileAppActionsPath = Paths.get(projectDirectory, "src", "main", "java",
                "com", "visionforge", "inferencebenchmark", "ui",
                "MobileAppActions.java");
        String mobileAppActions = new String(
                Files.readAllBytes(mobileAppActionsPath), StandardCharsets.UTF_8);
        Path uiAutomationIdsPath = Paths.get(projectDirectory, "src", "main", "java",
                "com", "visionforge", "inferencebenchmark", "ui",
                "UiAutomationIds.java");
        String uiAutomationIds = new String(
                Files.readAllBytes(uiAutomationIdsPath), StandardCharsets.UTF_8);
        Path bluetoothHidPermissionPolicyPath = Paths.get(projectDirectory, "src", "main",
                "java", "com", "visionforge", "inferencebenchmark",
                "BluetoothHidPermissionPolicy.java");
        String bluetoothHidPermissionPolicy = new String(
                Files.readAllBytes(bluetoothHidPermissionPolicyPath), StandardCharsets.UTF_8);
        Path bluetoothHidMoveProbePolicyPath = Paths.get(projectDirectory, "src", "main",
                "java", "com", "visionforge", "inferencebenchmark",
                "BluetoothHidDebugMoveProbePolicy.java");
        String bluetoothHidMoveProbePolicy = new String(
                Files.readAllBytes(bluetoothHidMoveProbePolicyPath), StandardCharsets.UTF_8);
        Path linkStatusSectionPath = Paths.get(projectDirectory, "src", "main", "java", "com",
                "visionforge", "inferencebenchmark", "ui", "LinkStatusSection.java");
        String linkStatusSection = new String(
                Files.readAllBytes(linkStatusSectionPath), StandardCharsets.UTF_8);
        Path particleBurstPath = Paths.get(projectDirectory, "src", "main", "java", "com",
                "visionforge", "inferencebenchmark", "ui", "FxParticleBurstView.java");
        String particleBurst = new String(
                Files.readAllBytes(particleBurstPath), StandardCharsets.UTF_8);
        Path inferenceScreenPath = Paths.get(projectDirectory, "src", "main", "java", "com",
                "visionforge", "inferencebenchmark", "ui", "InferenceScreen.java");
        String inferenceScreen = new String(
                Files.readAllBytes(inferenceScreenPath), StandardCharsets.UTF_8);
        Path stringsPath = Paths.get(projectDirectory, "src", "main", "res", "values",
                "strings.xml");
        String strings = new String(Files.readAllBytes(stringsPath), StandardCharsets.UTF_8);
        Path appBuildGradlePath = Paths.get(projectDirectory, "build.gradle");
        String appBuildGradle = new String(
                Files.readAllBytes(appBuildGradlePath), StandardCharsets.UTF_8);
        Path runtimeStringsPath = Paths.get(projectDirectory, "src", "main", "res", "values",
                "runtime_strings.xml");
        String runtimeStrings = new String(
                Files.readAllBytes(runtimeStringsPath), StandardCharsets.UTF_8);
        Path bluetoothHidStringsPath = Paths.get(projectDirectory, "src", "main", "res",
                "values", "bluetooth_hid_strings.xml");
        String bluetoothHidStrings = new String(
                Files.readAllBytes(bluetoothHidStringsPath), StandardCharsets.UTF_8);
        Path authorizationStringsPath = Paths.get(projectDirectory, "src", "main", "res",
                "values", "dual_machine_authorization_strings.xml");
        String authorizationStrings = new String(
                Files.readAllBytes(authorizationStringsPath), StandardCharsets.UTF_8);
        String productStrings = String.join("\n",
                strings, runtimeStrings, bluetoothHidStrings, authorizationStrings)
                .toLowerCase(Locale.ROOT);
        Path releaseSecurityConfigPath = Paths.get(projectDirectory, "src", "main", "java",
                "com", "visionforge", "inferencebenchmark",
                "DualMachineReleaseSecurityConfig.java");
        String releaseSecurityConfig = new String(
                Files.readAllBytes(releaseSecurityConfigPath), StandardCharsets.UTF_8);

        String ensureMethod = methodSlice(
                source, "static void ensureRunning(", "static void requestPowerPolicyRefresh(");
        String onCreateMethod = methodSlice(
                source, "public void onCreate()", "public int onStartCommand(");
        String requestGameModelSelectionMethod = methodSlice(
                source,
                "private void requestGameModelSelection(",
                "private void hotReloadGameModel(");
        require(ensureMethod.contains("context.startForegroundService(intent);"));
        require(ensureMethod.contains(".setAction(ACTION_ENSURE)"));
        require(!source.contains("ACTION_START_PIPELINE"));
        require(!source.contains("ACTION_STOP_PIPELINE"));
        require(!source.contains("ACTION_SHUTDOWN"));
        require(source.contains("controlRuntime = MobileControlRuntime.get(this);"));
        require(source.contains(
                "commitFormalPipelineOwnerIfCurrent("));
        require(source.contains("this::reconcileControlOutput"));
        require(source.contains("controlRuntime.closeForServiceStop("));
        require(controlRuntime.contains("private static volatile MobileControlRuntime instance;"));
        require(controlRuntime.contains("if (instance == null || instance.destroyed)"));
        require(controlRuntime.contains("makcu.destroy();"));
        require(controlRuntime.contains("if (instance == this) instance = null;"));
        require(controlRuntime.contains("return !destroyed && output.isOutputEnabled();"));
        require(controlRuntime.contains("return !destroyed && output.isOutputRecoverySuspended();"));
        require(controlRuntime.contains("return !destroyed && output.isControlTriggerPressed();"));
        require(controlRuntime.contains("return !destroyed && output.isControlTriggerStreamReady();"));
        require(controlRuntime.contains("return !destroyed && inference.isNativeConfigurationApplied();"));
        String controlReconcileMethod = methodSlice(
                controlRuntime,
                "synchronized void reconcile(",
                "synchronized void failClosed(String reason)");
        require(controlReconcileMethod.contains(
                "activeRoute == ControlOutputRoute.BLUETOOTH_HID"));
        int cat6WorkerMaintenanceIndex = controlReconcileMethod.indexOf(
                "cat6ButtonInput.updateEndpoint(transportEndpoint);");
        int deliveryReconcileIndex = controlReconcileMethod.indexOf(
                "output.reconcileDeliveryState();");
        require(cat6WorkerMaintenanceIndex >= 0);
        require(deliveryReconcileIndex > cat6WorkerMaintenanceIndex);
        require(cat6MouseButtonInput.contains(
                "private synchronized void acceptPacket("));
        require(controlRuntime.contains(
                "synchronized boolean installConfirmedPeerSession("));
        require(controlRuntime.contains(
                "synchronized void clearConfirmedPeerSession("));
        require(cat6MouseButtonInput.contains(
                "installConfirmedSession("));
        require(cat6MouseButtonInput.contains(
                "protocol.decode(bytes, datagram.getLength())"));
        require(cat6MouseButtonInput.contains(
                "clearConfirmedSession(\"session_install_rejected_\""));
        require(!cat6MouseButtonInput.contains(
                "Cat6MouseButtonProtocol.isNewerSequence("));
        String cat6AcceptPacketMethod = methodSlice(
                cat6MouseButtonInput,
                "private synchronized void acceptPacket(",
                "private void expireLeaseIfNeeded(");
        int cat6GenerationCheckIndex = cat6AcceptPacketMethod.indexOf(
                "generation.get() != workerGeneration");
        int cat6StateCommitIndex = cat6AcceptPacketMethod.indexOf(
                "buttonState.acceptPacket(");
        int cat6ListenerIndex = cat6AcceptPacketMethod.indexOf(
                "buttonNotifications.enqueue(");
        require(cat6GenerationCheckIndex >= 0);
        require(cat6StateCommitIndex > cat6GenerationCheckIndex);
        require(cat6ListenerIndex > cat6StateCommitIndex);
        require(cat6MouseButtonInput.contains(
                "private WorkerFailureClaim claimWorkerFailureIfCurrent("));
        String cat6WorkerFailureClaimMethod = methodSlice(
                cat6MouseButtonInput,
                "private WorkerFailureClaim claimWorkerFailureIfCurrent(",
                "private void receivePackets(");
        int cat6FastGenerationCheckIndex =
                cat6WorkerFailureClaimMethod.indexOf(
                        "generation.get() != workerGeneration");
        int cat6FailureLockIndex = cat6WorkerFailureClaimMethod.indexOf(
                "synchronized (this)");
        int cat6LockedGenerationCheckIndex =
                cat6WorkerFailureClaimMethod.indexOf(
                        "generation.get() != workerGeneration",
                        cat6FastGenerationCheckIndex + 1);
        int cat6WorkerReleaseIndex = cat6WorkerFailureClaimMethod.indexOf(
                "worker = null");
        int cat6FailureRecordIndex = cat6WorkerFailureClaimMethod.indexOf(
                "workerRecovery.recordFailure(nowNanos)");
        int cat6FailureLeaseClearIndex = cat6WorkerFailureClaimMethod.indexOf(
                "buttonState.clear()");
        require(cat6FastGenerationCheckIndex >= 0);
        require(cat6FailureLockIndex > cat6FastGenerationCheckIndex);
        require(cat6LockedGenerationCheckIndex > cat6FailureLockIndex);
        require(cat6WorkerReleaseIndex > cat6LockedGenerationCheckIndex);
        require(cat6FailureRecordIndex > cat6WorkerReleaseIndex);
        require(cat6FailureLeaseClearIndex > cat6FailureRecordIndex);
        String failClosedMethod = methodSlice(
                controlRuntime, "synchronized void failClosed(String reason)",
                "synchronized void closeForServiceStop(String reason)");
        require(failClosedMethod.indexOf("if (destroyed) return;")
                < failClosedMethod.indexOf("output.failClosed(reasonToken);"));
        require(!failClosedMethod.contains("output.disable();"));
        require(Pattern.compile("if \\(destroyed\\) return;\\s+output\\.setGain\\(value\\);")
                .matcher(controlRuntime).find());
        require(Pattern.compile("if \\(destroyed\\) return;\\s+output\\.setDeadzone\\(value\\);")
                .matcher(controlRuntime).find());
        require(Pattern.compile("if \\(destroyed\\) return;\\s+output\\.setMaximumAxisDelta\\(value\\);")
                .matcher(controlRuntime).find());
        require(Pattern.compile("if \\(destroyed\\) return;\\s+output\\.setProfile\\(")
                .matcher(controlRuntime).find());
        require(Pattern.compile("if \\(destroyed\\) return;\\s+output\\.setControlTrigger\\(trigger\\);")
                .matcher(controlRuntime).find());
        require(Pattern.compile("if \\(destroyed\\) return false;\\s+boolean imported")
                .matcher(controlRuntime).find());
        require(Pattern.compile("if \\(destroyed\\) return;\\s+output\\.setPersonalTrajectoryEnabled\\(enabled\\);")
                .matcher(controlRuntime).find());
        require(Pattern.compile("if \\(destroyed\\) return;\\s+output\\.setPersonalTrajectoryScales\\(")
                .matcher(controlRuntime).find());
        require(Pattern.compile("if \\(destroyed\\) return;\\s+inference\\.setConfidence\\(value\\);")
                .matcher(controlRuntime).find());
        require(controlRuntime.contains("if (destroyed) return \"runtime_destroyed\";"));
        require(activity.contains("MobileRuntimeService.ensureRunning(this);"));
        require(activity.contains("MobileRuntimeBinding runtimeBinder"));
        require(activity.contains("MobileRuntimeReadModelStore.snapshot()"));
        require(!activity.contains("MobileRuntimeService.LocalBinder"));
        require(!activity.contains("MobileRuntimeService.Phase"));
        require(!activity.contains("MobileRuntimeService.RuntimeStatus"));
        require(activity.contains("MobilePreviousExitInspector.inspect(this)"));
        require(activity.contains("showTaskCleanedGuidanceIfNeeded()"));
        require(strings.contains("不要上滑清理 VF Mobile"));
        require(strings.contains("Android 不允许 APP 自行绕过"));
        require(activity.contains("controlRuntime = MobileControlRuntime.get(this);"));
        require(activity.contains("ACTIVE_STATUS_REFRESH_MILLIS = 250L"));
        require(activity.contains("IDLE_STATUS_REFRESH_MILLIS = 1_500L"));
        require(activity.contains("nextStatusRefreshDelayMillis()"));
        require(activity.contains("runtimeStatus.phase == MobileRuntimePhase.RUNNING"));
        require(!activity.contains("STATUS_REFRESH_MILLIS = 500L"));
        require(ionField.contains("import android.view.Choreographer;"));
        require(ionField.contains("postFrameCallbackDelayed("));
        require(ionField.contains("IDLE_FRAME_DELAY_MILLIS = 50L"));
        require(ionField.contains("removeFrameCallback(frameCallback);"));
        require(ionField.contains("private void step(float deltaSeconds)"));
        require(ionField.contains("private boolean shouldAnimate()"));
        require(particleBurst.contains("setVisibility(INVISIBLE);"));
        require(!particleBurst.contains("post(() -> burst(color))"));
        require(makcuController.contains("context.unregisterReceiver(usbReceiver);"));
        require(makcuController.contains("writer.shutdownNow();"));
        require(makcuController.contains("reader.shutdownNow();"));
        require(makcuController.contains("if (instance == this) instance = null;"));
        require(!source.contains("getBoolean(PREF_PIPELINE_DESIRED, false)"));
        require(source.contains("clearLegacyPipelineRestoreFlag();"));
        require(!source.contains("persistPipelineDesired("));
        require(!onCreateMethod.contains("acquireRuntimeLocks("));
        int restoreGuardOnCreateIndex = onCreateMethod.indexOf(
                "restoreAutomaticUsageGuard();");
        require(restoreGuardOnCreateIndex >= 0);
        require(onCreateMethod.indexOf(
                "initialiseAuthorizationRuntimeAsync();")
                > restoreGuardOnCreateIndex);
        require(onCreateMethod.indexOf(
                "this::runPeriodicAuthorizationMaintenance")
                > restoreGuardOnCreateIndex);
        require(onCreateMethod.contains("this::runPeriodicRuntimeHealth"));
        require(!onCreateMethod.contains(
                "scheduleAtFixedRate(this::writeRuntimeHealth"));
        require(!onCreateMethod.contains(
                "this::scheduleAuthorizationMaintenance,"));
        String periodicTaskGuard = methodSlice(
                source,
                "private void runPeriodicAuthorizationMaintenance()",
                "private void maintainAuthorizationRuntime(");
        require(periodicTaskGuard.contains(
                "this::scheduleAuthorizationMaintenance"));
        require(periodicTaskGuard.contains("this::writeRuntimeHealth"));
        require(periodicTaskGuard.contains(
                "catch (RuntimeException | LinkageError failure)"));
        require(periodicTaskGuard.contains(
                "controlRuntime.failClosed("));
        require(periodicTaskGuard.contains(
                "scheduled_future_retained=true"));
        require(periodicTaskGuard.contains("automatic_retry=true"));
        String authorizationMaintenanceScheduler = methodSlice(
                source,
                "private void scheduleAuthorizationMaintenance()",
                "private void runPeriodicAuthorizationMaintenance()");
        require(authorizationMaintenanceScheduler.contains(
                "ensureAuthorizationStatusRetryScheduled();"));
        require(source.contains(
                "private void ensureAuthorizationStatusRetryScheduled()"));
        require(source.contains(
                "recordAuthorizationStatusRetryScheduleFailure("));
        require(source.contains(
                "authorization_health_rearm"));
        require(source.contains("!PROCESS_RETRY_GATE.canAttempt()"));
        require(source.contains("mobile_pipeline_automatic_recovery_suppressed"));
        int operatorRetryIndex = requestGameModelSelectionMethod.indexOf(
                "PROCESS_RETRY_GATE.authorizeOperatorAttempt()");
        require(requestGameModelSelectionMethod.contains(
                "boolean operatorInitiated"));
        int operatorGuardIndex = requestGameModelSelectionMethod.indexOf(
                "if (operatorInitiated)");
        require(operatorGuardIndex >= 0);
        require(operatorRetryIndex > operatorGuardIndex);
        require(operatorRetryIndex
                > requestGameModelSelectionMethod.indexOf(
                "MobileModelCatalog.isProductionSelectable(selected)"));
        require(operatorRetryIndex
                < requestGameModelSelectionMethod.indexOf(
                "runtimeExecutor.execute("));
        require(requestGameModelSelectionMethod.contains(
                "mobile_pipeline_operator_retry_authorized"));
        require(requestGameModelSelectionMethod.contains(
                "automatic_retry=false"));
        require(source.contains(
                "requestGameModelSelection(modelToken, true);"));
        require(source.contains(
                "requestGameModelSelection(deferredModel.token, false);"));
        require(source.contains("return START_NOT_STICKY;"));
        require(!source.contains("START_STICKY"));
        require(!source.contains("\"service_restore\""));
        require(!source.contains("mobile_pipeline_restore_requested"));
        require(!source.contains("scheduleAtFixedRate(this::checkReceiverLiveness"));
        require(source.contains("RECEIVER_ACTIVE_LIVENESS_PROBE_MILLIS = 100L"));
        require(source.contains("RECEIVER_IDLE_LIVENESS_PROBE_MILLIS = 1_000L"));
        require(source.contains("scheduleReceiverLivenessProbe(receiverLivenessDelayMillis(), true);"));
        require(source.contains("cancelReceiverLivenessProbe();"));
        require(source.contains("private void runReceiverLivenessProbe()"));
        require(source.contains("private long receiverLivenessDelayMillis()"));
        require(source.contains("private void ensureReceiverLivenessProbeScheduled()"));
        String runtimeHealthWrapper = methodSlice(
                source,
                "private void writeRuntimeHealth()",
                "private void writeRuntimeHealthUnchecked(");
        int livenessRearmIndex = runtimeHealthWrapper.indexOf(
                "ensureReceiverLivenessProbeScheduled();");
        int ownerCaptureIndex = runtimeHealthWrapper.indexOf(
                "owner = captureFormalPipelineOwner();");
        require(livenessRearmIndex >= 0);
        require(ownerCaptureIndex > livenessRearmIndex);
        require(source.contains("periodic_health_rearm=true"));
        require(source.contains(
                "recordReceiverLivenessScheduleFailure(delayMillis, schedulingFailure);"));
        require(!activity.contains("qnnAssetExecutor"));
        require(!activity.contains("restoreQnnSkeleton("));
        require(!activity.contains("QnnAssetBundleInstaller.DIRECTORY_NAME"));
        require(!activity.contains("MobileRuntimeService.requestPipelineStart("));
        require(!activity.contains("public void onStartInference()"));
        require(!activity.contains("public void onStopInference()"));
        require(!activity.contains("binder.startFormalUsage()"));
        require(!activity.contains("binder.stopFormalUsage()"));
        require(!mobileAppActions.contains("onStartInference"));
        require(!mobileAppActions.contains("onStopInference"));
        require(!uiAutomationIds.contains("INFERENCE_START"));
        require(!uiAutomationIds.contains("INFERENCE_STOP"));
        require(source.contains(
                "attemptAutomaticFormalUsageStart(runtime, generationReceipt);"));
        require(source.contains("requestFormalUsageStop(String reason)"));
        require(source.contains("AUTOMATIC_NO_PROGRESS_STOP_MILLIS = 1_500L"));
        require(source.contains(
                "requestFormalUsageStop(\"inference_progress_stalled\")"));
        require(!source.contains(
                "requestFormalUsageStop(\"host_stream_no_progress\")"));
        String authorizationInitializationMethod = methodSlice(
                source,
                "private void initialiseAuthorizationRuntimeAsync()",
                "private void refreshAuthorizationStatusAfterRestore(");
        String authorizationAttachmentMethod = methodSlice(
                source,
                "void attachAuthenticatedHost(",
                "/** Synchronous local fail-close entry");
        String hostProgressMethod = methodSlice(
                source,
                "private long readHostProgress()",
                "private long readAndroidProgress()");
        String androidProgressMethod = methodSlice(
                source,
                "private long readAndroidProgress()",
                "private void requestCardActivation(");
        require(authorizationInitializationMethod.contains(
                "this::readAndroidProgress"));
        require(authorizationInitializationMethod.contains(
                "initializationGeneration = ++authorizationInitializationGeneration;"));
        require(authorizationInitializationMethod.contains(
                "installAuthorizationRuntimeIfCurrent("));
        require(authorizationInitializationMethod.contains(
                "reason=initialization_superseded"));
        require(authorizationInitializationMethod.contains(
                "markAuthorizationInitializationFailed("));
        require(source.contains(
                "private final Object authorizationLifecycleLock = new Object();"));
        require(Pattern.compile(
                "initializationGeneration\\s*!=\\s*"
                        + "authorizationInitializationGeneration")
                .matcher(source).find());
        require(source.contains(
                "authorizationRuntime = null;"));
        require(source.contains(
                "authorizationDeadlines = null;"));
        require(source.contains(
                "reserveAuthorizationStatusRetryAttempt(long generation)"));
        String statusRetryScheduleMethod = methodSlice(
                source,
                "private void scheduleAuthorizationStatusRetry(",
                "private void signalAuthorizationNetworkChanged(");
        String compactStatusRetryScheduleMethod =
                statusRetryScheduleMethod.replaceAll("\\s+", "");
        require(compactStatusRetryScheduleMethod.contains(
                "attemptAuthorizationStatusRefresh("
                        + "runtime,source+\"_retry\",generation)"));
        int staleGenerationCheckIndex = statusRetryScheduleMethod.indexOf(
                "if (generation != authorizationStatusRetryGeneration)");
        int clearRetryFutureIndex = statusRetryScheduleMethod.indexOf(
                "authorizationStatusRetryFuture = null;");
        require(staleGenerationCheckIndex >= 0);
        require(clearRetryFutureIndex > staleGenerationCheckIndex);
        require(authorizationAttachmentMethod.contains(
                "this::readHostProgress"));
        require(countOccurrences(source, "this::readHostProgress") == 1);
        require(countOccurrences(source, "this::readAndroidProgress") == 1);
        require(hostProgressMethod.contains(
                "QnnHtpBridge.getNativeVideoReceiverReport()"));
        require(hostProgressMethod.contains(".reassembledAccessUnits"));
        require(!hostProgressMethod.contains(".qnnExecutionCount"));
        require(androidProgressMethod.contains(
                "QnnHtpBridge.getNativeH264DecoderReport()"));
        require(androidProgressMethod.contains(".qnnExecutionCount"));
        require(!androidProgressMethod.contains(".reassembledAccessUnits"));
        String noProgressDetailMethod = methodSlice(
                source,
                "private String noProgressRenewalDetail(",
                "private void commitFormalGeneration(");
        require(source.contains("outcome=no_progress"));
        require(noProgressDetailMethod.contains("observed_host_progress="));
        require(noProgressDetailMethod.contains("last_host_progress="));
        require(noProgressDetailMethod.contains("observed_android_progress="));
        require(noProgressDetailMethod.contains("last_android_progress="));
        require(noProgressDetailMethod.contains("video_age_ms="));
        require(noProgressDetailMethod.contains("qnn_age_ms="));
        require(formalCoordinator.contains(
                "final class RenewalProgressObservation"));
        require(authorizationRuntime.contains(
                "latestRenewalProgressObservation("));
        String startFormalUsageMethod = methodSlice(
                authorizationRuntime,
                "startFormalUsage()",
                "/** Fast local half of a lifecycle stop");
        int refreshStatusIndex = startFormalUsageMethod.indexOf(
                "refreshStatus(admission);");
        int prepareAdmissionIndex = startFormalUsageMethod.indexOf(
                ".prepareForNewFormalStart();");
        int formalStartIndex = startFormalUsageMethod.indexOf(
                ".startAfterVerifiedHostVideo(startToken);");
        require(refreshStatusIndex >= 0);
        require(prepareAdmissionIndex > refreshStatusIndex);
        require(formalStartIndex > prepareAdmissionIndex);
        require(authorizationRuntime.contains(
                "capturePendingStartRetryAdmission();"));
        require(authorizationRuntime.contains(
                "retryPendingStart(retryToken)"));
        require(authorizationRuntime.contains(
                "boolean cancelPendingFormalStart()"));
        require(authorizationRuntime.contains(
                "formal.cancelPendingStart()"));
        require(authorizationRuntime.contains(
                "capturePendingFormalStartCancellation()"));
        require(authorizationRuntime.contains(
                "retiringFormalCoordinator"));
        require(authorizationRuntime.contains(
                "retainRetiringCoordinator(formal);"));
        require(authorizationRuntime.contains(
                "final class FormalStartAdmission"));
        require(authorizationRuntime.contains(
                "attachment != admission.attachment"));
        require(authorizationRuntime.contains(
                "cardCoordinator != admission.cardCoordinator"));
        require(authorizationRuntime.contains(
                "formalCoordinator != admission.formalCoordinator"));
        require(authorizationRuntime.contains(
                "requireNoRetiringLifecycleGeneration();"));
        String beginLifecycleStopMethod = methodSlice(
                authorizationRuntime,
                "beginFormalUsageLifecycleStop()",
                "public boolean hasPendingFormalStartCancellation()");
        int stopEpochOwnerIndex = beginLifecycleStopMethod.indexOf(
                "stopEpoch = ++lifecycleStopEpoch;");
        int immediateClosureIndex = beginLifecycleStopMethod.indexOf(
                "requestImmediateLocalStop();");
        int lifecycleCaptureIndex = beginLifecycleStopMethod.indexOf(
                "coordinator.captureLifecycleStop();");
        int exactCancellationCaptureIndex = beginLifecycleStopMethod.indexOf(
                "lifecycle.startCancellationHandle();");
        require(stopEpochOwnerIndex >= 0);
        require(immediateClosureIndex > stopEpochOwnerIndex);
        require(lifecycleCaptureIndex > immediateClosureIndex);
        require(exactCancellationCaptureIndex > lifecycleCaptureIndex);
        require(authorizationRuntime.contains(
                "outcome = delegate == null"));
        require(authorizationRuntime.contains(
                "runtime.completeFormalUsageLifecycleStop("));
        require(authorizationRuntime.contains(
                "stopEpoch, coordinator, delegate, outcome"));
        String formalStopMethod = methodSlice(
                source,
                "private void requestFormalUsageStop(String reason)",
                "private void retryFormalUsageStopIfDue(");
        int stopClaimIndex = formalStopMethod.indexOf(
                "automaticFormalStopQueued.compareAndSet(");
        int lifecycleHandleIndex = formalStopMethod.indexOf(
                "runtime.beginFormalUsageLifecycleStop();");
        int cancellationHandleIndex = formalStopMethod.indexOf(
                "lifecycleStopHandle.startCancellationHandle();");
        int persistentBlockIndex = formalStopMethod.lastIndexOf(
                "blockAutomaticStartForCurrentHostStream(reason);");
        int bindingClearIndex = formalStopMethod.lastIndexOf(
                "clearFormalSessionBinding();");
        int cancelQueueIndex = formalStopMethod.indexOf(
                "queuePendingFormalStartCancellation(cancellationHandle, reason);");
        int stopQueueIndex = formalStopMethod.indexOf(
                "queueClaimedFormalUsageStop(lifecycleStopHandle, reason);");
        require(stopClaimIndex >= 0);
        require(lifecycleHandleIndex > stopClaimIndex);
        require(cancellationHandleIndex > lifecycleHandleIndex);
        require(persistentBlockIndex > cancellationHandleIndex);
        require(bindingClearIndex > persistentBlockIndex);
        require(cancelQueueIndex > bindingClearIndex);
        require(stopQueueIndex > cancelQueueIndex);
        require(source.contains(
                "visionforge-mobile-start-cancellation"));
        require(!source.contains(
                "runtime.cancelPendingFormalStart()"));
        require(source.contains(
                "handle.sendExactCancellation()"));
        require(source.contains(
                "handle.startRequestId"));
        require(source.contains(
                "stopWirelessStartWhenDisplayUnavailable("));
        String ownerStopMethod = methodSlice(
                source,
                "private FormalPipelineOwnerReceipt captureFormalPipelineOwner()",
                "private void requestFormalUsageStop(String reason)");
        require(ownerStopMethod.contains(
                "captureCurrentGenerationReceipt()"));
        require(ownerStopMethod.contains(
                "runtime.commitIfCurrent("));
        require(ownerStopMethod.contains(
                "synchronized (pipelineCommandLock)"));
        require(ownerStopMethod.contains(
                "beginFormalUsageLifecycleStopIfCurrent("));
        require(ownerStopMethod.contains(
                "formalPipelineOwnerIsCurrentLocked(owner)"));
        require(ownerStopMethod.contains(
                "failureStillPresentLocked"));
        require(ownerStopMethod.contains(
                "automaticFormalStopQueued.compareAndSet("));
        require(ownerStopMethod.contains(
                "claimedPipelineMutationLocked.run();"));
        require(ownerStopMethod.contains(
                "claimMutationFailure.set(failure);"));
        require(ownerStopMethod.contains(
                "queuePendingFormalStartCancellation("));
        require(ownerStopMethod.contains(
                "queueClaimedFormalUsageStop(handle, reason);"));
        require(!ownerStopMethod.contains(
                "authorizationRuntime.beginFormalUsageLifecycleStop"));
        require(authorizationRuntime.contains(
                "beginFormalUsageLifecycleStopIfCurrent("));
        require(authorizationRuntime.contains(
                "beginFormalUsageLifecycleStopRetryIfCurrent("));
        require(authorizationRuntime.contains(
                "if (!isCurrentReceipt(receipt)"));
        String authorizationScheduleMethod = methodSlice(
                source,
                "private void scheduleAuthorizationMaintenance()",
                "private void maintainAuthorizationRuntime(");
        int maintenanceClaimIndex = authorizationScheduleMethod.indexOf(
                "authorizationMaintenanceQueued.compareAndSet(");
        int serializedMaintenanceIndex = authorizationScheduleMethod.indexOf(
                "authorizationExecutor.execute(");
        int retiringRecoveryIndex = authorizationScheduleMethod.indexOf(
                "captureRetiringFormalUsageStopForMaintenance(");
        int receiptCaptureIndex = authorizationScheduleMethod.indexOf(
                "captureCurrentGenerationReceipt()");
        int receiptCommitIndex = authorizationScheduleMethod.indexOf(
                "commitFormalGeneration(");
        int earlyDisplayStopIndex = authorizationScheduleMethod.indexOf(
                "stopWirelessStartWhenDisplayUnavailable(");
        require(maintenanceClaimIndex >= 0);
        require(serializedMaintenanceIndex > maintenanceClaimIndex);
        require(retiringRecoveryIndex > serializedMaintenanceIndex);
        require(authorizationScheduleMethod.indexOf(
                "hasRetiringFormalUsageGeneration()")
                < retiringRecoveryIndex);
        require(authorizationScheduleMethod.contains(
                "automaticFormalStopQueued"));
        require(receiptCaptureIndex > retiringRecoveryIndex);
        require(receiptCommitIndex > receiptCaptureIndex);
        require(earlyDisplayStopIndex > receiptCommitIndex);
        require(formalCoordinator.contains(
                "StartCancellationRequest cancellationRequest"));
        require(formalCoordinator.contains(
                "final class StartCancellationHandle"));
        require(formalCoordinator.contains(
                "final class StartAdmissionToken"));
        require(formalCoordinator.contains(
                "preparedStartAdmission != admission"));
        require(formalCoordinator.contains(
                "preparedStartAdmission = null;"));
        require(formalCoordinator.contains(
                "private final Object generationStopLock = new Object();"));
        String exactGenerationStopMethod = methodSlice(
                formalCoordinator,
                "private boolean latchImmediateLocalStop(PendingStart",
                "/**\n     * Rearms only after the Runtime");
        require(exactGenerationStopMethod.indexOf(
                "synchronized (generationStopLock)")
                < exactGenerationStopMethod.indexOf(
                "synchronized (runtimeTransitionLock)"));
        require(exactGenerationStopMethod.contains(
                "if (lifecycleStart != expectedGeneration) return false;"));
        String formalRearmMethod = methodSlice(
                formalCoordinator,
                "StartAdmissionToken prepareForNewFormalStart()",
                "/**\n     * Sends the immutable, pre-signed cancellation");
        require(formalRearmMethod.contains(
                "synchronized (generationStopLock)"));
        String formalClearMethod = methodSlice(
                formalCoordinator,
                "private void clearGeneration()",
                "private String nextId(");
        require(formalClearMethod.contains(
                "synchronized (generationStopLock)"));
        String initialLeaseRequestMethod = methodSlice(
                formalCoordinator,
                "private DataPlanePermit requestAndInstallInitialLease(",
                "private DataPlanePermit installInitialResponse(");
        int generationPublishLockIndex = initialLeaseRequestMethod.indexOf(
                "synchronized (generationStopLock)");
        require(generationPublishLockIndex >= 0);
        require(initialLeaseRequestMethod.indexOf(
                "lifecycleStart = generation;") > generationPublishLockIndex);
        require(initialLeaseRequestMethod.indexOf(
                "pendingStart = generation;") > generationPublishLockIndex);
        require(formalCoordinator.contains(
                "final class RetryAdmissionToken"));
        require(formalCoordinator.contains(
                "pendingStart != admission.generation"));
        require(formalCoordinator.contains(
                "final class AdmissionSupersededException"));
        require(formalCoordinator.contains(
                "owner.sendAndRecordStartCancellation(generation)"));
        require(formalCoordinator.contains(
                "new StartCancellationHandle(this, pending)"));
        require(formalCoordinator.contains(
                "sendAndRecordStartCancellation(startToCancel)"));
        require(formalCoordinator.contains(
                "pendingCancellationAmbiguous"));
        require(formalCoordinator.contains(
                "completedLifecycleStop"));
        require(formalCoordinator.contains(
                "startResponseReceived = true;"));
        require(formalCoordinator.contains(
                "preservePendingStartForCancellation();"));
        require(formalCoordinator.contains(
                "stateMachine.closeLocalForRuntimeStop();"));
        String potentiallyBilledFailureMethod = methodSlice(
                source,
                "private void blockPotentiallyBilledStartIfAborted(",
                "private void blockAutomaticStartForCurrentHostStream(");
        require(potentiallyBilledFailureMethod.contains(
                "DualMachineFormalUsageStateMachine.State.STOPPING"));
        require(potentiallyBilledFailureMethod.contains(
                "requestFormalUsageStop(reason);"));
        String maintainAuthorizationMethod = methodSlice(
                source,
                "private void maintainAuthorizationRuntime(",
                "private void attemptAutomaticFormalUsageStart(");
        require(maintainAuthorizationMethod.indexOf(
                "recoverPendingFormalStart(runtime, generationReceipt)")
                < maintainAuthorizationMethod.indexOf(
                "attemptAutomaticFormalUsageStart(runtime, generationReceipt)"));
        require(maintainAuthorizationMethod.indexOf(
                "if (automaticFormalStopQueued.get())")
                < maintainAuthorizationMethod.indexOf(
                "recoverPendingFormalStart(runtime, generationReceipt)"));
        require(maintainAuthorizationMethod.contains(
                "DualMachineFormalUsageStateMachine.State.STOPPING"));
        require(maintainAuthorizationMethod.contains(
                "pending_start_cancellation_confirmation"));
        require(maintainAuthorizationMethod.contains(
                "retryFormalUsageStopIfDue("));
        require(maintainAuthorizationMethod.indexOf(
                "retryFormalUsageStopIfDue(")
                < maintainAuthorizationMethod.indexOf(
                "recoverPendingFormalStart(runtime, generationReceipt)"));
        int automaticStartGateIndex = maintainAuthorizationMethod.indexOf(
                "if (!automaticStartAllowed.get())");
        int automaticStartAttemptIndex = maintainAuthorizationMethod.indexOf(
                "attemptAutomaticFormalUsageStart(runtime, generationReceipt)");
        require(automaticStartGateIndex >= 0);
        require(maintainAuthorizationMethod.indexOf(
                "automaticUsageGuard.isAutomaticStartAllowed()")
                < automaticStartGateIndex);
        require(automaticStartAttemptIndex > automaticStartGateIndex);
        require(maintainAuthorizationMethod.contains(
                "maintainAutomaticUsageRearm(runtime, generationReceipt);"));
        require(maintainAuthorizationMethod.contains(
                "requestFormalUsageStop(\"formal_permit_closed\")"));
        int closedStateSnapshotIndex = maintainAuthorizationMethod.indexOf(
                "runtime.snapshot();");
        int closedStateLockReconcileIndex = maintainAuthorizationMethod.indexOf(
                "reconcileRuntimeLocksAfterDataPlaneClose(");
        require(closedStateSnapshotIndex >= 0);
        require(closedStateLockReconcileIndex > closedStateSnapshotIndex);
        int stagedGapGuardIndex = maintainAuthorizationMethod.indexOf(
                ".DataPlanePermitState.STAGED_WAITING");
        int clearFormalBindingIndex = maintainAuthorizationMethod.indexOf(
                "clearFormalSessionBinding();");
        int formalPermitStopIndex = maintainAuthorizationMethod.indexOf(
                "requestFormalUsageStop(\"formal_permit_closed\")");
        require(stagedGapGuardIndex >= 0);
        require(clearFormalBindingIndex > stagedGapGuardIndex);
        require(formalPermitStopIndex > stagedGapGuardIndex);
        require(maintainAuthorizationMethod.contains(
                "runtime.enforceDataPlanePermitState()"));
        require(maintainAuthorizationMethod.contains(
                "automaticUsageGuard.markProgressRenewed();"));
        require(!source.contains("automaticNoProgressSinceElapsedMillis"));
        require(!authorizationRuntime.contains(
                "isAwaitingStagedLeaseActivation"));
        String automaticStartMethod = methodSlice(
                source,
                "private void attemptAutomaticFormalUsageStart(",
                "private void stopAutomaticallyAfterSustainedInferenceStall(");
        require(automaticStartMethod.contains(
                "runtime.startFormalUsage(generationReceipt);"));
        require(automaticStartMethod.contains(
                "now < nextFormalStartRetryElapsedMillis.get()"));
        require(automaticStartMethod.indexOf(
                "now < nextFormalStartRetryElapsedMillis.get()")
                < automaticStartMethod.indexOf(
                "runtime.startFormalUsage(generationReceipt);"));
        require(automaticStartMethod.contains(
                "formalStartRetryPolicy.recordRejection()"));
        require(automaticStartMethod.contains("safe_error_code="));
        require(automaticStartMethod.contains("retry_delay_ms="));
        require(automaticStartMethod.contains(
                "HostVideoPresenceProbe.HostVideoNotObservedException"));
        int cancelledPreflightCatchIndex = automaticStartMethod.indexOf(
                "HostVideoPresenceProbe.HostVideoProbeCancelledException");
        int absentPreflightCatchIndex = automaticStartMethod.indexOf(
                "HostVideoPresenceProbe.HostVideoNotObservedException");
        require(cancelledPreflightCatchIndex >= 0);
        require(absentPreflightCatchIndex > cancelledPreflightCatchIndex);
        require(automaticStartMethod.contains(
                "reason=local_preflight_cancelled"));
        require(automaticStartMethod.contains(
                "automaticHostWaitLogPolicy.shouldWriteFailure("));
        require(automaticStartMethod.contains(
                "log_policy=state_change_or_heartbeat"));
        require(automaticStartMethod.contains(
                "automaticHostWaitLogPolicy.clearFailure()"));
        String recordHostVideoObservationMethod = methodSlice(
                source,
                "private void recordHostVideoObservation(",
                "private void recordLatestHostFrameFromNative()");
        require(recordHostVideoObservationMethod.contains(
                "automaticHostWaitLogPolicy.clearFailure();"));
        require(automaticStartMethod.contains("billing_started=false"));
        require(automaticStartMethod.contains(
                "runtime.retryPendingFormalStart(generationReceipt);"));
        require(automaticStartMethod.contains(
                "StartCancelledException cancelled"));
        require(automaticStartMethod.indexOf(
                "if (automaticFormalStopQueued.get()) return;")
                < automaticStartMethod.indexOf(
                "runtime.retryPendingFormalStart(generationReceipt);"));
        require(automaticStartMethod.contains(
                "cancelUnbilledStartReservationIfAborted("));
        require(automaticStartMethod.contains(
                "settleTerminalFormalStartFailure("));
        require(automaticStartMethod.contains(
                "fatal_start_transport_failure"));
        require(automaticStartMethod.contains(
                "fatal_exact_retry_transport_failure"));
        require(automaticStartMethod.contains(
                "exact_retry_security_failure"));
        require(automaticStartMethod.contains(
                "exact_retry_runtime_failure"));
        require(automaticStartMethod.contains(
                "start_security_failure"));
        require(automaticStartMethod.contains(
                "start_runtime_failure"));
        require(automaticStartMethod.contains(
                ".AdmissionSupersededException superseded"));
        require(automaticStartMethod.contains(
                "recordSupersededFormalStartAttempt(\"fresh_start\")"));
        require(automaticStartMethod.contains(
                "recordSupersededFormalStartAttempt(\"exact_retry\")"));
        require(automaticStartMethod.indexOf(
                "fatal_exact_retry_transport_failure")
                < automaticStartMethod.indexOf(
                "exact_retry_terminal_failure"));
        String terminalStartFailureMethod = methodSlice(
                source,
                "private void settleTerminalFormalStartFailure(",
                "private void blockPotentiallyBilledStartIfAborted(");
        require(terminalStartFailureMethod.contains(
                ".GenerationBoundStartFailure"));
        require(terminalStartFailureMethod.contains(
                "TerminalStartFailureHandle"));
        require(terminalStartFailureMethod.contains("handle.settle();"));
        require(terminalStartFailureMethod.contains(
                "settleAutomaticUsageReservation("));
        require(terminalStartFailureMethod.contains(
                "action=no_cross_generation_cleanup"));
        require(!terminalStartFailureMethod.contains(
                "requestFormalUsageStop("));
        require(!terminalStartFailureMethod.contains(
                "authorizationRuntime"));
        String supersededStartMethod = methodSlice(
                source,
                "private void recordSupersededFormalStartAttempt(",
                "private void blockPotentiallyBilledStartIfAborted(");
        require(supersededStartMethod.contains(
                "action=no_cross_generation_cleanup"));
        require(!supersededStartMethod.contains(
                "requestFormalUsageStop("));
        String inferenceStallMethod = methodSlice(
                source,
                "private void stopAutomaticallyAfterSustainedInferenceStall(",
                "private boolean recoverPendingFormalStart(");
        require(inferenceStallMethod.contains(
                "automaticUsageGuard.shouldStopAfterNoProgress("));
        require(inferenceStallMethod.contains(
                "progress_was_previously_renewed=true"));
        String recoverPendingStartMethod = methodSlice(
                source,
                "private boolean recoverPendingFormalStart(",
                "private boolean deferRenewalUntilWindow(");
        require(recoverPendingStartMethod.contains(
                "runtime.retryPendingFormalStart(generationReceipt)"));
        require(recoverPendingStartMethod.contains(
                "AUTHORIZATION_START_RETRY_BACKOFF_MILLIS"));
        require(recoverPendingStartMethod.contains("same_request=true"));
        require(recoverPendingStartMethod.contains(
                "if (automaticFormalStopQueued.get())"));
        require(recoverPendingStartMethod.contains("handled.set(true);"));
        require(recoverPendingStartMethod.contains(
                "fatal_pending_start_transport_failure"));
        require(recoverPendingStartMethod.contains(
                "settleTerminalFormalStartFailure("));
        require(recoverPendingStartMethod.contains(
                "pending_start_security_failure"));
        require(recoverPendingStartMethod.contains(
                "pending_start_runtime_failure"));
        require(recoverPendingStartMethod.contains(
                "recordSupersededFormalStartAttempt(\"pending_recovery\")"));
        require(recoverPendingStartMethod.indexOf(
                "fatal_pending_start_transport_failure")
                < recoverPendingStartMethod.indexOf(
                "pending_start_io_requires_cancellation"));
        require(!source.contains(
                "VisionForge.Android.LocalAuthorizationHost.v1"));
        require(!source.contains(
                "localAndroidAuthorizationAttachment("));
        require(!source.contains("androidOnlyChannelBinding("));
        String formalBoundary = methodSlice(
                source,
                "private final class AuthenticatedHostFormalRuntimeBoundary",
                "private void scheduleAuthorizationMaintenance()");
        require(formalBoundary.contains(
                "requiredAuthenticatedHostChannelBinding()"));
        int wirelessLockBeforeDiscoveryIndex = formalBoundary.indexOf(
                "acquireRuntimeLocks(transportCandidate);");
        int awaitTransportIndex = formalBoundary.indexOf(
                "awaitRequiredTransportEndpoint(\n"
                        + "                    cancellationRequested);");
        require(wirelessLockBeforeDiscoveryIndex >= 0);
        require(awaitTransportIndex > wirelessLockBeforeDiscoveryIndex);
        String awaitTransportMethod = methodSlice(
                source,
                "private MobileTransportEndpoint awaitRequiredTransportEndpoint(",
                "private void writeRuntimeHealth()");
        require(awaitTransportMethod.contains(
                "requireFormalStartNotCancelled(cancellationRequested);"));
        require(awaitTransportMethod.indexOf(
                "requireFormalStartNotCancelled(cancellationRequested);")
                < awaitTransportMethod.indexOf("SystemClock.sleep(50L);"));
        int hostVideoProbeIndex = formalBoundary.indexOf(
                "awaitFormalPreparationHostVideo(");
        int qnnPrepareIndex = formalBoundary.indexOf(
                "prepareModelDataPlaneClosed(");
        int pipelineStartingStatusIndex = formalBoundary.indexOf(
                "updateStatus(MobileRuntimePhase.STARTING,");
        int preparationAttemptedIndex = formalBoundary.indexOf(
                "pipelinePreparationAttempted = true;");
        int channelBindingIndex = formalBoundary.indexOf(
                "formalSessionChannelBinding = channelBinding;");
        require(hostVideoProbeIndex >= 0);
        require(pipelineStartingStatusIndex > hostVideoProbeIndex);
        require(qnnPrepareIndex > hostVideoProbeIndex);
        require(preparationAttemptedIndex > pipelineStartingStatusIndex);
        require(qnnPrepareIndex > preparationAttemptedIndex);
        require(channelBindingIndex > qnnPrepareIndex);
        require(formalBoundary.contains(
                "abandonFormalPreparation(\n"
                        + "                        \"formal_usage_prepare_failed\",\n"
                        + "                        pipelinePreparationAttempted);"));
        String abandonFormalPreparationMethod = methodSlice(
                source,
                "private void abandonFormalPreparation(",
                "private void installActiveRuntimePermitLocked(");
        require(abandonFormalPreparationMethod.contains(
                "if (pipelinePreparationAttempted) stopPreparedPipeline();"));
        require(!abandonFormalPreparationMethod.contains(
                "\n        stopPreparedPipeline();"));
        require(countOccurrences(
                formalBoundary,
                "hostVideoPresenceProbe.awaitValidHostVideo(") >= 1);
        require(formalBoundary.contains(
                "verifyFreshHostVideoBeforePotentialDebit("));
        require(formalBoundary.contains(
                "BooleanSupplier cancellationRequested"));
        require(formalBoundary.contains(
                "requireFormalStartNotCancelled(cancellationRequested);"));
        require(formalBoundary.contains(
                "ensureAutomaticFormalStartReserved(\n"
                        + "                        expectedStartRequestId,\n"
                        + "                        expectedChannelBindingSha256);"));
        require(formalBoundary.contains("preparedBinding.equals("));
        require(formalBoundary.contains("permit.channelBindingSha256"));
        require(formalBoundary.contains(
                "preparedEndpoint.hasSameDataPlaneRoute(endpoint)"));
        require(formalBoundary.contains("installActiveRuntimePermitLocked("));
        require(formalBoundary.contains("stageRuntimePermitLocked("));
        require(formalBoundary.contains("enforceRuntimePermitWindow()"));
        String formalOpenDataPlaneMethod = methodSlice(
                formalBoundary,
                "public void openDataPlane(",
                "public void stageFutureLease(");
        int runtimeLockAcquireIndex = formalOpenDataPlaneMethod.indexOf(
                "acquireRuntimeLocks(endpoint);");
        int preparedDataPlaneOpenIndex = formalOpenDataPlaneMethod.indexOf(
                "pipeline.openPreparedDataPlane(");
        require(runtimeLockAcquireIndex >= 0);
        require(preparedDataPlaneOpenIndex > runtimeLockAcquireIndex);
        int automaticSessionOpenIndex = formalOpenDataPlaneMethod.indexOf(
                "markAutomaticFormalSessionOpened(");
        require(automaticSessionOpenIndex >= 0);
        require(formalOpenDataPlaneMethod.indexOf(
                "MobileTransportEndpoint endpoint")
                > automaticSessionOpenIndex);
        require(formalOpenDataPlaneMethod.indexOf(
                "installActiveRuntimePermitLocked(")
                > automaticSessionOpenIndex);
        require(preparedDataPlaneOpenIndex > automaticSessionOpenIndex);
        require(formalOpenDataPlaneMethod.indexOf(
                "endpoint, activeModel", preparedDataPlaneOpenIndex)
                > preparedDataPlaneOpenIndex);
        int hotReloadPermitContinuationIndex =
                formalOpenDataPlaneMethod.indexOf(
                        "if (gameModelHotReloadInProgress");
        int normalPermitContinuationIndex =
                formalOpenDataPlaneMethod.indexOf(
                        "} else if (pipelineDesired",
                        hotReloadPermitContinuationIndex);
        require(hotReloadPermitContinuationIndex
                > formalOpenDataPlaneMethod.indexOf(
                "installActiveRuntimePermitLocked("));
        require(normalPermitContinuationIndex
                > hotReloadPermitContinuationIndex);
        String hotReloadPermitContinuation =
                formalOpenDataPlaneMethod.substring(
                        hotReloadPermitContinuationIndex,
                        normalPermitContinuationIndex);
        require(hotReloadPermitContinuation.contains(
                "hotReloadOwnsReopen = true;"));
        require(!hotReloadPermitContinuation.contains(
                "pipelineSessionGeneration.incrementAndGet()"));
        require(!hotReloadPermitContinuation.contains(
                "pipeline.openPreparedDataPlane("));
        require(!hotReloadPermitContinuation.contains(
                "updateStatus(MobileRuntimePhase.RUNNING"));
        require(!hotReloadPermitContinuation.contains(
                "runtimeStatus.phase"));
        require(formalOpenDataPlaneMethod.contains(
                "dual_machine_formal_permit_continued"));
        require(formalOpenDataPlaneMethod.contains(
                "data_plane_open="));
        require(source.contains("permit.notBeforeMonotonicNanos"));
        require(source.contains("permit.expiresAtMonotonicNanos"));
        require(source.contains("runtimePermitDeadlines.scheduleAt("));
        require(source.contains("enforceRuntimePermitDeadline("));
        require(source.contains("runtimePermitDeadlines::close"));
        String stagePermitMethod = methodSlice(
                source,
                "private void stageRuntimePermitLocked(",
                "private boolean runtimePermitIsActiveLocked(");
        require(stagePermitMethod.contains(
                "permit.notBeforeMonotonicNanos"));
        require(stagePermitMethod.contains(
                "scheduleRuntimePermitDeadlineLocked("));
        String enforcePermitWindowMethod = methodSlice(
                source,
                "enforceRuntimePermitWindow()",
                "private void enforceRuntimePermitDeadline(");
        int futurePermitIndex = enforcePermitWindowMethod.indexOf(
                "runtimePermitIsFutureLocked(");
        int stagedWaitingIndex = enforcePermitWindowMethod.indexOf(
                ".DataPlanePermitState.STAGED_WAITING");
        int fullCloseIndex = enforcePermitWindowMethod.indexOf(
                "closeFormalDataPlaneLocally(");
        require(futurePermitIndex >= 0);
        require(stagedWaitingIndex > futurePermitIndex);
        require(fullCloseIndex > stagedWaitingIndex);
        require(!enforcePermitWindowMethod.contains(
                "invalidateRuntimePermitWindowLocked()"));
        String permitDeadlineMethod = methodSlice(
                source,
                "private void enforceRuntimePermitDeadline(",
                "private Throwable closeRuntimeDataPlaneForPermitBoundaryLocked(");
        require(permitDeadlineMethod.contains(
                "runtimePermitIsActiveLocked(nowNanos, true)"));
        require(permitDeadlineMethod.contains(
                "stagedRuntimePermit.notBeforeMonotonicNanos"));
        require(permitDeadlineMethod.contains(
                "closeRuntimeDataPlaneForPermitBoundaryLocked("));
        String permitBoundaryCloseMethod = methodSlice(
                source,
                "private Throwable closeRuntimeDataPlaneForPermitBoundaryLocked(",
                "private void writeRuntimePermitExpiredEvent(");
        int deadlineDataPlaneCloseIndex = permitBoundaryCloseMethod.indexOf(
                "pipeline.closeDataPlane();");
        int deadlineProbeCancelIndex = permitBoundaryCloseMethod.indexOf(
                "cancelReceiverLivenessProbe();");
        int deadlineRuntimeLockReconcileIndex = permitBoundaryCloseMethod.indexOf(
                "reconcileRuntimeLocksAfterDataPlaneClose(reason);");
        int deadlineReadyStatusIndex = permitBoundaryCloseMethod.indexOf(
                "updateStatus(");
        require(deadlineDataPlaneCloseIndex >= 0);
        require(deadlineProbeCancelIndex > deadlineDataPlaneCloseIndex);
        require(deadlineRuntimeLockReconcileIndex > deadlineProbeCancelIndex);
        require(deadlineReadyStatusIndex > deadlineRuntimeLockReconcileIndex);
        require(permitBoundaryCloseMethod.contains(
                "boolean preservePreparedModelCommit ="));
        require(permitBoundaryCloseMethod.contains(
                "gameModelHotReloadInProgress"));
        require(permitBoundaryCloseMethod.contains(
                "if (!preservePreparedModelCommit)"));
        require(permitBoundaryCloseMethod.indexOf(
                "pipelineSessionGeneration.incrementAndGet()")
                > permitBoundaryCloseMethod.indexOf(
                "if (!preservePreparedModelCommit)"));
        require(formalCoordinator.contains("enum DataPlanePermitState"));
        require(formalCoordinator.contains(
                "enforceAndGetDataPlanePermitState()"));
        require(countOccurrences(
                formalCoordinator,
                "verifyFreshHostVideoBeforePotentialDebit(") >= 3);
        require(countOccurrences(
                formalCoordinator,
                "immediateStopRequested::get") >= 3);
        require(formalCoordinator.contains("runtimeTransitionLock"));
        require(formalCoordinator.contains("finishRuntimeStop("));
        String reserveGuardMethod = methodSlice(
                source,
                "private void ensureAutomaticFormalStartReserved(",
                "private void markAutomaticFormalSessionOpened(");
        int reserveGuardIndex = reserveGuardMethod.indexOf(
                "automaticUsageGuard.reserveFormalStart(\n"
                        + "                expectedStartRequestId,\n"
                        + "                expectedChannelBindingSha256);");
        int persistGuardIndex = reserveGuardMethod.indexOf(
                "persistAutomaticUsageBlock(true);", reserveGuardIndex);
        require(reserveGuardIndex >= 0);
        require(persistGuardIndex > reserveGuardIndex);
        String openGuardMethod = methodSlice(
                source,
                "private void markAutomaticFormalSessionOpened(",
                "private void cancelUnbilledStartReservationIfAborted(");
        int openStateIndex = openGuardMethod.indexOf(
                "automaticUsageGuard.markFormalSessionOpened(");
        int openPersistIndex = openGuardMethod.indexOf(
                "persistAutomaticUsageBlock(true);", openStateIndex);
        require(openStateIndex >= 0);
        require(openPersistIndex > openStateIndex);
        String closeGuardMethod = methodSlice(
                source,
                "private void closeOpenedAutomaticSessionForBoundary(",
                "private void settleAutomaticUsageReservation(");
        int closeStateIndex = closeGuardMethod.indexOf(
                "automaticUsageGuard.markFormalSessionClosed(");
        int closePersistIndex = closeGuardMethod.indexOf(
                "persistClosedAutomaticUsageGeneration(reason);",
                closeStateIndex);
        require(closeStateIndex >= 0);
        require(closePersistIndex > closeStateIndex);
        String closedPersistenceMethod = methodSlice(
                source,
                "private void persistClosedAutomaticUsageGeneration(",
                "private void recordHostVideoObservation(");
        require(closedPersistenceMethod.contains(
                "persistAutomaticUsageBlock(true);"));
        String checkpointMethod = methodSlice(
                source,
                "private void checkpointAutomaticUsageGuardIfDue(",
                "private void persistAutomaticUsageBlock(");
        int checkpointDecisionIndex = checkpointMethod.indexOf(
                "automaticUsageCheckpointPolicy.evaluate(");
        int checkpointPersistIndex = checkpointMethod.indexOf(
                "persistAutomaticUsageBlock(true);", checkpointDecisionIndex);
        int checkpointRecordedIndex = checkpointMethod.indexOf(
                "automaticUsageCheckpointPolicy.recordCheckpointSucceeded(",
                checkpointPersistIndex);
        require(checkpointPolicy.contains(
                "CHECKPOINT_INTERVAL_MILLIS = 30_000L"));
        require(checkpointPolicy.contains(
                "FRAME_SEQUENCE_REGRESSED"));
        require(checkpointDecisionIndex >= 0);
        require(checkpointPersistIndex > checkpointDecisionIndex);
        require(checkpointRecordedIndex > checkpointPersistIndex);
        require(!checkpointMethod.contains(
                "AUTHORIZATION_RENEWAL_MIN_INTERVAL_MILLIS"));
        String persistGuardMethod = methodSlice(
                source,
                "private void persistAutomaticUsageBlock(",
                "private void clearPersistedAutomaticUsageBlock()");
        require(persistGuardMethod.contains(
                ".putBoolean(AUTOMATIC_USAGE_GUARD_BLOCKED, blocked)"));
        require(persistGuardMethod.contains(
                "AUTOMATIC_USAGE_GUARD_LAST_FRAME,"));
        require(persistGuardMethod.contains(
                "AUTOMATIC_USAGE_GUARD_RESUMABLE_BOUNDARY,"));
        require(persistGuardMethod.contains(".commit();"));
        require(persistGuardMethod.contains(
                "automaticUsageCheckpointPolicy.recordPersistence("));
        require(source.contains("automaticUsageGuard.restoreBlocked("));
        require(source.contains(
                "automaticUsageCheckpointPolicy.restorePersisted("));
        String rearmMethod = methodSlice(
                source,
                "private void maintainAutomaticUsageRearm(",
                "private void attemptAutomaticFormalUsageStart(");
        int hostAbsenceIndex = rearmMethod.indexOf(
                "automaticUsageGuard.recordHostAbsent(");
        int newStreamIndex = rearmMethod.indexOf(".NEW_STREAM_REARMED");
        int clearBlockedIndex = rearmMethod.indexOf(
                "clearPersistedAutomaticUsageBlock();");
        require(rearmMethod.contains(
                "hostVideoPresenceProbe.pollValidHostVideo("));
        require(rearmMethod.contains("AUTOMATIC_REARM_HOST_ABSENCE_MILLIS"));
        require(hostAbsenceIndex >= 0);
        require(newStreamIndex > hostAbsenceIndex);
        require(clearBlockedIndex > newStreamIndex);
        require(source.contains(".RESTART_CANDIDATE_RECORDED"));
        String quietHostVideoProbeMethod = methodSlice(
                hostVideoPresenceProbeSource,
                "HostVideoObservation pollValidHostVideo(",
                "private HostVideoObservation receiveValidHostVideo(");
        require(Pattern.compile(
                "endpoint,\\s*port,\\s*timeoutMillis,\\s*false,\\s*2")
                .matcher(quietHostVideoProbeMethod).find());
        require(!quietHostVideoProbeMethod.contains(
                "catch (HostVideoProbeCancelledException"));
        require(rearmMethod.contains(
                "HostVideoPresenceProbe.HostVideoProbeCancelledException"));
        require(rearmMethod.indexOf(
                "HostVideoPresenceProbe.HostVideoProbeCancelledException")
                < rearmMethod.indexOf("catch (IOException failure)"));
        String billableHostVideoProbeMethod = methodSlice(
                hostVideoPresenceProbeSource,
                "HostVideoObservation awaitValidHostVideo(",
                "/**\n     * Performs one quiet non-billing observation");
        require(Pattern.compile(
                "endpoint,\\s*port,\\s*timeoutMillis,\\s*true,\\s*2")
                .matcher(billableHostVideoProbeMethod).find());
        require(hostVideoPresenceProbeSource.contains(
                "failureLogPolicy.shouldWriteFailure("));
        require(hostVideoPresenceProbeSource.contains(
                "failureLogPolicy.clearFailure();"));
        require(hostVideoPresenceProbeSource.contains(
                "HostVideoProbeCancelledException"));
        require(hostVideoPresenceProbeSource.contains(
                "cancellationObserved(cancellationRequested, generation)"));
        require(hostVideoPresenceProbeSource.contains(
                "HostVideoPreflightVerifier"));
        require(hostVideoPresenceProbeSource.contains(
                "verifier.offer("));
        require(hostVideoPresenceProbeSource.contains(
                "proof.confirmedCompleteAccessUnits()"));
        require(!hostVideoPresenceProbeSource.contains(
                "previousFrameStart"));
        require(!hostVideoPresenceProbeSource.contains(
                "VideoWireProtocol.isForwardFrameStart("));
        require(!hostVideoPresenceProbeSource.contains("VFRG"));
        require(!hostVideoPresenceProbeSource.contains("VFRR"));
        require(source.contains("WifiManager.WIFI_MODE_FULL_HIGH_PERF"));
        require(source.contains("wifiLock.setReferenceCounted(false);"));
        require(activity.contains(
                "WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON"));
        require(activity.contains(
                "runtimeBinder.setActivityForeground(activityStarted);"));
        require(activity.contains(
                "runtimeBinder.setActivityForeground(true);"));
        String activityStartMethod = methodSlice(
                activity,
                "protected void onStart()",
                "protected void onResume()");
        require(activityStartMethod.contains("activityStarted = true;"));
        String activityPauseMethod = methodSlice(
                activity,
                "protected void onPause()",
                "protected void onStop()");
        String activityStopMethod = methodSlice(
                activity,
                "protected void onStop()",
                "protected void onDestroy()");
        require(!activityPauseMethod.contains(
                "runtimeBinder.setActivityForeground(false);"));
        int configurationGuardIndex = activityStopMethod.indexOf(
                "if (!isChangingConfigurations() && runtimeBinder != null)");
        int foregroundFalseIndex = activityStopMethod.indexOf(
                "runtimeBinder.setActivityForeground(false);");
        int binderDetachIndex = activityStopMethod.indexOf(
                "runtimeBinder = null;");
        require(configurationGuardIndex >= 0);
        require(foregroundFalseIndex > configurationGuardIndex);
        require(activityStopMethod.indexOf("activityStarted = false;")
                > foregroundFalseIndex);
        require(binderDetachIndex > foregroundFalseIndex);
        require(source.contains("power.isInteractive()"));
        String displayGuardMethod = methodSlice(
                source,
                "private boolean isWirelessForegroundDisplayReady(",
                "private void requireWirelessForegroundDisplay(");
        require(displayGuardMethod.contains("endpoint.isCat6()"));
        require(displayGuardMethod.contains("power.isInteractive()"));
        require(displayGuardMethod.contains("activityForeground.get()"));
        String preDebitMethod = methodSlice(
                source,
                "public void verifyFreshHostVideoBeforePotentialDebit(",
                "public void openDataPlane(");
        int preDebitDisplayIndex = preDebitMethod.lastIndexOf(
                "requireWirelessForegroundDisplay(expectedEndpoint);");
        int preDebitCancellationIndex = preDebitMethod.lastIndexOf(
                "requireFormalStartNotCancelled(cancellationRequested);");
        int preDebitReserveIndex = preDebitMethod.indexOf(
                "ensureAutomaticFormalStartReserved(\n"
                        + "                        expectedStartRequestId,\n"
                        + "                        expectedChannelBindingSha256);");
        require(preDebitDisplayIndex >= 0);
        require(preDebitCancellationIndex >= 0);
        require(preDebitCancellationIndex < preDebitReserveIndex);
        require(preDebitReserveIndex > preDebitDisplayIndex);
        String openDataPlaneMethod = methodSlice(
                source,
                "public void openDataPlane(",
                "public void closeDataPlane()");
        require(openDataPlaneMethod.indexOf(
                "markAutomaticFormalSessionOpened(")
                < openDataPlaneMethod.indexOf(
                "if (!isWirelessForegroundDisplayReady(endpoint))"));
        String foregroundAutomaticStartMethod = methodSlice(
                source,
                "private void attemptAutomaticFormalUsageStart(",
                "private void stopAutomaticallyAfterSustainedInferenceStall(");
        require(foregroundAutomaticStartMethod.indexOf(
                "if (!isWirelessForegroundDisplayReady(transportCandidate))")
                < foregroundAutomaticStartMethod.indexOf(
                "runtime.startFormalUsage(generationReceipt);"));
        String wirelessDisplayWaitMethod = methodSlice(
                source,
                "private void reportWirelessDisplayWait(",
                "private void updateActivityForeground(");
        require(wirelessDisplayWaitMethod.contains(
                "boolean displayInteractive = isDisplayInteractive();"));
        require(wirelessDisplayWaitMethod.contains(
                "snapshot != null && snapshot.billingStarted"));
        require(wirelessDisplayWaitMethod.contains(
                "snapshot != null && snapshot.permitsDataPlane"));
        require(wirelessDisplayWaitMethod.contains(
                "formalDataPlanePermitOpen.get() && pipelineStarted"));
        require(!wirelessDisplayWaitMethod.contains(
                "display_interactive=false"));
        require(!wirelessDisplayWaitMethod.contains(
                "billing_started=false data_plane_open=false"));
        String maintenanceMethod = methodSlice(
                source,
                "private void maintainAuthorizationRuntime(",
                "private void reconcileAutomaticUsageGuardWithIdleRuntime(");
        require(maintenanceMethod.contains("requestFormalUsageStop("));
        require(maintenanceMethod.contains(
                "\"wireless_foreground_display_unavailable\""));
        String activityForegroundMethod = methodSlice(
                source,
                "private void updateActivityForeground(",
                "private boolean updateCat6ReadyAgent(");
        int activityExecutorIndex = activityForegroundMethod.indexOf(
                "authorizationExecutor.execute(");
        int activityReceiptIndex = activityForegroundMethod.indexOf(
                "captureCurrentGenerationReceipt()");
        int activityCommitIndex = activityForegroundMethod.indexOf(
                "commitFormalGeneration(");
        int activityEndpointReadIndex = activityForegroundMethod.indexOf(
                "MobileTransportEndpoint endpoint =");
        int activityRouteReadIndex = activityForegroundMethod.indexOf(
                "transportCatalog.selected()");
        require(activityExecutorIndex >= 0);
        require(activityReceiptIndex > activityExecutorIndex);
        require(activityCommitIndex > activityReceiptIndex);
        require(activityEndpointReadIndex > activityCommitIndex);
        require(activityRouteReadIndex > activityCommitIndex);
        require(activityForegroundMethod.contains(
                "requestFormalUsageStop(\n"
                        + "                                        \"wireless_activity_not_foreground\")"));
        require(source.contains("wifi_lock_required="));
        require(source.contains("wifi_lock_held="));
        String refreshRuntimeLocksMethod = methodSlice(
                source,
                "private synchronized void refreshRuntimeLocks()",
                "private boolean shouldRetainAutomaticRuntimeLocks()");
        require(refreshRuntimeLocksMethod.contains(
                "acquireRuntimeLocks(transportCatalog.selected());"));
        int retainDecisionIndex = refreshRuntimeLocksMethod.indexOf(
                "if (!shouldRetainAutomaticRuntimeLocks()");
        require(retainDecisionIndex >= 0);
        require(refreshRuntimeLocksMethod.indexOf(
                "releaseRuntimeLocks();") > retainDecisionIndex);
        String retainLocksMethod = methodSlice(
                source,
                "private boolean shouldRetainAutomaticRuntimeLocks()",
                "private void reconcileRuntimeLocksAfterDataPlaneClose(");
        require(retainLocksMethod.contains("destroying"));
        require(retainLocksMethod.contains("authorizationSecurityFatal"));
        require(retainLocksMethod.contains(".State.EXHAUSTED"));
        require(retainLocksMethod.contains(".State.REVOKED"));
        require(retainLocksMethod.contains(".State.UNACTIVATED"));
        String onDestroyMethod = methodSlice(
                source,
                "public void onDestroy()",
                "private void initialiseAuthorizationRuntimeAsync(");
        require(onDestroyMethod.contains(
                "MobileServiceDestroyCleanup cleanup ="));
        require(onDestroyMethod.contains("finally {"));
        require(onDestroyMethod.indexOf("super.onDestroy();")
                > onDestroyMethod.indexOf("finally {"));
        require(countOccurrences(onDestroyMethod, "super.onDestroy();") == 1);
        int beginDestroyIndex = onDestroyMethod.indexOf(
                "beginServiceDestroy();");
        int closeAuthorizationResourcesIndex = onDestroyMethod.indexOf(
                "closeControlAndAuthorizationResources(cleanup);");
        int closeTransportResourcesIndex = onDestroyMethod.indexOf(
                "closeTransportResources(cleanup);");
        int closePipelineResourcesIndex = onDestroyMethod.indexOf(
                "closePipelineResources(cleanup);");
        int publishDestroyOutcomeIndex = onDestroyMethod.indexOf(
                "publishDestroyOutcome(cleanup);");
        require(beginDestroyIndex >= 0);
        require(closeAuthorizationResourcesIndex > beginDestroyIndex);
        require(closeTransportResourcesIndex > closeAuthorizationResourcesIndex);
        require(closePipelineResourcesIndex > closeTransportResourcesIndex);
        require(publishDestroyOutcomeIndex > closePipelineResourcesIndex);

        String beginDestroyMethod = methodSlice(
                source,
                "private void beginServiceDestroy()",
                "private void closeControlAndAuthorizationResources(");
        require(beginDestroyMethod.contains(
                "pipelineSessionGeneration.incrementAndGet();"));
        require(beginDestroyMethod.contains("destroying = true;"));
        require(beginDestroyMethod.contains(
                "authorizationInitializationGeneration++;"));
        String closeAuthorizationResourcesMethod = methodSlice(
                source,
                "private void closeControlAndAuthorizationResources(",
                "private void closeTransportResources(");
        require(countOccurrences(
                closeAuthorizationResourcesMethod, "cleanup.run(") == 7);
        require(closeAuthorizationResourcesMethod.contains(
                "requestFormalUsageStop(\"service_destroyed\")"));
        require(closeAuthorizationResourcesMethod.contains(
                "authorizationExecutor, \"authorization\""));
        require(closeAuthorizationResourcesMethod.contains(
                "startCancellationExecutor, \"start_cancellation\""));
        require(closeAuthorizationResourcesMethod.contains(
                "this::closePublishedAuthorizationRuntime"));
        int destroyFormalStopIndex = closeAuthorizationResourcesMethod.indexOf(
                ".FORMAL_USAGE_STOP");
        int destroyAuthorizationShutdownIndex = closeAuthorizationResourcesMethod.indexOf(
                ".AUTHORIZATION_EXECUTOR_SHUTDOWN");
        int destroyCancellationShutdownIndex = closeAuthorizationResourcesMethod.indexOf(
                ".START_CANCELLATION_EXECUTOR_SHUTDOWN");
        int destroyAuthorizationCloseIndex = closeAuthorizationResourcesMethod.indexOf(
                ".AUTHORIZATION_RUNTIME_CLOSE");
        require(destroyFormalStopIndex >= 0);
        require(destroyAuthorizationShutdownIndex > destroyFormalStopIndex);
        require(destroyCancellationShutdownIndex
                > destroyAuthorizationShutdownIndex);
        require(destroyAuthorizationCloseIndex
                > destroyCancellationShutdownIndex);
        String closeTransportResourcesMethod = methodSlice(
                source,
                "private void closeTransportResources(",
                "private void closePipelineResources(");
        String closePipelineResourcesMethod = methodSlice(
                source,
                "private void closePipelineResources(",
                "private void publishDestroyOutcome(");
        String publishDestroyOutcomeMethod = methodSlice(
                source,
                "private void publishDestroyOutcome(",
                "private void reportDestroyCleanupFailures(");
        require(countOccurrences(
                closeTransportResourcesMethod, "cleanup.run(") == 7);
        require(countOccurrences(
                closePipelineResourcesMethod, "cleanup.run(") == 5);
        require(countOccurrences(
                publishDestroyOutcomeMethod, "cleanup.run(") == 1);
        require(closeTransportResourcesMethod.contains(
                "if (ethernetRecovery != null) ethernetRecovery.destroy();"));
        require(closePipelineResourcesMethod.contains(
                "if (cat6ReadyLifecycle != null) cat6ReadyLifecycle.stop();"));
        require(closePipelineResourcesMethod.contains(
                "this::releaseRuntimeLocks"));
        require(closePipelineResourcesMethod.indexOf(
                "cat6ReadyLifecycle.stop();")
                < closePipelineResourcesMethod.indexOf(
                "this::releaseRuntimeLocks"));
        require(publishDestroyOutcomeMethod.contains(
                "int cleanupFailureCount = cleanup.failureCount();"));
        require(publishDestroyOutcomeMethod.contains(
                "reportDestroyCleanupFailures(cleanup);"));
        require(publishDestroyOutcomeMethod.contains(
                "\"resources_released=\""));
        require(publishDestroyOutcomeMethod.contains(
                "\" cleanup_failures=\""));
        require(!publishDestroyOutcomeMethod.contains(
                "\"resources_released=true\""));
        String closeAuthorizationRuntimeMethod = methodSlice(
                source,
                "private void closePublishedAuthorizationRuntime()",
                "private void refreshAuthorizationStatusAfterRestore(");
        int detachRuntimeIndex = closeAuthorizationRuntimeMethod.indexOf(
                "authorizationRuntime = null;");
        int detachDeadlinesIndex = closeAuthorizationRuntimeMethod.indexOf(
                "authorizationDeadlines = null;");
        int closeRuntimeIndex = closeAuthorizationRuntimeMethod.indexOf(
                "runtime.close();");
        int closeDeadlinesIndex = closeAuthorizationRuntimeMethod.indexOf(
                "deadlines.close();");
        require(detachRuntimeIndex >= 0);
        require(detachDeadlinesIndex > detachRuntimeIndex);
        require(closeRuntimeIndex > detachDeadlinesIndex);
        require(closeDeadlinesIndex > closeRuntimeIndex);
        require(countOccurrences(
                closeAuthorizationRuntimeMethod,
                "MobileServiceDestroyCleanup.appendFailure(") == 2);
        require(closeAuthorizationRuntimeMethod.contains(
                "MobileServiceDestroyCleanup.rethrowFailure(closeFailure);"));
        String releaseRuntimeLocksMethod = methodSlice(
                source,
                "private synchronized void releaseRuntimeLocks()",
                "private void clearLegacyPipelineRestoreFlag()");
        int detachWifiLockIndex = releaseRuntimeLocksMethod.indexOf(
                "wifiLock = null;");
        int detachWakeLockIndex = releaseRuntimeLocksMethod.indexOf(
                "wakeLock = null;");
        int releaseHeldLocksIndex = releaseRuntimeLocksMethod.indexOf(
                "MobileServiceDestroyCleanup.releaseIfHeld(");
        require(detachWifiLockIndex >= 0);
        require(detachWakeLockIndex > detachWifiLockIndex);
        require(releaseHeldLocksIndex > detachWakeLockIndex);
        require(countOccurrences(
                releaseRuntimeLocksMethod,
                "MobileServiceDestroyCleanup.releaseIfHeld(") == 2);
        require(releaseRuntimeLocksMethod.contains(
                "MobileServiceDestroyCleanup.rethrowFailure(releaseFailure);"));
        String acquireRuntimeLocksMethod = methodSlice(
                source,
                "private synchronized void acquireRuntimeLocks(",
                "@SuppressWarnings(\"deprecation\")");
        require(countOccurrences(
                acquireRuntimeLocksMethod,
                "suppressRuntimeLockReleaseFailure(") == 2);
        require(acquireRuntimeLocksMethod.contains(
                "IOException wrapped = new IOException("));
        String suppressLockReleaseFailureMethod = methodSlice(
                source,
                "private void suppressRuntimeLockReleaseFailure(",
                "private void clearLegacyPipelineRestoreFlag()");
        require(suppressLockReleaseFailureMethod.contains(
                "primaryFailure.addSuppressed(releaseFailure);"));
        require(source.contains(
                "\"mobile_runtime_service_cleanup_failed\""));
        require(source.contains("\" cleanup_continued=true stack={\""));
        require(source.contains(
                "MobileThrowableDiagnostics.format(\n"
                        + "                                failure.cause)"));
        String shutdownExecutorMethods = methodSlice(
                source,
                "private void shutdownExecutor(",
                "private synchronized void acquireRuntimeLocks(");
        require(shutdownExecutorMethods.contains(
                "catch (RuntimeException | LinkageError shutdownFailure)"));
        require(shutdownExecutorMethods.contains(
                "forceShutdownExecutorAfterFailure("));
        require(shutdownExecutorMethods.contains(
                "executor.shutdownNow().size()"));
        require(shutdownExecutorMethods.contains(
                "MobileServiceDestroyCleanup.appendFailure("));
        require(shutdownExecutorMethods.contains(
                "MobileServiceDestroyCleanup.rethrowFailure(primaryFailure);"));
        require(source.contains(
                "current.balanceKnown,\n"
                        + "                        current.permanent,"));
        String queueStopMethod = methodSlice(
                source,
                "private void queueClaimedFormalUsageStop(",
                "private void executeAuthorizationOperation(");
        int serverStopIndex = queueStopMethod.indexOf(
                "handle.stopFormalUsage();");
        int stopLockReconcileIndex = queueStopMethod.indexOf(
                "reconcileRuntimeLocksAfterDataPlaneClose(");
        int releaseTransportPinIndex = queueStopMethod.indexOf(
                "releaseFormalTransportPinAfterSession(");
        require(serverStopIndex >= 0);
        require(releaseTransportPinIndex > serverStopIndex);
        require(stopLockReconcileIndex > serverStopIndex);
        require(stopLockReconcileIndex > releaseTransportPinIndex);
        require(queueStopMethod.contains(
                "startCancellationExecutor.execute("));
        require(queueStopMethod.contains(
                "runClaimedFormalUsageStop(handle, reason)"));
        require(queueStopMethod.contains(
                "empty_stop_barrier_completed=true"));
        String coordinatorDeadlineMethod = methodSlice(
                formalCoordinator,
                "private void runLeaseDeadline(",
                "private void scheduleStagedActivationIfNeeded(");
        int coordinatorMonitorIndex = coordinatorDeadlineMethod.indexOf(
                "synchronized (this)");
        require(coordinatorMonitorIndex >= 0);
        require(!coordinatorDeadlineMethod.substring(
                0, coordinatorMonitorIndex).contains(
                "closeDataPlaneOnly();"));
        String hotReloadMethod = methodSlice(
                source,
                "private void hotReloadGameModel(",
                "private void requestOutputRouteSelection(");
        require(hotReloadMethod.contains("pipeline.prepareDataPlaneClosed("));
        require(hotReloadMethod.contains("pipeline.openPreparedDataPlane("));
        require(hotReloadMethod.contains(
                "commitPreparedHotReloadModelIfCurrent("));
        require(hotReloadMethod.contains(
                "hotReloadSessionIdentityIsCurrentLocked("));
        require(hotReloadMethod.contains("rollbackGameModelHotReload("));
        require(hotReloadMethod.contains("lease_reused=true"));
        require(hotReloadMethod.contains(
                "formalModelPreparationInProgress"));
        require(hotReloadMethod.contains(
                "pendingGameModelSelection = selected;"));
        require(hotReloadMethod.indexOf(
                "pendingGameModelSelection = selected;")
                < hotReloadMethod.indexOf(
                "if (previous == selected) return;"));
        require(hotReloadMethod.contains(
                "prepareModelDataPlaneClosed("));
        require(hotReloadMethod.contains(
                "boolean preparedFormalGap = sessionEndpoint != null"));
        require(hotReloadMethod.contains(
                "pipeline.isPreparedDataPlaneClosed()"));
        require(hotReloadMethod.contains(
                "reloadBoundFormalPipeline = runningWithPermit"));
        require(hotReloadMethod.contains(
                "pipelineDesired = true;"));
        require(hotReloadMethod.contains(
                "finishSupersededGameModelHotReload("));
        require(hotReloadMethod.contains(
                "FormalPipelineOwnerReceipt formalOwner ="));
        require(hotReloadMethod.contains("captureFormalPipelineOwner();"));
        require(hotReloadMethod.contains("|| !formalOwner.owns("));
        require(hotReloadMethod.contains("generation, sessionEndpoint)"));
        require(!hotReloadMethod.contains("stopPipeline(\"game_model_changed"));
        String commitPreparedModelMethod = methodSlice(
                hotReloadMethod,
                "private HotReloadCommitResult commitPreparedHotReloadModelIfCurrent(",
                "private boolean hotReloadSessionIdentityIsCurrentLocked(");
        int commitLockIndex = commitPreparedModelMethod.indexOf(
                "synchronized (pipelineCommandLock)");
        int commitGenerationCheckIndex = commitPreparedModelMethod.indexOf(
                "hotReloadSessionIdentityIsCurrentLocked(");
        int commitPostprocessIndex = commitPreparedModelMethod.indexOf(
                "controlRuntime.selectModel(selected);");
        int commitPermitIndex = commitPreparedModelMethod.indexOf(
                "runtimePermitIsActiveLocked(");
        int commitOpenIndex = commitPreparedModelMethod.indexOf(
                "pipeline.openPreparedDataPlane(");
        require(commitLockIndex >= 0);
        require(commitGenerationCheckIndex > commitLockIndex);
        require(commitPostprocessIndex > commitGenerationCheckIndex);
        require(commitPermitIndex > commitPostprocessIndex);
        require(commitOpenIndex > commitPermitIndex);
        require(commitPreparedModelMethod.indexOf(
                "expectedEndpoint, selected", commitOpenIndex)
                > commitOpenIndex);
        require(commitPreparedModelMethod.contains(
                "HotReloadCommitResult.appliedWaitingForPermit()"));
        String requestModelMethod = methodSlice(
                source,
                "private void requestGameModelSelection(",
                "private void hotReloadGameModel(");
        require(!requestModelMethod.contains("pipeline.stop();"));
        require(!requestModelMethod.contains(
                "game_model_selection_unexpected_exception"));
        String unexpectedReloadFailureMethod = methodSlice(
                hotReloadMethod,
                "private void failUnexpectedGameModelHotReloadIfCurrent(",
                "private enum HotReloadCommitOutcome");
        int unexpectedOwnerCheckIndex = unexpectedReloadFailureMethod.indexOf(
                "hotReloadOwnerIsCurrentLocked(");
        int unexpectedPermitRevokeIndex = unexpectedReloadFailureMethod.indexOf(
                "invalidateRuntimePermitWindowLocked()");
        int unexpectedGenerationIndex = unexpectedReloadFailureMethod.indexOf(
                "pipelineSessionGeneration.incrementAndGet()");
        int unexpectedBindingClearIndex = unexpectedReloadFailureMethod.indexOf(
                "formalSessionEndpoint = null;");
        int unexpectedStopIndex = unexpectedReloadFailureMethod.indexOf(
                "pipeline.stop();");
        int unexpectedExactOwnerStopIndex =
                unexpectedReloadFailureMethod.indexOf(
                        "stopFormalUsageIfCurrentOwner(");
        require(unexpectedOwnerCheckIndex >= 0);
        require(unexpectedExactOwnerStopIndex >= 0);
        require(unexpectedPermitRevokeIndex > unexpectedOwnerCheckIndex);
        require(unexpectedGenerationIndex > unexpectedPermitRevokeIndex);
        require(unexpectedBindingClearIndex > unexpectedGenerationIndex);
        require(unexpectedStopIndex > unexpectedBindingClearIndex);
        require(!unexpectedReloadFailureMethod.contains(
                "automaticFormalStopQueued.compareAndSet("));
        require(!unexpectedReloadFailureMethod.contains(
                "beginFormalUsageLifecycleStop()"));
        require(!unexpectedReloadFailureMethod.contains(
                "requestFormalUsageStop("));
        require(unexpectedReloadFailureMethod.contains(
                "no_cross_generation_cleanup"));
        require(formalBoundary.contains(
                "final MobileModelCatalog.Profile preparationModel;"));
        require(formalBoundary.contains(
                "formalModelPreparationInProgress = true;"));
        require(formalBoundary.contains(
                "selectPreferredTransportForFormalStart();"));
        String formalTransportSelection = methodSlice(
                source,
                "private void selectPreferredTransportForFormalStart()",
                "private HostVideoPresenceProbe.HostVideoObservation");
        require(!formalTransportSelection.contains(
                "resetSelectedWirelessHostDiscovery"));
        require(formalTransportSelection.contains(
                "discovered_host_preserved=true"));
        String formalHostVideoPreflight = methodSlice(
                source,
                "private HostVideoPresenceProbe.HostVideoObservation",
                "private void resetStaleWirelessHostDiscovery(");
        require(formalHostVideoPreflight.contains(
                "HostVideoNotObservedException"));
        require(formalHostVideoPreflight.contains(
                "resetStaleWirelessHostDiscovery(endpoint);"));
        String staleWirelessReset = methodSlice(
                source,
                "private void resetStaleWirelessHostDiscovery(",
                "private void releaseFormalTransportPinAfterSession(");
        require(staleWirelessReset.contains(
                "resetWirelessHostDiscoveryIfSelectedRoute(failedEndpoint)"));
        require(staleWirelessReset.contains(
                "formal_preflight_host_not_observed"));
        require(countOccurrences(
                formalBoundary, "awaitFormalPreparationHostVideo(") == 2);
        require(formalBoundary.contains(
                "transportCatalog.pinForFormalSession("));
        require(formalBoundary.contains(
                "controlRuntime.selectModel(preparationModel);"));
        String formalPrepareMethod = methodSlice(
                formalBoundary,
                "prepareWithDataPlaneClosed(",
                "verifyFreshHostVideoBeforePotentialDebit(");
        int formalCommitLockIndex = formalPrepareMethod.indexOf(
                "synchronized (pipelineCommandLock)",
                formalPrepareMethod.indexOf("prepareModelDataPlaneClosed("));
        int formalCommitGenerationCheckIndex = formalPrepareMethod.indexOf(
                "preparationGeneration",
                formalCommitLockIndex);
        int formalCommitModelIndex = formalPrepareMethod.indexOf(
                "controlRuntime.selectModel(preparationModel);",
                formalCommitLockIndex);
        require(formalCommitLockIndex >= 0);
        require(formalCommitGenerationCheckIndex > formalCommitLockIndex);
        require(formalCommitModelIndex > formalCommitGenerationCheckIndex);
        require(strings.contains(
                "<string name=\"app_name\">VF MOBILE</string>"));
        require(strings.contains(
                "<string name=\"runtime_log_export_filename\">"
                        + "VFMobile-runtime-log.jsonl</string>"));
        require(strings.contains("导入 VF 轨迹画像 JSON"));
        require(strings.contains("请允许 VF Mobile 不受电池优化限制"));
        require(strings.contains("请在应用信息中允许 VF Mobile 通知"));
        require(bluetoothHidStrings.contains("“VF 无线鼠标”"));
        require(!productStrings.contains("visionforge"));
        require(appBuildGradle.contains(
                "resValue 'string', 'app_name', 'VF QA'"));
        require(appBuildGradle.contains("applicationId 'com.visionforge.mobile'"));
        require(appBuildGradle.contains(
                "canonicalDualMachineApiBaseUrl = 'https://www.visionforge.cloud'"));
        require(!strings.contains("title_inference"));
        require(!strings.contains("title_control"));
        require(!authorizationStrings.contains("title_authorization"));
        require(appShell.contains("R.drawable.visionforge_launcher"));
        require(appShell.contains("context.getString(R.string.app_name)"));
        require(appShell.contains("appBar.setOrientation(LinearLayout.HORIZONTAL);"));
        require(appShell.contains("title.setSingleLine(true);"));
        require(appShell.contains("title.setHorizontallyScrolling(false);"));
        require(appShell.contains("title.setMaxLines(1);"));
        require(appShell.contains("title.setEllipsize(TextUtils.TruncateAt.END);"));
        require(appShell.contains("title.setAutoSizeTextTypeUniformWithConfiguration("));
        require(appShell.contains("screenWidthDp <= 360"));
        require(appShell.contains("compactHeader ? 8 : 12"));
        require(appShell.contains("compactHeader ? 40 : 46"));
        require(!appShell.contains("updateHeader()"));
        require(!appShell.contains("brandFrame.setVisibility(View.GONE)"));
        require(source.contains("QnnAssetBundleInstaller.ensureInstalled("));
        require(source.contains("BuildConfig.QNN_HTP_ARCHITECTURES"));
        require(source.contains("QnnHtpCompatibilityPolicy.evaluate("));
        require(source.contains("mobile_qnn_htp_compatibility"));
        require(source.contains("MobileInferenceBackendPolicy.evaluate("));
        require(source.contains(
                "MobileInferenceFailurePolicy.Accumulator failures ="));
        require(source.contains("failures.record(backend, assetFailure);"));
        require(source.contains("failures.record(backend, prepared);"));
        require(source.contains("return failures.resolve();"));
        require(!source.contains("lastFailure = prepared;"));
        require(source.contains("PortableModelAssetInstaller.ensureInstalled("));
        require(source.contains("mobile_inference_backend_plan"));
        require(source.contains("mobile_inference_backend_attempt"));
        require(source.contains("MobileRuntimeReadModel"));
        require(source.contains("result.failureCode);"));
        require(activity.contains("runtimeStatus.failureCode"));
        require(!source.contains("qnn_htp_architecture_not_packaged "));
        require(activity.contains("status_qnn_htp_architecture_not_packaged"));
        require(strings.contains("当前版本未包含此手机所需的骁龙 HTP 运行时"));
        require(appBuildGradle.contains("discoverQnnHtpArchitectures"));
        require(appBuildGradle.contains("libQnnHtpV([0-9]{2,3})Stub"));
        require(appBuildGradle.contains("verifyQnnHtpArchitectureDiscoveryPolicy"));
        require(appBuildGradle.contains("readQnnSdkIdentity"));
        require(appBuildGradle.contains("readQnnModelSdkIdentity"));
        require(appBuildGradle.contains(
                "QNN SDK/model toolchain identity mismatch"));
        require(appBuildGradle.contains(
                "verifyQnnSdkModelToolchainIdentityPolicy"));
        require(source.contains("formalSessionChannelBinding"));
        require(source.contains("formalSessionEndpoint"));
        require(!source.contains("mobile_pipeline_legacy_start_rejected"));
        require(!source.contains("explicit_formal_start"));
        require(source.contains("formalDataPlanePermitOpen.get()"));
        require(source.contains(
                "HostVideoPresenceProbe.HostVideoNotObservedException"));
        require(authorizationStrings.contains(
                "authorization_host_video_not_ready"));
        require(releaseSecurityConfig.contains("import java.security.interfaces.RSAPublicKey;"));
        require(releaseSecurityConfig.contains("dual_machine_ticket_key_duplicated"));
        require(releaseSecurityConfig.contains("rsaPublicKey.getModulus().bitLength() < 3072"));
        require(releaseSecurityConfig.contains("dual_machine_ticket_public_key_too_weak"));
        require(releaseSecurityConfig.contains("sha256Hex(publicKey.getEncoded())"));
        require(releaseSecurityConfig.contains(
                "BuildConfig.DUAL_MACHINE_PAIR_CREDENTIAL_PUBLIC_KEYS_BASE64"));
        require(releaseSecurityConfig.contains(
                "pairGenerationCredentialVerifier"));
        require(releaseSecurityConfig.contains(
                "new PairGenerationCredentialV1Verifier("));
        require(releaseSecurityConfig.contains(
                "pairCredentialKeys.toArray(new PublicKey[0])"));
        require(releaseSecurityConfig.contains(
                "ticketKeys.toArray(new PublicKey[0])"));
        require(releaseSecurityConfig.contains(
                "dual_machine_pair_credential_key_duplicated"));
        require(releaseSecurityConfig.contains(
                "dual_machine_pair_credential_public_key_too_weak"));
        require(!source.contains("pipeline.start("));
        require(!source.contains("requestIdr("));
        require(onCreateMethod.contains(
                "service_created_legacy_ready_fail_closed"));
        require(source.contains("synchronized (pipelineCommandLock)"));
        require(!source.contains("executePipelineStartWork("));
        require(!source.contains("clearAutomaticPipelineStartSchedule("));
        require(!source.contains("automaticPipelineStartRescanRequired"));
        require(!source.contains("PipelineStartScheduleResult"));
        require(!source.contains("startPipelineOnRequiredEthernet("));
        require(!source.contains("recoverPipelineIfNeeded("));
        require(!source.contains("rebindPipelineForEthernetReplacement("));
        require(!source.contains("stopPipelineForMissingEthernet("));
        require(source.contains("action=fresh_formal_session"));
        require(source.contains("requestFormalUsageStop("));
        require(source.contains("mobile_pipeline_stop_schedule_failed"));
        String destroyStopMethod = methodSlice(
                source,
                "private void stopPipelineBeforeDestroy()",
                "private void stopPipelineSynchronously(String reason)");
        require(destroyStopMethod.contains("mobile_pipeline_destroy_stop_schedule_failed"));
        require(destroyStopMethod.contains(
                "stopPipelineSynchronously(\"service_destroyed_inline_fallback\")"));
        require(destroyStopMethod.contains("fallback=inline"));
        String stopPipelineSyncMethod = methodSlice(
                source,
                "private void stopPipelineSynchronously(String reason)",
                "private boolean pipelineResourcesMayBeRunning()");
        require(stopPipelineSyncMethod.contains(
                "if (pipelineResourcesMayBeRunning()) stopPreparedPipeline();"));
        String pipelineResourcesMethod = methodSlice(
                source,
                "private boolean pipelineResourcesMayBeRunning()",
                "private boolean pipelineSessionIsCurrentLocked(");
        require(pipelineResourcesMethod.contains("pipelineStarted"));
        require(pipelineResourcesMethod.contains("runtimeStatus.phase == MobileRuntimePhase.STARTING"));
        require(pipelineResourcesMethod.contains(
                "pipeline.isPreparedDataPlaneClosed()"));
        require(pipelineResourcesMethod.contains(
                "synchronized (modelPreparationLock)"));
        require(pipelineResourcesMethod.contains("nativeVideoReceiverRunningSafely()"));
        require(qnnBridge.contains("QNN_BACKEND_ERROR_UNSUPPORTED_PLATFORM"));
        require(qnnBridge.contains("Unsupported SnapdragonModel"));
        require(qnnBridge.contains("qnn_htp_unsupported_snapdragon_model"));
        require(qnnBridge.contains("qnn_runtime_abi_invalid"));
        require(qnnBridge.contains("qnn_model_contract_invalid"));
        require(qnnBridge.contains("retryable="));
        require(dualMachineReceiver.contains("worker_thread_failed"));
        require(dualMachineReceiver.contains("catch (const std::system_error& failure)"));
        require(dualMachineReceiver.contains("startup_errno_ = failure.code().value() == 0 ? EAGAIN : failure.code().value();"));
        require(dualMachineReceiver.contains("network_bound_ = false;"));
        require(dualMachineReceiver.contains("socket_ = -1;"));
        String cat6ReadyAgent = methodSlice(
                dualMachineReceiver, "class Cat6ReadyAgent final {",
                "Cat6ReadyAgent& cat6_ready_agent()");
        require(cat6ReadyAgent.contains("[[nodiscard]] std::string report() const {\n"
                + "    std::scoped_lock lock(mutex_);"));
        require(cat6ReadyAgent.contains("android_setsocknetwork(network_handle, socket)"));
        require(dualMachineReceiver.contains(
                "return error == EPERM || error == EACCES;"));
        require(cat6ReadyAgent.contains(
                "local.sin_addr = local_ipv4_bind_fallback_"));
        require(cat6ReadyAgent.contains("? local_address"));
        require(cat6ReadyAgent.contains(
                ": in_addr{htonl(INADDR_ANY)};"));
        require(cat6ReadyAgent.contains(
                "network_handle_bind_errno_ = network_bind_error;"));
        require(cat6ReadyAgent.contains(
                "[[nodiscard]] bool running() const noexcept"));
        require(dualMachineReceiver.contains(
                "QnnHtpBridge_isNativeCat6ReadyAgentRunning"));
        require(cat6ReadyAgent.contains("mutable std::mutex mutex_;"));
        require(source.contains("snapshot.qnnExecutionLive"));
        require(source.contains("makcuReport"));
        String runtimeHealthMethod = methodSlice(
                source,
                "private void writeRuntimeHealthUnchecked(",
                "private void checkReceiverLiveness()");
        require(runtimeHealthMethod.contains(
                "FormalPipelineOwnerReceipt owner"));
        require(runtimeHealthMethod.contains(
                "commitFormalPipelineOwnerIfCurrent("));
        require(runtimeHealthMethod.contains(
                "stopFormalUsageIfCurrentOwner("));
        require(runtimeHealthMethod.contains(
                "recoverCat6ReadyAgentIfStopped(selectedEndpoint);"));
        require(runtimeHealthMethod.contains(
                "cat6ReadyLifecycle.isRunning()"));
        require(runtimeHealthMethod.contains(
                "health_ready_agent_recovery"));
        require(!runtimeHealthMethod.contains(
                "requestFormalUsageStop("));
        require(runtimeHealthMethod.contains(
                "MobileTransportEndpoint selectedEndpoint = requiredTransportEndpoint();"));
        require(runtimeHealthMethod.contains(
                "selectedEndpoint == null || selectedEndpoint.network == null"));
        require(runtimeHealthMethod.contains(
                "events.write(\"mobile_control_health\""));
        require(runtimeHealthMethod.contains(
                "MobileControlHealthSummary.format(decoderReport)"));
        require(runtimeHealthMethod.contains(
                "String inferenceReport = controlRuntime.inferenceAuditDetail();"));
        require(runtimeHealthMethod.contains(
                "\" inference={\" + inferenceReport + \"}\""));
        require(runtimeHealthMethod.contains(
                "MobileExternalHealthSnapshotFormatter.format("));
        require(runtimeHealthMethod.contains(
                "inferenceReport, metrics,"));
        require(source.contains(
                "new MobileExternalHealthSnapshotWriter(\n"
                        + "                getExternalFilesDir(null))"));
        require(runtimeHealthMethod.contains(
                "externalHealthMetricsSampler.sampleIfDue("));
        require(runtimeHealthMethod.contains(
                "externalHealthSnapshotPolicy.shouldWrite("));
        require(runtimeHealthMethod.contains(
                "externalHealthMetricsSampler.formatCurrent(snapshot)"));
        require(runtimeHealthMethod.contains(
                "externalHealthSnapshotPolicy.recordSuccessfulWrite("));
        require(runtimeHealthMethod.contains(
                "externalHealthSnapshotWriter.overwrite(payload)"));
        require(source.contains("EthernetNetworkDiagnostics.evaluate("));
        require(source.contains("rejection_reason=network_evaluation_exception"));
        require(source.contains("MobileThrowableDiagnostics.format(failure)"));
        require(source.contains(
                ".addTransportType(NetworkCapabilities.TRANSPORT_ETHERNET)"));
        require(source.contains(
                ".addTransportType(NetworkCapabilities.TRANSPORT_WIFI)"));
        require(source.contains("preference=cat6_then_wireless_lan_udp"));
        String ethernetDemandMethod = methodSlice(
                source,
                "private boolean registerEthernetNetworkDemand()",
                "private void unregisterEthernetNetworkDemand()");
        require(ethernetDemandMethod.contains("manager.requestNetwork("));
        require(ethernetDemandMethod.contains(
                ".addTransportType(NetworkCapabilities.TRANSPORT_ETHERNET)"));
        require(ethernetDemandMethod.contains(
                ".removeCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)"));
        require(!ethernetDemandMethod.contains("bindProcessToNetwork("));
        require(source.contains("this::unregisterEthernetNetworkDemand"));
        require(source.contains("mobile_ethernet_demand_registered"));
        require(ethernetDiagnostics.contains("\"transport_not_ethernet_or_wifi\""));
        require(ethernetDiagnostics.contains("MobileTransportEndpoint.wirelessLan("));
        require(mobileTransportEndpoint.contains("WIRELESS_LAN_UDP"));
        require(mobileTransportEndpoint.contains("static MobileTransportEndpoint wirelessLan("));
        require(mobileTransportEndpoint.contains("String readyAnnouncementIpv4()"));
        require(mobileTransportCatalog.contains(
                "MobileTransportEndpoint formalSessionPinnedRoute"));
        require(!mobileTransportCatalog.contains(
                "formalSessionPinnedNetworkHandle"));
        require(mobileTransportCatalog.contains(
                "formalSessionPinnedRoute.hasSameDataPlaneRoute("));
        require(mobileTransportCatalog.contains(
                "currentPinnedCandidate == null"));
        String networkChangedMethod = methodSlice(
                source,
                "private void networkChanged(",
                "private void refreshEthernetDiagnosticsFromKernel(");
        int catalogUpsertIndex = networkChangedMethod.indexOf(
                "transportCatalog.upsert(evaluatedEndpoint)");
        int routeUnavailableIndex = networkChangedMethod.indexOf(
                "ethernetRecovery.onLinkUnavailable(");
        int pinnedRouteMutationIndex = networkChangedMethod.indexOf(
                "formalSessionRouteWasMutated(");
        int immediateRouteStopIndex = networkChangedMethod.indexOf(
                "stopFormalUsageIfCurrentOwner(");
        require(catalogUpsertIndex >= 0);
        require(routeUnavailableIndex > catalogUpsertIndex);
        require(pinnedRouteMutationIndex > catalogUpsertIndex);
        require(immediateRouteStopIndex > routeUnavailableIndex);
        require(networkChangedMethod.contains(
                "mobile_transport_pinned_route_changed"));
        require(networkChangedMethod.contains(
                "transport_route_changed_"));
        require(networkChangedMethod.contains(
                "FormalPipelineOwnerReceipt eventOwner"));
        require(!networkChangedMethod.contains(
                "requestFormalUsageStop("));
        require(nativeReadyAgent.contains("endpoint.readyAnnouncementIpv4()"));
        require(nativeReadyAgent.contains(
                "QnnHtpBridge.isNativeCat6ReadyAgentRunning()"));
        require(!nativeReadyAgent.contains("endpoint.hostIpv4,"));
        require(source.contains("mobile_runtime_phase_changed"));
        require(source.contains("mobile_wireless_lan_host_discovery_timeout"));
        require(source.contains("cat6ReadyAgentLogPolicy.shouldWrite("));
        require(source.contains(
                "observeCat6ReadyAgentState("));
        require(source.contains(
                "cat6ReadyAgentReportFailureReported.compareAndSet("));
        require(source.contains(
                "mobile_cat6_ready_agent_report_recovered"));
        require(source.contains("log_policy=state_change_or_heartbeat"));
        require(source.contains(
                "Cat6ReadyAgentLogPolicy.STABLE_HEARTBEAT_MILLIS"));
        require(source.contains(
                "if (logger != null && previous.phase != current.phase)"));
        require(source.contains(
                "MobileRuntimePresentationUpdatePolicy.evaluateStatus("));
        require(source.contains("if (!decision.shouldPublish) return false;"));
        require(source.contains(
                "runtimePresentationUpdatePolicy.shouldPublishNotification("));
        require(runtimePresentationPolicy.contains(
                "changed ? previousRevision + 1L : previousRevision"));
        require(activity.contains(
                "MobileRuntimePresentationUpdatePolicy.enteredPhase("));
        require(activity.contains("MobileRuntimeReadModelStore.ethernetDiagnostics()"));
        require(activity.contains("ethernetStatusDetail(runtimeStatus, ethernetDiagnostics)"));
        require(activity.contains("containsDiagnostic(diagnostics, \"has_ipv4=false\")"));
        require(activity.contains("connection_ethernet_no_ipv4_detail"));
        require(!activity.contains("boolean diagnosticsChanged = appShell.isDiagnosticsVisible()"));
        require(!activity.contains("presentationChanged || diagnosticsChanged"));
        require(!appShell.contains("public boolean isDiagnosticsVisible()"));
        require(!mobileUiState.contains("rawDiagnostics"));
        require(!activity.contains("buildRawDiagnostics("));
        require(linkStatusSection.contains("state.ethernetDetail"));
        require(linkStatusSection.contains("detailOrDefault("));
        require(strings.contains("connection_ethernet_missing_detail"));
        require(strings.contains("connection_ethernet_no_ipv4_detail"));
        require(strings.contains("CAT6"));
        require(strings.contains("无线局域网"));
        require(!source.contains("fresh_manual_enable_required"));
        require(activity.contains("controlRuntime = MobileControlRuntime.get(this);"));
        require(!activity.contains("activity_not_visible"));
        require(!activity.contains("makcuSerialController.destroy()"));
        require(!activity.contains("controlOutputCoordinator.disable()"));
        require(installScript.contains("$packageName = \"com.visionforge.mobile\""));
        require(installScript.contains(
                "$legacyBenchmarkPackageName = \"com.visionforge.inferencebenchmark\""));
        require(installScript.contains("INSTALL_FAILED_USER_RESTRICTED"));
        require(installScript.contains("function ConvertTo-QuotedAdbProcessArgument"));
        require(installScript.contains(
                "(ConvertTo-QuotedAdbProcessArgument $Serial)"));
        require(installScript.contains(
                "(ConvertTo-QuotedAdbProcessArgument $Apk)"));
        require(installScript.contains("Start-Process -FilePath $Adb"));
        require(installScript.contains("-RedirectStandardOutput $stdoutPath"));
        require(installScript.contains("-RedirectStandardError $stderrPath"));
        require(installScript.contains("Remove-Item -LiteralPath $temporaryPath"));
        require(installScript.contains("RemoveLegacyBenchmarkPackage"));
        require(installScript.contains("Stop-DevicePackageIfPresent"));
        require(installScript.contains("function Get-AdbDeviceRows"));
        require(installScript.contains("function Get-AdbPhysicalDeviceKey"));
        require(installScript.contains("function Assert-NoDuplicateAdbTransports"));
        require(installScript.contains("Duplicate ADB mDNS transports detected for the same phone"));
        require(installScript.contains("debug APK can overwrite the verified release package"));
        require(installScript.contains("function Resolve-ApkSignerPath"));
        require(installScript.contains("function Assert-MobileApkSigningIdentity"));
        require(installScript.contains("APK Signature Scheme v2"));
        require(installScript.contains("APK Signature Scheme v3"));
        require(installScript.contains(
                "Production APK must not use APK Signature Scheme v1"));
        require(installScript.contains(
                "Production APK must contain exactly one current signer"));
        require(installScript.contains(
                "[string]::IsNullOrWhiteSpace($env:QNN_SDK_ROOT)"));
        require(installScript.contains("$defaultQnnRoot"));
        require(installScript.contains("Resolve-Path -LiteralPath $qnnRoot"));
        require(installScript.contains("CN=Android Debug"));
        require(installScript.contains(
                "APK is signed with the Android Debug certificate and cannot be used"));
        require(portableProbeLoop.contains(
                "portable_backend_probe_recovery_deferred"));
        require(portableProbeLoop.contains(
                "retry_forever_until_stop_file = $true"));
        require(portableProbeLoop.contains(
                "$failureBackoff.Wait([int]$recoveryDelayMillis)"));
        require(portableProbeLoop.contains("if ($succeeded) {"));
        require(portableProbeLoop.contains("$consecutiveFailures = 0"));
        require(portableProbeLoop.contains(
                "[int]$ProbeTimeoutSeconds = 600"));
        require(portableProbeLoop.contains(
                "$process.WaitForExit($ProbeTimeoutSeconds * 1000)"));
        require(portableProbeLoop.contains("$null = $process.Handle"));
        require(portableProbeLoop.contains("$process.WaitForExit()"));
        require(portableProbeLoop.contains("$process.Refresh()"));
        require(portableProbeLoop.contains(
                "ExitCode = $completedExitCode"));
        require(portableProbeLoop.contains(
                "portable_backend_probe_instrumentation_timeout"));
        require(portableProbeLoop.contains(
                "$failureType = \"instrumentation_timeout\""));
        require(portableProbeLoop.contains(
                "VISIONFORGE_PORTABLE_PROBE_TIMEOUT"));
        require(!portableProbeLoop.contains(
                "throw \"Portable backend probe failed:"));
        require(installScript.contains(
                "Assert-MobileApkSigningIdentity $apk $workspaceRoot ([bool]$AllowDevelopmentSigning)"));
        require(installScript.contains("Ensure-MobileForeground"));
        require(installScript.contains("Get-FocusedPackage"));
        require(installScript.contains("KEYCODE_HOME"));
        require(installScript.contains("vf.page_scroll.inference"));
        require(!installScript.contains("vf.page_scroll.link"));
        require(!installScript.contains("Find-FormalUsageAction"));
        require(installScript.contains(
                "Manual inference start/stop controls must be absent"));
        require(installScript.contains(
                "Standalone link navigation must be absent after link/inference merge."));
        require(installScript.contains("android.widget.ScrollView"));
        require(installScript.contains("function Capture-ControlState"));
        require(installScript.contains(
                "Control page did not become visible for $Label after model/navigation update."));
        require(installScript.contains("focused_package=$focusedPackage expected=$packageName"));
        require(installScript.contains(
                "APK installation reported success, but package $packageName is not installed."));
        require(linkStatusSection.contains(
                "root.setContentDescription(UiAutomationIds.INFERENCE_LINK_STATUS);"));
        require(inferenceScreen.contains(
                "root.setContentDescription(UiAutomationIds.SCROLL_INFERENCE);"));
        require(inferenceScreen.contains("new LinkStatusSection(context)"));
        require(inferenceScreen.contains("page.addView(linkStatusSection.view()"));
        require(inferenceScreen.contains("linkStatusSection.render(state)"));
        int linkStatusIndex = inferenceScreen.indexOf(
                "page.addView(linkStatusSection.view()");
        int trendCardIndex = inferenceScreen.indexOf(
                "page.addView(createTrendCard()");
        require(!inferenceScreen.contains("createPipelineAction"));
        require(!inferenceScreen.contains("onStartInference"));
        require(!inferenceScreen.contains("onStopInference"));
        require(linkStatusIndex >= 0);
        require(trendCardIndex > linkStatusIndex);
        require(!inferenceScreen.contains("createRuntimeStateCard()"));
        require(!inferenceScreen.contains("createPipelineCard()"));
        require(!inferenceScreen.contains("createDetailsCard()"));
        require(!inferenceScreen.contains("createLatencyCard()"));
        require(!inferenceScreen.contains("actualThroughputValue"));
        require(linkStatusSection.contains("state.accessUnitFps"));
        require(linkStatusSection.contains("state.decodedFrameFps"));
        require(linkStatusSection.contains("state.qnnFps"));
        require(linkStatusSection.contains("state.phoneProcessingP50"));
        require(linkStatusSection.contains("state.qnnP50"));
        require(linkStatusSection.contains("state.qnnFailures"));
        require(controlScreen.contains("root.setContentDescription(UiAutomationIds.SCROLL_CONTROL);"));
        require(!controlScreen.contains("createSafetyCard()"));
        require(!controlScreen.contains("UiAutomationIds.CONTROL_OUTPUT"));
        require(!controlScreen.contains("R.string.control_locked"));
        require(controlScreen.contains("createOutputRouteCard()"));
        require(controlScreen.contains("UiAutomationIds.OUTPUT_ROUTE_MAKCU"));
        require(controlScreen.contains("UiAutomationIds.OUTPUT_ROUTE_BLUETOOTH_HID"));
        require(controlScreen.contains("actions.onSelectMakcuOutputRoute()"));
        require(controlScreen.contains("actions.onSelectBluetoothHidOutputRoute()"));
        require(controlScreen.contains("actions.onRetryOutputDevice()"));
        require(controlScreen.contains("state.selectedOutputTransportReady()"));
        require(linkStatusSection.contains("state.selectedOutputTransportReady()"));
        require(controlScreen.contains("state.bluetoothHidOutputRouteAvailable"));
        require(controlScreen.contains("state.bluetoothHidPermissionGranted"));
        require(mobileAppActions.contains("void onSelectMakcuOutputRoute();"));
        require(mobileAppActions.contains("void onSelectBluetoothHidOutputRoute();"));
        require(mobileAppActions.contains("void onRetryOutputDevice();"));
        require(mobileAppActions.contains("void onExportRuntimeLog();"));
        require(appShell.contains("actions.onExportRuntimeLog()"));
        require(strings.contains("action_export_runtime_log"));
        require(uiAutomationIds.contains("OUTPUT_ROUTE_MAKCU"));
        require(uiAutomationIds.contains("OUTPUT_ROUTE_BLUETOOTH_HID"));
        require(uiAutomationIds.contains("INFERENCE_LINK_STATUS"));
        require(!uiAutomationIds.contains("NAV_LINK"));
        require(!uiAutomationIds.contains("CONTROL_OUTPUT"));
        require(mobileUiState.contains("bluetoothHidOutputRouteActive"));
        require(mobileUiState.contains("bluetoothHidOutputRouteAvailable"));
        require(mobileUiState.contains("bluetoothHidSessionReady"));
        require(mobileUiState.contains("bluetoothHidPermissionGranted"));
        require(mobileUiState.contains("boolean selectedOutputTransportReady()"));
        require(mobileUiStateMapper.contains("public boolean bluetoothHidOutputRouteActive;"));
        require(mobileUiStateMapper.contains("public boolean bluetoothHidOutputRouteAvailable;"));
        require(mobileUiStateMapper.contains("public boolean bluetoothHidSessionReady;"));
        require(mobileUiStateMapper.contains("public boolean bluetoothHidPermissionGranted;"));
        require(bluetoothHidPermissionPolicy.contains("Manifest.permission.BLUETOOTH_CONNECT"));
        require(bluetoothHidPermissionPolicy.contains("Manifest.permission.BLUETOOTH_ADVERTISE"));
        require(activity.contains("BLUETOOTH_HID_PERMISSION_REQUEST_CODE = 1703"));
        require(activity.contains("new BluetoothHidPermissionPolicy(this)"));
        require(activity.contains("bluetoothHidPermissionPolicy.request(BLUETOOTH_HID_PERMISSION_REQUEST_CODE)"));
        require(activity.contains("ControlOutputRoute.MAKCU_USB.storageToken"));
        require(activity.contains("ControlOutputRoute.BLUETOOTH_HID.storageToken"));
        require(activity.contains("binder.selectOutputRoute("));
        require(activity.contains("isBluetoothHidOutputRouteAvailable()"));
        require(activity.contains("BluetoothAdapter.ACTION_REQUEST_ENABLE"));
        require(activity.contains("BluetoothAdapter.ACTION_REQUEST_DISCOVERABLE"));
        require(activity.contains("status_output_route_bluetooth_requested"));
        require(activity.contains("DIAGNOSTIC_BLUETOOTH_HID_SELECT_ROUTE"));
        require(activity.contains("requestDebugBluetoothHidRouteSelection()"));
        require(activity.contains("mobile_control_bluetooth_hid_route_probe_request"));
        require(activity.contains("mobile_control_bluetooth_hid_route_probe_result"));
        require(activity.contains("path=control_runtime_debug_fallback"));
        require(activity.contains("selectBluetoothHidOutputRoute(false);"));
        require(activity.contains("controlRuntime.selectOutputRoute("));
        require(activity.contains("DIAGNOSTIC_BLUETOOTH_HID_MOVE_PROBE"));
        require(activity.contains("isDebuggableBuild()"));
        require(activity.contains("BluetoothHidDebugMoveProbePolicy.sanitize("));
        require(activity.contains("binder.runDebugBluetoothHidMoveProbe("));
        require(activity.contains("controlRuntime.runDebugBluetoothHidMoveProbe("));
        require(source.contains("void runDebugBluetoothHidMoveProbe("));
        require(source.contains("requestDebugBluetoothHidMoveProbe("));
        require(controlRuntime.contains("if (!BuildConfig.DEBUG)"));
        require(controlRuntime.contains(
                "activeRoute != ControlOutputRoute.BLUETOOTH_HID"));
        require(controlRuntime.contains("probeTransport.sendDiagnosticMove("));
        require(!controlRuntime.contains("long ticket = System.nanoTime();"));
        require(controlRuntime.contains("activeTransport.setOutputDeliveryAllowed(false);"));
        require(bluetoothHidMoveProbePolicy.contains("MAX_ABSOLUTE_DELTA = 8"));
        require(bluetoothHidMoveProbePolicy.contains("MAX_REPORTS = 8"));
        require(bluetoothHidMoveProbePolicy.contains("MAX_INTERVAL_MILLIS = 250"));
        require(bluetoothHidStrings.contains(
                "<string name=\"section_output_route\">鼠标输出路线</string>"));
        require(bluetoothHidStrings.contains(
                "<string name=\"output_route_makcu\">MAKCU 有线盒子</string>"));
        require(bluetoothHidStrings.contains(
                "<string name=\"output_route_bluetooth_hid\">蓝牙 HID 无线</string>"));
        require(bluetoothHidStrings.contains("status_output_route_bluetooth_permission_requested"));
        require(!strings.contains("action_start_inference"));
        require(!strings.contains("action_stop_inference"));
        require(!strings.contains("actual_inference_throughput"));
        require(!strings.contains("model_postprocess"));
        require(!strings.contains("AI推理等待画面"));
        require(!strings.contains("实时管线"));
        require(!productStrings.contains("开始推理"));
        require(activity.contains(
                "snapshot.freshDecodedFrameCount, snapshot.qnnExecutionCount,"));
        require(activity.contains("input.qnnFps = rates.qnnFps;"));
        require(activity.contains(
                "\"mobile_pipeline_metrics\",\n"
                        + "                    controlRuntime.inferenceAuditDetail()"
                        + " + \" \" + metricsEvent"));
        require(!productStrings.contains("output route"));
        require(!productStrings.contains("beta"));
        require(!productStrings.contains("experimental"));
        require(!productStrings.contains("tier 3"));
        require(!productStrings.contains("理论吞吐"));
        require(!productStrings.contains("theoretical throughput"));
        require(controlScreen.contains("MobileModelCatalog.OVERWATCH_2"));
        require(controlScreen.contains("R.string.game_overwatch2"));
        require(controlScreen.contains("MobileModelCatalog.COUNTER_STRIKE_2"));
        require(controlScreen.contains("R.string.game_counter_strike_2"));
        require(controlScreen.contains("state.activeModel.supports(entry.getKey())"));
        require(controlScreen.contains("setVisibility(supported ? View.VISIBLE : View.GONE)"));
        require(controlScreen.contains("supported && entry.getKey() == state.aimTarget"));
        require(controlRuntime.contains("!inference.model().supports(target)"));
        require(inferenceProfile.contains("if (!model.supports(selected)) return;"));
        require(inferenceProfile.contains("return profile.supports(restored) ? restored : profile.defaultAimTarget;"));
        require(controlProfile.contains("model.supports(selectedAimTarget)"));
        require(sharedModelContract.contains(".token = \"overwatch2-416-yolov5\""));
        require(sharedModelContract.contains(".body_class_id = 0U"));
        require(sharedModelContract.contains(".head_class_id = kNoModelClass"));
        require(sharedModelContract.contains(".high_confidence_threshold = 0.40F"));
        require(sharedModelContract.contains(".low_confidence_threshold = 0.20F"));
        require(sharedModelContract.contains(".new_track_confidence_threshold = 0.40F"));
        require(sharedModelContract.contains(".class_names = {\"enemy_body\", \"non_enemy_body\""));
        require(sharedModelContract.contains(
                ".token = \"counter-strike-2-vombit-416-v8s\""));
        require(sharedModelContract.contains(
                ".class_names = {\"ct_body\", \"ct_head\", \"t_body\", \"t_head\""));
        require(makcuMoveBridge.contains(
                "model->tracking_confidence.high_confidence_threshold"));
        require(makcuMoveBridge.contains(
                "model->tracking_confidence.low_confidence_threshold"));
        require(makcuMoveBridge.contains(
                "model->tracking_confidence.new_track_confidence_threshold"));
        require(runtimeStrings.contains("<string name=\"game_valorant\">无畏契约</string>"));
        require(runtimeStrings.contains("<string name=\"game_overwatch2\">守望先锋</string>"));
        require(runtimeStrings.contains("<string name=\"game_delta_force\">三角洲行动</string>"));
        require(runtimeStrings.contains("<string name=\"game_counter_strike_2\">反恐精英2</string>"));
        require(!runtimeStrings.contains(">VALORANT<"));
        require(!runtimeStrings.contains(">Overwatch 2<"));
        require(!runtimeStrings.contains(">Delta Force<"));
        require(!runtimeStrings.contains(">Counter-Strike 2<"));
    }

    private static String methodSlice(String source, String start, String end) {
        String normalizedSource = source.replace("\r\n", "\n").replace('\r', '\n');
        String normalizedStart = start.replace("\r\n", "\n").replace('\r', '\n');
        String normalizedEnd = end.replace("\r\n", "\n").replace('\r', '\n');
        int startIndex = normalizedSource.indexOf(normalizedStart);
        int endIndex = normalizedSource.indexOf(
                normalizedEnd, startIndex + normalizedStart.length());
        require(startIndex >= 0 && endIndex > startIndex);
        return normalizedSource.substring(startIndex, endIndex);
    }

    private static int countOccurrences(String source, String value) {
        int count = 0;
        int offset = 0;
        while (true) {
            int found = source.indexOf(value, offset);
            if (found < 0) return count;
            count++;
            offset = found + value.length();
        }
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError("Mobile runtime service command contract failed");
        }
    }
}
