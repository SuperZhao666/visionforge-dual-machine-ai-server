package com.visionforge.inferencebenchmark;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Locale;

/** Keeps the Android authorization UI in traditional card-key mode. */
final class DualMachineAuthorizationCardModeContractSelfTest {
    private static final String PROJECT_DIRECTORY_PROPERTY =
            "visionforge.android.project.dir";

    private DualMachineAuthorizationCardModeContractSelfTest() {
    }

    static void run() throws Exception {
        String projectDirectory = System.getProperty(PROJECT_DIRECTORY_PROPERTY, "");
        require(!projectDirectory.isEmpty());
        Path uiRoot = Paths.get(projectDirectory, "src", "main", "java", "com",
                "visionforge", "inferencebenchmark", "ui");
        String authorizationScreen = read(uiRoot.resolve("AuthorizationScreen.java"));
        Path runtimeRoot = Paths.get(projectDirectory, "src", "main", "java", "com",
                "visionforge", "inferencebenchmark");
        String mobileRuntime = read(runtimeRoot.resolve("MobileRuntimeService.java"));
        String pendingStore = read(runtimeRoot.resolve(
                "AndroidPendingActivationStore.java"));
        String queuedCardCoordinator = read(runtimeRoot.resolve(
                "QueuedCardActivationCoordinator.java"));
        String firstPairing = read(runtimeRoot.resolve(
                "AndroidFirstPairingCoordinatorV1.java"));
        String boundControl = read(runtimeRoot.resolve(
                "AndroidBoundAuthenticatedControlCoordinatorV1.java"));
        String tcpChannel = read(runtimeRoot.resolve("handshake").resolve(
                "AuthenticatedControlTcpChannelV1.java"));
        String controlScreen = read(uiRoot.resolve("ControlScreen.java"));
        String actions = read(uiRoot.resolve("MobileAppActions.java"));
        String automationIds = read(uiRoot.resolve("UiAutomationIds.java"));
        String strings = read(Paths.get(projectDirectory, "src", "main", "res",
                "values", "dual_machine_authorization_strings.xml"));
        String generalStrings = read(Paths.get(projectDirectory, "src", "main", "res",
                "values", "strings.xml"));

        require(authorizationScreen.contains(
                "Card-key activation and remaining-time presentation boundary"));
        require(authorizationScreen.contains("private final EditText cardCode;"));
        require(count(authorizationScreen, "new EditText(context)") == 1);
        require(count(authorizationScreen, "PasswordTransformationMethod.getInstance()") == 1);
        require(count(authorizationScreen,
                "View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS") == 1);
        require(authorizationScreen.contains(
                "DualMachineCardCode.normalizeAndValidate(raw);"));
        require(authorizationScreen.contains("cardCode.getText().clear();"));
        require(authorizationScreen.contains("actions.onActivateCard(normalized);"));
        require(authorizationScreen.contains(
                "authorization.canEnterCardCode()"));
        require(!authorizationScreen.contains(
                "if (!submissionEnabled) return;"));
        require(!authorizationScreen.contains(
                "R.string.authorization_start_host_before_activation"));
        require(mobileRuntime.contains(
                "QueuedCardActivationCoordinator queuedCardActivation"));
        require(mobileRuntime.contains(
                "queuedCardActivation.submit(cardCode)"));
        require(queuedCardCoordinator.contains(
                "DualMachineCardCode.normalizeAndValidate(cardCode)"));
        require(queuedCardCoordinator.contains(
                "store.saveQueuedCard(canonicalCardCode)"));
        require(queuedCardCoordinator.contains("activateIfReady()"));
        require(queuedCardCoordinator.contains("store.clearQueuedCard()"));
        require(pendingStore.contains("loadQueuedCard()"));
        require(pendingStore.contains("saveQueuedCard(String cardCode)"));
        require(pendingStore.contains("QUEUED_CARD_AAD"));
        require(pendingStore.contains(
                "plaintext, QUEUED_CARD_AAD,\n"
                        + "                    (byte) QUEUED_CARD_SCHEMA_VERSION"));
        require(pendingStore.contains("envelope[0] = envelopeVersion;"));
        require(tcpChannel.contains("FIRST_PAIRING_PORT = 5006"));
        require(tcpChannel.contains("AUTHENTICATED_CONTROL_PORT = 5008"));
        require(firstPairing.contains(
                "AuthenticatedControlTcpChannelV1.FIRST_PAIRING_PORT"));
        require(firstPairing.contains(
                "AuthenticatedControlTcpChannelV1.AUTHENTICATED_CONTROL_PORT"));
        require(boundControl.contains(
                "AuthenticatedControlTcpChannelV1.AUTHENTICATED_CONTROL_PORT"));
        require(!authorizationScreen.contains(
                "R.string.authorization_zero_cost_notice"));
        require(!strings.contains("authorization_zero_cost_notice"));
        require(!authorizationScreen.contains(
                "R.string.authorization_ready_detail"));
        require(!strings.contains("authorization_ready_detail"));
        require(authorizationScreen.contains(
                "case READY_FOR_ACTIVATION:\n"
                        + "                titleResource = "
                        + "R.string.authorization_ready;\n"
                        + "                detailResource = 0;"));
        require(authorizationScreen.contains(
                "detail.isEmpty() ? View.GONE : View.VISIBLE"));
        require(!controlScreen.contains("createAdvancedNoteCard"));
        require(!controlScreen.contains("toggleAdvancedNote"));
        require(!controlScreen.contains("createPersonalTrajectoryCard"));
        require(!controlScreen.contains("renderPersonalTrajectory"));
        require(!controlScreen.contains("R.string.advanced_smoothing"));
        require(!controlScreen.contains("R.string.personal_trajectory_title"));
        require(!generalStrings.contains(
                "<string name=\"advanced_smoothing\">"));
        require(!generalStrings.contains(
                "<string name=\"personal_trajectory_title\">"));
        require(!authorizationScreen.contains("pairingPackage"));
        require(!authorizationScreen.contains("submitPairingPackage"));
        require(!actions.contains("onImportPairingPackage"));
        require(!automationIds.contains("PAIRING_PACKAGE"));
        require(!authorizationScreen.contains("section_formal_usage"));
        require(!authorizationScreen.contains("authorization_consumed"));
        require(!authorizationScreen.contains("action_refresh_authorization"));
        require(!authorizationScreen.contains("action_start_formal_usage"));
        require(!authorizationScreen.contains("action_stop_formal_usage"));
        require(!authorizationScreen.contains("onStartFormalUsage"));
        require(!authorizationScreen.contains("onStopFormalUsage"));
        require(!authorizationScreen.contains("onRefreshAuthorization"));
        require(actions.contains("void onActivateCard(String cardCode);"));
        require(!actions.contains("onStartInference"));
        require(!actions.contains("onStopInference"));
        require(!actions.contains("onStartFormalUsage"));
        require(!actions.contains("onStopFormalUsage"));
        require(!actions.contains("onRefreshAuthorization"));
        require(!actions.contains("onLogin"));
        require(!actions.contains("onSubmitPassword"));
        require(automationIds.contains(
                "static final String CARD_CODE_INPUT = \"vf.authorization.card_code\";"));
        require(!automationIds.contains("INFERENCE_START"));
        require(!automationIds.contains("INFERENCE_STOP"));
        require(!automationIds.contains("FORMAL_USAGE_START"));
        require(!automationIds.contains("FORMAL_USAGE_STOP"));
        require(!automationIds.contains("AUTHORIZATION_REFRESH"));
        require(!strings.contains("正式使用"));
        require(!strings.contains("累计正式使用"));
        require(!strings.contains("刷新余额与授权状态"));
        require(!strings.contains("Secure v2"));
        require(!strings.contains("票据"));
        require(!strings.contains("数据面"));
        require(strings.contains(
                "<string name=\"section_card_activation\">激活卡密</string>"));
        require(strings.contains(
                "<string name=\"section_authorization_balance\">卡密剩余时间</string>"));
        require(strings.contains(
                "<string name=\"authorization_balance_not_activated\">未激活</string>"));
        require(strings.contains(
                "<string name=\"authorization_balance_activating\">激活中</string>"));
        require(strings.contains(
                "<string name=\"authorization_balance_verifying\">核验中</string>"));
        require(!strings.contains("待同步"));
        require(strings.contains(
                "<string name=\"authorization_balance_unavailable\">不可用</string>"));
        require(strings.contains(
                "<string name=\"authorization_security_configuration_error\">授权配置不可用</string>"));
        require(!strings.contains("卡密与剩余时间"));
        require(!strings.contains("authorization_remaining"));
        require(!strings.contains("action_top_up_card"));
        require(!strings.contains("续充"));
        require(!strings.contains("续费"));
        require(!strings.contains("续时"));
        require(count(authorizationScreen, "section_authorization_balance") == 1);
        require(authorizationScreen.contains(
                "authorization.displayBalanceKnown"));
        require(authorizationScreen.contains(
                "if (!authorization.displayBalanceKnown)"));
        require(authorizationScreen.contains(
                "R.string.authorization_balance_not_activated"));
        require(authorizationScreen.contains(
                "R.string.authorization_balance_activating"));
        require(authorizationScreen.contains(
                "R.string.authorization_balance_verifying"));
        require(authorizationScreen.contains(
                "case SECURITY_CONFIGURATION_ERROR:"));
        require(authorizationScreen.contains(
                "R.string.authorization_security_configuration_error"));
        require(authorizationScreen.contains(
                "R.string.authorization_balance_unavailable"));
        int unavailableBalanceBranch = authorizationScreen.indexOf(
                "authorization.status"
                        + " == DualMachineAuthorizationUiState.Status"
                        + ".SECURITY_CONFIGURATION_ERROR");
        require(authorizationScreen.contains(
                "authorization.isActivationCardVisible()"));
        int permanentBranch = authorizationScreen.indexOf(
                "if (authorization.permanent)");
        int knownBalanceBranch = authorizationScreen.indexOf(
                "if (!authorization.displayBalanceKnown)", permanentBranch);
        int notActivatedBalanceBranch = authorizationScreen.indexOf(
                "R.string.authorization_balance_not_activated",
                knownBalanceBranch);
        int activatingBalanceBranch = authorizationScreen.indexOf(
                "R.string.authorization_balance_activating",
                notActivatedBalanceBranch);
        int verifyingBalanceBranch = authorizationScreen.indexOf(
                "R.string.authorization_balance_verifying",
                activatingBalanceBranch);
        int durationBranch = authorizationScreen.indexOf(
                "formatDuration(authorization.remainingSeconds)",
                verifyingBalanceBranch);
        require(permanentBranch >= 0);
        require(unavailableBalanceBranch > permanentBranch);
        require(knownBalanceBranch > unavailableBalanceBranch);
        require(knownBalanceBranch > permanentBranch);
        require(notActivatedBalanceBranch > knownBalanceBranch);
        require(activatingBalanceBranch > notActivatedBalanceBranch);
        require(verifyingBalanceBranch > activatingBalanceBranch);
        require(durationBranch > verifyingBalanceBranch);
        require(authorizationScreen.contains(
                "authorization.balanceStale"));
        require(authorizationScreen.contains(
                "R.string.authorization_balance_last_verified"));
        require(!authorizationScreen.contains("authorization_remaining"));
        require(!authorizationScreen.contains("action_top_up_card"));
        require(!containsLoginFieldToken(authorizationScreen));
        require(!containsLoginFieldToken(actions));
        require(!containsLoginFieldToken(automationIds));
        require(!containsLoginFieldToken(strings));
    }

    private static boolean containsLoginFieldToken(String source) {
        String normalized = source.toLowerCase(Locale.ROOT);
        return normalized.contains("authorization_username")
                || normalized.contains("authorization_password")
                || normalized.contains("username")
                || normalized.contains("user_name")
                || normalized.contains("password_input")
                || normalized.contains("login_password")
                || normalized.contains("action_login");
    }

    private static String read(Path path) throws Exception {
        return new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
    }

    private static int count(String source, String token) {
        int occurrences = 0;
        int offset = 0;
        while (true) {
            int index = source.indexOf(token, offset);
            if (index < 0) return occurrences;
            occurrences++;
            offset = index + token.length();
        }
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError();
    }
}
