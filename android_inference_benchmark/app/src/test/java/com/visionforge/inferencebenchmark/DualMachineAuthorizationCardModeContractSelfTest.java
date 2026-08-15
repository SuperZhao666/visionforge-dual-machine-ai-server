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
        String actions = read(uiRoot.resolve("MobileAppActions.java"));
        String automationIds = read(uiRoot.resolve("UiAutomationIds.java"));
        String strings = read(Paths.get(projectDirectory, "src", "main", "res",
                "values", "dual_machine_authorization_strings.xml"));

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
                "<string name=\"authorization_balance_pending\">待同步</string>"));
        require(!strings.contains("卡密与剩余时间"));
        require(!strings.contains("authorization_remaining"));
        require(!strings.contains("action_top_up_card"));
        require(!strings.contains("续充"));
        require(!strings.contains("续费"));
        require(!strings.contains("续时"));
        require(count(authorizationScreen, "section_authorization_balance") == 1);
        require(authorizationScreen.contains("authorization.balanceKnown"));
        require(authorizationScreen.contains(
                "if (!authorization.balanceKnown)"));
        require(authorizationScreen.contains(
                "R.string.authorization_balance_pending"));
        require(authorizationScreen.contains(
                "authorization.isActivationCardVisible()"));
        int permanentBranch = authorizationScreen.indexOf(
                "if (authorization.permanent)");
        int knownBalanceBranch = authorizationScreen.indexOf(
                "if (!authorization.balanceKnown)", permanentBranch);
        int pendingBalanceBranch = authorizationScreen.indexOf(
                "R.string.authorization_balance_pending",
                knownBalanceBranch);
        int durationBranch = authorizationScreen.indexOf(
                "return formatDuration(authorization.remainingSeconds)",
                pendingBalanceBranch);
        require(permanentBranch >= 0);
        require(knownBalanceBranch > permanentBranch);
        require(pendingBalanceBranch > knownBalanceBranch);
        require(durationBranch > pendingBalanceBranch);
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
