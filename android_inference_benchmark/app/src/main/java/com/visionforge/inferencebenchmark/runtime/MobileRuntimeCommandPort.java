package com.visionforge.inferencebenchmark.runtime;

/**
 * UI 可以提交的运行时意图。
 *
 * <p>接口只表达业务命令，不暴露 Binder、线程、JNI、MediaCodec、USB 或
 * Bluetooth 实现。未知/非法参数由实现端 fail-closed 处理。</p>
 */
public interface MobileRuntimeCommandPort {
    void setAuthorizationObserver(MobileRuntimeAuthorizationObserver observer);

    void setFirstPairingObserver(MobileFirstPairingObserver observer);

    void setActivityForeground(boolean foreground);

    void activateCard(String cardCode);

    void resumePendingActivation();

    void confirmFirstPairing(boolean matchingCodes);

    void refreshAuthorization();

    void selectGameModel(String modelToken);

    void selectOutputRoute(String routeToken);

    void runDebugBluetoothHidMoveProbe(
            int deltaX,
            int deltaY,
            int reports,
            int intervalMillis);
}
