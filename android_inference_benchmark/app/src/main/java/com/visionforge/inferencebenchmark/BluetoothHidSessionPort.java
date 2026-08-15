package com.visionforge.inferencebenchmark;

/** Narrow runtime-owned boundary for the production Bluetooth HID session. */
interface BluetoothHidSessionPort
        extends BluetoothHidMouseTransportCore.SessionPort, AutoCloseable {
    void setForegroundSessionActive(boolean active);

    BluetoothHidOutputFailClosedPolicy.SessionState sessionState();

    @Override
    void close();
}
