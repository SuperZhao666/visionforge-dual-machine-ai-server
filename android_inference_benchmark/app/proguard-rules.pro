# VisionForge release-only R8 rules. Keep this file narrow: blanket package
# rules would preserve the implementation names that release obfuscation is
# intended to remove.

# Native code receives this Class object and resolves these callbacks by their
# literal method names and descriptors in MakcuMoveBridge.cpp.
-keepclassmembers,includedescriptorclasses class com.visionforge.inferencebenchmark.ControlOutputMoveDispatcher {
    static boolean offerNativeMove(int,int,long,long);
    static boolean suspendNativeDeliveryForRecovery(long);
    static boolean resumeNativeDeliveryAfterRecovery(long);
    static boolean failClosedNativeDelivery();
}

# NativeH264Decoder.cpp receives this object and resolves these five methods by
# literal JNI names. The remaining decoder implementation stays obfuscatable.
-keepclassmembers,includedescriptorclasses class com.visionforge.inferencebenchmark.FlexibleYuvMediaCodecDecoder {
    int offerAccessUnit(java.nio.ByteBuffer,int,long,boolean);
    boolean hasFatalFailure();
    java.lang.String fatalDiagnostic();
    boolean requestStreamRestart(int,int,long);
    java.lang.String inputHealthReport();
}
