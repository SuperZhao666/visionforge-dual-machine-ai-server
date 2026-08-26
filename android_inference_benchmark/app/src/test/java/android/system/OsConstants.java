package android.system;

/** Minimal test-only errno constants used by the dependency-free JavaCompile gate. */
public final class OsConstants {
    public static final int EPERM = 1;
    public static final int EACCES = 13;

    private OsConstants() {}
}
