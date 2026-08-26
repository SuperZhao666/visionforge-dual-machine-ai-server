package android.system;

/** Minimal test-only Android ErrnoException used by the dependency-free JavaCompile gate. */
public final class ErrnoException extends Exception {
    public final int errno;

    public ErrnoException(String functionName, int errno) {
        super(functionName + " failed: errno " + errno);
        this.errno = errno;
    }
}
