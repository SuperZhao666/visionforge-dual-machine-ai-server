package android.net;

import java.io.IOException;
import java.net.DatagramSocket;

/** Minimal test-only Android Network stub for dependency-free JavaCompile gates. */
public final class Network {
    private final long networkHandle;

    public Network() {
        this(0L);
    }

    public Network(long networkHandle) {
        this.networkHandle = networkHandle;
    }

    public long getNetworkHandle() {
        return networkHandle;
    }

    public void bindSocket(DatagramSocket socket) throws IOException {
        if (socket == null) throw new IOException("socket is required");
    }
}
