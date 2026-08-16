package com.visionforge.inferencebenchmark.video;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * 有界候选会话重组器。
 *
 * <p>新 epoch 先在这里完整重组并验证 IDR；只有通过后，调用者才能把它
 * 提交给正式解码会话。单个未来分片、冲突重复或超时半帧不会替换当前流。</p>
 */
public final class VideoPreflightReassemblyWindow {
    public static final class CompletedCandidate {
        public final VideoFrameIdentity identity;
        public final boolean repeatedContent;
        public final byte[] accessUnit;

        CompletedCandidate(
                VideoFrameIdentity identity,
                boolean repeatedContent,
                byte[] accessUnit) {
            this.identity = identity;
            this.repeatedContent = repeatedContent;
            this.accessUnit = accessUnit;
        }

        public boolean isCommittableIdr() {
            return !repeatedContent
                    && VideoAccessUnitInspector.containsIdr(accessUnit);
        }
    }

    private static final class Pending {
        final VideoFrameIdentity identity;
        final boolean repeated;
        final long firstSeenNanos;
        final byte[][] parts;
        int received;
        int bytes;

        Pending(VideoFragmentHeader header, long nowNanos) {
            identity = header.identity;
            repeated = header.repeatedContent;
            firstSeenNanos = nowNanos;
            parts = new byte[header.fragmentCount][];
        }
    }

    private final int maximumFrames;
    private final int maximumBytes;
    private final Map<VideoFrameIdentity, Pending> pending = new HashMap<>();
    private int inflightBytes;
    private long conflicts;
    private long expirations;

    public VideoPreflightReassemblyWindow(int maximumFrames, int maximumBytes) {
        if (maximumFrames <= 0 || maximumBytes <= 0) {
            throw new IllegalArgumentException("positive reassembly bounds required");
        }
        this.maximumFrames = maximumFrames;
        this.maximumBytes = maximumBytes;
    }

    public CompletedCandidate offer(byte[] datagram, int length, long nowNanos) {
        VideoFragmentHeader header = VideoWireProtocol.parse(datagram, length);
        if (header == null) return null;
        int offset = VideoWireProtocol.HEADER_BYTES;
        byte[] part = Arrays.copyOfRange(datagram, offset, length);
        Pending frame = pending.get(header.identity);
        if (frame == null) {
            if (pending.size() >= maximumFrames) evictOldest();
            frame = new Pending(header, nowNanos);
            pending.put(header.identity, frame);
        } else if (frame.parts.length != header.fragmentCount
                || frame.repeated != header.repeatedContent) {
            remove(frame);
            conflicts++;
            return null;
        }

        byte[] previous = frame.parts[header.fragmentIndex];
        if (previous != null) {
            if (!Arrays.equals(previous, part)) {
                remove(frame);
                conflicts++;
            }
            return null;
        }
        if (part.length > maximumBytes - inflightBytes
                || part.length > VideoWireProtocol.MAX_ACCESS_UNIT_BYTES - frame.bytes) {
            remove(frame);
            return null;
        }
        frame.parts[header.fragmentIndex] = part;
        frame.received++;
        frame.bytes += part.length;
        inflightBytes += part.length;
        if (frame.received != frame.parts.length) return null;

        ByteArrayOutputStream output = new ByteArrayOutputStream(frame.bytes);
        for (byte[] fragment : frame.parts) {
            output.write(fragment, 0, fragment.length);
        }
        CompletedCandidate result = new CompletedCandidate(
                frame.identity, frame.repeated, output.toByteArray());
        remove(frame);
        return result;
    }

    public int discardExpired(long nowNanos, long ttlNanos) {
        int discarded = 0;
        Iterator<Pending> iterator = pending.values().iterator();
        while (iterator.hasNext()) {
            Pending frame = iterator.next();
            if (nowNanos >= frame.firstSeenNanos
                    && nowNanos - frame.firstSeenNanos > ttlNanos) {
                inflightBytes -= frame.bytes;
                iterator.remove();
                discarded++;
            }
        }
        expirations += discarded;
        return discarded;
    }

    public int inflightFrames() { return pending.size(); }
    public int inflightBytes() { return inflightBytes; }
    public long conflicts() { return conflicts; }
    public long expirations() { return expirations; }

    public void clear() {
        pending.clear();
        inflightBytes = 0;
    }

    private void evictOldest() {
        Pending oldest = null;
        for (Pending candidate : pending.values()) {
            if (oldest == null || candidate.firstSeenNanos < oldest.firstSeenNanos) {
                oldest = candidate;
            }
        }
        if (oldest != null) remove(oldest);
    }

    private void remove(Pending frame) {
        if (pending.remove(frame.identity) != null) {
            inflightBytes -= frame.bytes;
        }
    }
}
