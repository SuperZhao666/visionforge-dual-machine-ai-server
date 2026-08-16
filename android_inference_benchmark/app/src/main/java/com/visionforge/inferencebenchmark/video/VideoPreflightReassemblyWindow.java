package com.visionforge.inferencebenchmark.video;

import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
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
    // Insertion order makes oldest-frame eviction O(1) and deterministic.
    private final Map<VideoFrameIdentity, Pending> pending = new LinkedHashMap<>();
    private int inflightBytes;
    private long conflicts;
    private long expirations;
    private long evictions;
    private long payloadBytesCopied;
    private long duplicatePayloadBytesAvoided;

    public VideoPreflightReassemblyWindow(int maximumFrames, int maximumBytes) {
        if (maximumFrames <= 0 || maximumBytes <= 0) {
            throw new IllegalArgumentException("positive reassembly bounds required");
        }
        this.maximumFrames = maximumFrames;
        this.maximumBytes = maximumBytes;
    }

    public CompletedCandidate offer(byte[] datagram, int length, long nowNanos) {
        if (datagram == null || nowNanos < 0L) return null;
        VideoFragmentHeader header = VideoWireProtocol.parse(datagram, length);
        if (header == null) return null;
        int offset = VideoWireProtocol.HEADER_BYTES;
        int partLength = length - offset;
        if (partLength <= 0
                || partLength > maximumBytes
                || partLength > VideoWireProtocol.MAX_ACCESS_UNIT_BYTES) {
            return null;
        }
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
            if (!rangeEquals(previous, datagram, offset, partLength)) {
                remove(frame);
                conflicts++;
            } else {
                duplicatePayloadBytesAvoided += partLength;
            }
            return null;
        }
        if (partLength > maximumBytes - inflightBytes
                || partLength > VideoWireProtocol.MAX_ACCESS_UNIT_BYTES - frame.bytes) {
            remove(frame);
            return null;
        }
        byte[] part = Arrays.copyOfRange(datagram, offset, length);
        payloadBytesCopied += partLength;
        frame.parts[header.fragmentIndex] = part;
        frame.received++;
        frame.bytes += partLength;
        inflightBytes += partLength;
        if (frame.received != frame.parts.length) return null;

        byte[] accessUnit = new byte[frame.bytes];
        int writeOffset = 0;
        for (byte[] fragment : frame.parts) {
            System.arraycopy(fragment, 0, accessUnit, writeOffset, fragment.length);
            writeOffset += fragment.length;
        }
        CompletedCandidate result = new CompletedCandidate(
                frame.identity, frame.repeated, accessUnit);
        remove(frame);
        return result;
    }

    public int discardExpired(long nowNanos, long ttlNanos) {
        if (nowNanos < 0L || ttlNanos < 0L) {
            throw new IllegalArgumentException("time values must be non-negative");
        }
        int discarded = 0;
        Iterator<Pending> iterator = pending.values().iterator();
        while (iterator.hasNext()) {
            Pending frame = iterator.next();
            if (nowNanos >= frame.firstSeenNanos
                    && nowNanos - frame.firstSeenNanos >= ttlNanos) {
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
    public long evictions() { return evictions; }
    public long payloadBytesCopied() { return payloadBytesCopied; }
    public long duplicatePayloadBytesAvoided() { return duplicatePayloadBytesAvoided; }

    public void clear() {
        pending.clear();
        inflightBytes = 0;
    }

    private void evictOldest() {
        Iterator<Pending> iterator = pending.values().iterator();
        if (iterator.hasNext()) {
            Pending oldest = iterator.next();
            inflightBytes -= oldest.bytes;
            iterator.remove();
            evictions++;
        }
    }

    private void remove(Pending frame) {
        if (pending.remove(frame.identity) != null) {
            inflightBytes -= frame.bytes;
        }
    }

    private static boolean rangeEquals(
            byte[] stored, byte[] source, int offset, int length) {
        if (stored.length != length) return false;
        for (int index = 0; index < length; index++) {
            if (stored[index] != source[offset + index]) return false;
        }
        return true;
    }
}
