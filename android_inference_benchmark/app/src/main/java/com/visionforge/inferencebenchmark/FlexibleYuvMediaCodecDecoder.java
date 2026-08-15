package com.visionforge.inferencebenchmark;

import android.graphics.ImageFormat;
import android.graphics.Rect;
import android.media.Image;
import android.media.MediaCodec;
import android.media.MediaCodecInfo;
import android.media.MediaCodecList;
import android.media.MediaFormat;
import android.os.Build;
import android.util.Log;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Owns the only portable Android software-visible decoder output path.
 *
 * <p>{@link MediaCodec#getOutputImage(int)} exposes the real Y/U/V planes and
 * their row/pixel strides. A numeric MediaFormat color-format value alone is
 * not a byte-layout contract on vendor Codec2 implementations.</p>
 */
final class FlexibleYuvMediaCodecDecoder {
    private static final String TAG = "VisionForgeDecoder";
    private static final int DEQUEUE_TIMEOUT_US = 1_000;
    private static final long INPUT_QUEUE_WAIT_MILLIS = 5L;
    private static final long WORKER_JOIN_TIMEOUT_MILLIS = 250L;
    private static final long MAX_INPUT_AGE_NANOS = 50_000_000L;
    // This is a memory/latency safety budget, not an FPS ceiling. The 50 ms age
    // boundary remains authoritative while the byte budget absorbs short bursts
    // from displays faster than 144 Hz without depending on a frame-count guess.
    private static final long MAX_QUEUED_COMPRESSED_BYTES = 1_048_576L;
    private static final int COLOR_FORMAT_YUV420_FLEXIBLE = 0x7f420888;
    private static final int REALTIME_CODEC_PRIORITY = 0;
    private static final int OFFER_ACCEPTED = 0;
    private static final int OFFER_INVALID = 1;
    private static final int OFFER_NOT_RUNNING = 2;
    private static final int OFFER_QUEUE_CAPACITY = 3;
    private static final int OFFER_RESTARTING = 4;
    private static final int OFFER_REFERENCE_RECOVERY = 5;

    private final Object lifecycleLock = new Object();
    private final Object restartLock = new Object();
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicBoolean fatalFailure = new AtomicBoolean(false);
    private final AtomicBoolean restartInProgress = new AtomicBoolean(false);
    private final AtomicLong lifecycleGeneration = new AtomicLong();
    private final AtomicLong inputNoBufferPolls = new AtomicLong();
    private final AtomicLong inputStaleBeforeCodecDrops = new AtomicLong();
    private final AtomicLong inputQueueCapacityDrops = new AtomicLong();
    private final AtomicLong inputBufferCapacityDrops = new AtomicLong();
    private final AtomicLong inputCodecExceptionDrops = new AtomicLong();
    private final AtomicLong inputStateExceptionDrops = new AtomicLong();
    private final AtomicLong inputRestartDrops = new AtomicLong();
    private final AtomicLong inputNotRunningDrops = new AtomicLong();
    private final AtomicLong inputInvalidDrops = new AtomicLong();
    private final AtomicLong inputFatalFlushDrops = new AtomicLong();
    private final AtomicLong inputRecoveryFlushDrops = new AtomicLong();
    private final AtomicLong inputStopFlushDrops = new AtomicLong();
    private final AtomicLong inputReferenceRecoveryDrops = new AtomicLong();
    private final AtomicLong inputQueueHighWatermark = new AtomicLong();
    private volatile DecoderOutputState decoderOutputState =
            new DecoderOutputState();
    private volatile String fatalDiagnostic = "none";
    private volatile String activeCodecDescription = "unavailable";
    private volatile boolean forceSoftwareFallback;

    private MediaCodec codec;
    private Thread outputThread;
    private Thread inputThread;
    private DecoderAccessUnitQueue inputQueue;

    /** Mutable counters owned by exactly one published codec generation. */
    private static final class DecoderOutputState {
        final DecoderOutputProgressTracker progress =
                new DecoderOutputProgressTracker();
        int consecutiveFailures;
        long nativeRejectedOutputs;
    }

    boolean start(int width, int height) {
        synchronized (restartLock) {
            resetInputMetrics();
            long generation = lifecycleGeneration.incrementAndGet();
            detachAndReleaseActiveCodec("start_replacement");
            return startReplacement(width, height, generation);
        }
    }

    /** Schedules codec replacement without ever blocking the native UDP receive thread. */
    boolean requestStreamRestart(int width, int height, long nativeGeneration) {
        if (width <= 0 || height <= 0 || !restartInProgress.compareAndSet(false, true)) {
            return false;
        }
        long lifecycleToken = lifecycleGeneration.incrementAndGet();
        long startedNanos = System.nanoTime();
        Log.i(TAG, "decoder_stream_restart stage=requested generation=" + nativeGeneration);
        detachAndReleaseActiveCodec("stream_discontinuity");
        Thread restartWorker = new Thread(() -> {
            boolean restarted = false;
            String diagnostic = "replacement_start_failed";
            try {
                restarted = startReplacement(width, height, lifecycleToken);
                diagnostic = restarted ? "none" : "replacement_cancelled_or_failed";
            } catch (RuntimeException failure) {
                diagnostic = failure.getClass().getSimpleName() + ":replacement";
                Log.e(TAG, "decoder_stream_restart stage=replacement_exception", failure);
            } finally {
                restartInProgress.set(false);
                long elapsedUs = (System.nanoTime() - startedNanos) / 1_000L;
                QnnHtpBridge.completeNativeH264StreamRestart(
                        nativeGeneration, restarted, elapsedUs, diagnostic);
                Log.i(TAG, "decoder_stream_restart stage=completed generation="
                        + nativeGeneration + " completed=" + restarted
                        + " elapsed_us=" + elapsedUs + " diagnostic=" + diagnostic);
            }
        }, "vf-decoder-restart");
        restartWorker.setDaemon(true);
        restartWorker.start();
        return true;
    }

    private boolean startReplacement(int width, int height, long generation) {
        if (width <= 0 || height <= 0) {
            return false;
        }
        MediaCodec created = null;
        try {
            created = createDecoder();
            MediaFormat format = MediaFormat.createVideoFormat(
                    MediaFormat.MIMETYPE_VIDEO_AVC, width, height);
            format.setInteger(MediaFormat.KEY_COLOR_FORMAT, COLOR_FORMAT_YUV420_FLEXIBLE);
            format.setInteger(MediaFormat.KEY_COLOR_STANDARD, MediaFormat.COLOR_STANDARD_BT709);
            format.setInteger(MediaFormat.KEY_COLOR_RANGE, MediaFormat.COLOR_RANGE_LIMITED);
            format.setInteger(MediaFormat.KEY_PRIORITY, REALTIME_CODEC_PRIORITY);
            float operatingRate = maximumAdvertisedOperatingRate(created, width, height);
            if (operatingRate > 0.0f) {
                format.setFloat(MediaFormat.KEY_OPERATING_RATE, operatingRate);
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                format.setInteger(MediaFormat.KEY_LOW_LATENCY, 1);
            }
            created.configure(format, null, null, 0);
            created.start();
            if (lifecycleGeneration.get() != generation) {
                releaseCodecAfterWorkersExitAsync(created, null, null, "stale_replacement");
                return false;
            }
            final MediaCodec activeCodec = created;
            final String activeDescription = describeCodec(created);
            final DecoderAccessUnitQueue activeInputQueue =
                    new DecoderAccessUnitQueue(
                            MAX_INPUT_AGE_NANOS, MAX_QUEUED_COMPRESSED_BYTES);
            final DecoderOutputState activeOutputState =
                    new DecoderOutputState();
            synchronized (lifecycleLock) {
                if (lifecycleGeneration.get() != generation) {
                    releaseCodecAfterWorkersExitAsync(
                            activeCodec, null, null, "stale_replacement_locked");
                    return false;
                }
                codec = activeCodec;
                activeCodecDescription = activeDescription;
                inputQueue = activeInputQueue;
                decoderOutputState = activeOutputState;
                // Only the generation that actually wins publication may
                // clear an older fatal result. A stale replacement that was
                // overtaken while configuring must not erase the active
                // generation's failure evidence.
                fatalFailure.set(false);
                fatalDiagnostic = "none";
                running.set(true);
                inputThread = new Thread(
                        () -> drainInput(
                                activeCodec, activeInputQueue,
                                activeOutputState.progress),
                        "vf-flexible-yuv-decoder-input");
                outputThread = new Thread(
                        () -> drainOutput(
                                activeCodec, activeOutputState,
                                activeDescription),
                        "vf-flexible-yuv-decoder");
                inputThread.start();
                outputThread.start();
            }
            QnnHtpBridge.updateNativeH264JavaDecoderFormat(
                    activeDescription, COLOR_FORMAT_YUV420_FLEXIBLE,
                    MediaFormat.COLOR_STANDARD_BT709, MediaFormat.COLOR_RANGE_LIMITED,
                    width, height);
            Log.i(TAG, "decoder_started codec=" + activeDescription
                    + " requested=YUV_420_888 size=" + width + "x" + height
                    + " priority=" + REALTIME_CODEC_PRIORITY
                    + " operating_rate="
                    + (operatingRate > 0.0f
                            ? Float.toString(operatingRate) : "codec_default")
                    + " low_latency=" + (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)
                    + " software_fallback=" + forceSoftwareFallback);
            return true;
        } catch (IOException | IllegalArgumentException | IllegalStateException error) {
            Log.e(TAG, "decoder_start_failed size=" + width + "x" + height, error);
            if (created != null) {
                releaseCodecAfterWorkersExitAsync(created, null, null, "failed_replacement");
            }
            return false;
        }
    }

    /** Copies into a bounded FIFO; MediaCodec is never called on the native UDP receiver thread. */
    int offerAccessUnit(
            ByteBuffer source, int size, long presentationTimeUs, boolean syncFrame) {
        if (source == null || !source.isDirect() || size <= 0 || size > source.capacity()) {
            inputInvalidDrops.incrementAndGet();
            return OFFER_INVALID;
        }
        final MediaCodec activeCodec;
        final DecoderAccessUnitQueue activeInputQueue;
        synchronized (lifecycleLock) {
            activeCodec = codec;
            activeInputQueue = inputQueue;
        }
        if (restartInProgress.get()) {
            inputRestartDrops.incrementAndGet();
            return OFFER_RESTARTING;
        }
        if (!running.get() || activeCodec == null || activeInputQueue == null) {
            inputNotRunningDrops.incrementAndGet();
            return OFFER_NOT_RUNNING;
        }
        if (syncFrame) {
            List<DecoderAccessUnitQueue.AccessUnit> discarded =
                    activeInputQueue.prepareForIncomingSyncFrame(
                            size, System.nanoTime());
            if (!discarded.isEmpty()) {
                long total = inputRecoveryFlushDrops.addAndGet(discarded.size());
                for (DecoderAccessUnitQueue.AccessUnit accessUnit : discarded) {
                    QnnHtpBridge.discardNativeCompressedAccessUnit(
                            accessUnit.presentationTimeUs, "input_recovery_flush", false);
                    activeInputQueue.recycle(accessUnit);
                }
                if (shouldLog(total)) {
                    Log.w(TAG, "decoder_input_queue_recovered reason=sync_priority flushed="
                            + discarded.size() + " total=" + total);
                }
            }
        }
        DecoderAccessUnitQueue.OfferResult result = activeInputQueue.offer(
                source, size, presentationTimeUs, syncFrame, System.nanoTime());
        if (result == DecoderAccessUnitQueue.OfferResult.ACCEPTED) {
            inputQueueHighWatermark.accumulateAndGet(
                    activeInputQueue.highWatermark(), Math::max);
            return OFFER_ACCEPTED;
        }
        if (result == DecoderAccessUnitQueue.OfferResult.CAPACITY) {
            long count = inputQueueCapacityDrops.incrementAndGet();
            if (shouldLog(count)) {
                Log.w(TAG, "decoder_input_queue_rejected reason=capacity count=" + count
                        + " depth=" + activeInputQueue.size()
                        + " queued_bytes=" + activeInputQueue.queuedBytes()
                        + " maximum_queued_bytes=" + MAX_QUEUED_COMPRESSED_BYTES);
            }
            return OFFER_QUEUE_CAPACITY;
        }
        if (result == DecoderAccessUnitQueue.OfferResult.REFERENCE_RECOVERY) {
            long count = inputReferenceRecoveryDrops.incrementAndGet();
            if (shouldLog(count)) {
                Log.w(TAG, "decoder_input_queue_rejected reason=awaiting_sync_frame count="
                        + count + " depth=" + activeInputQueue.size());
            }
            return OFFER_REFERENCE_RECOVERY;
        }
        if (result == DecoderAccessUnitQueue.OfferResult.CLOSED) {
            inputRestartDrops.incrementAndGet();
            return OFFER_RESTARTING;
        }
        inputInvalidDrops.incrementAndGet();
        return OFFER_INVALID;
    }

    void stop() {
        synchronized (restartLock) {
            lifecycleGeneration.incrementAndGet();
            restartInProgress.set(false);
            detachAndReleaseActiveCodec("operator_stop");
        }
    }

    private void detachAndReleaseActiveCodec(String reason) {
        running.set(false);
        final MediaCodec oldCodec;
        final Thread oldWorker;
        final Thread oldInputWorker;
        final DecoderAccessUnitQueue oldInputQueue;
        synchronized (lifecycleLock) {
            oldCodec = codec;
            oldWorker = outputThread;
            oldInputWorker = inputThread;
            oldInputQueue = inputQueue;
            codec = null;
            outputThread = null;
            inputThread = null;
            inputQueue = null;
            decoderOutputState = new DecoderOutputState();
            activeCodecDescription = "unavailable";
        }
        List<DecoderAccessUnitQueue.AccessUnit> discarded = oldInputQueue == null
                ? Collections.emptyList() : oldInputQueue.closeAndDrain();
        int discardedInputs = discarded.size();
        discardDrainedInputs(oldInputQueue, discarded,
                "stream_discontinuity".equals(reason)
                        ? "input_restart_flush" : "input_stop_flush");
        if (oldCodec != null) {
            Log.i(TAG, "decoder_detached reason=" + reason
                    + " input_discarded=" + discardedInputs
                    + " input_thread_alive="
                    + (oldInputWorker != null && oldInputWorker.isAlive())
                    + " output_thread_alive=" + (oldWorker != null && oldWorker.isAlive()));
            releaseCodecAfterWorkersExitAsync(oldCodec, oldInputWorker, oldWorker, reason);
        }
    }

    private void drainInput(
            MediaCodec activeCodec,
            DecoderAccessUnitQueue activeInputQueue,
            DecoderOutputProgressTracker activeOutputProgress) {
        promotePipelineThread("input");
        try {
            while (running.get() && isActive(activeCodec) && !activeInputQueue.isClosed()) {
                DecoderAccessUnitQueue.AccessUnit accessUnit =
                        activeInputQueue.awaitNext(INPUT_QUEUE_WAIT_MILLIS);
                if (accessUnit == null) continue;
                if (!queueInputWhenAvailable(
                        activeCodec, activeInputQueue, activeOutputProgress,
                        accessUnit)) break;
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        } finally {
            Log.i(TAG, "decoder_input_loop_ended running=" + running.get()
                    + " queue_depth=" + activeInputQueue.size());
        }
    }

    private boolean queueInputWhenAvailable(
            MediaCodec activeCodec, DecoderAccessUnitQueue activeInputQueue,
            DecoderOutputProgressTracker activeOutputProgress,
            DecoderAccessUnitQueue.AccessUnit accessUnit) {
        try {
            while (running.get() && isActive(activeCodec)) {
                if (DecoderAccessUnitQueue.isStale(
                        accessUnit.enqueuedNanos, System.nanoTime(), MAX_INPUT_AGE_NANOS)) {
                    discardStaleBeforeCodec(activeInputQueue, accessUnit);
                    return true;
                }
                int index = activeCodec.dequeueInputBuffer(DEQUEUE_TIMEOUT_US);
                if (!running.get() || !isActive(activeCodec) || activeInputQueue.isClosed()) {
                    activeInputQueue.recycle(accessUnit);
                    return false;
                }
                if (index < 0) {
                    inputNoBufferPolls.incrementAndGet();
                    continue;
                }
                ByteBuffer input = activeCodec.getInputBuffer(index);
                if (input == null || input.capacity() < accessUnit.size) {
                    activeCodec.queueInputBuffer(
                            index, 0, 0, accessUnit.presentationTimeUs, 0);
                    inputBufferCapacityDrops.incrementAndGet();
                    failInput(activeCodec, activeInputQueue, accessUnit,
                            "input_buffer_capacity",
                            DecoderFallbackPolicy.FailureKind.CODEC_CONTRACT);
                    return false;
                }
                input.clear();
                input.put(accessUnit.bytes, 0, accessUnit.size);
                activeCodec.queueInputBuffer(
                        index, 0, accessUnit.size, accessUnit.presentationTimeUs,
                        accessUnit.syncFrame ? MediaCodec.BUFFER_FLAG_KEY_FRAME : 0);
                activeOutputProgress.recordQueuedInput(System.nanoTime());
                activeInputQueue.recycle(accessUnit);
                return true;
            }
            activeInputQueue.recycle(accessUnit);
            return false;
        } catch (MediaCodec.CodecException error) {
            if (!isActive(activeCodec)) {
                activeInputQueue.recycle(accessUnit);
                Log.i(TAG, "stale_decoder_input_cancelled diagnostic="
                        + error.getDiagnosticInfo());
                return false;
            }
            inputCodecExceptionDrops.incrementAndGet();
            failInput(activeCodec, activeInputQueue, accessUnit,
                    "input_codec_exception",
                    DecoderFallbackPolicy.FailureKind.CODEC_EXCEPTION);
            Log.e(TAG, "decoder_input_codec_failure diagnostic="
                    + error.getDiagnosticInfo() + " recoverable=" + error.isRecoverable()
                    + " transient=" + error.isTransient(), error);
            return false;
        } catch (IllegalStateException | IllegalArgumentException error) {
            if (!isActive(activeCodec)) {
                activeInputQueue.recycle(accessUnit);
                Log.i(TAG, "stale_decoder_input_cancelled type="
                        + error.getClass().getSimpleName());
                return false;
            }
            inputStateExceptionDrops.incrementAndGet();
            failInput(activeCodec, activeInputQueue, accessUnit,
                    "input_state_exception",
                    DecoderFallbackPolicy.FailureKind.STATE_EXCEPTION);
            Log.e(TAG, "decoder_input_failure", error);
            return false;
        }
    }

    private void discardStaleBeforeCodec(
            DecoderAccessUnitQueue activeInputQueue,
            DecoderAccessUnitQueue.AccessUnit stale) {
        List<DecoderAccessUnitQueue.AccessUnit> dependent =
                activeInputQueue.enterReferenceRecoveryAndDrain();
        long staleCount = inputStaleBeforeCodecDrops.incrementAndGet();
        QnnHtpBridge.discardNativeCompressedAccessUnit(
                stale.presentationTimeUs, "input_stale_before_codec", false);
        activeInputQueue.recycle(stale);
        inputRecoveryFlushDrops.addAndGet(dependent.size());
        for (DecoderAccessUnitQueue.AccessUnit discarded : dependent) {
            QnnHtpBridge.discardNativeCompressedAccessUnit(
                    discarded.presentationTimeUs, "input_recovery_flush", false);
            activeInputQueue.recycle(discarded);
        }
        if (shouldLog(staleCount)) {
            Log.w(TAG, "decoder_input_stale_before_codec_dropped"
                    + " count=" + staleCount
                    + " dependent_flushed=" + dependent.size()
                    + " awaiting_sync_frame=true fatal=false");
        }
    }

    private void failInput(
            MediaCodec activeCodec,
            DecoderAccessUnitQueue activeInputQueue,
            DecoderAccessUnitQueue.AccessUnit failed,
            String reason,
            DecoderFallbackPolicy.FailureKind failureKind) {
        if (!failActiveDecoder(activeCodec, reason, failureKind)) {
            QnnHtpBridge.discardNativeCompressedAccessUnit(
                    failed.presentationTimeUs,
                    "input_stale_generation", false);
            activeInputQueue.recycle(failed);
            return;
        }
        QnnHtpBridge.discardNativeCompressedAccessUnit(
                failed.presentationTimeUs, reason, true);
        activeInputQueue.recycle(failed);
        List<DecoderAccessUnitQueue.AccessUnit> flushed = activeInputQueue.closeAndDrain();
        inputFatalFlushDrops.addAndGet(flushed.size());
        for (DecoderAccessUnitQueue.AccessUnit discarded : flushed) {
            QnnHtpBridge.discardNativeCompressedAccessUnit(
                    discarded.presentationTimeUs, "input_fatal_flush", false);
            activeInputQueue.recycle(discarded);
        }
        Log.e(TAG, "decoder_input_rejected reason=" + reason
                + " fatal=true flushed=" + flushed.size());
    }

    private void discardDrainedInputs(
            DecoderAccessUnitQueue owner,
            List<DecoderAccessUnitQueue.AccessUnit> discarded,
            String reason) {
        if (discarded.isEmpty()) return;
        if ("input_restart_flush".equals(reason)) {
            inputRestartDrops.addAndGet(discarded.size());
        } else if ("input_stop_flush".equals(reason)) {
            inputStopFlushDrops.addAndGet(discarded.size());
        }
        for (DecoderAccessUnitQueue.AccessUnit accessUnit : discarded) {
            QnnHtpBridge.discardNativeCompressedAccessUnit(
                    accessUnit.presentationTimeUs, reason, false);
            if (owner != null) owner.recycle(accessUnit);
        }
    }

    private static void releaseCodecAfterWorkersExitAsync(
            MediaCodec target, Thread inputWorker, Thread outputWorker, String reason) {
        Thread cleanup = new Thread(() -> {
            long startedNanos = System.nanoTime();
            Log.i(TAG, "decoder_cleanup stage=started reason=" + reason);
            joinWorker(inputWorker, "input", reason);
            joinWorker(outputWorker, "output", reason);
            boolean inputAlive = inputWorker != null && inputWorker.isAlive();
            boolean outputAlive = outputWorker != null && outputWorker.isAlive();
            if (inputAlive || outputAlive) {
                Log.w(TAG, "decoder_cleanup_workers_timeout reason=" + reason
                        + " input_alive=" + inputAlive + " output_alive=" + outputAlive);
            }
            releaseCodec(target);
            Log.i(TAG, "decoder_cleanup stage=completed reason=" + reason
                    + " input_alive=" + inputAlive + " output_alive=" + outputAlive
                    + " elapsed_us=" + (System.nanoTime() - startedNanos) / 1_000L);
        }, "vf-decoder-cleanup");
        cleanup.setDaemon(true);
        cleanup.start();
    }

    private static void joinWorker(Thread worker, String role, String reason) {
        if (worker == null || worker == Thread.currentThread()) return;
        worker.interrupt();
        try {
            worker.join(WORKER_JOIN_TIMEOUT_MILLIS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            Log.w(TAG, "decoder_cleanup_join_interrupted reason=" + reason
                    + " role=" + role);
        }
    }

    private void drainOutput(
            MediaCodec activeCodec,
            DecoderOutputState activeOutputState,
            String activeDescription) {
        promotePipelineThread("output");
        MediaCodec.BufferInfo info = new MediaCodec.BufferInfo();
        try {
            while (running.get() && isActive(activeCodec)) {
                final int index;
                try {
                    index = activeCodec.dequeueOutputBuffer(info, DEQUEUE_TIMEOUT_US);
                } catch (IllegalStateException cancelled) {
                    if (!isActive(activeCodec)) {
                        Log.i(TAG, "stale_decoder_output_cancelled_during_dequeue");
                        break;
                    }
                    String message = cancelled.getMessage();
                    if (running.get() && message != null
                            && message.contains("Pending dequeue output buffer request cancelled")) {
                        Log.w(TAG, "decoder_output_dequeue_cancelled_transient");
                        if (hasOutputStalled(
                                activeCodec, activeOutputState.progress)) {
                            break;
                        }
                        continue;
                    }
                    throw cancelled;
                }
                // A replacement can make running true again while this old generation is still
                // blocked in dequeue. Never let that stale thread publish format/stall state or
                // mutate the counters owned by the replacement codec.
                if (!isActive(activeCodec)) {
                    Log.i(TAG, "stale_decoder_output_cancelled_after_dequeue index=" + index);
                    break;
                }
                if (!running.get()) break;
                if (index == MediaCodec.INFO_OUTPUT_FORMAT_CHANGED) {
                    publishOutputFormat(
                            activeCodec, activeDescription,
                            activeCodec.getOutputFormat());
                    continue;
                }
                if (index < 0) {
                    if (hasOutputStalled(
                            activeCodec, activeOutputState.progress)) {
                        break;
                    }
                    continue;
                }
                Image image = null;
                try {
                    image = activeCodec.getOutputImage(index);
                    if (image == null) {
                        rejectOutput(activeCodec, activeOutputState,
                                info.presentationTimeUs,
                                "output_image_missing", false);
                        continue;
                    }
                    offerImageToNative(
                            activeCodec, activeOutputState, image,
                            info.presentationTimeUs);
                    activeOutputState.progress.recordDecodedOutput(
                            System.nanoTime());
                } finally {
                    if (image != null) {
                        try {
                            image.close();
                        } catch (RuntimeException closeFailure) {
                            Log.e(TAG, "decoder_image_close_failure", closeFailure);
                        }
                    }
                    activeCodec.releaseOutputBuffer(index, false);
                }
            }
        } catch (MediaCodec.CodecException error) {
            if (!failActiveDecoder(
                    activeCodec, error.getDiagnosticInfo(),
                    DecoderFallbackPolicy.FailureKind.CODEC_EXCEPTION)) {
                Log.i(TAG, "stale_decoder_output_cancelled diagnostic="
                        + error.getDiagnosticInfo());
                return;
            }
            Log.e(TAG, "decoder_output_codec_failure diagnostic="
                    + error.getDiagnosticInfo() + " recoverable=" + error.isRecoverable()
                    + " transient=" + error.isTransient(), error);
        } catch (IllegalStateException | IllegalArgumentException error) {
            if (!failActiveDecoder(
                    activeCodec,
                    error.getClass().getSimpleName() + ":output",
                    DecoderFallbackPolicy.FailureKind.STATE_EXCEPTION)) {
                Log.i(TAG, "stale_decoder_output_cancelled type="
                        + error.getClass().getSimpleName());
                return;
            }
            Log.e(TAG, "decoder_output_failure", error);
        } finally {
            Log.i(TAG, "decoder_output_loop_ended running=" + running.get());
        }
    }

    private void offerImageToNative(
            MediaCodec sourceCodec,
            DecoderOutputState activeOutputState,
            Image image,
            long presentationTimeUs) {
        if (!isActive(sourceCodec)) return;
        if (image.getFormat() != ImageFormat.YUV_420_888) {
            rejectOutput(sourceCodec, activeOutputState, presentationTimeUs,
                    "image_format=" + image.getFormat(), true);
            return;
        }
        Image.Plane[] planes = image.getPlanes();
        if (planes == null || planes.length != 3) {
            rejectOutput(sourceCodec, activeOutputState, presentationTimeUs,
                    "plane_count=" + (planes == null ? -1 : planes.length), true);
            return;
        }
        ByteBuffer y = planes[0].getBuffer();
        ByteBuffer u = planes[1].getBuffer();
        ByteBuffer v = planes[2].getBuffer();
        Rect crop = image.getCropRect();
        boolean accepted = QnnHtpBridge.offerNativeDecodedYuv420(
                y, y.position(), y.remaining(), planes[0].getRowStride(), planes[0].getPixelStride(),
                u, u.position(), u.remaining(), planes[1].getRowStride(), planes[1].getPixelStride(),
                v, v.position(), v.remaining(), planes[2].getRowStride(), planes[2].getPixelStride(),
                image.getWidth(), image.getHeight(),
                crop.left, crop.top, crop.right, crop.bottom, presentationTimeUs);
        if (!accepted) {
            if (!isActive(sourceCodec)) return;
            activeOutputState.nativeRejectedOutputs++;
            activeOutputState.consecutiveFailures++;
            if (activeOutputState.consecutiveFailures >= 3
                    && !failActiveDecoder(
                    sourceCodec, "native_plane_rejected",
                    DecoderFallbackPolicy.FailureKind.CODEC_CONTRACT)) {
                return;
            }
            if (shouldLog(activeOutputState.nativeRejectedOutputs)) {
                Log.w(TAG, "decoder_output_native_rejected count="
                        + activeOutputState.nativeRejectedOutputs
                        + " pts_us=" + presentationTimeUs + " crop=" + crop.toShortString());
            }
        } else {
            activeOutputState.consecutiveFailures = 0;
        }
    }

    private void rejectOutput(
            MediaCodec sourceCodec,
            DecoderOutputState activeOutputState,
            long presentationTimeUs,
            String reason,
            boolean immediatelyFatal) {
        if (!isActive(sourceCodec)) return;
        activeOutputState.consecutiveFailures++;
        boolean fatal = immediatelyFatal
                || activeOutputState.consecutiveFailures >= 3;
        QnnHtpBridge.discardNativeDecodedOutput(presentationTimeUs, reason, fatal);
        if (fatal && !failActiveDecoder(
                sourceCodec, reason,
                DecoderFallbackPolicy.FailureKind.CODEC_CONTRACT)) {
            return;
        }
        if (shouldLog(activeOutputState.consecutiveFailures)) {
            Log.e(TAG, "decoder_output_rejected consecutive="
                    + activeOutputState.consecutiveFailures
                    + " reason=" + reason + " fatal=" + fatal);
        }
    }

    private static boolean shouldLog(long count) {
        return count <= 3 || (count & (count - 1)) == 0;
    }

    private void publishOutputFormat(
            MediaCodec sourceCodec,
            String sourceDescription,
            MediaFormat format) {
        int colorFormat = readInteger(format, MediaFormat.KEY_COLOR_FORMAT, -1);
        int colorStandard = readInteger(
                format, MediaFormat.KEY_COLOR_STANDARD, MediaFormat.COLOR_STANDARD_BT709);
        int colorRange = readInteger(
                format, MediaFormat.KEY_COLOR_RANGE, MediaFormat.COLOR_RANGE_LIMITED);
        int width = readInteger(format, MediaFormat.KEY_WIDTH, 0);
        int height = readInteger(format, MediaFormat.KEY_HEIGHT, 0);
        synchronized (lifecycleLock) {
            if (codec != sourceCodec) return;
            QnnHtpBridge.updateNativeH264JavaDecoderFormat(
                    sourceDescription, colorFormat, colorStandard,
                    colorRange, width, height);
        }
        Log.i(TAG, "decoder_output_format " + format);
    }

    private MediaCodec createDecoder() throws IOException {
        if (!forceSoftwareFallback) {
            return MediaCodec.createDecoderByType(MediaFormat.MIMETYPE_VIDEO_AVC);
        }
        for (MediaCodecInfo codecInfo : new MediaCodecList(MediaCodecList.ALL_CODECS).getCodecInfos()) {
            if (codecInfo.isEncoder() || !codecInfo.isSoftwareOnly()
                    || !supportsMime(codecInfo, MediaFormat.MIMETYPE_VIDEO_AVC)) {
                continue;
            }
            Log.w(TAG, "decoder_selecting_software_fallback codec=" + codecInfo.getName());
            return MediaCodec.createByCodecName(codecInfo.getName());
        }
        throw new IOException("No software AVC decoder is available after vendor failure");
    }

    private static boolean supportsMime(MediaCodecInfo codecInfo, String mime) {
        for (String supported : codecInfo.getSupportedTypes()) {
            if (mime.equalsIgnoreCase(supported)) {
                return true;
            }
        }
        return false;
    }

    private static float maximumAdvertisedOperatingRate(
            MediaCodec codec, int width, int height) {
        try {
            double maximumRate = codec.getCodecInfo()
                    .getCapabilitiesForType(MediaFormat.MIMETYPE_VIDEO_AVC)
                    .getVideoCapabilities()
                    .getSupportedFrameRatesFor(width, height)
                    .getUpper();
            if (Double.isFinite(maximumRate) && maximumRate > 0.0) {
                return (float) maximumRate;
            }
        } catch (IllegalArgumentException | IllegalStateException error) {
            Log.w(TAG, "decoder_operating_rate_query_failed codec=" + codec.getName()
                    + " size=" + width + "x" + height, error);
        }
        return 0.0f;
    }

    private static String describeCodec(MediaCodec codec) {
        try {
            MediaCodecInfo info = codec.getCodecInfo();
            return info.getName() + ";canonical=" + info.getCanonicalName()
                    + ";hardware=" + info.isHardwareAccelerated()
                    + ";software=" + info.isSoftwareOnly()
                    + ";vendor=" + info.isVendor();
        } catch (IllegalStateException error) {
            return codec.getName();
        }
    }

    private boolean isActive(MediaCodec candidate) {
        synchronized (lifecycleLock) {
            return codec == candidate;
        }
    }

    /** Commits a fatal result only if the reporting codec still owns state. */
    private boolean failActiveDecoder(
            MediaCodec candidate,
            String diagnostic,
            DecoderFallbackPolicy.FailureKind failureKind) {
        synchronized (lifecycleLock) {
            if (codec != candidate) return false;
            running.set(false);
            recordDecoderFailure(diagnostic, failureKind);
            return true;
        }
    }

    boolean hasFatalFailure() {
        return fatalFailure.get();
    }

    String fatalDiagnostic() {
        return fatalDiagnostic;
    }

    String inputHealthReport() {
        DecoderAccessUnitQueue activeInputQueue;
        DecoderOutputState activeOutputState;
        synchronized (lifecycleLock) {
            activeInputQueue = inputQueue;
            activeOutputState = decoderOutputState;
        }
        int depth = activeInputQueue == null ? 0 : activeInputQueue.size();
        long queuedBytes = activeInputQueue == null ? 0L : activeInputQueue.queuedBytes();
        long highWatermarkBytes = activeInputQueue == null
                ? 0L : activeInputQueue.highWatermarkBytes();
        return "contract=ordered_age_and_byte_bounded_sync_priority"
                + " queue_depth=" + depth
                + " queue_high_watermark=" + inputQueueHighWatermark.get()
                + " queued_bytes=" + queuedBytes
                + " queue_high_watermark_bytes=" + highWatermarkBytes
                + " maximum_queued_bytes=" + MAX_QUEUED_COMPRESSED_BYTES
                + " max_input_age_ms=" + MAX_INPUT_AGE_NANOS / 1_000_000L
                + " media_codec_queued_inputs="
                + activeOutputState.progress.queuedInputs()
                + " decoded_outputs="
                + activeOutputState.progress.decodedOutputs()
                + " no_input_buffer_polls=" + inputNoBufferPolls.get()
                + " stale_before_codec_drops=" + inputStaleBeforeCodecDrops.get()
                + " queue_capacity_drops=" + inputQueueCapacityDrops.get()
                + " buffer_capacity_drops=" + inputBufferCapacityDrops.get()
                + " codec_exception_drops=" + inputCodecExceptionDrops.get()
                + " state_exception_drops=" + inputStateExceptionDrops.get()
                + " restart_drops=" + inputRestartDrops.get()
                + " not_running_drops=" + inputNotRunningDrops.get()
                + " invalid_drops=" + inputInvalidDrops.get()
                + " fatal_flush_drops=" + inputFatalFlushDrops.get()
                + " recovery_flush_drops=" + inputRecoveryFlushDrops.get()
                + " stop_flush_drops=" + inputStopFlushDrops.get()
                + " reference_recovery_drops=" + inputReferenceRecoveryDrops.get()
                + " awaiting_sync_frame="
                + (activeInputQueue != null && activeInputQueue.isAwaitingSyncFrame());
    }

    private void resetInputMetrics() {
        inputNoBufferPolls.set(0);
        inputStaleBeforeCodecDrops.set(0);
        inputQueueCapacityDrops.set(0);
        inputBufferCapacityDrops.set(0);
        inputCodecExceptionDrops.set(0);
        inputStateExceptionDrops.set(0);
        inputRestartDrops.set(0);
        inputNotRunningDrops.set(0);
        inputInvalidDrops.set(0);
        inputFatalFlushDrops.set(0);
        inputRecoveryFlushDrops.set(0);
        inputStopFlushDrops.set(0);
        inputReferenceRecoveryDrops.set(0);
        inputQueueHighWatermark.set(0);
    }

    private void recordFatalFailure(String diagnostic) {
        fatalDiagnostic = diagnostic == null || diagnostic.isBlank() ? "unknown" : diagnostic;
        fatalFailure.set(true);
    }

    private void recordDecoderFailure(
            String diagnostic, DecoderFallbackPolicy.FailureKind failureKind) {
        if (DecoderFallbackPolicy.permitsSoftwareFallback(failureKind)) {
            forceSoftwareFallback = true;
        }
        recordFatalFailure(diagnostic);
    }

    private static void promotePipelineThread(String role) {
        try {
            android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_DISPLAY);
        } catch (IllegalArgumentException | SecurityException error) {
            Log.w(TAG, "decoder_thread_priority_unavailable role=" + role
                    + " type=" + error.getClass().getSimpleName());
        }
    }

    private boolean hasOutputStalled(
            MediaCodec sourceCodec,
            DecoderOutputProgressTracker activeOutputProgress) {
        DecoderOutputProgressTracker.Snapshot progress =
                activeOutputProgress.snapshot(System.nanoTime());
        if (!DecoderOutputStallPolicy.isStalled(
                progress.backlog, progress.stalledNanos, progress.inputIdleNanos)) return false;
        if (!failActiveDecoder(
                sourceCodec,
                "decoder_output_stalled backlog=" + progress.backlog
                        + " stalled_ms="
                        + progress.stalledNanos / 1_000_000L,
                DecoderFallbackPolicy.FailureKind.WATCHDOG_STALL)) {
            return false;
        }
        Log.e(TAG, fatalDiagnostic + " recovery=retry_hardware software_fallback=false");
        return true;
    }

    private static int readInteger(MediaFormat format, String key, int fallback) {
        try {
            return format.containsKey(key) ? format.getInteger(key) : fallback;
        } catch (ClassCastException | NullPointerException error) {
            return fallback;
        }
    }

    private static void releaseCodec(MediaCodec target) {
        try {
            target.stop();
        } catch (IllegalStateException error) {
            Log.w(TAG, "decoder_stop_after_failure", error);
        }
        try {
            target.release();
        } catch (IllegalStateException error) {
            Log.w(TAG, "decoder_release_after_failure", error);
        }
    }
}
