package com.visionforge.mobile.domain.control;

import java.util.Objects;

/**
 * 控制输出的单一 fail-closed 判定器。
 *
 * <p>“检测到了目标”不等于“具备跟踪资格”；deadzone 与 subcount 不可解析也不是
 * 同一种状态。把这些概念拆开后，UI、日志和恢复策略才能指向真实 blocker。</p>
 */
public final class ControlDecisionEngine {
    public enum Blocker {
        RUNNABLE,
        TRANSPORT_NOT_READY,
        NO_FRESH_CONTENT,
        DETECTION_ABSENT,
        DETECTED_NOT_TRACK_ELIGIBLE,
        INSIDE_DEADZONE,
        SUBCOUNT_UNRESOLVABLE,
        TICKET_PENDING,
        POST_ACK_VISIBILITY,
        RECOVERY_REQUIRED
    }

    public record Facts(
            boolean transportReady,
            boolean freshContent,
            boolean detectionPresent,
            boolean trackEligible,
            boolean insideDeadzone,
            boolean subcountResolvable,
            boolean ticketPending,
            boolean postAckVisible,
            boolean recoveryRequired) {}

    public record Decision(boolean outputAllowed, Blocker blocker) {
        public Decision {
            Objects.requireNonNull(blocker, "blocker");
            if (outputAllowed != (blocker == Blocker.RUNNABLE)) {
                throw new IllegalArgumentException("output permission and blocker disagree");
            }
        }
    }

    public Decision decide(Facts facts) {
        Objects.requireNonNull(facts, "facts");
        if (facts.recoveryRequired()) {
            return blocked(Blocker.RECOVERY_REQUIRED);
        }
        if (!facts.transportReady()) {
            return blocked(Blocker.TRANSPORT_NOT_READY);
        }
        if (!facts.freshContent()) {
            return blocked(Blocker.NO_FRESH_CONTENT);
        }
        if (!facts.detectionPresent()) {
            return blocked(Blocker.DETECTION_ABSENT);
        }
        if (!facts.trackEligible()) {
            return blocked(Blocker.DETECTED_NOT_TRACK_ELIGIBLE);
        }
        if (!facts.subcountResolvable()) {
            return blocked(Blocker.SUBCOUNT_UNRESOLVABLE);
        }
        if (facts.insideDeadzone()) {
            return blocked(Blocker.INSIDE_DEADZONE);
        }
        if (facts.ticketPending()) {
            return blocked(Blocker.TICKET_PENDING);
        }
        if (!facts.postAckVisible()) {
            return blocked(Blocker.POST_ACK_VISIBILITY);
        }
        return new Decision(true, Blocker.RUNNABLE);
    }

    private static Decision blocked(Blocker blocker) {
        return new Decision(false, blocker);
    }
}
