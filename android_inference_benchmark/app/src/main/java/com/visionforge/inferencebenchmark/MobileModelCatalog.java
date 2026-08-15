package com.visionforge.inferencebenchmark;

/** Immutable Java-side mirror of model lifecycle data required before JNI is ready. */
public final class MobileModelCatalog {
    public static final Profile VALORANT = new Profile(
            "valorant-yellow-416-v11s-no-flash",
            "libvalorant_416_v11s_no_flash_w8a16.so",
            "valorant-yellow-416-v11s-no-flash.onnx",
            44_641_316L,
            "6BF15ED6554667C1FAD4D7240F7E5EB2AD3EE76CCDE121D0B69E8E5963F95669",
            416,
            416,
            3549,
            5,
            0.27f,
            0.45f,
            0.10f,
            0.85f,
            0.36f,
            0.5f,
            127,
            MobileAimTarget.HEAD,
            bodyTarget(MobileAimTarget.BODY, 0, 1),
            headBoxTarget(MobileAimTarget.HEAD, 0, 1));
    public static final Profile OVERWATCH_2 = new Profile(
            "overwatch2-416-yolov5",
            "libow2_416_w8a16.so",
            "overwatch2-416-yolov5.onnx",
            9_038_527L,
            "805C575BBF6FFEE00002BC20D4BFAF362AABD5DB9B839C457C78416C2756FBA3",
            416,
            416,
            3549,
            2,
            0.20f,
            0.45f,
            0.10f,
            0.85f,
            0.60f,
            0.5f,
            127,
            MobileAimTarget.HEAD,
            bodyTarget(MobileAimTarget.BODY, 0, -1),
            geometricHeadTarget(MobileAimTarget.HEAD, 0));
    public static final Profile DELTA_FORCE = new Profile(
            "delta-force-416-v8s",
            "libdelta_416_v8s_w8a16.so",
            "delta-force-416-v8s.onnx",
            44_641_532L,
            "AA560084EB4880AA748E4B32FE545C0AA37EC1FA9EBA55F3B986B3E577BD347A",
            416,
            416,
            3549,
            5,
            0.20f,
            0.70f,
            0.10f,
            0.85f,
            0.36f,
            0.5f,
            127,
            MobileAimTarget.HEAD,
            bodyTarget(MobileAimTarget.BODY, 0, 1),
            headBoxTarget(MobileAimTarget.HEAD, 0, 1),
            directClassTarget(MobileAimTarget.TEAMMATE, 0, 1, 2),
            directClassTarget(MobileAimTarget.AI, 0, 1, 3),
            directClassTarget(MobileAimTarget.CROSSHAIR, 0, 1, 4));
    public static final Profile COUNTER_STRIKE_2 = new Profile(
            "counter-strike-2-vombit-416-v8s",
            "libcs2_vombit_416_v8s_w8a16.so",
            "counter-strike-2-vombit-416-v8s.onnx",
            44_653_998L,
            "DD70F00F040421EA216C3FC913B35E9BE822F65F4C3354C41F6787F5282E0E7D",
            416,
            416,
            3549,
            4,
            0.25f,
            0.45f,
            0.10f,
            0.85f,
            0.36f,
            0.5f,
            127,
            MobileAimTarget.T_HEAD,
            bodyTarget(MobileAimTarget.CT_BODY, 0, 1),
            headBoxTarget(MobileAimTarget.CT_HEAD, 0, 1),
            bodyTarget(MobileAimTarget.T_BODY, 2, 3),
            headBoxTarget(MobileAimTarget.T_HEAD, 2, 3));
    public static final Profile DEFAULT = VALORANT;
    public static final Profile[] ALL = {
            VALORANT, OVERWATCH_2, DELTA_FORCE, COUNTER_STRIKE_2};
    public static final Profile[] PRODUCTION_SELECTABLE = {
            VALORANT, OVERWATCH_2, DELTA_FORCE, COUNTER_STRIKE_2};

    private MobileModelCatalog() {}

    private static AimTargetContract bodyTarget(
            MobileAimTarget target, int bodyClassId, int headClassId) {
        return new AimTargetContract(
                target, bodyClassId, headClassId, bodyClassId, false, false, 0.50f);
    }

    private static AimTargetContract headBoxTarget(
            MobileAimTarget target, int bodyClassId, int headClassId) {
        return new AimTargetContract(
                target, bodyClassId, headClassId, headClassId, true, false, 0.50f);
    }

    private static AimTargetContract geometricHeadTarget(
            MobileAimTarget target, int bodyClassId) {
        return new AimTargetContract(
                target, bodyClassId, -1, bodyClassId, false, true, 0.18f);
    }

    private static AimTargetContract directClassTarget(
            MobileAimTarget target, int bodyClassId, int headClassId, int selectedClassId) {
        return new AimTargetContract(
                target, bodyClassId, headClassId, selectedClassId, false, false, 0.50f);
    }

    public static Profile forToken(String token) {
        if (token != null) {
            for (Profile profile : ALL) {
                if (profile.token.equals(token)) return profile;
            }
        }
        return DEFAULT;
    }

    public static Profile forProductionToken(String token) {
        if (token != null) {
            for (Profile profile : PRODUCTION_SELECTABLE) {
                if (profile.token.equals(token)) return profile;
            }
        }
        return DEFAULT;
    }

    public static boolean isProductionSelectable(Profile profile) {
        if (profile == null) return false;
        for (Profile candidate : PRODUCTION_SELECTABLE) {
            if (candidate == profile) return true;
        }
        return false;
    }

    public static final class Profile {
        public final String token;
        public final String qnnLibrary;
        public final String portableModelAsset;
        public final long portableModelBytes;
        public final String portableModelSha256;
        public final int inputWidth;
        public final int inputHeight;
        public final int anchorCount;
        public final int classCount;
        public final int bodyClassId;
        public final int headClassId;
        public final float defaultConfidence;
        public final float nmsIou;
        public final float minimumConfidence;
        public final float maximumConfidence;
        public final float defaultControlGain;
        public final float defaultDeadzonePixels;
        public final int defaultMaximumAxisDelta;
        public final MobileAimTarget defaultAimTarget;
        public final MobileAimTarget[] aimTargets;
        private final AimTargetContract[] aimTargetContracts;

        Profile(
                String token,
                String qnnLibrary,
                String portableModelAsset,
                long portableModelBytes,
                String portableModelSha256,
                int inputWidth,
                int inputHeight,
                int anchorCount,
                int classCount,
                float defaultConfidence,
                float nmsIou,
                float minimumConfidence,
                float maximumConfidence,
                float defaultControlGain,
                float defaultDeadzonePixels,
                int defaultMaximumAxisDelta,
                MobileAimTarget defaultAimTarget,
                AimTargetContract... aimTargetContracts) {
            if (token == null || token.isBlank() || qnnLibrary == null || qnnLibrary.isBlank()
                    || portableModelAsset == null || portableModelAsset.isBlank()
                    || portableModelBytes <= 0L
                    || portableModelSha256 == null
                    || !portableModelSha256.matches("[0-9A-F]{64}")
                    || inputWidth <= 0 || inputHeight <= 0
                    || anchorCount <= 0 || classCount <= 0
                    || !validThreshold(defaultConfidence)
                    || !validThreshold(nmsIou)
                    || !validThreshold(minimumConfidence)
                    || !validThreshold(maximumConfidence)
                    || minimumConfidence > defaultConfidence
                    || defaultConfidence > maximumConfidence
                    || !Float.isFinite(defaultControlGain) || defaultControlGain < 0.01f
                    || defaultControlGain > 2.0f
                    || !Float.isFinite(defaultDeadzonePixels) || defaultDeadzonePixels < 0.0f
                    || defaultDeadzonePixels > 64.0f
                    || defaultMaximumAxisDelta < 1 || defaultMaximumAxisDelta > 127
                    || defaultAimTarget == null || aimTargetContracts == null
                    || aimTargetContracts.length == 0) {
                throw new IllegalArgumentException("invalid mobile model profile");
            }
            this.token = token;
            this.qnnLibrary = qnnLibrary;
            this.portableModelAsset = portableModelAsset;
            this.portableModelBytes = portableModelBytes;
            this.portableModelSha256 = portableModelSha256;
            this.inputWidth = inputWidth;
            this.inputHeight = inputHeight;
            this.anchorCount = anchorCount;
            this.classCount = classCount;
            this.defaultConfidence = defaultConfidence;
            this.nmsIou = nmsIou;
            this.minimumConfidence = minimumConfidence;
            this.maximumConfidence = maximumConfidence;
            this.defaultControlGain = defaultControlGain;
            this.defaultDeadzonePixels = defaultDeadzonePixels;
            this.defaultMaximumAxisDelta = defaultMaximumAxisDelta;
            this.defaultAimTarget = defaultAimTarget;
            this.aimTargetContracts = aimTargetContracts.clone();
            this.aimTargets = new MobileAimTarget[aimTargetContracts.length];
            for (int index = 0; index < aimTargetContracts.length; index++) {
                AimTargetContract contract = aimTargetContracts[index];
                if (!contract.isValidFor(classCount) || containsTarget(contract.target, index)) {
                    throw new IllegalArgumentException("invalid mobile aim target contract");
                }
                this.aimTargets[index] = contract.target;
            }
            AimTargetContract defaultContract = contractFor(defaultAimTarget);
            if (defaultContract == null) {
                throw new IllegalArgumentException("default aim target is unsupported");
            }
            this.bodyClassId = defaultContract.bodyClassId;
            this.headClassId = defaultContract.headClassId;
        }

        public boolean supports(MobileAimTarget target) {
            if (target == null) return false;
            for (MobileAimTarget candidate : aimTargets) {
                if (candidate == target) return true;
            }
            return false;
        }

        public int classIdFor(MobileAimTarget target) {
            return requireContract(target).selectedClassId;
        }

        public int bodyClassIdFor(MobileAimTarget target) {
            return requireContract(target).bodyClassId;
        }

        public int headClassIdFor(MobileAimTarget target) {
            return requireContract(target).headClassId;
        }

        public boolean usesHeadBox(MobileAimTarget target) {
            return requireContract(target).usesHeadBox;
        }

        public boolean usesGeometricHead(MobileAimTarget target) {
            return requireContract(target).usesGeometricHead;
        }

        public float targetYRatio(MobileAimTarget target) {
            return requireContract(target).targetYRatio;
        }

        private AimTargetContract requireContract(MobileAimTarget target) {
            AimTargetContract contract = contractFor(target);
            if (contract == null) throw new IllegalArgumentException("unsupported aim target");
            return contract;
        }

        private AimTargetContract contractFor(MobileAimTarget target) {
            if (target == null) return null;
            for (AimTargetContract contract : aimTargetContracts) {
                if (contract.target == target) return contract;
            }
            return null;
        }

        private boolean containsTarget(MobileAimTarget target, int beforeIndex) {
            for (int index = 0; index < beforeIndex; index++) {
                if (aimTargetContracts[index].target == target) return true;
            }
            return false;
        }

        private static boolean validThreshold(float value) {
            return Float.isFinite(value) && value >= 0.0f && value <= 1.0f;
        }
    }

    private static final class AimTargetContract {
        final MobileAimTarget target;
        final int bodyClassId;
        final int headClassId;
        final int selectedClassId;
        final boolean usesHeadBox;
        final boolean usesGeometricHead;
        final float targetYRatio;

        AimTargetContract(
                MobileAimTarget target,
                int bodyClassId,
                int headClassId,
                int selectedClassId,
                boolean usesHeadBox,
                boolean usesGeometricHead,
                float targetYRatio) {
            this.target = target;
            this.bodyClassId = bodyClassId;
            this.headClassId = headClassId;
            this.selectedClassId = selectedClassId;
            this.usesHeadBox = usesHeadBox;
            this.usesGeometricHead = usesGeometricHead;
            this.targetYRatio = targetYRatio;
        }

        boolean isValidFor(int classCount) {
            boolean classesValid = target != null
                    && bodyClassId >= 0 && bodyClassId < classCount
                    && headClassId >= -1 && headClassId < classCount
                    && selectedClassId >= 0 && selectedClassId < classCount;
            boolean geometryValid = !(usesHeadBox && usesGeometricHead)
                    && (!usesHeadBox || headClassId >= 0 && selectedClassId == headClassId)
                    && (!usesGeometricHead || headClassId < 0
                    && selectedClassId == bodyClassId);
            return classesValid && geometryValid && Float.isFinite(targetYRatio)
                    && targetYRatio >= 0.0f && targetYRatio <= 1.0f;
        }
    }
}
