package com.visionforge.inferencebenchmark;

/** Regression coverage for the production phone-side model contracts. */
final class MobileModelCatalogSelfTest {
    private MobileModelCatalogSelfTest() {
    }

    static void run() {
        verifiesDefaultValorantYellow416();
        verifiesOverwatchUsesGeometricHeadTarget();
        verifiesEveryMigratedModelIsProductionSelectable();
        verifiesDeltaForceClassMapping();
        verifiesCounterStrike2FactionMappings();
        verifiesAllProfilesAre416QnnGraphs();
    }

    private static void verifiesDefaultValorantYellow416() {
        MobileModelCatalog.Profile model = MobileModelCatalog.DEFAULT;

        require(model == MobileModelCatalog.VALORANT);
        require("valorant-yellow-416-v11s-no-flash".equals(model.token));
        require("libvalorant_416_v11s_no_flash_w8a16.so".equals(model.qnnLibrary));
        require("valorant-yellow-416-v11s-no-flash.onnx".equals(
                model.portableModelAsset));
        require(model.portableModelBytes == 44_641_316L);
        require(model.portableModelSha256.length() == 64);
        require(model.inputWidth == 416 && model.inputHeight == 416);
        require(model.anchorCount == 3549 && model.classCount == 5);
        require(model.bodyClassId == 0 && model.headClassId == 1);
        require(model.classIdFor(MobileAimTarget.BODY) == 0);
        require(model.classIdFor(MobileAimTarget.HEAD) == 1);
        require(model.usesHeadBox(MobileAimTarget.HEAD));
        require(!model.usesGeometricHead(MobileAimTarget.HEAD));
        require(!model.supports(MobileAimTarget.TEAMMATE));
        require(MobileModelCatalog.forToken(model.token) == model);
        require(MobileModelCatalog.forToken("missing") == MobileModelCatalog.DEFAULT);
    }

    private static void verifiesOverwatchUsesGeometricHeadTarget() {
        MobileModelCatalog.Profile model = MobileModelCatalog.OVERWATCH_2;

        require("overwatch2-416-yolov5".equals(model.token));
        require("libow2_416_w8a16.so".equals(model.qnnLibrary));
        require(model.inputWidth == 416 && model.inputHeight == 416);
        require(model.anchorCount == 3549 && model.classCount == 2);
        require(model.defaultConfidence == 0.20f);
        require(model.bodyClassId == 0 && model.headClassId == -1);
        require(model.supports(MobileAimTarget.BODY));
        require(model.supports(MobileAimTarget.HEAD));
        require(!model.supports(MobileAimTarget.TEAMMATE));
        require(!model.supports(MobileAimTarget.AI));
        require(!model.supports(MobileAimTarget.CROSSHAIR));
        require(model.classIdFor(MobileAimTarget.BODY) == 0);
        require(model.classIdFor(MobileAimTarget.HEAD) == 0);
        requireUnsupportedTarget(model, MobileAimTarget.TEAMMATE);
        requireUnsupportedTarget(model, MobileAimTarget.AI);
        requireUnsupportedTarget(model, MobileAimTarget.CROSSHAIR);
        require(!model.usesHeadBox(MobileAimTarget.HEAD));
        require(model.usesGeometricHead(MobileAimTarget.HEAD));
        require(model.targetYRatio(MobileAimTarget.HEAD) == 0.18f);
        require(model.targetYRatio(MobileAimTarget.BODY) == 0.50f);
        require(model.defaultControlGain == 0.60f);
        require(model.defaultDeadzonePixels == 0.5f);
    }

    private static void verifiesEveryMigratedModelIsProductionSelectable() {
        require(MobileModelCatalog.isProductionSelectable(MobileModelCatalog.VALORANT));
        require(MobileModelCatalog.isProductionSelectable(MobileModelCatalog.OVERWATCH_2));
        require(MobileModelCatalog.isProductionSelectable(MobileModelCatalog.DELTA_FORCE));
        require(MobileModelCatalog.isProductionSelectable(
                MobileModelCatalog.COUNTER_STRIKE_2));
        require(MobileModelCatalog.PRODUCTION_SELECTABLE.length == 4);
        for (MobileModelCatalog.Profile selectable : MobileModelCatalog.PRODUCTION_SELECTABLE) {
            require(MobileModelCatalog.forToken(selectable.token) == selectable);
            require(MobileModelCatalog.forProductionToken(selectable.token) == selectable);
        }
    }

    private static void verifiesDeltaForceClassMapping() {
        MobileModelCatalog.Profile model = MobileModelCatalog.DELTA_FORCE;

        require("delta-force-416-v8s".equals(model.token));
        require("libdelta_416_v8s_w8a16.so".equals(model.qnnLibrary));
        require(model.inputWidth == 416 && model.inputHeight == 416);
        require(model.anchorCount == 3549 && model.classCount == 5);
        require(model.defaultConfidence == 0.20f);
        require(model.bodyClassId == 0 && model.headClassId == 1);
        require(model.classIdFor(MobileAimTarget.BODY) == 0);
        require(model.classIdFor(MobileAimTarget.HEAD) == 1);
        require(model.classIdFor(MobileAimTarget.TEAMMATE) == 2);
        require(model.classIdFor(MobileAimTarget.AI) == 3);
        require(model.classIdFor(MobileAimTarget.CROSSHAIR) == 4);
        require(model.usesHeadBox(MobileAimTarget.HEAD));
        require(!model.usesGeometricHead(MobileAimTarget.HEAD));
    }

    private static void verifiesCounterStrike2FactionMappings() {
        MobileModelCatalog.Profile model = MobileModelCatalog.COUNTER_STRIKE_2;

        require("counter-strike-2-vombit-416-v8s".equals(model.token));
        require("libcs2_vombit_416_v8s_w8a16.so".equals(model.qnnLibrary));
        require(model.inputWidth == 416 && model.inputHeight == 416);
        require(model.anchorCount == 3549 && model.classCount == 4);
        require(model.defaultConfidence == 0.25f);
        require(model.defaultAimTarget == MobileAimTarget.T_HEAD);
        require(model.bodyClassId == 2 && model.headClassId == 3);
        require(model.bodyClassIdFor(MobileAimTarget.CT_BODY) == 0);
        require(model.headClassIdFor(MobileAimTarget.CT_BODY) == 1);
        require(model.classIdFor(MobileAimTarget.CT_BODY) == 0);
        require(model.classIdFor(MobileAimTarget.CT_HEAD) == 1);
        require(model.bodyClassIdFor(MobileAimTarget.T_HEAD) == 2);
        require(model.headClassIdFor(MobileAimTarget.T_HEAD) == 3);
        require(model.classIdFor(MobileAimTarget.T_BODY) == 2);
        require(model.classIdFor(MobileAimTarget.T_HEAD) == 3);
        require(model.usesHeadBox(MobileAimTarget.CT_HEAD));
        require(model.usesHeadBox(MobileAimTarget.T_HEAD));
        require(!model.usesHeadBox(MobileAimTarget.CT_BODY));
        require(!model.usesGeometricHead(MobileAimTarget.T_HEAD));
        require(!model.supports(MobileAimTarget.BODY));
        require(!model.supports(MobileAimTarget.HEAD));
        requireUnsupportedTarget(model, MobileAimTarget.BODY);
        requireUnsupportedTarget(model, MobileAimTarget.HEAD);
    }

    private static void verifiesAllProfilesAre416QnnGraphs() {
        require(MobileModelCatalog.ALL.length == 4);
        for (MobileModelCatalog.Profile model : MobileModelCatalog.ALL) {
            require(model.inputWidth == 416 && model.inputHeight == 416);
            require(model.anchorCount == 3549);
            require(model.qnnLibrary.startsWith("lib"));
            require(model.qnnLibrary.endsWith(".so"));
            require(model.portableModelAsset.endsWith(".onnx"));
            require(model.portableModelBytes > 0L);
            require(model.portableModelSha256.matches("[0-9A-F]{64}"));
            require(model.defaultConfidence >= model.minimumConfidence);
            require(model.defaultConfidence <= model.maximumConfidence);
            require(model.supports(model.defaultAimTarget));
        }
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("Mobile model catalog contract failed");
    }

    private static void requireUnsupportedTarget(
            MobileModelCatalog.Profile model, MobileAimTarget target) {
        try {
            model.classIdFor(target);
            throw new AssertionError("Mobile model catalog accepted unsupported target");
        } catch (IllegalArgumentException expected) {
            // Expected fail-closed path for unsupported classes.
        }
    }
}
