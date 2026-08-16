package com.visionforge.inferencebenchmark;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.regex.Pattern;

/** Static JNI contract: the Java callback class is the third native argument and is bound. */
final class MakcuJniContractSelfTest {
    private static final String PROJECT_DIRECTORY_PROPERTY =
            "visionforge.android.project.dir";

    static void run() throws Exception {
        String projectDirectory = System.getProperty(PROJECT_DIRECTORY_PROPERTY, "");
        require(!projectDirectory.isEmpty());
        Path sourceRoot = Paths.get(projectDirectory, "src", "main");
        String javaBridge = readUtf8(sourceRoot.resolve(Paths.get(
                "java", "com", "visionforge", "inferencebenchmark", "QnnHtpBridge.java")));
        String controlProfile = readUtf8(sourceRoot.resolve(Paths.get(
                "java", "com", "visionforge", "inferencebenchmark", "ControlProfile.java")));
        String controller = readUtf8(sourceRoot.resolve(Paths.get(
                "java", "com", "visionforge", "inferencebenchmark", "MakcuSerialController.java")));
        String dispatcher = readUtf8(sourceRoot.resolve(Paths.get(
                "java", "com", "visionforge", "inferencebenchmark",
                "ControlOutputMoveDispatcher.java")));
        String moveDeadline = readUtf8(sourceRoot.resolve(Paths.get(
                "java", "com", "visionforge", "inferencebenchmark",
                "ControlMoveDeadline.java")));
        String nativeBridge = readUtf8(sourceRoot.resolve(Paths.get(
                "cpp", "QnnHtpBridge.cpp")));
        String moveBridge = readUtf8(sourceRoot.resolve(Paths.get(
                "cpp", "MakcuMoveBridge.cpp")));

        require(Pattern.compile("static\\s+native\\s+boolean\\s+bindNativeMakcuMoveBridge"
                + "\\s*\\(Class<\\?>\\s+controllerClass\\s*\\)\\s*;")
                .matcher(javaBridge).find());
        require(Pattern.compile("if\\s*\\(\\s*!QnnHtpBridge\\.bindNativeMakcuMoveBridge"
                + "\\s*\\(ControlOutputMoveDispatcher\\.class\\s*\\)\\s*\\)")
                .matcher(controller).find());
        require(Pattern.compile("final\\s+class\\s+MakcuSerialController\\s+implements\\s+"
                + "MakcuConnection\\s*,\\s*MakcuButtonInput\\s*,\\s*ControlOutputMoveSink")
                .matcher(controller).find());
        java.util.regex.Matcher javaBudget = Pattern.compile(
                "DEFAULT_BUDGET_US\\s*=\\s*([0-9_]+)L")
                .matcher(moveDeadline);
        java.util.regex.Matcher nativeBudget = Pattern.compile(
                "kMaximumMoveCompletionAgeUs\\s*=\\s*([0-9']+)U")
                .matcher(moveBridge);
        require(javaBudget.find() && nativeBudget.find());
        require(parseNumericLiteral(javaBudget.group(1))
                == parseNumericLiteral(nativeBudget.group(1)));

        require(Pattern.compile("static\\s+boolean\\s+offerNativeMove\\s*\\("
                        + "\\s*int\\s+deltaX\\s*,\\s*int\\s+deltaY\\s*,"
                        + "\\s*long\\s+ticket\\s*,"
                        + "\\s*long\\s+remainingBudgetUs\\s*\\).*?"
                        + "current\\.offerMoveFromNative\\("
                        + "\\s*deltaX,\\s*deltaY,\\s*ticket,"
                        + "\\s*remainingBudgetUs\\s*\\)",
                Pattern.DOTALL).matcher(dispatcher).find());
        require(dispatcher.contains(
                "current.suspendMoveDeliveryForNativeRecovery(generation)"));
        require(dispatcher.contains(
                "current.resumeMoveDeliveryAfterNativeRecovery(generation)"));
        require(dispatcher.contains("current.failClosedNativeMoveDelivery()"));
        require(Pattern.compile("offerMoveFromNative\\s*\\("
                        + "\\s*int\\s+deltaX\\s*,\\s*int\\s+deltaY\\s*,"
                        + "\\s*long\\s+ticket\\s*,"
                        + "\\s*long\\s+remainingBudgetUs\\s*\\)")
                .matcher(controller).find());
        require(controller.contains("suspendMoveDeliveryForNativeRecovery(long generation)"));
        require(controller.contains("resumeMoveDeliveryAfterNativeRecovery(long generation)"));
        require(controller.contains("failClosedNativeMoveDelivery()"));
        require(controller.contains("suspendNativeDeliveryForRecovery(long generation)"));
        require(controller.contains("resumeNativeDeliveryAfterRecovery(long generation)"));
        require(controller.contains("failClosedNativeDelivery()"));
        require(controller.contains("UsbManager.ACTION_USB_DEVICE_ATTACHED"));
        require(controller.contains("handleDeviceAttached(device)"));
        require(controller.contains("automatic_connect=true"));
        require(Pattern.compile("offerNativeMove\\s*\\("
                        + "\\s*int\\s+deltaX\\s*,\\s*int\\s+deltaY\\s*,"
                        + "\\s*long\\s+ticket\\s*,"
                        + "\\s*long\\s+remainingBudgetUs\\s*\\)")
                .matcher(controller).find());
        require(Pattern.compile("private\\s+boolean\\s+offerMove\\s*\\(.*?"
                        + "!deliveryGate\\.isPhysicalTriggerSatisfied\\(\\).*?"
                        + "pendingMoveSlot\\.offer\\("
                        + "packed,\\s*ticket,\\s*deadlineNanos\\).*?"
                        + "!deliveryGate\\.isPhysicalTriggerSatisfied\\(\\)",
                Pattern.DOTALL).matcher(controller).find());
        require(controller.contains(
                "pendingMoveSlot.takeInto(reusablePendingMove)"));
        require(!controller.contains("pendingMoveSlot.take()"));
        require(!controller.contains("SystemClock.sleep(2L)"));
        require(controller.contains(
                "private final AtomicLong responseReaderLeaseGeneration"));
        require(Pattern.compile("if\\s*\\(\\s*!startResponseReader"
                        + "\\(attempt\\.generation\\)\\s*\\)\\s*\\{"
                        + ".*?closeActiveTransport\\(\\).*?return\\s+false",
                Pattern.DOTALL).matcher(controller).find());
        require(Pattern.compile("runResponseReader\\s*\\(.*?readerLease.*?"
                        + "connectionGeneration.*?RawUsbTransport\\s+target.*?"
                        + "MakcuResponseStreamParser\\s+parser",
                Pattern.DOTALL).matcher(controller).find());
        require(Pattern.compile("isResponseReaderLeaseCurrent\\s*\\(.*?"
                        + "responseReaderLeaseGeneration\\.get\\(\\)"
                        + "\\s*==\\s*readerLease.*?activeConnectionGeneration"
                        + "\\s*==\\s*connectionGeneration.*?activeTransport\\s*==\\s*target",
                Pattern.DOTALL).matcher(controller).find());
        require(Pattern.compile("while\\s*\\(isResponseReaderLeaseCurrent\\s*\\("
                        + "\\s*readerLease\\s*,\\s*connectionGeneration\\s*,\\s*target\\s*\\)\\)"
                        + ".*?if\\s*\\(read\\s*>\\s*0\\).*?"
                        + "!isResponseReaderLeaseCurrent\\s*\\("
                        + "\\s*readerLease\\s*,\\s*connectionGeneration\\s*,\\s*target\\s*\\)"
                        + ".*?break\\s*;.*?parser\\.accept\\(buffer,\\s*read\\)",
                Pattern.DOTALL).matcher(controller).find());
        require(controller.contains("parser.accept(buffer, read)"));
        require(controller.contains("private final Object buttonStateLock"));
        require(Pattern.compile("onButtonMask\\s*\\(int\\s+mask\\)"
                        + ".*?synchronized\\s*\\(buttonStateLock\\).*?"
                        + "deliveryGate\\.updatePhysicalButtonMask\\(mask\\)",
                Pattern.DOTALL).matcher(controller).find());
        require(controller.contains(
                "expectedResponseConnectionGeneration = connectionGeneration"));
        require(controller.contains("expectedResponseReaderLease = readerLease"));
        require(Pattern.compile("onResponse\\s*\\(String\\s+response\\).*?"
                        + "expectedResponseConnectionGeneration"
                        + "\\s*==\\s*connectionGeneration.*?"
                        + "expectedResponseReaderLease\\s*==\\s*readerLease.*?"
                        + "expectedResponseAcknowledged\\s*=\\s*true",
                Pattern.DOTALL).matcher(controller).find());
        require(Pattern.compile("onResponseOverflow\\s*\\(\\).*?"
                        + "responseParserOverflows\\.incrementAndGet\\(\\).*?"
                        + "throw\\s+new\\s+IllegalStateException",
                Pattern.DOTALL).matcher(controller).find());
        require(controller.contains("responseReaderLeaseGeneration.incrementAndGet();"));
        require(Pattern.compile("public\\s+boolean\\s+isReady\\s*\\(\\)"
                        + ".*?isVerifiedSerialTransportReady\\(\\)"
                        + "\\s*&&\\s*responseReaderRunning\\.get\\(\\)",
                Pattern.DOTALL).matcher(controller).find());
        require(!controller.contains("catch (RuntimeException exception) {\n"
                + "                    read = -1;"));
        require(controller.contains("handleUnexpectedResponseReaderStop("));
        require(controller.contains(
                "response_reader_stopped type="));
        require(Pattern.compile("responseReaderLeaseGeneration\\.get\\(\\)"
                        + "\\s*==\\s*readerLease.*?activeConnectionGeneration"
                        + "\\s*==\\s*connectionGeneration.*?activeTransport\\s*==\\s*target"
                        + ".*?protocolIdentityVerified\\s*=\\s*false"
                        + ".*?recordDeliveryFailureLocked",
                Pattern.DOTALL).matcher(controller).find());
        require(controller.contains(
                "invalidateProtocolAfterDeliveryFailureLocked("));
        require(Pattern.compile("invalidateProtocolAfterDeliveryFailureLocked"
                        + "\\s*\\(String\\s+reason\\).*?"
                        + "protocolIdentityVerified\\s*=\\s*false.*?"
                        + "activeConnectionGeneration\\s*=\\s*0L.*?"
                        + "recordDeliveryFailureLocked\\(reason\\s*\\+\\s*"
                        + "\" reconnect_required=true\"\\).*?"
                        + "notifyReconnectFailure\\(\\)",
                Pattern.DOTALL).matcher(controller).find());
        require(Pattern.compile("invalidateProtocolAfterDeliveryFailureLocked"
                        + "\\s*\\(\\s*\"partial_write bytes=\"",
                Pattern.DOTALL).matcher(controller).find());
        require(Pattern.compile("invalidateProtocolAfterDeliveryFailureLocked"
                        + "\\s*\\(\\s*\"button_stream_partial_write bytes=\"",
                Pattern.DOTALL).matcher(controller).find());
        require(Pattern.compile("configureButtonStream\\(desired\\)\\s*;"
                        + ".*?catch\\s*\\(RuntimeException\\s*\\|\\s*LinkageError\\s+failure\\)"
                        + ".*?handleUnexpectedButtonStreamConfigurationFailure\\(failure\\)",
                Pattern.DOTALL).matcher(controller).find());
        require(Pattern.compile("handleUnexpectedButtonStreamConfigurationFailure"
                        + "\\s*\\(Throwable\\s+failure\\).*?"
                        + "buttonStreamReady\\.set\\(false\\).*?"
                        + "invalidateProtocolAfterDeliveryFailureLocked\\s*\\("
                        + "\\s*\"button_stream_exception type=\".*?"
                        + "makcu_button_stream_exception.*?reconnect_required=true",
                Pattern.DOTALL).matcher(controller).find());
        require(controller.contains("private final Object bulkInTransferLock"));
        require(controller.contains("private final Object bulkOutTransferLock"));
        require(!Pattern.compile(
                        "private\\s+synchronized\\s+int\\s+(?:read|write)\\s*\\(")
                .matcher(controller).find());
        require(Pattern.compile("private\\s+void\\s+writeMoveIfStillAllowed\\s*\\(.*?"
                        + "!deliveryGate\\.isPhysicalTriggerSatisfied\\(\\).*?"
                        + "target\\.write\\(command",
                Pattern.DOTALL).matcher(controller).find());
        require(controller.indexOf(
                        "deliveryGate.updatePhysicalButtonMask(mask)")
                < controller.indexOf("notifyButtonStateChanged(mask)"));
        require(Pattern.compile("if\\s*\\(\\s*previous\\s*!=\\s*mask\\s*\\)\\s*\\{"
                        + "\\s*notifyButtonStateChanged\\(mask\\)", Pattern.DOTALL)
                .matcher(controller).find());
        require(!controller.contains("previous != mask || buttonStreamReady.get()"));
        require(Pattern.compile("reportNativeMakcuMoveResult\\s*\\("
                        + "\\s*ticket\\s*,\\s*true\\s*,"
                        + "\\s*acknowledgementMicros\\s*\\)")
                .matcher(controller).find());
        require(Pattern.compile("static\\s+native\\s+void\\s+"
                        + "reportNativeMakcuMoveResult\\s*\\("
                        + "\\s*long\\s+ticket\\s*,"
                        + "\\s*boolean\\s+deviceAcknowledged\\s*,"
                        + "\\s*long\\s+acknowledgementMicros\\s*\\)\\s*;")
                .matcher(javaBridge).find());
        require(javaBridge.contains("boolean personalTrajectoryEnabled"));
        require(javaBridge.contains("int switchConfirmationMillis"));
        require(javaBridge.contains("long personalProfileSeed"));
        require(javaBridge.contains("float[] personalSpeedEnvelope"));
        require(nativeBridge.contains("jboolean personal_trajectory_enabled"));
        require(nativeBridge.contains("jint switch_confirmation_ms"));
        require(nativeBridge.contains("jlong personal_profile_seed"));
        require(nativeBridge.contains("jfloatArray personal_speed_envelope"));
        require(nativeBridge.contains("GetFloatArrayRegion("));
        require(moveBridge.contains(
                "control_config.motion.personal_trajectory_enabled"));
        require(moveBridge.contains(
                "control_config.switch_confirmation_duration_us"));
        int switchTimingIndex = moveBridge.indexOf(
                "control_config.switch_confirmation_duration_us =");
        int modelTuningIndex = moveBridge.indexOf(
                "apply_mobile_model_control_tuning(*model, control_config);");
        require(switchTimingIndex >= 0 && modelTuningIndex > switchTimingIndex);
        int profileConfigureStart = moveBridge.indexOf(
                "bool configure_makcu_control_profile(");
        int profileConfigureEnd = moveBridge.indexOf(
                "void activate_makcu_stream_generation(", profileConfigureStart);
        int profilePublishLock = moveBridge.indexOf(
                "std::scoped_lock publish_lock(g_publish_mutex);",
                profileConfigureStart);
        int nativeCoreConfigure = moveBridge.indexOf(
                "g_control_core.configure(control_config);",
                profileConfigureStart);
        require(profileConfigureStart >= 0
                && profileConfigureEnd > profileConfigureStart
                && profilePublishLock > profileConfigureStart
                && profilePublishLock < profileConfigureEnd
                && nativeCoreConfigure > profilePublishLock);
        require(moveBridge.contains("switch_confirmation_duration_us="));
        require(moveBridge.contains("lost_target_hold_duration_us="));
        require(moveBridge.contains("tracker_lost_duration_us="));
        require(moveBridge.contains(
                "control_config.motion.personal_speed_envelope"));
        require(javaBridge.contains("String modelToken"));
        require(javaBridge.contains("int bodyClassId"));
        require(javaBridge.contains("int headClassId"));
        require(javaBridge.contains("int selectedClassId"));
        require(javaBridge.contains("boolean selectedClassUsesHeadBox"));
        require(javaBridge.contains("boolean selectedClassUsesGeometricHead"));
        require(javaBridge.contains("float targetYRatio"));
        require(Pattern.compile("QnnHtpBridge\\.configureNativeMakcuControl\\s*\\(.*?"
                        + "model\\.token\\s*,\\s*model\\.bodyClassIdFor\\(aimTarget\\)\\s*,"
                        + "\\s*model\\.headClassIdFor\\(aimTarget\\)\\s*,"
                        + "\\s*model\\.classIdFor\\(aimTarget\\)\\s*,"
                        + "\\s*model\\.usesHeadBox\\(aimTarget\\)\\s*,"
                        + "\\s*model\\.usesGeometricHead\\(aimTarget\\)\\s*,"
                        + "\\s*model\\.targetYRatio\\(aimTarget\\)\\s*\\)",
                Pattern.DOTALL).matcher(controlProfile).find());
        require(nativeBridge.contains("jstring model_token"));
        require(nativeBridge.contains("jint body_class_id"));
        require(nativeBridge.contains("jint head_class_id"));
        require(nativeBridge.contains("jint selected_class_id"));
        require(nativeBridge.contains("jboolean selected_class_uses_head_box"));
        require(nativeBridge.contains("jboolean selected_class_uses_geometric_head"));
        require(nativeBridge.contains("jfloat target_y_ratio"));
        require(nativeBridge.contains("profile.model_token = model_token == nullptr"));
        require(nativeBridge.contains("profile.body_class_id = static_cast<std::uint32_t>(body_class_id);"));
        require(nativeBridge.contains("profile.head_class_id = head_class_id < 0"));
        require(nativeBridge.contains("profile.selected_class_id = static_cast<std::uint32_t>(selected_class_id);"));
        require(nativeBridge.contains("profile.selected_class_uses_head_box ="));
        require(nativeBridge.contains("profile.selected_class_uses_geometric_head ="));
        require(nativeBridge.contains("profile.target_y_ratio = target_y_ratio;"));
        require(moveBridge.contains("vfdual::find_mobile_model(profile.model_token)"));
        require(moveBridge.contains("vfdual::matches_mobile_aim_target_contract("));
        require(moveBridge.contains(
                "*model, profile.body_class_id, profile.head_class_id"));
        require(moveBridge.contains(
                "profile.selected_class_id, profile.selected_class_uses_head_box"));
        require(!moveBridge.contains("profile.body_class_id == model->body_class_id"));
        require(moveBridge.contains("control_config.body_class_id = profile.body_class_id;"));
        require(moveBridge.contains("control_config.head_class_id = profile.head_class_id;"));
        require(moveBridge.contains("control_config.selected_class_id = profile.selected_class_id;"));
        require(moveBridge.contains("profile.selected_class_uses_head_box;"));
        require(moveBridge.contains("profile.selected_class_uses_geometric_head;"));
        require(moveBridge.contains("control_config.body_fallback_y_ratio = profile.target_y_ratio;"));

        Pattern exactNativeBinding = Pattern.compile(
                "JNIEXPORT\\s+jboolean\\s+JNICALL\\s+"
                        + "Java_com_visionforge_inferencebenchmark_QnnHtpBridge_"
                        + "bindNativeMakcuMoveBridge\\s*\\("
                        + "\\s*JNIEnv\\s*\\*\\s*environment\\s*,"
                        + "\\s*jclass\\s*,\\s*jclass\\s+controller_class\\s*\\)"
                        + "\\s*\\{.*?vfdual_android::bind_makcu_move_bridge"
                        + "\\s*\\(environment\\s*,\\s*controller_class\\s*\\)",
                Pattern.DOTALL);
        require(exactNativeBinding.matcher(nativeBridge).find());
        require(moveBridge.contains("environment->GetJavaVM(&candidate_vm) != JNI_OK"));
        require(moveBridge.contains("environment->NewGlobalRef(controller_class)"));
        require(moveBridge.contains("environment->GetStaticMethodID"));
        require(moveBridge.contains(
                "candidate_class, \"offerNativeMove\", \"(IIJJ)Z\""));
        require(moveBridge.contains("environment->ExceptionCheck()"));
        require(moveBridge.contains("g_java_bridge_ready.store(false"));
        require(moveBridge.contains("g_move_commit_gate.pending()"));
        require(moveBridge.contains("g_move_commit_gate.expire_if_older("));
        require(moveBridge.contains("g_move_visibility_gate.evaluate("));
        require(moveBridge.indexOf("g_move_commit_gate.pending()")
                < moveBridge.indexOf("g_control_core.process("));
        require(moveBridge.indexOf("g_move_visibility_gate.evaluate(")
                < moveBridge.indexOf("g_control_core.process("));
        require(moveBridge.contains("completed_move_became_visible"));
        require(moveBridge.contains("g_control_core.apply_visible_ego_motion("));
        require(moveBridge.indexOf("g_control_core.apply_visible_ego_motion(")
                < moveBridge.indexOf("g_control_core.process("));
        require(moveBridge.contains("candidate_moves="));
        require(moveBridge.contains("native_device_ack_completions="));
        require(moveBridge.contains("native_last_device_ack_interval_us="));
        require(moveBridge.contains("native_last_offered_delta_x="));
        require(moveBridge.contains("native_last_offered_delta_y="));
        require(moveBridge.contains("native_offered_absolute_x_counts="));
        require(moveBridge.contains("native_offered_absolute_y_counts="));
        require(moveBridge.contains("native_maximum_offered_absolute_axis_delta="));
        require(moveBridge.contains("native_offered_direction_flips_x="));
        require(moveBridge.contains("native_offered_direction_flips_y="));
        require(moveBridge.contains("native_last_offer_interval_us="));
        require(moveBridge.contains("observe_accepted_move(output.delta_x, output.delta_y)"));
        require(moveBridge.contains("observe_matching_device_ack()"));
        require(moveBridge.contains("tracker_control_filter_blends="));
        require(moveBridge.contains("tracker_control_filter_bypasses="));
        require(moveBridge.contains("tracker_time_based_velocity_updates="));
        require(moveBridge.contains("tracker_maximum_observation_interval_us="));
        require(moveBridge.contains(
                "tracker_maximum_control_innovation_pixels="));
        require(moveBridge.contains("native_bluetooth_hid_api_acceptances="));
        require(moveBridge.contains(
                "android_hid_stack_accepted_not_host_or_physical_ack"));
        require(controller.contains(
                "device_ack_semantics=firmware_echo_and_prompt_not_physical_execution"));
        require(controller.contains("physical_execution_verified=0"));
        int completionHelperStart = moveBridge.indexOf("bool complete_matching_move(");
        int completionHelperEnd = moveBridge.indexOf("}  // namespace", completionHelperStart);
        require(completionHelperStart >= 0 && completionHelperEnd > completionHelperStart);
        String completionHelper = moveBridge.substring(
                completionHelperStart, completionHelperEnd);
        require(completionHelper.contains("++stale_counter;"));
        require(!completionHelper.contains("g_move_visibility_gate.fail_closed();"));
        require(!completionHelper.contains("fail_closed_native_state();"));
        require(completionHelper.contains("g_move_commit_gate.complete_with("));
        require(completionHelper.contains("g_move_visibility_gate.arm("));
        require(Pattern.compile("complete_matching_move\\s*\\(\\s*ticket\\s*,"
                        + "\\s*g_stale_device_feedback\\s*,"
                        + "\\s*kPostAcknowledgementAdditionalDelayUs\\s*\\)")
                .matcher(moveBridge).find());
        int makcuCompletionStart = moveBridge.indexOf("void report_makcu_move_result(");
        int bluetoothCallbackStart = moveBridge.indexOf(
                "bool report_bluetooth_hid_move_accepted(", makcuCompletionStart);
        int bluetoothCallbackEnd = moveBridge.indexOf(
                "std::string makcu_move_bridge_report()", bluetoothCallbackStart);
        require(makcuCompletionStart >= 0
                && bluetoothCallbackStart > makcuCompletionStart
                && bluetoothCallbackEnd > bluetoothCallbackStart);
        String makcuCompletionSource = moveBridge.substring(
                makcuCompletionStart, bluetoothCallbackStart);
        String bluetoothCallbackSource = moveBridge.substring(
                bluetoothCallbackStart, bluetoothCallbackEnd);
        require(makcuCompletionSource.contains("fail_closed_bridge();"));
        require(!makcuCompletionSource.contains(
                "std::scoped_lock publish_lock(g_publish_mutex)"));
        require(makcuCompletionSource.contains(
                "classify_makcu_move_feedback("));
        require(makcuCompletionSource.contains(
                "action == MakcuMoveFeedbackAction::ignore_stale"));
        require(makcuCompletionSource.contains(
                "g_output_gate.revoke_immediately();"));
        // Bluetooth acceptance re-enters native while execute_if_enabled owns
        // the output mutex. It must return false and let the outer offer path
        // fail closed after that mutex has been released.
        require(!bluetoothCallbackSource.contains("fail_closed_bridge();"));
        require(!bluetoothCallbackSource.contains("fail_closed_native_state();"));
        require(Pattern.compile("complete_matching_move\\s*\\(\\s*ticket\\s*,"
                        + "\\s*g_stale_bluetooth_hid_api_acceptances\\s*,"
                        + "\\s*kPostAcknowledgementAdditionalDelayUs\\s*\\)")
                .matcher(moveBridge).find());
        require(Pattern.compile(
                "action\\s*==\\s*MakcuMoveFeedbackAction::ignore_stale"
                        + ".*?\\+\\+g_stale_device_feedback\\s*;.*?return\\s*;"
                        + ".*?\\+\\+g_device_ack_failures\\s*;"
                        + ".*?fail_closed_bridge\\(\\)\\s*;",
                Pattern.DOTALL).matcher(moveBridge).find());
        int recoverySuspendStart = moveBridge.indexOf(
                "void suspend_makcu_output_for_recovery");
        int recoveryResumeStart = moveBridge.indexOf(
                "bool resume_makcu_output_after_valid_frame",
                recoverySuspendStart);
        require(recoverySuspendStart >= 0 && recoveryResumeStart > recoverySuspendStart);
        String recoverySuspend = moveBridge.substring(
                recoverySuspendStart, recoveryResumeStart);
        require(recoverySuspend.indexOf(
                "invoke_java_delivery_gate(JavaDeliveryCall::suspend, generation)")
                < recoverySuspend.indexOf("g_move_commit_gate.fail_closed()"));
        require(recoverySuspend.contains("if (!java_suspended ||"));
        require(controller.contains(
                "reportUndeliveredMoveUnlessRecoveryCancelled(ticket)"));
        require(controller.contains(
                "!deliveryGate.isRecoverySuspended()"));
        require(Pattern.compile("maximum_axis_delta\\s*>\\s*kMaximumAxisDelta\\s*\\|\\|"
                        + "\\s*profile\\.switch_confirmation_ms\\s*<\\s*kMinimumSwitchConfirmationMs\\s*\\|\\|"
                        + "\\s*profile\\.switch_confirmation_ms\\s*>\\s*kMaximumSwitchConfirmationMs\\s*\\)\\s*\\{"
                        + ".*?fail_closed_bridge\\(\\)\\s*;.*?return\\s+false\\s*;",
                Pattern.DOTALL).matcher(moveBridge).find());
        require(Pattern.compile(
                "JNIEXPORT\\s+void\\s+JNICALL\\s+"
                        + "Java_com_visionforge_inferencebenchmark_QnnHtpBridge_"
                        + "reportNativeMakcuMoveResult\\s*\\("
                        + ".*?vfdual_android::report_makcu_move_result\\s*\\(",
                Pattern.DOTALL).matcher(nativeBridge).find());
        int deliveryFailCloseStart = nativeBridge.indexOf(
                "Java_com_visionforge_inferencebenchmark_QnnHtpBridge_"
                        + "failClosedNativeMakcuOutput(");
        int deliveryFailCloseEnd = nativeBridge.indexOf(
                "extern \"C\" JNIEXPORT", deliveryFailCloseStart + 1);
        require(deliveryFailCloseStart >= 0
                && deliveryFailCloseEnd > deliveryFailCloseStart);
        String deliveryFailCloseBinding = nativeBridge.substring(
                deliveryFailCloseStart, deliveryFailCloseEnd);
        require(deliveryFailCloseBinding.contains(
                "vfdual_android::fail_closed_makcu_delivery();"));
        require(!deliveryFailCloseBinding.contains(
                "vfdual_android::disable_makcu_output();"));
        int nativeProfileStart = nativeBridge.indexOf(
                "Java_com_visionforge_inferencebenchmark_QnnHtpBridge_"
                        + "configureNativeMakcuControl(");
        int nativeProfileEnd = nativeBridge.indexOf(
                "extern \"C\" JNIEXPORT", nativeProfileStart + 1);
        require(nativeProfileStart >= 0 && nativeProfileEnd > nativeProfileStart);
        String nativeProfileBinding = nativeBridge.substring(
                nativeProfileStart, nativeProfileEnd);
        require(Pattern.compile(
                "if\\s*\\(environment->ExceptionCheck\\(\\)\\)\\s*\\{"
                        + ".*?environment->ExceptionClear\\(\\)\\s*;"
                        + ".*?vfdual_android::fail_closed_makcu_delivery\\(\\)\\s*;"
                        + ".*?return\\s+JNI_FALSE\\s*;",
                Pattern.DOTALL).matcher(nativeProfileBinding).find());
        require(!nativeProfileBinding.contains(
                "vfdual_android::disable_makcu_output();"));
        require(moveBridge.contains(
                "MakcuStreamCloseScope::delivery_failure"));
        require(moveBridge.contains(
                "MakcuStreamCloseScope::stream_lifecycle"));
        require(moveBridge.contains(
                "native_delivery_fail_close_requests="));
        require(moveBridge.contains(
                "native_stream_lifecycle_close_requests="));
        require(Pattern.compile(
                "void\\s+fail_closed_native_state\\s*\\(.*?"
                        + "MakcuStreamCloseScope\\s+scope.*?\\)\\s*noexcept"
                        + ".*?g_stream_generation_gate\\.fail_closed\\(scope\\)"
                        + ".*?scope\\s*==\\s*MakcuStreamCloseScope::delivery_failure"
                        + ".*?\\+\\+g_delivery_fail_close_requests"
                        + ".*?\\+\\+g_stream_lifecycle_close_requests",
                Pattern.DOTALL).matcher(moveBridge).find());
        require(Pattern.compile(
                "void\\s+disable_makcu_output\\s*\\(\\)\\s*noexcept"
                        + ".*?fail_closed_bridge\\("
                        + "MakcuStreamCloseScope::stream_lifecycle\\)\\s*;",
                Pattern.DOTALL).matcher(moveBridge).find());
        int publishStart = moveBridge.indexOf(
                "void publish_makcu_move_for_detections(");
        int publishEnd = moveBridge.indexOf(
                "void report_makcu_move_result(", publishStart);
        require(publishStart >= 0 && publishEnd > publishStart);
        String publishHotPath = moveBridge.substring(publishStart, publishEnd);
        require(!publishHotPath.contains("g_delivery_fail_close_requests"));
        require(!publishHotPath.contains("g_stream_lifecycle_close_requests"));
        Pattern bluetoothApiAcceptance = Pattern.compile(
                "JNIEXPORT\\s+jboolean\\s+JNICALL\\s+"
                        + "Java_com_visionforge_inferencebenchmark_QnnHtpBridge_"
                        + "reportNativeBluetoothHidMoveAccepted\\s*\\("
                        + ".*?vfdual_android::report_bluetooth_hid_move_accepted\\s*\\("
                        + ".*?\\n\\}",
                Pattern.DOTALL);
        java.util.regex.Matcher bluetoothBinding =
                bluetoothApiAcceptance.matcher(nativeBridge);
        require(bluetoothBinding.find());
        require(!bluetoothBinding.group().contains("report_makcu_move_result"));

        Pattern bluetoothCompletion = Pattern.compile(
                "bool\\s+report_bluetooth_hid_move_accepted\\s*\\("
                        + ".*?if\\s*\\(\\s*!complete_matching_move\\s*\\("
                        + ".*?g_stale_bluetooth_hid_api_acceptances.*?return\\s+false\\s*;"
                        + ".*?\\+\\+g_bluetooth_hid_api_acceptances\\s*;"
                        + ".*?return\\s+true\\s*;",
                Pattern.DOTALL);
        require(bluetoothCompletion.matcher(moveBridge).find());
    }

    private static long parseNumericLiteral(String value) {
        return Long.parseLong(value.replace("_", "").replace("'", ""));
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("MAKCU JNI controller-class contract failed");
    }

    private static String readUtf8(Path path) throws Exception {
        return new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
    }
}
