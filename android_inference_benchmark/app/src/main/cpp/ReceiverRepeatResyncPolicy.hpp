#pragma once

namespace vfdual_android {

struct ReceiverRepeatAdmission final {
  bool submit{};
  bool content_updated{};
  bool resync_unlock{};
};

/**
 * Keeps synthetic VFRR access units outside a fresh/restarted decoder session
 * until that session has accepted a real VFRG access unit.
 *
 * A successfully submitted VFRG is a current decoder reference. VFRR access
 * units submitted afterwards still preserve the H.264 reference chain, but
 * the inference layer may suppress their duplicate pixels. A repeat may never
 * be the first access unit that unlocks a fresh/restarted decoder session.
 */
class ReceiverRepeatResyncPolicy final {
public:
  [[nodiscard]] ReceiverRepeatAdmission admit(
      bool repeated_content) const noexcept {
    if (repeated_content && !real_frame_accepted_) return {};
    return {
        .submit = true,
        .content_updated = !repeated_content,
        .resync_unlock = !repeated_content && !real_frame_accepted_,
    };
  }

  void record_submit_result(
      bool repeated_content, bool accepted) noexcept {
    if (!accepted) {
      real_frame_accepted_ = false;
      return;
    }
    if (!repeated_content) real_frame_accepted_ = true;
  }

  void require_resync() noexcept { real_frame_accepted_ = false; }
  void reset() noexcept { require_resync(); }

  [[nodiscard]] bool real_frame_accepted() const noexcept {
    return real_frame_accepted_;
  }

private:
  bool real_frame_accepted_{};
};

}  // namespace vfdual_android
