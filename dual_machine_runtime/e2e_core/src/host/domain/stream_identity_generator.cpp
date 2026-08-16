#include "vf/host/domain/stream_identity_generator.hpp"

#include <limits>
#include <stdexcept>

namespace vf::host::domain {

StreamIdentityGenerator::StreamIdentityGenerator(
    std::uint64_t reserved_epoch,
    std::uint32_t first_sequence)
    : epoch_(reserved_epoch), sequence_(first_sequence) {
    if (!FrameIdentity{reserved_epoch, first_sequence}.valid()) {
        throw std::invalid_argument("reserved epoch is outside the shared protocol range");
    }
}

FrameIdentity StreamIdentityGenerator::next() {
    std::scoped_lock lock(mutex_);
    if (rollover_before_next_) {
        // epoch 必须由持久化分配器预留。这里绝不能在内存中自行 +1，否则进程
        // 崩溃或双实例并发时可能重新使用同一代次并制造跨会话身份碰撞。
        throw std::overflow_error("a newly persisted stream epoch reservation is required");
    }
    const FrameIdentity result{epoch_, sequence_};
    if (sequence_ == std::numeric_limits<std::uint32_t>::max()) {
        rollover_before_next_ = true;
    } else {
        ++sequence_;
    }
    return result;
}

std::uint64_t StreamIdentityGenerator::current_epoch() const noexcept {
    std::scoped_lock lock(mutex_);
    return epoch_;
}

std::uint32_t StreamIdentityGenerator::next_sequence() const noexcept {
    std::scoped_lock lock(mutex_);
    return rollover_before_next_ ? 0 : sequence_;
}

bool StreamIdentityGenerator::rotation_required() const noexcept {
    std::scoped_lock lock(mutex_);
    return rollover_before_next_;
}

void StreamIdentityGenerator::rotate_to(std::uint64_t reserved_epoch) {
    std::scoped_lock lock(mutex_);
    if (reserved_epoch <= epoch_ || reserved_epoch > kMaxStreamEpoch) {
        throw std::invalid_argument("rotated epoch must be higher and inside protocol range");
    }
    epoch_ = reserved_epoch;
    sequence_ = 0;
    rollover_before_next_ = false;
}

}  // namespace vf::host::domain
