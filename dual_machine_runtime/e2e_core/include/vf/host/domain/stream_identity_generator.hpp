#pragma once

#include "vf/host/domain/frame_identity.hpp"

#include <cstdint>
#include <mutex>

namespace vf::host::domain {

/**
 * 单线程/多线程安全的帧身份发生器。
 *
 * <p>构造时必须注入由持久化层预留的正 epoch；因此进程重启不会被默认值悄悄重置。
 * sequence 到达 uint32 最大值后，下一次 next() 会拒绝继续，直到调用方从持久化
 * 分配器取得更高 epoch 并执行 rotate_to()；绝不在进程内猜测一个新代次。</p>
 */
class StreamIdentityGenerator {
public:
    explicit StreamIdentityGenerator(std::uint64_t reserved_epoch, std::uint32_t first_sequence = 0);

    [[nodiscard]] FrameIdentity next();
    [[nodiscard]] std::uint64_t current_epoch() const noexcept;
    [[nodiscard]] std::uint32_t next_sequence() const noexcept;
    [[nodiscard]] bool rotation_required() const noexcept;

    /** 外部持久化分配器预留更高 epoch 后可显式切换；低/同 epoch 会被拒绝。 */
    void rotate_to(std::uint64_t reserved_epoch);

private:
    mutable std::mutex mutex_;
    std::uint64_t epoch_{};
    std::uint32_t sequence_{};
    bool rollover_before_next_{};
};

}  // namespace vf::host::domain
