#pragma once

#include "vf/wire_protocol.hpp"

#include <cstdint>
#include <filesystem>
#include <mutex>

namespace vf::host::infrastructure {

/**
 * 跨进程、崩溃安全的 stream epoch 预留器。
 *
 * <p>状态文件只保存最后一次成功预留的 epoch。reserve_next() 在独立锁文件上取得
 * 排他锁，随后以“临时文件 + fsync/FlushFileBuffers + 原子替换”持久化新值。这样
 * 两个 Host 实例不会获得同一 epoch，进程重启也不会把代次重置为 1。</p>
 */
class FileEpochReservationStore {
public:
    explicit FileEpochReservationStore(
        std::filesystem::path state_file,
        std::uint64_t maximum_epoch = kMaxStreamEpoch);

    [[nodiscard]] std::uint64_t reserve_next();
    [[nodiscard]] const std::filesystem::path& state_file() const noexcept {
        return state_file_;
    }

private:
    std::filesystem::path state_file_;
    std::filesystem::path lock_file_;
    std::uint64_t maximum_epoch_{};
    std::mutex process_mutex_;
};

}  // namespace vf::host::infrastructure
