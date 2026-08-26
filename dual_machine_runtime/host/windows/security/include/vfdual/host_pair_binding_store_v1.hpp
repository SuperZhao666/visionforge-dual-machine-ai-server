#pragma once

#include "vfdual/host_authenticated_control_coordinator_v1.hpp"

#include <filesystem>
#include <mutex>
#include <optional>
#include <string>

namespace vfdual {

/**
 * Crash-safe local owner for the server-authorized Host/Android pair binding.
 *
 * The record contains no card code, token, signature, lease, or session key.
 * Its generation high-water mark is committed before Host Finished is sent so
 * a process restart cannot reuse an already accepted generation.
 */
class HostPairBindingStoreV1 final {
public:
    explicit HostPairBindingStoreV1(std::filesystem::path state_file);

    [[nodiscard]] std::optional<HostAuthenticatedControlPairBindingV1> load(
        std::string& error);

    /** Installs the first server-authorized binding; a different pair fails closed. */
    [[nodiscard]] bool commit_initial_binding(
        const HostAuthenticatedControlPairBindingV1& binding,
        std::string& error);

    /** Commits a strictly newer server generation for the exact stored pair. */
    [[nodiscard]] bool commit_generation(
        const HostAuthenticatedControlPairBindingV1& expected_binding,
        std::uint64_t generation,
        std::string& error);

    [[nodiscard]] const std::filesystem::path& state_file() const noexcept {
        return state_file_;
    }

private:
    std::filesystem::path state_file_;
    std::filesystem::path lock_file_;
    std::mutex process_mutex_;
};

}  // namespace vfdual
