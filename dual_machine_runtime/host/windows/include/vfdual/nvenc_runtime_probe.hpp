#pragma once

namespace vfdual {

struct NvencRuntimeProbeResult {
    bool library_loaded{};
    bool api_entrypoint_available{};
};

/** Lightweight driver capability probe; it does not claim that an encoder session was created. */
[[nodiscard]] NvencRuntimeProbeResult probe_nvenc_runtime() noexcept;

}  // namespace vfdual
