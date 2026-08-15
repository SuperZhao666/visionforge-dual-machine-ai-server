#include "vfdual/nvenc_runtime_probe.hpp"

#include <iostream>

int main() {
    const auto result = vfdual::probe_nvenc_runtime();
    std::cout << "nvenc_library=" << result.library_loaded << " api_entrypoint=" << result.api_entrypoint_available << '\n';
    if (!result.library_loaded || !result.api_entrypoint_available) {
        std::cerr << "nvenc_runtime_probe_skipped reason=runtime_unavailable\n";
        return 77;
    }
    return 0;
}
