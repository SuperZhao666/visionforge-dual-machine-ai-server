#include "vfdual/nvenc_runtime_probe.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace vfdual {
NvencRuntimeProbeResult probe_nvenc_runtime() noexcept {
    HMODULE library = LoadLibraryW(L"nvEncodeAPI64.dll");
    if (library == nullptr) return {};
    const bool entrypoint = GetProcAddress(library, "NvEncodeAPICreateInstance") != nullptr;
    FreeLibrary(library);
    return {true, entrypoint};
}
}  // namespace vfdual
