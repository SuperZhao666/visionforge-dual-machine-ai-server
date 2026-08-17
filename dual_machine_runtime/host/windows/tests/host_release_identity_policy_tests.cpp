#include "vfdual/host_release_identity_policy.hpp"

#include <cstdlib>
#include <iostream>

namespace {

void require(bool condition, const char* expression, const char* file, int line) {
    if (condition) return;
    std::cerr << file << ':' << line << ": CHECK failed: " << expression << '\n';
    std::exit(EXIT_FAILURE);
}

}  // namespace

#define CHECK(expression) \
    require(static_cast<bool>(expression), #expression, __FILE__, __LINE__)

int main() {
    CHECK(vfdual::host_release_executable_name_is_recognized(
        L"VFHost-1.0.8-x64.exe"));
    CHECK(vfdual::host_release_executable_name_is_recognized(
        L"VisionForgeHost-18.2.104-x64.exe"));
    CHECK(vfdual::host_release_executable_name_is_recognized(
        L"VFHost_1.0.8.exe"));
    CHECK(vfdual::host_release_executable_name_is_recognized(
        L"VisionForgeHost_18.2.104.exe"));
    CHECK(vfdual::host_release_executable_name_is_recognized(
        L"vfhost-1.0.8-X64.EXE"));

    CHECK(!vfdual::host_release_executable_name_is_recognized(
        L"VFHost-1.0.8-x86.exe"));
    CHECK(!vfdual::host_release_executable_name_is_recognized(
        L"VFHost-1.0.8-arm64.exe"));
    CHECK(!vfdual::host_release_executable_name_is_recognized(
        L"VFHost-1.0-x64.exe"));
    CHECK(!vfdual::host_release_executable_name_is_recognized(
        L"VFHost-1.0.8-beta-x64.exe"));
    CHECK(!vfdual::host_release_executable_name_is_recognized(
        L"VFHost-1.0.8-x64.exe.bak"));
    CHECK(!vfdual::host_release_executable_name_is_recognized(
        L"Other-VFHost-1.0.8-x64.exe"));
    CHECK(!vfdual::host_release_executable_name_is_recognized(
        L"VFHost-1..8-x64.exe"));
    CHECK(!vfdual::host_release_executable_name_is_recognized(
        L"VFHost-12345678901.0.8-x64.exe"));
    return 0;
}
