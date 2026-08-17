#include "vfdual/host_release_identity_policy.hpp"

#include <array>
#include <algorithm>

namespace vfdual {
namespace {

wchar_t fold_ascii_case(wchar_t value) noexcept {
    if (value >= L'A' && value <= L'Z') {
        return static_cast<wchar_t>(value - L'A' + L'a');
    }
    return value;
}

bool equals_insensitive(
    std::wstring_view left,
    std::wstring_view right) noexcept {
    return left.size() == right.size() && std::equal(
        left.begin(), left.end(), right.begin(),
        [](wchar_t lhs, wchar_t rhs) {
            return fold_ascii_case(lhs) == fold_ascii_case(rhs);
        });
}

bool stable_semver(std::wstring_view value) noexcept {
    std::size_t segment_start{};
    std::size_t segment_count{};
    for (std::size_t index = 0U; index <= value.size(); ++index) {
        if (index != value.size() && value[index] != L'.') continue;
        const std::wstring_view segment = value.substr(
            segment_start, index - segment_start);
        if (segment.empty() || segment.size() > 10U ||
            !std::all_of(
                segment.begin(), segment.end(),
                [](wchar_t character) {
                    return character >= L'0' && character <= L'9';
                })) {
            return false;
        }
        ++segment_count;
        segment_start = index + 1U;
    }
    return segment_count == 3U;
}

bool matches_release_shape(
    std::wstring_view filename,
    std::wstring_view prefix,
    std::wstring_view suffix) noexcept {
    if (filename.size() <= prefix.size() + suffix.size() ||
        !equals_insensitive(filename.substr(0U, prefix.size()), prefix) ||
        !equals_insensitive(
            filename.substr(filename.size() - suffix.size()), suffix)) {
        return false;
    }
    return stable_semver(filename.substr(
        prefix.size(), filename.size() - prefix.size() - suffix.size()));
}

}  // namespace

bool host_release_executable_name_is_recognized(
    std::wstring_view filename) noexcept {
    constexpr std::array<std::wstring_view, 2U> kExecutablePrefixes{
        L"VisionForgeHost_", L"VFHost_"};
    for (const std::wstring_view prefix : kExecutablePrefixes) {
        if (matches_release_shape(filename, prefix, L".exe")) return true;
    }

    // The production Windows bundle names the versioned executable with a
    // hyphen and architecture suffix, for example VFHost-1.0.8-x64.exe.
    constexpr std::array<std::wstring_view, 2U> kBundlePrefixes{
        L"VisionForgeHost-", L"VFHost-"};
    for (const std::wstring_view prefix : kBundlePrefixes) {
        if (matches_release_shape(filename, prefix, L"-x64.exe")) return true;
    }
    return false;
}

}  // namespace vfdual
