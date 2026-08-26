#include "vfdual/host_pair_binding_store_v1.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace vfdual {
namespace {

constexpr std::string_view kMagic{"VFPB1"};
constexpr std::uint64_t kSigned64Maximum =
    static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)());

class InterprocessLock final {
public:
    explicit InterprocessLock(const std::filesystem::path& path) {
        handle_ = CreateFileW(
            path.c_str(), GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (handle_ == INVALID_HANDLE_VALUE) {
            throw std::system_error(
                static_cast<int>(GetLastError()), std::system_category(),
                "cannot open pair-binding lock");
        }
        OVERLAPPED overlapped{};
        if (!LockFileEx(
                handle_, LOCKFILE_EXCLUSIVE_LOCK, 0, MAXDWORD, MAXDWORD,
                &overlapped)) {
            const DWORD error = GetLastError();
            CloseHandle(handle_);
            handle_ = INVALID_HANDLE_VALUE;
            throw std::system_error(
                static_cast<int>(error), std::system_category(),
                "cannot lock pair-binding state");
        }
    }

    ~InterprocessLock() {
        if (handle_ == INVALID_HANDLE_VALUE) return;
        OVERLAPPED overlapped{};
        (void)UnlockFileEx(handle_, 0, MAXDWORD, MAXDWORD, &overlapped);
        CloseHandle(handle_);
    }

    InterprocessLock(const InterprocessLock&) = delete;
    InterprocessLock& operator=(const InterprocessLock&) = delete;

private:
    HANDLE handle_{INVALID_HANDLE_VALUE};
};

[[nodiscard]] bool lower_hex(
    const std::string_view value, const std::size_t exact_size) noexcept {
    if (value.size() != exact_size) return false;
    return std::all_of(value.begin(), value.end(), [](const char character) {
        return (character >= '0' && character <= '9') ||
            (character >= 'a' && character <= 'f');
    });
}

[[nodiscard]] bool spki_fingerprint_matches(
    const std::vector<std::uint8_t>& spki,
    const std::string_view expected) noexcept {
    if (spki.empty() || spki.size() > 4096U ||
        !lower_hex(expected, 64U)) {
        return false;
    }
    BCRYPT_ALG_HANDLE algorithm{};
    if (BCryptOpenAlgorithmProvider(
            &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0U) < 0) {
        return false;
    }
    std::array<std::uint8_t, 32U> digest{};
    const NTSTATUS status = BCryptHash(
        algorithm, nullptr, 0U,
        const_cast<PUCHAR>(spki.data()),
        static_cast<ULONG>(spki.size()),
        digest.data(), static_cast<ULONG>(digest.size()));
    (void)BCryptCloseAlgorithmProvider(algorithm, 0U);
    if (status < 0) return false;
    constexpr char alphabet[] = "0123456789abcdef";
    for (std::size_t index{}; index < digest.size(); ++index) {
        if (expected[index * 2U] != alphabet[digest[index] >> 4U] ||
            expected[index * 2U + 1U] != alphabet[digest[index] & 0x0fU]) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool valid_binding(
    const HostAuthenticatedControlPairBindingV1& binding) noexcept {
    return lower_hex(binding.entitlement_id, 32U) &&
        lower_hex(binding.pair_id, 32U) &&
        lower_hex(binding.binding_id, 32U) &&
        binding.binding_revision > 0U &&
        binding.binding_revision <= kSigned64Maximum &&
        binding.revocation_version > 0U &&
        binding.revocation_version <= kSigned64Maximum &&
        binding.generation_high_watermark <= kSigned64Maximum &&
        lower_hex(binding.host_identity_spki_sha256, 64U) &&
        lower_hex(binding.android_identity_spki_sha256, 64U) &&
        spki_fingerprint_matches(
            binding.android_subject_public_key_info_der,
            binding.android_identity_spki_sha256);
}

[[nodiscard]] bool same_pair(
    const HostAuthenticatedControlPairBindingV1& left,
    const HostAuthenticatedControlPairBindingV1& right) noexcept {
    return left.entitlement_id == right.entitlement_id &&
        left.pair_id == right.pair_id &&
        left.binding_id == right.binding_id &&
        left.binding_revision == right.binding_revision &&
        left.revocation_version == right.revocation_version &&
        left.host_identity_spki_sha256 == right.host_identity_spki_sha256 &&
        left.android_identity_spki_sha256 ==
            right.android_identity_spki_sha256 &&
        left.android_subject_public_key_info_der ==
            right.android_subject_public_key_info_der;
}

[[nodiscard]] std::string encode_hex(
    const std::span<const std::uint8_t> bytes) {
    constexpr char alphabet[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2U);
    for (const std::uint8_t byte : bytes) {
        result.push_back(alphabet[byte >> 4U]);
        result.push_back(alphabet[byte & 0x0fU]);
    }
    return result;
}

[[nodiscard]] std::vector<std::uint8_t> decode_hex(
    const std::string_view text) {
    if (text.empty() || text.size() % 2U != 0U || text.size() > 8192U) {
        throw std::runtime_error("pair-binding SPKI encoding is invalid");
    }
    const auto nibble = [](const char value) -> std::uint8_t {
        if (value >= '0' && value <= '9') {
            return static_cast<std::uint8_t>(value - '0');
        }
        if (value >= 'a' && value <= 'f') {
            return static_cast<std::uint8_t>(10 + value - 'a');
        }
        throw std::runtime_error("pair-binding SPKI encoding is invalid");
    };
    std::vector<std::uint8_t> result(text.size() / 2U);
    for (std::size_t index{}; index < result.size(); ++index) {
        result[index] = static_cast<std::uint8_t>(
            (nibble(text[index * 2U]) << 4U) |
            nibble(text[index * 2U + 1U]));
    }
    return result;
}

[[nodiscard]] std::uint64_t parse_u64(
    const std::string_view text, const bool allow_zero) {
    std::uint64_t value{};
    const auto parsed = std::from_chars(
        text.data(), text.data() + text.size(), value);
    if (text.empty() || parsed.ec != std::errc{} ||
        parsed.ptr != text.data() + text.size() ||
        (!allow_zero && value == 0U) || value > kSigned64Maximum) {
        throw std::runtime_error("pair-binding integer is invalid");
    }
    return value;
}

[[nodiscard]] std::string serialize(
    const HostAuthenticatedControlPairBindingV1& binding) {
    if (!valid_binding(binding)) {
        throw std::runtime_error("pair-binding record is invalid");
    }
    return std::string{kMagic} + "\n" +
        "entitlement_id=" + binding.entitlement_id + "\n" +
        "pair_id=" + binding.pair_id + "\n" +
        "binding_id=" + binding.binding_id + "\n" +
        "binding_revision=" + std::to_string(binding.binding_revision) + "\n" +
        "revocation_version=" + std::to_string(binding.revocation_version) + "\n" +
        "generation_high_watermark=" +
            std::to_string(binding.generation_high_watermark) + "\n" +
        "host_identity_spki_sha256=" +
            binding.host_identity_spki_sha256 + "\n" +
        "android_identity_spki_sha256=" +
            binding.android_identity_spki_sha256 + "\n" +
        "android_subject_public_key_info_der=" + encode_hex(
            binding.android_subject_public_key_info_der) + "\n";
}

[[nodiscard]] std::vector<std::string> lines(const std::string& text) {
    std::vector<std::string> result;
    std::size_t start{};
    while (start < text.size()) {
        const std::size_t end = text.find('\n', start);
        const std::size_t length = end == std::string::npos
            ? text.size() - start : end - start;
        std::string line = text.substr(start, length);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        result.push_back(std::move(line));
        if (end == std::string::npos) break;
        start = end + 1U;
    }
    return result;
}

[[nodiscard]] std::string_view value_of(
    const std::string& line, const std::string_view key) {
    if (line.size() <= key.size() ||
        line.compare(0U, key.size(), key) != 0 ||
        line[key.size()] != '=') {
        throw std::runtime_error("pair-binding field order is invalid");
    }
    return std::string_view{line}.substr(key.size() + 1U);
}

[[nodiscard]] HostAuthenticatedControlPairBindingV1 parse(
    const std::string& text) {
    const auto source = lines(text);
    if (source.size() != 10U || source[0] != kMagic) {
        throw std::runtime_error("pair-binding schema is invalid");
    }
    HostAuthenticatedControlPairBindingV1 binding{
        .entitlement_id = std::string{value_of(source[1], "entitlement_id")},
        .pair_id = std::string{value_of(source[2], "pair_id")},
        .binding_id = std::string{value_of(source[3], "binding_id")},
        .binding_revision = parse_u64(
            value_of(source[4], "binding_revision"), false),
        .revocation_version = parse_u64(
            value_of(source[5], "revocation_version"), false),
        .generation_high_watermark = parse_u64(
            value_of(source[6], "generation_high_watermark"), true),
        .host_identity_spki_sha256 = std::string{
            value_of(source[7], "host_identity_spki_sha256")},
        .android_identity_spki_sha256 = std::string{
            value_of(source[8], "android_identity_spki_sha256")},
        .android_subject_public_key_info_der = decode_hex(
            value_of(source[9], "android_subject_public_key_info_der")),
    };
    if (!valid_binding(binding)) {
        throw std::runtime_error("pair-binding record is invalid");
    }
    return binding;
}

[[nodiscard]] std::optional<HostAuthenticatedControlPairBindingV1>
load_unlocked(const std::filesystem::path& path) {
    std::error_code exists_error;
    const bool exists = std::filesystem::exists(path, exists_error);
    if (exists_error) {
        throw std::system_error(exists_error, "cannot inspect pair-binding state");
    }
    if (!exists) return std::nullopt;
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("cannot read pair-binding state");
    std::string text{
        std::istreambuf_iterator<char>{input},
        std::istreambuf_iterator<char>{}};
    if (input.bad() || text.empty() || text.size() > 16U * 1024U) {
        throw std::runtime_error("pair-binding state length is invalid");
    }
    return parse(text);
}

void persist_atomically(
    const std::filesystem::path& path, const std::string_view content) {
    const auto parent = path.parent_path();
    if (!parent.empty()) {
        std::error_code directory_error;
        std::filesystem::create_directories(parent, directory_error);
        if (directory_error) {
            throw std::system_error(
                directory_error, "cannot create pair-binding directory");
        }
    }
    auto temporary = path;
    temporary += L".tmp";
    HANDLE file = CreateFileW(
        temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        throw std::system_error(
            static_cast<int>(GetLastError()), std::system_category(),
            "cannot create temporary pair-binding state");
    }
    DWORD written{};
    const bool sized = content.size() <= static_cast<std::size_t>(MAXDWORD);
    const DWORD expected = sized ? static_cast<DWORD>(content.size()) : 0U;
    const bool wrote = sized && WriteFile(
        file, content.data(), expected, &written, nullptr) &&
        written == expected;
    const bool flushed = wrote && FlushFileBuffers(file);
    const DWORD write_error = flushed ? ERROR_SUCCESS : GetLastError();
    CloseHandle(file);
    if (!flushed) {
        (void)DeleteFileW(temporary.c_str());
        throw std::system_error(
            static_cast<int>(write_error), std::system_category(),
            "cannot persist pair-binding state");
    }
    if (!MoveFileExW(
            temporary.c_str(), path.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        const DWORD replace_error = GetLastError();
        (void)DeleteFileW(temporary.c_str());
        throw std::system_error(
            static_cast<int>(replace_error), std::system_category(),
            "cannot atomically replace pair-binding state");
    }
}

template <typename Operation>
[[nodiscard]] bool guarded(std::string& error, Operation&& operation) noexcept {
    error.clear();
    try {
        operation();
        return true;
    } catch (const std::exception& failure) {
        error = failure.what();
        return false;
    } catch (...) {
        error = "pair-binding storage failed";
        return false;
    }
}

}  // namespace

HostPairBindingStoreV1::HostPairBindingStoreV1(
    std::filesystem::path state_file)
    : state_file_(std::move(state_file)) {
    if (state_file_.empty()) {
        throw std::invalid_argument("pair-binding state path is required");
    }
    lock_file_ = state_file_;
    lock_file_ += L".lock";
}

std::optional<HostAuthenticatedControlPairBindingV1>
HostPairBindingStoreV1::load(std::string& error) {
    std::optional<HostAuthenticatedControlPairBindingV1> result;
    const bool loaded = guarded(error, [&] {
        std::scoped_lock process_lock(process_mutex_);
        const auto parent = state_file_.parent_path();
        if (!parent.empty()) std::filesystem::create_directories(parent);
        InterprocessLock interprocess_lock(lock_file_);
        result = load_unlocked(state_file_);
    });
    return loaded ? result : std::nullopt;
}

bool HostPairBindingStoreV1::commit_initial_binding(
    const HostAuthenticatedControlPairBindingV1& binding,
    std::string& error) {
    return guarded(error, [&] {
        if (!valid_binding(binding) || binding.generation_high_watermark != 0U) {
            throw std::runtime_error("initial pair-binding is invalid");
        }
        std::scoped_lock process_lock(process_mutex_);
        const auto parent = state_file_.parent_path();
        if (!parent.empty()) std::filesystem::create_directories(parent);
        InterprocessLock interprocess_lock(lock_file_);
        const auto existing = load_unlocked(state_file_);
        if (existing.has_value()) {
            if (!same_pair(*existing, binding)) {
                throw std::runtime_error(
                    "a different pair-binding is already installed");
            }
            return;
        }
        persist_atomically(state_file_, serialize(binding));
    });
}

bool HostPairBindingStoreV1::commit_generation(
    const HostAuthenticatedControlPairBindingV1& expected_binding,
    const std::uint64_t generation,
    std::string& error) {
    return guarded(error, [&] {
        if (!valid_binding(expected_binding) || generation == 0U ||
            generation > kSigned64Maximum) {
            throw std::runtime_error("pair generation is invalid");
        }
        std::scoped_lock process_lock(process_mutex_);
        const auto parent = state_file_.parent_path();
        if (!parent.empty()) std::filesystem::create_directories(parent);
        InterprocessLock interprocess_lock(lock_file_);
        auto existing = load_unlocked(state_file_);
        if (!existing.has_value() || !same_pair(*existing, expected_binding)) {
            throw std::runtime_error("pair-binding does not match stored state");
        }
        if (generation <= existing->generation_high_watermark) {
            throw std::runtime_error("pair generation did not advance");
        }
        existing->generation_high_watermark = generation;
        persist_atomically(state_file_, serialize(*existing));
    });
}

}  // namespace vfdual
