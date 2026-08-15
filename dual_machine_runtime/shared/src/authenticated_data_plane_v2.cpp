#include "vfdual/authenticated_data_plane_v2.hpp"

#include <algorithm>
#include <limits>
#include <new>
#include <utility>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#endif

namespace vfdual {
namespace {

constexpr std::array<std::byte, 4U> kPacketMagic{
    std::byte{'V'}, std::byte{'F'}, std::byte{'A'}, std::byte{'2'}};
constexpr std::size_t kVersionOffset = 4U;
constexpr std::size_t kHeaderSizeOffset = 5U;
constexpr std::size_t kPacketTypeOffset = 6U;
constexpr std::size_t kDirectionOffset = 7U;
constexpr std::size_t kConnectionIdOffset = 8U;
constexpr std::size_t kKeyEpochOffset = 16U;
constexpr std::size_t kCounterOffset = 20U;
constexpr std::size_t kPayloadLengthOffset = 28U;
constexpr std::size_t kMinimumPacketBytes =
    kAuthenticatedPacketHeaderBytes + kGcmTagBytes;

[[nodiscard]] bool packet_type_valid(
    const AuthenticatedPacketType packet_type) noexcept {
    switch (packet_type) {
        case AuthenticatedPacketType::video:
        case AuthenticatedPacketType::presence_probe:
        case AuthenticatedPacketType::idr_request:
        case AuthenticatedPacketType::mouse_button:
            return true;
        case AuthenticatedPacketType::invalid:
            return false;
    }
    return false;
}

[[nodiscard]] bool direction_valid(
    const DataPlaneDirection direction) noexcept {
    switch (direction) {
        case DataPlaneDirection::host_to_android:
        case DataPlaneDirection::android_to_host:
            return true;
        case DataPlaneDirection::invalid:
            return false;
    }
    return false;
}

[[nodiscard]] bool tuple_valid(
    const AuthenticatedPacketTuple& tuple) noexcept {
    return tuple.connection_id != 0U &&
        tuple.key_epoch != 0U &&
        direction_valid(tuple.direction) &&
        packet_type_valid(tuple.packet_type);
}

void store_u32(
    const std::span<std::byte> output,
    std::size_t offset,
    const std::uint32_t value) noexcept {
    for (int shift = 24; shift >= 0; shift -= 8) {
        output[offset++] = std::byte{static_cast<std::uint8_t>(value >> shift)};
    }
}

void store_u64(
    const std::span<std::byte> output,
    std::size_t offset,
    const std::uint64_t value) noexcept {
    for (int shift = 56; shift >= 0; shift -= 8) {
        output[offset++] = std::byte{static_cast<std::uint8_t>(value >> shift)};
    }
}

[[nodiscard]] std::uint32_t load_u32(
    const std::span<const std::byte> input,
    const std::size_t offset) noexcept {
    std::uint32_t value{};
    for (std::size_t index{}; index < sizeof(value); ++index) {
        value = (value << 8U) |
            std::to_integer<std::uint8_t>(input[offset + index]);
    }
    return value;
}

[[nodiscard]] std::uint64_t load_u64(
    const std::span<const std::byte> input,
    const std::size_t offset) noexcept {
    std::uint64_t value{};
    for (std::size_t index{}; index < sizeof(value); ++index) {
        value = (value << 8U) |
            std::to_integer<std::uint8_t>(input[offset + index]);
    }
    return value;
}

void erase_bytes(const std::span<std::byte> bytes) noexcept {
    if (bytes.empty()) return;
#if defined(_WIN32)
    SecureZeroMemory(bytes.data(), bytes.size());
#else
    volatile auto* destination =
        reinterpret_cast<volatile unsigned char*>(bytes.data());
    for (std::size_t index{}; index < bytes.size(); ++index) {
        destination[index] = 0U;
    }
#endif
}

void encode_header(
    const AuthenticatedPacketTuple& tuple,
    const std::uint64_t counter,
    const std::uint32_t payload_size,
    const std::span<std::byte> header) noexcept {
    std::copy(kPacketMagic.begin(), kPacketMagic.end(), header.begin());
    header[kVersionOffset] = std::byte{kAuthenticatedDataPlaneVersion};
    header[kHeaderSizeOffset] =
        std::byte{static_cast<std::uint8_t>(kAuthenticatedPacketHeaderBytes)};
    header[kPacketTypeOffset] =
        std::byte{static_cast<std::uint8_t>(tuple.packet_type)};
    header[kDirectionOffset] =
        std::byte{static_cast<std::uint8_t>(tuple.direction)};
    store_u64(header, kConnectionIdOffset, tuple.connection_id);
    store_u32(header, kKeyEpochOffset, tuple.key_epoch);
    store_u64(header, kCounterOffset, counter);
    store_u32(header, kPayloadLengthOffset, payload_size);
}

[[nodiscard]] PacketOpenStatus map_validation_status(
    const PacketValidationStatus status) noexcept {
    switch (status) {
        case PacketValidationStatus::valid:
            return PacketOpenStatus::opened;
        case PacketValidationStatus::invalid_expected_tuple:
            return PacketOpenStatus::invalid_configuration;
        case PacketValidationStatus::wrong_connection_id:
            return PacketOpenStatus::wrong_connection_id;
        case PacketValidationStatus::wrong_key_epoch:
            return PacketOpenStatus::wrong_key_epoch;
        case PacketValidationStatus::wrong_direction:
            return PacketOpenStatus::wrong_direction;
        case PacketValidationStatus::wrong_packet_type:
            return PacketOpenStatus::wrong_packet_type;
    }
    return PacketOpenStatus::invalid_configuration;
}

#if defined(_WIN32)

[[nodiscard]] bool bcrypt_succeeded(const NTSTATUS status) noexcept {
    return status >= 0;
}

[[nodiscard]] PUCHAR writable_bytes(
    const std::span<std::byte> bytes) noexcept {
    return reinterpret_cast<PUCHAR>(bytes.data());
}

[[nodiscard]] PUCHAR readonly_bytes(
    const std::span<const std::byte> bytes) noexcept {
    return const_cast<PUCHAR>(
        reinterpret_cast<const UCHAR*>(bytes.data()));
}

class BCryptAes256GcmCipher final : public Aes256GcmCipher {
public:
    BCryptAes256GcmCipher() = default;

    ~BCryptAes256GcmCipher() override {
        if (key_ != nullptr) {
            static_cast<void>(BCryptDestroyKey(key_));
            key_ = nullptr;
        }
        erase_bytes(key_object_);
        if (algorithm_ != nullptr) {
            static_cast<void>(BCryptCloseAlgorithmProvider(algorithm_, 0U));
            algorithm_ = nullptr;
        }
    }

    BCryptAes256GcmCipher(const BCryptAes256GcmCipher&) = delete;
    BCryptAes256GcmCipher& operator=(const BCryptAes256GcmCipher&) = delete;

    [[nodiscard]] static std::unique_ptr<BCryptAes256GcmCipher> create(
        const std::span<const std::byte, kAes256KeyBytes> key) noexcept {
        try {
            auto cipher = std::make_unique<BCryptAes256GcmCipher>();
            if (!cipher->initialize(key)) return {};
            return cipher;
        } catch (...) {
            return {};
        }
    }

    [[nodiscard]] bool encrypt(
        const std::span<const std::byte, kGcmNonceBytes> nonce,
        const std::span<const std::byte> authenticated_data,
        const std::span<const std::byte> plaintext,
        const std::span<std::byte> ciphertext,
        const std::span<std::byte, kGcmTagBytes> tag) noexcept override {
        if (!sizes_valid(authenticated_data, plaintext, ciphertext) ||
            key_ == nullptr) {
            return false;
        }

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authentication_info;
        BCRYPT_INIT_AUTH_MODE_INFO(authentication_info);
        authentication_info.pbNonce = readonly_bytes(nonce);
        authentication_info.cbNonce = static_cast<ULONG>(nonce.size());
        authentication_info.pbAuthData = readonly_bytes(authenticated_data);
        authentication_info.cbAuthData =
            static_cast<ULONG>(authenticated_data.size());
        authentication_info.pbTag = writable_bytes(
            std::span<std::byte>{tag.data(), tag.size()});
        authentication_info.cbTag = static_cast<ULONG>(tag.size());

        ULONG bytes_written{};
        const NTSTATUS status = BCryptEncrypt(
            key_,
            readonly_bytes(plaintext),
            static_cast<ULONG>(plaintext.size()),
            &authentication_info,
            nullptr,
            0U,
            writable_bytes(ciphertext),
            static_cast<ULONG>(ciphertext.size()),
            &bytes_written,
            0U);
        return bcrypt_succeeded(status) && bytes_written == ciphertext.size();
    }

    [[nodiscard]] bool decrypt(
        const std::span<const std::byte, kGcmNonceBytes> nonce,
        const std::span<const std::byte> authenticated_data,
        const std::span<const std::byte> ciphertext,
        const std::span<const std::byte, kGcmTagBytes> tag,
        const std::span<std::byte> plaintext) noexcept override {
        if (!sizes_valid(authenticated_data, ciphertext, plaintext) ||
            key_ == nullptr) {
            erase_bytes(plaintext);
            return false;
        }

        std::array<std::byte, kGcmTagBytes> mutable_tag{};
        std::copy(tag.begin(), tag.end(), mutable_tag.begin());
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authentication_info;
        BCRYPT_INIT_AUTH_MODE_INFO(authentication_info);
        authentication_info.pbNonce = readonly_bytes(nonce);
        authentication_info.cbNonce = static_cast<ULONG>(nonce.size());
        authentication_info.pbAuthData = readonly_bytes(authenticated_data);
        authentication_info.cbAuthData =
            static_cast<ULONG>(authenticated_data.size());
        authentication_info.pbTag = writable_bytes(
            std::span<std::byte>{mutable_tag});
        authentication_info.cbTag = static_cast<ULONG>(mutable_tag.size());

        ULONG bytes_written{};
        const NTSTATUS status = BCryptDecrypt(
            key_,
            readonly_bytes(ciphertext),
            static_cast<ULONG>(ciphertext.size()),
            &authentication_info,
            nullptr,
            0U,
            writable_bytes(plaintext),
            static_cast<ULONG>(plaintext.size()),
            &bytes_written,
            0U);
        const bool succeeded =
            bcrypt_succeeded(status) && bytes_written == plaintext.size();
        if (!succeeded) erase_bytes(plaintext);
        return succeeded;
    }

private:
    [[nodiscard]] bool initialize(
        const std::span<const std::byte, kAes256KeyBytes> key) {
        if (!bcrypt_succeeded(BCryptOpenAlgorithmProvider(
                &algorithm_, BCRYPT_AES_ALGORITHM, nullptr, 0U))) {
            return false;
        }
        if (!bcrypt_succeeded(BCryptSetProperty(
                algorithm_,
                BCRYPT_CHAINING_MODE,
                reinterpret_cast<PUCHAR>(
                    const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
                sizeof(BCRYPT_CHAIN_MODE_GCM),
                0U))) {
            return false;
        }

        DWORD object_bytes{};
        ULONG copied{};
        if (!bcrypt_succeeded(BCryptGetProperty(
                algorithm_,
                BCRYPT_OBJECT_LENGTH,
                reinterpret_cast<PUCHAR>(&object_bytes),
                sizeof(object_bytes),
                &copied,
                0U)) ||
            copied != sizeof(object_bytes) || object_bytes == 0U) {
            return false;
        }
        key_object_.resize(object_bytes);
        return bcrypt_succeeded(BCryptGenerateSymmetricKey(
            algorithm_,
            &key_,
            writable_bytes(std::span<std::byte>{key_object_}),
            static_cast<ULONG>(key_object_.size()),
            readonly_bytes(key),
            static_cast<ULONG>(key.size()),
            0U));
    }

    [[nodiscard]] static bool sizes_valid(
        const std::span<const std::byte> authenticated_data,
        const std::span<const std::byte> input,
        const std::span<std::byte> output) noexcept {
        constexpr auto maximum_ulong =
            static_cast<std::size_t>((std::numeric_limits<ULONG>::max)());
        return input.size() == output.size() &&
            authenticated_data.size() <= maximum_ulong &&
            input.size() <= maximum_ulong;
    }

    BCRYPT_ALG_HANDLE algorithm_{};
    BCRYPT_KEY_HANDLE key_{};
    std::vector<std::byte> key_object_;
};

class BCryptAes256GcmProvider final : public Aes256GcmProvider {
public:
    [[nodiscard]] std::unique_ptr<Aes256GcmCipher> import_key(
        const std::span<const std::byte, kAes256KeyBytes> key)
        noexcept override {
        return BCryptAes256GcmCipher::create(key);
    }
};

#endif

}  // namespace

std::unique_ptr<Aes256GcmProvider>
make_platform_aes_256_gcm_provider() noexcept {
#if defined(_WIN32)
    try {
        return std::make_unique<BCryptAes256GcmProvider>();
    } catch (...) {
        return {};
    }
#else
    return {};
#endif
}

AuthenticatedTrafficKey::~AuthenticatedTrafficKey() {
    erase_bytes(aes_256_key);
    erase_bytes(nonce_prefix);
    tuple = {};
}

AuthenticatedTrafficKey::AuthenticatedTrafficKey(
    AuthenticatedTrafficKey&& other) noexcept
    : tuple(other.tuple),
      aes_256_key(other.aes_256_key),
      nonce_prefix(other.nonce_prefix) {
    erase_bytes(other.aes_256_key);
    erase_bytes(other.nonce_prefix);
    other.tuple = {};
}

AuthenticatedTrafficKey& AuthenticatedTrafficKey::operator=(
    AuthenticatedTrafficKey&& other) noexcept {
    if (this == &other) return *this;
    erase_bytes(aes_256_key);
    erase_bytes(nonce_prefix);
    tuple = other.tuple;
    aes_256_key = other.aes_256_key;
    nonce_prefix = other.nonce_prefix;
    erase_bytes(other.aes_256_key);
    erase_bytes(other.nonce_prefix);
    other.tuple = {};
    return *this;
}

PacketParseResult parse_authenticated_packet_v2(
    const std::span<const std::byte> datagram) noexcept {
    PacketParseResult result{};
    if (datagram.size() < kMinimumPacketBytes) {
        result.status = PacketParseStatus::packet_too_short;
        return result;
    }
    if (!std::equal(kPacketMagic.begin(), kPacketMagic.end(), datagram.begin())) {
        result.status = PacketParseStatus::invalid_magic;
        return result;
    }
    if (std::to_integer<std::uint8_t>(datagram[kVersionOffset]) !=
        kAuthenticatedDataPlaneVersion) {
        result.status = PacketParseStatus::unsupported_version;
        return result;
    }
    if (std::to_integer<std::uint8_t>(datagram[kHeaderSizeOffset]) !=
        kAuthenticatedPacketHeaderBytes) {
        result.status = PacketParseStatus::invalid_header_size;
        return result;
    }

    const auto packet_type = static_cast<AuthenticatedPacketType>(
        std::to_integer<std::uint8_t>(datagram[kPacketTypeOffset]));
    if (!packet_type_valid(packet_type)) {
        result.status = PacketParseStatus::invalid_packet_type;
        return result;
    }
    const auto direction = static_cast<DataPlaneDirection>(
        std::to_integer<std::uint8_t>(datagram[kDirectionOffset]));
    if (!direction_valid(direction)) {
        result.status = PacketParseStatus::invalid_direction;
        return result;
    }

    const std::uint64_t counter = load_u64(datagram, kCounterOffset);
    if (counter > kMaximumAuthenticatedPacketCounter) {
        result.status = PacketParseStatus::counter_exceeds_key_lifetime;
        return result;
    }

    const std::uint32_t payload_size =
        load_u32(datagram, kPayloadLengthOffset);
    if (payload_size > kMaximumAuthenticatedPayloadBytes) {
        result.status = PacketParseStatus::payload_too_large;
        return result;
    }
    const std::size_t expected_size =
        kAuthenticatedPacketHeaderBytes +
        static_cast<std::size_t>(payload_size) +
        kGcmTagBytes;
    if (datagram.size() != expected_size) {
        result.status = PacketParseStatus::length_mismatch;
        return result;
    }

    result.status = PacketParseStatus::parsed;
    result.packet = ParsedAuthenticatedPacket{
        .tuple = {
            .connection_id = load_u64(datagram, kConnectionIdOffset),
            .key_epoch = load_u32(datagram, kKeyEpochOffset),
            .direction = direction,
            .packet_type = packet_type,
        },
        .counter = counter,
        .authenticated_header = datagram.first(kAuthenticatedPacketHeaderBytes),
        .ciphertext = datagram.subspan(
            kAuthenticatedPacketHeaderBytes, payload_size),
        .tag = datagram.last(kGcmTagBytes),
    };
    return result;
}

PacketValidationStatus validate_authenticated_packet_v2(
    const ParsedAuthenticatedPacket& packet,
    const AuthenticatedPacketTuple& expected) noexcept {
    if (!tuple_valid(expected)) {
        return PacketValidationStatus::invalid_expected_tuple;
    }
    if (packet.tuple.connection_id != expected.connection_id) {
        return PacketValidationStatus::wrong_connection_id;
    }
    if (packet.tuple.key_epoch != expected.key_epoch) {
        return PacketValidationStatus::wrong_key_epoch;
    }
    if (packet.tuple.direction != expected.direction) {
        return PacketValidationStatus::wrong_direction;
    }
    if (packet.tuple.packet_type != expected.packet_type) {
        return PacketValidationStatus::wrong_packet_type;
    }
    return PacketValidationStatus::valid;
}

ReplayDisposition SlidingReplayWindow1024::classify(
    const std::uint64_t counter) const noexcept {
    if (!initialized_ || counter > highest_counter_) {
        return ReplayDisposition::fresh;
    }
    const std::uint64_t distance = highest_counter_ - counter;
    if (distance >= kReplayWindowBits) {
        return ReplayDisposition::too_old;
    }
    const std::size_t word = static_cast<std::size_t>(distance / 64U);
    const std::size_t bit = static_cast<std::size_t>(distance % 64U);
    return (seen_[word] & (std::uint64_t{1U} << bit)) != 0U
        ? ReplayDisposition::duplicate
        : ReplayDisposition::fresh;
}

ReplayWindowSnapshot SlidingReplayWindow1024::snapshot() const noexcept {
    return ReplayWindowSnapshot{
        .initialized = initialized_,
        .highest_authenticated_counter = highest_counter_,
    };
}

bool SlidingReplayWindow1024::commit_authenticated(
    const std::uint64_t counter) noexcept {
    if (classify(counter) != ReplayDisposition::fresh) return false;
    if (!initialized_) {
        seen_.fill(0U);
        seen_.front() = 1U;
        highest_counter_ = counter;
        initialized_ = true;
        return true;
    }
    if (counter <= highest_counter_) {
        const std::uint64_t distance = highest_counter_ - counter;
        const std::size_t word = static_cast<std::size_t>(distance / 64U);
        const std::size_t bit = static_cast<std::size_t>(distance % 64U);
        seen_[word] |= std::uint64_t{1U} << bit;
        return true;
    }

    const std::uint64_t advance = counter - highest_counter_;
    if (advance >= kReplayWindowBits) {
        seen_.fill(0U);
    } else {
        std::array<std::uint64_t, kReplayWindowBits / 64U> shifted{};
        const std::size_t word_shift =
            static_cast<std::size_t>(advance / 64U);
        const std::size_t bit_shift =
            static_cast<std::size_t>(advance % 64U);
        for (std::size_t source{}; source < seen_.size(); ++source) {
            const std::size_t destination = source + word_shift;
            if (destination >= shifted.size()) break;
            shifted[destination] |= seen_[source] << bit_shift;
            if (bit_shift != 0U && destination + 1U < shifted.size()) {
                shifted[destination + 1U] |=
                    seen_[source] >> (64U - bit_shift);
            }
        }
        seen_ = shifted;
    }
    highest_counter_ = counter;
    seen_.front() |= 1U;
    return true;
}

std::array<std::byte, kGcmNonceBytes> compose_authenticated_packet_nonce(
    const std::span<const std::byte, kGcmNoncePrefixBytes> prefix,
    const std::uint64_t counter) noexcept {
    std::array<std::byte, kGcmNonceBytes> nonce{};
    std::copy(prefix.begin(), prefix.end(), nonce.begin());
    store_u64(nonce, kGcmNoncePrefixBytes, counter);
    return nonce;
}

AuthenticatedPacketSealer::AuthenticatedPacketSealer(
    AuthenticatedTrafficKey traffic_key,
    Aes256GcmProvider& provider) noexcept
    : AuthenticatedPacketSealer(std::move(traffic_key), provider, 0U) {}

AuthenticatedPacketSealer::AuthenticatedPacketSealer(
    AuthenticatedTrafficKey traffic_key,
    Aes256GcmProvider& provider,
    const std::uint64_t initial_counter) noexcept
    : tuple_(traffic_key.tuple),
      nonce_prefix_(traffic_key.nonce_prefix),
      next_counter_(initial_counter),
      counter_available_(
          initial_counter <= kMaximumAuthenticatedPacketCounter) {
    if (tuple_valid(tuple_)) {
        cipher_ = provider.import_key(traffic_key.aes_256_key);
    }
    erase_bytes(traffic_key.aes_256_key);
}

AuthenticatedPacketSealer::~AuthenticatedPacketSealer() {
    cipher_.reset();
    erase_bytes(nonce_prefix_);
}

PacketSealResult AuthenticatedPacketSealer::seal(
    const std::span<const std::byte> plaintext) noexcept {
    std::lock_guard lock(mutex_);
    PacketSealResult result{};
    if (!tuple_valid(tuple_) || cipher_ == nullptr) {
        result.status = PacketSealStatus::invalid_configuration;
        return result;
    }
    if (plaintext.size() > kMaximumAuthenticatedPayloadBytes) {
        result.status = PacketSealStatus::plaintext_too_large;
        return result;
    }
    if (!counter_available_) {
        result.status = PacketSealStatus::counter_exhausted;
        return result;
    }

    const std::uint64_t counter = next_counter_;
    try {
        result.datagram.resize(
            kAuthenticatedPacketHeaderBytes + plaintext.size() + kGcmTagBytes);
    } catch (...) {
        result.status = PacketSealStatus::allocation_failed;
        return result;
    }
    const auto datagram = std::span<std::byte>{result.datagram};
    const auto header = datagram.first(kAuthenticatedPacketHeaderBytes);
    encode_header(
        tuple_, counter, static_cast<std::uint32_t>(plaintext.size()), header);
    const auto ciphertext = datagram.subspan(
        kAuthenticatedPacketHeaderBytes, plaintext.size());
    const auto tag = std::span<std::byte, kGcmTagBytes>{
        result.datagram.data() +
            static_cast<std::ptrdiff_t>(
                kAuthenticatedPacketHeaderBytes + plaintext.size()),
        kGcmTagBytes};
    const auto nonce =
        compose_authenticated_packet_nonce(nonce_prefix_, counter);
    // Burn the nonce before entering the provider. A provider is allowed to
    // fail after it has already consumed the nonce or produced partial output;
    // retrying the same counter would therefore violate the GCM contract.
    result.counter = counter;
    if (counter == kMaximumAuthenticatedPacketCounter) {
        counter_available_ = false;
    } else {
        ++next_counter_;
    }
    if (!cipher_->encrypt(nonce, header, plaintext, ciphertext, tag)) {
        erase_bytes(result.datagram);
        result.datagram.clear();
        result.status = PacketSealStatus::encryption_failed;
        return result;
    }

    result.status = PacketSealStatus::sealed;
    return result;
}

AuthenticatedPacketOpener::AuthenticatedPacketOpener(
    AuthenticatedTrafficKey traffic_key,
    Aes256GcmProvider& provider) noexcept
    : tuple_(traffic_key.tuple),
      nonce_prefix_(traffic_key.nonce_prefix) {
    if (tuple_valid(tuple_)) {
        cipher_ = provider.import_key(traffic_key.aes_256_key);
    }
    erase_bytes(traffic_key.aes_256_key);
}

AuthenticatedPacketOpener::~AuthenticatedPacketOpener() {
    cipher_.reset();
    erase_bytes(nonce_prefix_);
}

PacketOpenResult AuthenticatedPacketOpener::open(
    const std::span<const std::byte> datagram) noexcept {
    PacketOpenResult result{};
    if (!tuple_valid(tuple_) || cipher_ == nullptr) {
        result.status = PacketOpenStatus::invalid_configuration;
        return result;
    }

    const PacketParseResult parsed = parse_authenticated_packet_v2(datagram);
    result.parse_status = parsed.status;
    if (parsed.status != PacketParseStatus::parsed) {
        result.status = PacketOpenStatus::malformed_packet;
        return result;
    }

    const PacketValidationStatus validation =
        validate_authenticated_packet_v2(parsed.packet, tuple_);
    result.validation_status = validation;
    if (validation != PacketValidationStatus::valid) {
        result.status = map_validation_status(validation);
        return result;
    }

    std::lock_guard lock(mutex_);
    const ReplayDisposition replay =
        replay_window_.classify(parsed.packet.counter);
    if (replay == ReplayDisposition::duplicate) {
        result.status = PacketOpenStatus::duplicate;
        return result;
    }
    if (replay == ReplayDisposition::too_old) {
        result.status = PacketOpenStatus::too_old;
        return result;
    }

    try {
        result.plaintext.resize(parsed.packet.ciphertext.size());
    } catch (...) {
        result.status = PacketOpenStatus::allocation_failed;
        return result;
    }
    const auto nonce = compose_authenticated_packet_nonce(
        nonce_prefix_, parsed.packet.counter);
    const auto tag = std::span<const std::byte, kGcmTagBytes>{
        parsed.packet.tag.data(), parsed.packet.tag.size()};
    if (!cipher_->decrypt(
            nonce,
            parsed.packet.authenticated_header,
            parsed.packet.ciphertext,
            tag,
            result.plaintext)) {
        erase_bytes(result.plaintext);
        result.plaintext.clear();
        result.status = PacketOpenStatus::authentication_failed;
        return result;
    }
    if (!replay_window_.commit_authenticated(parsed.packet.counter)) {
        erase_bytes(result.plaintext);
        result.plaintext.clear();
        result.status = PacketOpenStatus::invalid_configuration;
        return result;
    }

    result.status = PacketOpenStatus::opened;
    result.authenticated_counter = parsed.packet.counter;
    return result;
}

ReplayWindowSnapshot AuthenticatedPacketOpener::replay_snapshot()
    const noexcept {
    std::lock_guard lock(mutex_);
    return replay_window_.snapshot();
}

}  // namespace vfdual
