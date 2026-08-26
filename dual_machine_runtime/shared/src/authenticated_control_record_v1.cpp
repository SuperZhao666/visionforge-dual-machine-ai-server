#include "vfdual/authenticated_control_record_v1.hpp"

#include <algorithm>
#include <new>
#include <utility>

#if defined(_WIN32)
#include <windows.h>
#endif

namespace vfdual {
namespace {

constexpr std::array<std::byte, 4U> kControlMagic{
    std::byte{'V'}, std::byte{'F'}, std::byte{'C'}, std::byte{'1'}};
constexpr std::size_t kVersionOffset = 4U;
constexpr std::size_t kHeaderSizeOffset = 5U;
constexpr std::size_t kDirectionOffset = 6U;
constexpr std::size_t kMessageTypeOffset = 7U;
constexpr std::size_t kConnectionIdOffset = 8U;
constexpr std::size_t kSessionGenerationOffset = 16U;
constexpr std::size_t kKeyEpochOffset = 24U;
constexpr std::size_t kCounterOffset = 28U;
constexpr std::size_t kCiphertextLengthOffset = 36U;
constexpr std::size_t kMinimumRecordBytes =
    kAuthenticatedControlHeaderBytes + kGcmTagBytes;

[[nodiscard]] bool direction_valid(
    const ControlRecordDirectionV1 direction) noexcept {
    switch (direction) {
        case ControlRecordDirectionV1::host_to_android:
        case ControlRecordDirectionV1::android_to_host:
            return true;
        case ControlRecordDirectionV1::invalid:
            return false;
    }
    return false;
}

[[nodiscard]] bool message_type_valid(
    const ControlMessageTypeV1 message_type) noexcept {
    switch (message_type) {
        case ControlMessageTypeV1::lease_offer:
        case ControlMessageTypeV1::lease_accept:
        case ControlMessageTypeV1::lease_commit:
        case ControlMessageTypeV1::session_close:
        case ControlMessageTypeV1::session_close_ack:
        case ControlMessageTypeV1::entitlement_status_sign_request:
        case ControlMessageTypeV1::entitlement_status_sign_response:
        case ControlMessageTypeV1::usage_authorization_sign_request:
        case ControlMessageTypeV1::usage_authorization_sign_response:
        case ControlMessageTypeV1::host_start_intent_claim_request:
        case ControlMessageTypeV1::host_start_intent_claim_response:
            return true;
        case ControlMessageTypeV1::invalid:
            return false;
    }
    return false;
}

[[nodiscard]] bool tuple_valid(
    const AuthenticatedControlTupleV1& tuple) noexcept {
    return tuple.connection_id != 0U &&
        tuple.session_generation != 0U &&
        tuple.key_epoch != 0U &&
        direction_valid(tuple.direction);
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
    const AuthenticatedControlTupleV1& tuple,
    const ControlMessageTypeV1 message_type,
    const std::uint64_t counter,
    const std::uint32_t ciphertext_size,
    const std::span<std::byte> header) noexcept {
    std::copy(kControlMagic.begin(), kControlMagic.end(), header.begin());
    header[kVersionOffset] = std::byte{kAuthenticatedControlRecordVersion};
    header[kHeaderSizeOffset] =
        std::byte{static_cast<std::uint8_t>(kAuthenticatedControlHeaderBytes)};
    header[kDirectionOffset] =
        std::byte{static_cast<std::uint8_t>(tuple.direction)};
    header[kMessageTypeOffset] =
        std::byte{static_cast<std::uint8_t>(message_type)};
    store_u64(header, kConnectionIdOffset, tuple.connection_id);
    store_u64(header, kSessionGenerationOffset, tuple.session_generation);
    store_u32(header, kKeyEpochOffset, tuple.key_epoch);
    store_u64(header, kCounterOffset, counter);
    store_u32(header, kCiphertextLengthOffset, ciphertext_size);
}

}  // namespace

AuthenticatedControlTrafficKeyV1::~AuthenticatedControlTrafficKeyV1() {
    erase_bytes(aes_256_key);
    erase_bytes(nonce_prefix);
    tuple = {};
}

AuthenticatedControlTrafficKeyV1::AuthenticatedControlTrafficKeyV1(
    AuthenticatedControlTrafficKeyV1&& other) noexcept
    : tuple(other.tuple),
      aes_256_key(other.aes_256_key),
      nonce_prefix(other.nonce_prefix) {
    erase_bytes(other.aes_256_key);
    erase_bytes(other.nonce_prefix);
    other.tuple = {};
}

AuthenticatedControlTrafficKeyV1&
AuthenticatedControlTrafficKeyV1::operator=(
    AuthenticatedControlTrafficKeyV1&& other) noexcept {
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

ControlRecordParseResultV1 parse_authenticated_control_record_v1(
    const std::span<const std::byte> envelope) noexcept {
    ControlRecordParseResultV1 result{};
    if (envelope.size() < kMinimumRecordBytes) {
        result.status = ControlRecordParseStatusV1::record_too_short;
        return result;
    }
    if (!std::equal(kControlMagic.begin(), kControlMagic.end(), envelope.begin())) {
        result.status = ControlRecordParseStatusV1::invalid_magic;
        return result;
    }
    if (std::to_integer<std::uint8_t>(envelope[kVersionOffset]) !=
        kAuthenticatedControlRecordVersion) {
        result.status = ControlRecordParseStatusV1::unsupported_version;
        return result;
    }
    if (std::to_integer<std::uint8_t>(envelope[kHeaderSizeOffset]) !=
        kAuthenticatedControlHeaderBytes) {
        result.status = ControlRecordParseStatusV1::invalid_header_size;
        return result;
    }

    const auto direction = static_cast<ControlRecordDirectionV1>(
        std::to_integer<std::uint8_t>(envelope[kDirectionOffset]));
    if (!direction_valid(direction)) {
        result.status = ControlRecordParseStatusV1::invalid_direction;
        return result;
    }
    const auto message_type = static_cast<ControlMessageTypeV1>(
        std::to_integer<std::uint8_t>(envelope[kMessageTypeOffset]));
    if (!message_type_valid(message_type)) {
        result.status = ControlRecordParseStatusV1::invalid_message_type;
        return result;
    }

    const AuthenticatedControlTupleV1 tuple{
        .connection_id = load_u64(envelope, kConnectionIdOffset),
        .session_generation = load_u64(envelope, kSessionGenerationOffset),
        .key_epoch = load_u32(envelope, kKeyEpochOffset),
        .direction = direction,
    };
    if (!tuple_valid(tuple)) {
        result.status = ControlRecordParseStatusV1::invalid_tuple;
        return result;
    }
    const std::uint64_t counter = load_u64(envelope, kCounterOffset);
    if (counter > kMaximumAuthenticatedControlCounter) {
        result.status =
            ControlRecordParseStatusV1::counter_exceeds_key_lifetime;
        return result;
    }
    const std::uint32_t ciphertext_size =
        load_u32(envelope, kCiphertextLengthOffset);
    if (ciphertext_size > kMaximumAuthenticatedControlPayloadBytes) {
        result.status = ControlRecordParseStatusV1::payload_too_large;
        return result;
    }
    const std::size_t expected_size =
        kAuthenticatedControlHeaderBytes +
        static_cast<std::size_t>(ciphertext_size) + kGcmTagBytes;
    if (envelope.size() != expected_size) {
        result.status = ControlRecordParseStatusV1::length_mismatch;
        return result;
    }

    result.status = ControlRecordParseStatusV1::parsed;
    result.record = ParsedAuthenticatedControlRecordV1{
        .tuple = tuple,
        .message_type = message_type,
        .counter = counter,
        .authenticated_header =
            envelope.first(kAuthenticatedControlHeaderBytes),
        .ciphertext = envelope.subspan(
            kAuthenticatedControlHeaderBytes, ciphertext_size),
        .tag = envelope.last(kGcmTagBytes),
    };
    return result;
}

std::array<std::byte, kGcmNonceBytes>
compose_authenticated_control_nonce_v1(
    const std::span<const std::byte, kGcmNoncePrefixBytes> prefix,
    const std::uint64_t counter) noexcept {
    std::array<std::byte, kGcmNonceBytes> nonce{};
    std::copy(prefix.begin(), prefix.end(), nonce.begin());
    store_u64(nonce, kGcmNoncePrefixBytes, counter);
    return nonce;
}

AuthenticatedControlRecordSealerV1::AuthenticatedControlRecordSealerV1(
    AuthenticatedControlTrafficKeyV1 traffic_key,
    Aes256GcmProvider& provider) noexcept
    : AuthenticatedControlRecordSealerV1(
          std::move(traffic_key), provider, 0U) {}

AuthenticatedControlRecordSealerV1::AuthenticatedControlRecordSealerV1(
    AuthenticatedControlTrafficKeyV1 traffic_key,
    Aes256GcmProvider& provider,
    const std::uint64_t initial_counter) noexcept
    : tuple_(traffic_key.tuple),
      nonce_prefix_(traffic_key.nonce_prefix),
      next_counter_(initial_counter),
      counter_available_(initial_counter <= kMaximumAuthenticatedControlCounter) {
    if (tuple_valid(tuple_)) {
        cipher_ = provider.import_key(traffic_key.aes_256_key);
    }
    erase_bytes(traffic_key.aes_256_key);
}

AuthenticatedControlRecordSealerV1::~AuthenticatedControlRecordSealerV1() {
    cipher_.reset();
    erase_bytes(nonce_prefix_);
}

ControlRecordSealResultV1 AuthenticatedControlRecordSealerV1::seal(
    const ControlMessageTypeV1 message_type,
    const std::span<const std::byte> plaintext) noexcept {
    std::lock_guard lock(mutex_);
    ControlRecordSealResultV1 result{};
    if (!tuple_valid(tuple_) || cipher_ == nullptr) {
        result.status = ControlRecordSealStatusV1::invalid_configuration;
        return result;
    }
    if (!message_type_valid(message_type)) {
        result.status = ControlRecordSealStatusV1::invalid_message_type;
        return result;
    }
    if (plaintext.size() > kMaximumAuthenticatedControlPayloadBytes) {
        result.status = ControlRecordSealStatusV1::plaintext_too_large;
        return result;
    }
    if (!counter_available_) {
        result.status = ControlRecordSealStatusV1::counter_exhausted;
        return result;
    }

    const std::uint64_t counter = next_counter_;
    try {
        result.envelope.resize(
            kAuthenticatedControlHeaderBytes + plaintext.size() + kGcmTagBytes);
    } catch (...) {
        result.status = ControlRecordSealStatusV1::allocation_failed;
        return result;
    }
    const auto envelope = std::span<std::byte>{result.envelope};
    const auto header = envelope.first(kAuthenticatedControlHeaderBytes);
    encode_header(
        tuple_, message_type, counter,
        static_cast<std::uint32_t>(plaintext.size()), header);
    const auto ciphertext = envelope.subspan(
        kAuthenticatedControlHeaderBytes, plaintext.size());
    const auto tag = std::span<std::byte, kGcmTagBytes>{
        result.envelope.data() + static_cast<std::ptrdiff_t>(
            kAuthenticatedControlHeaderBytes + plaintext.size()),
        kGcmTagBytes};
    const auto nonce =
        compose_authenticated_control_nonce_v1(nonce_prefix_, counter);

    // Burn before entering the provider: a failed attempt may already have
    // consumed this nonce or exposed partial output.
    result.counter = counter;
    if (counter == kMaximumAuthenticatedControlCounter) {
        counter_available_ = false;
    } else {
        ++next_counter_;
    }
    if (!cipher_->encrypt(nonce, header, plaintext, ciphertext, tag)) {
        erase_bytes(result.envelope);
        result.envelope.clear();
        result.status = ControlRecordSealStatusV1::encryption_failed;
        return result;
    }
    result.status = ControlRecordSealStatusV1::sealed;
    return result;
}

AuthenticatedControlRecordOpenerV1::AuthenticatedControlRecordOpenerV1(
    AuthenticatedControlTrafficKeyV1 traffic_key,
    Aes256GcmProvider& provider) noexcept
    : tuple_(traffic_key.tuple),
      nonce_prefix_(traffic_key.nonce_prefix) {
    if (tuple_valid(tuple_)) {
        cipher_ = provider.import_key(traffic_key.aes_256_key);
    }
    erase_bytes(traffic_key.aes_256_key);
}

AuthenticatedControlRecordOpenerV1::~AuthenticatedControlRecordOpenerV1() {
    cipher_.reset();
    erase_bytes(nonce_prefix_);
}

ControlRecordOpenResultV1 AuthenticatedControlRecordOpenerV1::open(
    const std::span<const std::byte> envelope) noexcept {
    ControlRecordOpenResultV1 result{};
    if (!tuple_valid(tuple_) || cipher_ == nullptr) {
        result.status = ControlRecordOpenStatusV1::invalid_configuration;
        return result;
    }
    const auto parsed = parse_authenticated_control_record_v1(envelope);
    if (parsed.status != ControlRecordParseStatusV1::parsed ||
        parsed.record.tuple != tuple_) {
        result.status = ControlRecordOpenStatusV1::unauthenticated_record;
        return result;
    }

    std::lock_guard lock(mutex_);
    if (replay_window_.classify(parsed.record.counter) !=
        ReplayDisposition::fresh) {
        result.status = ControlRecordOpenStatusV1::unauthenticated_record;
        return result;
    }
    try {
        result.plaintext.resize(parsed.record.ciphertext.size());
    } catch (...) {
        result.status = ControlRecordOpenStatusV1::allocation_failed;
        return result;
    }
    const auto nonce = compose_authenticated_control_nonce_v1(
        nonce_prefix_, parsed.record.counter);
    const auto tag = std::span<const std::byte, kGcmTagBytes>{
        parsed.record.tag.data(), parsed.record.tag.size()};
    if (!cipher_->decrypt(
            nonce,
            parsed.record.authenticated_header,
            parsed.record.ciphertext,
            tag,
            result.plaintext) ||
        !replay_window_.commit_authenticated(parsed.record.counter)) {
        erase_bytes(result.plaintext);
        result.plaintext.clear();
        result.status = ControlRecordOpenStatusV1::unauthenticated_record;
        return result;
    }

    result.status = ControlRecordOpenStatusV1::opened;
    result.message_type = parsed.record.message_type;
    result.authenticated_counter = parsed.record.counter;
    return result;
}

ReplayWindowSnapshot AuthenticatedControlRecordOpenerV1::replay_snapshot()
    const noexcept {
    std::lock_guard lock(mutex_);
    return replay_window_.snapshot();
}

}  // namespace vfdual
