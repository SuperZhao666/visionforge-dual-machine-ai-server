#pragma once

#include "vfdual/authenticated_data_plane_v2.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace vfdual {

/**
 * Mouse-button specialization of the authenticated data-plane v2 envelope.
 *
 * The 36-byte traffic material must be the confirmed peer-handshake v1
 * mouse_host_to_android output: AES-256 key[32] followed by nonce prefix[4].
 * Handshake v1 defines no in-session rekey, so its only valid key epoch is 1.
 */
inline constexpr std::uint32_t kAuthenticatedMouseButtonKeyEpochV1 = 1U;
inline constexpr std::size_t kAuthenticatedMouseButtonPayloadBytes = 1U;
inline constexpr std::size_t kAuthenticatedMouseButtonTrafficMaterialBytes =
    kAes256KeyBytes + kGcmNoncePrefixBytes;
inline constexpr std::uint8_t kAuthenticatedMouseButtonValidMask = 0x1fU;

[[nodiscard]] AuthenticatedPacketTuple
make_authenticated_mouse_button_host_to_android_tuple(
    std::uint64_t connection_id) noexcept;

/** Copies confirmed handshake material into one move-only traffic-key owner. */
[[nodiscard]] AuthenticatedTrafficKey
make_authenticated_mouse_button_host_to_android_key(
    std::uint64_t connection_id,
    std::span<
        const std::byte,
        kAuthenticatedMouseButtonTrafficMaterialBytes> traffic_material)
    noexcept;

/** Encodes exactly one complete physical-button snapshot. */
[[nodiscard]] bool encode_authenticated_mouse_button_payload(
    std::uint8_t button_mask,
    std::span<std::byte, kAuthenticatedMouseButtonPayloadBytes> destination)
    noexcept;

/**
 * Decodes only the canonical one-byte payload after its VFA2 envelope has
 * authenticated. The destination is cleared on every rejection.
 */
[[nodiscard]] bool decode_authenticated_mouse_button_payload(
    std::span<const std::byte> plaintext,
    std::uint8_t& destination) noexcept;

}  // namespace vfdual
