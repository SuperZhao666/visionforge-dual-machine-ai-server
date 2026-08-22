#include "vfdual/authenticated_mouse_button_v2.hpp"

#include <algorithm>

namespace vfdual {

AuthenticatedPacketTuple
make_authenticated_mouse_button_host_to_android_tuple(
    const std::uint64_t connection_id) noexcept {
    return AuthenticatedPacketTuple{
        .connection_id = connection_id,
        .key_epoch = kAuthenticatedMouseButtonKeyEpochV1,
        .direction = DataPlaneDirection::host_to_android,
        .packet_type = AuthenticatedPacketType::mouse_button,
    };
}

AuthenticatedTrafficKey
make_authenticated_mouse_button_host_to_android_key(
    const std::uint64_t connection_id,
    const std::span<
        const std::byte,
        kAuthenticatedMouseButtonTrafficMaterialBytes> traffic_material)
    noexcept {
    AuthenticatedTrafficKey traffic_key;
    traffic_key.tuple =
        make_authenticated_mouse_button_host_to_android_tuple(connection_id);
    std::copy_n(
        traffic_material.begin(),
        traffic_key.aes_256_key.size(),
        traffic_key.aes_256_key.begin());
    std::copy_n(
        traffic_material.begin() +
            static_cast<std::ptrdiff_t>(traffic_key.aes_256_key.size()),
        traffic_key.nonce_prefix.size(),
        traffic_key.nonce_prefix.begin());
    return traffic_key;
}

bool encode_authenticated_mouse_button_payload(
    const std::uint8_t button_mask,
    const std::span<
        std::byte,
        kAuthenticatedMouseButtonPayloadBytes> destination) noexcept {
    destination[0] = std::byte{0U};
    if ((button_mask & ~kAuthenticatedMouseButtonValidMask) != 0U) {
        return false;
    }
    destination[0] = std::byte{button_mask};
    return true;
}

bool decode_authenticated_mouse_button_payload(
    const std::span<const std::byte> plaintext,
    std::uint8_t& destination) noexcept {
    destination = 0U;
    if (plaintext.size() != kAuthenticatedMouseButtonPayloadBytes) {
        return false;
    }
    const auto button_mask = std::to_integer<std::uint8_t>(plaintext[0]);
    if ((button_mask & ~kAuthenticatedMouseButtonValidMask) != 0U) {
        return false;
    }
    destination = button_mask;
    return true;
}

}  // namespace vfdual
