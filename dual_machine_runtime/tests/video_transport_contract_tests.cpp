#include "vfdual/protocol.hpp"
#include "vfdual/video_transport_contract.hpp"

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>

int main() {
  static_assert(vfdual::VideoTransportContract::header_bytes == 20U);
  static_assert(vfdual::VideoTransportContract::normal_magic == 0x56463247U);
  static_assert(vfdual::VideoTransportContract::repeated_magic == 0x56463252U);

  const vfdual::VideoFrameIdentity identity{0x0102'0304'0506'0708ULL, 9U};
  assert(identity.valid());
  const std::array<std::byte, 3> payload{
      std::byte{0x11}, std::byte{0x22}, std::byte{0x33}};
  std::array<std::byte, vfdual::kMaxDatagramBytes> storage{};
  const std::size_t size = vfdual::encode_video_packet_into(
      identity, false, 1U, 2U, payload, storage);
  assert(size == vfdual::kVideoPacketHeaderBytes + payload.size());
  assert(storage[0] == std::byte{0x56});
  assert(storage[1] == std::byte{0x46});
  assert(storage[2] == std::byte{0x32});
  assert(storage[3] == std::byte{0x47});
  assert(storage[4] == std::byte{0x01});
  assert(storage[11] == std::byte{0x08});
  assert(storage[15] == std::byte{0x09});
  assert(storage[17] == std::byte{0x01});
  assert(storage[19] == std::byte{0x02});

  vfdual::VideoFragment decoded{};
  assert(vfdual::decode_video_packet(
      std::span<const std::byte>(storage.data(), size), decoded));
  assert(decoded.identity == identity);
  assert(!decoded.repeated_content);
  assert(decoded.fragment_index == 1U);
  assert(decoded.fragment_count == 2U);
  assert(decoded.access_unit_part.size() == payload.size());

  std::uint32_t next{};
  assert(vfdual::advance_video_frame_sequence(8U, next));
  assert(next == 9U);
  assert(!vfdual::advance_video_frame_sequence(UINT32_MAX, next));

  const auto epoch = vfdual::derive_video_stream_epoch(0U, 0U);
  assert(epoch != 0U && epoch <= vfdual::kVideoStreamEpochMax);
  assert(!vfdual::valid_video_fragment_metadata(
      {0U, 1U}, 0U, 1U, 1U));
  return 0;
}
