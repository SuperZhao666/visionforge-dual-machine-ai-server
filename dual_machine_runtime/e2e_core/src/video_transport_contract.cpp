#include "vf/video_transport_contract.hpp"

namespace vf::transport {

ContractViolation validate(const WireHeader& header) noexcept {
    if (header.stream_epoch < kMinimumStreamEpoch) {
        return ContractViolation::ZeroEpoch;
    }
    if (header.stream_epoch > kMaximumStreamEpoch) {
        return ContractViolation::EpochOutOfRange;
    }
    if (header.fragment_count == 0) {
        return ContractViolation::ZeroFragmentCount;
    }
    if (header.fragment_count > kMaximumFragmentCount) {
        return ContractViolation::TooManyFragments;
    }
    if (header.fragment_index >= header.fragment_count) {
        return ContractViolation::FragmentIndexOutOfRange;
    }
    if (header.kind == PacketKind::Repeat &&
        (header.fragment_index != 0 || header.fragment_count != 1)) {
        return ContractViolation::RepeatShapeInvalid;
    }
    return ContractViolation::None;
}

std::string_view violation_name(ContractViolation violation) noexcept {
    switch (violation) {
        case ContractViolation::None: return "NONE";
        case ContractViolation::ZeroEpoch: return "ZERO_EPOCH";
        case ContractViolation::EpochOutOfRange: return "EPOCH_OUT_OF_RANGE";
        case ContractViolation::ZeroFragmentCount: return "ZERO_FRAGMENT_COUNT";
        case ContractViolation::TooManyFragments: return "TOO_MANY_FRAGMENTS";
        case ContractViolation::FragmentIndexOutOfRange: return "FRAGMENT_INDEX_OUT_OF_RANGE";
        case ContractViolation::RepeatShapeInvalid: return "REPEAT_SHAPE_INVALID";
    }
    return "UNKNOWN";
}

}  // namespace vf::transport
