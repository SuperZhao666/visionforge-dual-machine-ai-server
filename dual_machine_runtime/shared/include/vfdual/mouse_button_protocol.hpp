#pragma once

#include "vfdual/authenticated_mouse_button_v2.hpp"

namespace vfdual {

/**
 * Compatibility tombstone: the unauthenticated mouse-button wire codec was
 * removed from the production library. All callers must use the VFA2
 * confirmed-session specialization in authenticated_mouse_button_v2.hpp.
 */
inline constexpr bool kLegacyPlaintextMouseButtonProtocolRemoved = true;

}  // namespace vfdual
