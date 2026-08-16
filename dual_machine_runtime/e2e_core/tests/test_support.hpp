#pragma once

#include <stdexcept>

namespace vf::test {

inline void expect(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

}  // namespace vf::test
