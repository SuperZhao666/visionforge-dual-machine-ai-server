#pragma once

#include <array>
#include <cstddef>
#include <type_traits>
#include <utility>

namespace vfdual_android {

/** Fixed-capacity oldest-to-newest metric history with no runtime allocation. */
template <typename Value, std::size_t Capacity>
class FixedMetricRing final {
 public:
  static_assert(Capacity > 0U);
  static_assert(std::is_nothrow_move_assignable_v<Value>);

  [[nodiscard]] bool push(Value value) noexcept {
    const bool dropped = size_ == Capacity;
    if (dropped) {
      head_ = (head_ + 1U) % Capacity;
      --size_;
    }
    values_[(head_ + size_) % Capacity] = std::move(value);
    ++size_;
    return dropped;
  }

  void clear() noexcept {
    head_ = 0U;
    size_ = 0U;
  }

  [[nodiscard]] bool empty() const noexcept { return size_ == 0U; }
  [[nodiscard]] std::size_t size() const noexcept { return size_; }

  /** Caller must pass index < size(); index zero is always the oldest sample. */
  [[nodiscard]] const Value& oldest_at(std::size_t index) const noexcept {
    return values_[(head_ + index) % Capacity];
  }

 private:
  std::array<Value, Capacity> values_{};
  std::size_t head_{};
  std::size_t size_{};
};

}  // namespace vfdual_android
