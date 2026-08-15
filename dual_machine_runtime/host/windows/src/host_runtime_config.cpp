#include "vfdual/host_runtime_config.hpp"

#include <charconv>
#include <cctype>
#include <fstream>
#include <limits>
#include <string_view>
#include <unordered_map>

namespace vfdual {
namespace {

std::string trim(std::string value) {
  const auto is_space = [](unsigned char character) { return std::isspace(character) != 0; };
  while (!value.empty() && is_space(static_cast<unsigned char>(value.front()))) value.erase(value.begin());
  while (!value.empty() && is_space(static_cast<unsigned char>(value.back()))) value.pop_back();
  if (value.size() >= 2 && value.front() == '"' && value.back() == '"') value = value.substr(1, value.size() - 2);
  return value;
}

bool parse_unsigned(std::string_view text, std::uint64_t& destination) {
  const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), destination);
  return error == std::errc{} && end == text.data() + text.size();
}

bool require_unsigned(
    const std::unordered_map<std::string, std::string>& values, std::string_view key,
    std::uint64_t minimum, std::uint64_t maximum, std::uint64_t& destination, std::string& error) {
  const auto iterator = values.find(std::string(key));
  if (iterator == values.end() || !parse_unsigned(iterator->second, destination) ||
      destination < minimum || destination > maximum) {
    error = "invalid or missing " + std::string(key);
    return false;
  }
  return true;
}

}  // namespace

bool load_host_runtime_config(const std::string& file_path, HostRuntimeConfig& destination, std::string& error) {
  std::ifstream file(file_path);
  if (!file) {
    error = "cannot open configuration: " + file_path;
    return false;
  }
  std::unordered_map<std::string, std::string> values;
  std::string line;
  std::uint32_t line_number{};
  while (std::getline(file, line)) {
    ++line_number;
    const auto comment = line.find('#');
    if (comment != std::string::npos) line.resize(comment);
    line = trim(std::move(line));
    if (line.empty() || line.front() == '[') continue;
    const auto separator = line.find('=');
    if (separator == std::string::npos) {
      error = "configuration line " + std::to_string(line_number) + " is not key=value";
      return false;
    }
    const std::string key = trim(line.substr(0, separator));
    const std::string value = trim(line.substr(separator + 1));
    if (key.empty() || value.empty() || !values.emplace(key, value).second) {
      error = "duplicate or empty configuration key at line " + std::to_string(line_number);
      return false;
    }
  }

  HostRuntimeConfig parsed{};
  const auto phone = values.find("phone_host");
  if (phone == values.end() || phone->second.empty()) {
    error = "invalid or missing phone_host";
    return false;
  }
  parsed.video.phone_host = phone->second;
  if (const auto metrics = values.find("metrics_csv_path"); metrics != values.end()) {
    parsed.metrics_csv_path = metrics->second;
  }
  std::uint64_t value{};
  if (!require_unsigned(values, "video_port", 1024, 65535, value, error)) return false;
  parsed.video.phone_port = static_cast<std::uint16_t>(value);
  if (!require_unsigned(values, "width", 64, 3840, value, error)) return false;
  parsed.video.encoder.width = static_cast<std::uint32_t>(value);
  if (!require_unsigned(values, "height", 64, 2160, value, error)) return false;
  parsed.video.encoder.height = static_cast<std::uint32_t>(value);
  if (!require_unsigned(values, "frames_per_second", 1, 1000, value, error)) return false;
  parsed.video.encoder.frames_per_second = static_cast<std::uint32_t>(value);
  if (!require_unsigned(values, "keyframe_interval_frames", 1, 600, value, error)) return false;
  parsed.video.encoder.keyframe_interval_frames = static_cast<std::uint32_t>(value);
  if (!require_unsigned(values, "adapter_index", 0, 16, value, error)) return false;
  parsed.video.adapter_index = static_cast<std::uint32_t>(value);
  if (!require_unsigned(values, "output_index", 0, 16, value, error)) return false;
  parsed.video.output_index = static_cast<std::uint32_t>(value);
  if (!require_unsigned(values, "metrics_interval_frames", 1, 3600, value, error)) return false;
  parsed.metrics_interval_frames = static_cast<std::uint32_t>(value);
  destination = std::move(parsed);
  return true;
}

}  // namespace vfdual
