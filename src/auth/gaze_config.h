#pragma once

#include <chrono>
#include <optional>

namespace sdbus {
  class Variant;
}

// Reads what the face lane needs from Gaze's `Config` D-Bus property.
namespace gaze_config {

  /// The longest delay pam_gaze may wait before opening the camera:
  /// max(auth.start_delay_ms, auth.resume_grace_ms). pam_gaze budgets with the same
  /// upper bound (camera_auth_timeout in gaze crates/pam-gaze/src/core/mod.rs).
  /// nullopt when `config` doesn't have Gaze's frozen DbusConfig layout.
  std::optional<std::chrono::milliseconds> maxStartDelay(const sdbus::Variant& config) noexcept;

} // namespace gaze_config
