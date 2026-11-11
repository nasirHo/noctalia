#include "auth/gaze_config.h"

#include <algorithm>
#include <cstdint>
#include <exception>
#include <limits>
#include <sdbus-c++/Types.h>
#include <string>
#include <tuple>

namespace gaze_config {

  namespace {

    // Gaze's DbusConfig wire layout, frozen for compatibility (gaze crates/gaze-core/src/dbus.rs):
    // ((ss)(sssdds)(ssbys)(bbbbbtts)(ud)(bdd)(b)).
    using Inference = sdbus::Struct<std::string, std::string>;
    using Security = sdbus::Struct<std::string, std::string, std::string, double, double, std::string>;
    using Cameras = sdbus::Struct<std::string, std::string, bool, std::uint8_t, std::string>;
    // abort_if_ssh, abort_if_lid_closed, abort_before_first_resume,
    // require_confirmation_lock_screen, require_confirmation_elevation,
    // resume_grace_ms, start_delay_ms, start_delay_scope
    using Auth = sdbus::Struct<bool, bool, bool, bool, bool, std::uint64_t, std::uint64_t, std::string>;
    using Enrollment = sdbus::Struct<std::uint32_t, double>;
    using Liveness = sdbus::Struct<bool, double, double>;
    using Storage = sdbus::Struct<bool>;
    using DbusConfig = sdbus::Struct<Inference, Security, Cameras, Auth, Enrollment, Liveness, Storage>;

    constexpr std::size_t kAuthIndex = 3;
    constexpr std::size_t kResumeGraceIndex = 5;
    constexpr std::size_t kStartDelayIndex = 6;

  } // namespace

  std::optional<std::chrono::milliseconds> maxStartDelay(const sdbus::Variant& config) noexcept {
    try {
      if (!config.containsValueOfType<DbusConfig>()) {
        return std::nullopt;
      }
      const auto parsed = config.get<DbusConfig>();
      const Auth& auth = std::get<kAuthIndex>(parsed);
      const std::uint64_t delay = std::max(std::get<kStartDelayIndex>(auth), std::get<kResumeGraceIndex>(auth));
      constexpr auto kMax = static_cast<std::uint64_t>(std::numeric_limits<std::chrono::milliseconds::rep>::max());
      return std::chrono::milliseconds(static_cast<std::chrono::milliseconds::rep>(std::min(delay, kMax)));
    } catch (const std::exception&) {
      return std::nullopt;
    }
  }

} // namespace gaze_config
