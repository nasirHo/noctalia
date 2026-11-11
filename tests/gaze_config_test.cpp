#include "auth/gaze_config.h"
#include "tests/test_check.h"

#include <chrono>
#include <cstdint>
#include <sdbus-c++/Types.h>
#include <string>

namespace {

  using namespace std::chrono_literals;

  using Inference = sdbus::Struct<std::string, std::string>;
  using Security = sdbus::Struct<std::string, std::string, std::string, double, double, std::string>;
  using Cameras = sdbus::Struct<std::string, std::string, bool, std::uint8_t, std::string>;
  using Auth = sdbus::Struct<bool, bool, bool, bool, bool, std::uint64_t, std::uint64_t, std::string>;
  using Enrollment = sdbus::Struct<std::uint32_t, double>;
  using Liveness = sdbus::Struct<bool, double, double>;
  using Storage = sdbus::Struct<bool>;
  using DbusConfig = sdbus::Struct<Inference, Security, Cameras, Auth, Enrollment, Liveness, Storage>;

  sdbus::Variant makeConfig(std::uint64_t resumeGraceMs, std::uint64_t startDelayMs) {
    return sdbus::Variant(
        DbusConfig{
            Inference{"cpu", "auto"},
            Security{"balanced", "scrfd", "arcface", 0.5, 0.5, "either"},
            Cameras{"/dev/video0", "/dev/video2", true, std::uint8_t{20}, "auto"},
            Auth{true, true, false, false, true, resumeGraceMs, startDelayMs, "lock"},
            Enrollment{std::uint32_t{5}, 0.1},
            Liveness{true, 0.5, 3.0},
            Storage{false},
        }
    );
  }

} // namespace

int main() {
  // Pinned to Gaze's frozen DbusConfig layout (gaze crates/gaze-core/src/dbus.rs).
  TEST_CHECK(std::string(makeConfig(0, 0).peekValueType()) == "((ss)(sssdds)(ssbys)(bbbbbtts)(ud)(bdd)(b))");

  // The longer of the start delay and the resume grace.
  TEST_CHECK(gaze_config::maxStartDelay(makeConfig(0, 0)) == 0ms);
  TEST_CHECK(gaze_config::maxStartDelay(makeConfig(1500, 9000)) == 9000ms);
  TEST_CHECK(gaze_config::maxStartDelay(makeConfig(4000, 250)) == 4000ms);

  // Anything else is unreadable rather than a guess.
  TEST_CHECK(!gaze_config::maxStartDelay(sdbus::Variant(std::string("nope"))).has_value());
  TEST_CHECK(
      !gaze_config::maxStartDelay(sdbus::Variant(Auth{true, true, false, false, true, 1, 2, "lock"})).has_value()
  );
  TEST_CHECK(!gaze_config::maxStartDelay(sdbus::Variant()).has_value());
  return 0;
}
