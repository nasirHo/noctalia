#include "compositors/output_power_state.h"
#include "tests/test_check.h"

using compositors::allOutputsKnownOff;

int main() {
  const std::vector<std::string> two = {"DP-1", "eDP-1"};

  // All on, one off, all off.
  TEST_CHECK(!allOutputsKnownOff(two, {{"DP-1", true}, {"eDP-1", true}}, false));
  TEST_CHECK(!allOutputsKnownOff(two, {{"DP-1", false}, {"eDP-1", true}}, false));
  TEST_CHECK(allOutputsKnownOff(two, {{"DP-1", false}, {"eDP-1", false}}, false));

  // Unreported outputs count as on: without reports nothing is known to be off.
  TEST_CHECK(!allOutputsKnownOff(two, {}, false));
  TEST_CHECK(!allOutputsKnownOff(two, {{"DP-1", false}}, false));
  // States for outputs that aren't usable are ignored.
  TEST_CHECK(!allOutputsKnownOff({"DP-1"}, {{"HDMI-A-1", false}}, false));

  // A pending power-off counts as off, whatever the reports say.
  TEST_CHECK(allOutputsKnownOff(two, {{"DP-1", true}, {"eDP-1", true}}, true));
  TEST_CHECK(allOutputsKnownOff({}, {}, true));

  // No usable outputs and nothing pending: not known to be off.
  TEST_CHECK(!allOutputsKnownOff({}, {}, false));
  return 0;
}
