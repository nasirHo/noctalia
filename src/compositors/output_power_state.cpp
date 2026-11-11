#include "compositors/output_power_state.h"

#include <algorithm>

namespace compositors {

  bool allOutputsKnownOff(
      const std::vector<std::string>& connectors, const std::unordered_map<std::string, bool>& states,
      bool powerOffPending
  ) {
    if (powerOffPending) {
      return true;
    }
    if (connectors.empty()) {
      return false;
    }
    return std::ranges::all_of(connectors, [&states](const std::string& connector) {
      const auto state = states.find(connector);
      return state != states.end() && !state->second;
    });
  }

} // namespace compositors
