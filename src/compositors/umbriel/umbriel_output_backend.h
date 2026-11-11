#pragma once

#include "compositors/umbriel/umbriel_event_handler.h"

#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace compositors::umbriel {
  class UmbrielRuntime;
} // namespace compositors::umbriel

// Caches focused output and power changes from the persistent event stream.
// outputPowerStates() takes a fresh snapshot to include commands not yet dispatched in
// the stream; cachedOutputPowerStates() is for callers that must not block on IPC.
// The focused workspace names the output even when that workspace is empty.
class UmbrielOutputBackend final : public compositors::umbriel::UmbrielEventHandler {
public:
  explicit UmbrielOutputBackend(compositors::umbriel::UmbrielRuntime& runtime);

  std::optional<std::string> focusedOutputName() const;
  std::unordered_map<std::string, bool> outputPowerStates() const;
  /// The states last pushed on the event stream. No IPC. Umbriel sends an outputs
  /// snapshot right after the stream subscribes, so this is empty only until that
  /// arrives (or after the stream drops).
  const std::unordered_map<std::string, bool>& cachedOutputPowerStates() const noexcept { return m_outputPowerStates; }
  void setOutputPowerChangeCallback(std::function<void()> callback);

  void handleEvent(std::string_view event, const nlohmann::json& data) override;
  void handleStreamReset() override;

private:
  std::optional<std::string> m_focusedOutput;
  std::unordered_map<std::string, bool> m_outputPowerStates;
  std::function<void()> m_outputPowerChangeCallback;
};

namespace compositors::umbriel {

  [[nodiscard]] bool setOutputPower(UmbrielRuntime& runtime, bool on);

} // namespace compositors::umbriel
