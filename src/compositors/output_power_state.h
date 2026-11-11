#pragma once

#include <concepts>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

namespace compositors {

  /// A backend that pushes output power changes and exposes the cache they fill. Only
  /// that cache is read through this concept: outputPowerStates() may be a synchronous
  /// IPC query on any backend.
  template <typename BackendT>
  concept CachesPushedOutputPower = requires(BackendT& backend, const BackendT& constBackend) {
    backend.setOutputPowerChangeCallback(std::function<void()>{});
    { constBackend.cachedOutputPowerStates() } noexcept -> std::same_as<const std::unordered_map<std::string, bool>&>;
  };

  /// The power states `backend` already holds from pushed events; empty for a backend
  /// that only answers queries. Never does IPC, so the lock path may call it.
  template <typename BackendT> std::unordered_map<std::string, bool> pushedOutputPowerStates(const BackendT& backend) {
    if constexpr (CachesPushedOutputPower<BackendT>) {
      return backend.cachedOutputPowerStates();
    } else {
      return {};
    }
  }

  /// True only when every usable output is known to be powered off: a pending Noctalia
  /// power-off, or a compositor report of "off" for each connector. Anything unreported
  /// counts as on, since the compositor may have woken outputs that Noctalia last turned
  /// off, and a stale "off" would block face unlock indefinitely.
  bool allOutputsKnownOff(
      const std::vector<std::string>& connectors, const std::unordered_map<std::string, bool>& states,
      bool powerOffPending
  );

} // namespace compositors
