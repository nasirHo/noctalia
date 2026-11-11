#pragma once

#include "auth/face_lane.h"
#include "auth/interactive_pam_session.h"
#include "core/timer_manager.h"

#include <functional>
#include <memory>
#include <string>

class GazePamInternalRegistration;
class SystemBus;

namespace sdbus {
  class IProxy;
}

/// Face unlock through Gaze. Runs pam_gaze in its own "noctalia-face" PAM
/// conversation next to the password lane, and unlocks only on PAM_SUCCESS from
/// it; Gaze's D-Bus verify signals are never used to decide anything.
class FaceAuthenticator final : private face::LaneDriver {
public:
  using AuthenticatedCallback = std::function<void()>;
  using StatusCallback = std::function<void(const std::string& message, bool isError)>;

  explicit FaceAuthenticator(SystemBus& bus);
  ~FaceAuthenticator() override;

  FaceAuthenticator(const FaceAuthenticator&) = delete;
  FaceAuthenticator& operator=(const FaceAuthenticator&) = delete;

  void setAuthenticatedCallback(AuthenticatedCallback callback);
  void setStatusCallback(StatusCallback callback);

  /// Follows the [lockscreen] face setting; disabling cancels any scan and drops
  /// the token registration.
  void setEnabled(bool enabled);
  void setLockCooldown(std::chrono::milliseconds cooldown);
  /// The session lock began; see face::Lane::beginLock().
  void beginLock(bool gracePending);
  /// The lock's grace window closed; see face::Lane::graceEnded().
  void graceEnded();
  void start();
  void stop();
  void retry();
  void confirm(face::LanePolicy::Clock::time_point pressedAt);
  void declineConfirmation();
  void noteUserPresence();
  void setScreenOn(bool on);

  bool isBusy() const noexcept { return m_lane.busy(); }
  bool isConfirming() const noexcept { return m_lane.confirming(); }

private:
  bool faceServiceInstalled() override;
  void ensureTokenMode() override;
  void probeReadiness(std::function<void(face::Readiness readiness)> done) override;
  [[nodiscard]] bool startSession() override;
  void cancelSession() override;
  [[nodiscard]] bool respond(std::string_view text) override;
  [[nodiscard]] bool abortPrompt() override;
  void startTimer(TimerSlot slot, std::chrono::milliseconds delay, std::function<void()> callback) override;
  void stopTimer(TimerSlot slot) override;
  face::LanePolicy::Clock::time_point now() override;

  void readStartDelay(std::function<void(std::optional<std::chrono::milliseconds>)> done);
  void handleStatus(const face::Status& status);
  Timer& timer(TimerSlot slot);

  SystemBus& m_bus;
  std::unique_ptr<sdbus::IProxy> m_gaze;
  std::unique_ptr<GazePamInternalRegistration> m_registration;
  InteractivePamSession m_session;
  Timer m_delayTimer;
  Timer m_timeoutTimer;
  Timer m_confirmTimer;
  face::Lane m_lane{*this};
  std::string m_user;
  bool m_enabled = true;
  bool m_untrustedServiceReported = false;

  AuthenticatedCallback m_onAuthenticated;
  StatusCallback m_onStatus;
};
