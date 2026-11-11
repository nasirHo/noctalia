#pragma once

#include "auth/face_policy.h"

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

namespace face {

  /// What the lane learns from Gaze before a scan, without touching the camera.
  struct Readiness {
    // HasEnrolledFaces: true/false, or nullopt when the call failed.
    std::optional<bool> enrolled;
    // From Gaze's Config: max(start_delay_ms, resume_grace_ms), or nullopt if unreadable.
    std::optional<std::chrono::milliseconds> maxStartDelay;
  };

  /// Side effects the lane needs. FaceAuthenticator implements it with a PAM helper,
  /// main-loop timers and D-Bus; tests use a fake.
  class LaneDriver {
  public:
    enum class TimerSlot : std::uint8_t { Delay, Timeout, Confirm };

    virtual ~LaneDriver() = default;
    /// The face PAM service exists and passes pam_service::inspectServiceFile().
    virtual bool faceServiceInstalled() = 0;
    /// Asks gazed for token mode (AddPamInternal). Only called once the service passed
    /// the check above, so an unconfigured system never wakes gazed.
    virtual void ensureTokenMode() = 0;
    /// Asks Gaze whether the user has faces and how long pam_gaze may delay.
    virtual void probeReadiness(std::function<void(Readiness readiness)> done) = 0;
    [[nodiscard]] virtual bool startSession() = 0;
    virtual void cancelSession() = 0;
    [[nodiscard]] virtual bool respond(std::string_view text) = 0;
    [[nodiscard]] virtual bool abortPrompt() = 0;
    virtual void startTimer(TimerSlot slot, std::chrono::milliseconds delay, std::function<void()> callback) = 0;
    virtual void stopTimer(TimerSlot slot) = 0;
    virtual LanePolicy::Clock::time_point now() = 0;
  };

  enum class StatusKind : std::uint8_t {
    Clear,
    Look,
    NotDetected,
    TooDark,
    Unavailable,
    NotRecognized,
    Failed,
    Confirm,
    ConfirmExpired,
    Raw, // text from another module in the face stack, shown unchanged
  };

  struct Status {
    StatusKind kind = StatusKind::Clear;
    std::string text;
    bool isError = false;
  };

  /// The face lane's state machine: when to scan, how to read pam_gaze's
  /// conversation, and what to show. Unlocks only on a successful PAM finish that
  /// follows evidence from this attempt: Gaze said the face was verified, or the
  /// lane answered Gaze's confirmation prompt.
  class Lane {
  public:
    using AuthenticatedCallback = std::function<void()>;
    using StatusCallback = std::function<void(const Status& status)>;

    static constexpr auto kAutoDelay = std::chrono::milliseconds(500);
    // How long a verified face waits for Enter. Gaze sets no deadline of its own.
    static constexpr auto kConfirmWindow = std::chrono::seconds(10);

    explicit Lane(LaneDriver& driver);

    void setAuthenticatedCallback(AuthenticatedCallback callback);
    void setStatusCallback(StatusCallback callback);

    void setEnabled(bool enabled);
    void setLockCooldown(std::chrono::milliseconds cooldown);
    /// The session lock began: cancels anything left over and starts the lock cooldown,
    /// or, with `gracePending`, holds it until graceEnded(). Never scans by itself.
    void beginLock(bool gracePending = false);
    /// The lock's passwordless grace window closed now; the lock cooldown starts here.
    void graceEnded();
    /// Automatic start for a wake; at most once per wake, never for the lock itself.
    void start();
    /// Cancels without classifying an outcome.
    void stop();
    /// Manual retry (Enter on an empty field): starts now whatever the last outcome was.
    void retry();
    /// Enter while confirming: answers Gaze, unless the confirmation window has passed.
    /// `pressedAt` is when that key went down. A press from before the prompt appeared
    /// (the one that started the scan, held down) is ignored and the prompt keeps waiting.
    void confirm(LanePolicy::Clock::time_point pressedAt);
    /// Escape while confirming: kills the helper without answering, so PAM counts nothing.
    void declineConfirmation();
    /// Pointer activity or a key that doesn't type: may start the first scan after the
    /// lock cooldown, or retry after an undecided scan.
    void noteUserPresence();
    void setScreenOn(bool on);

    bool busy() const noexcept { return m_state != State::Idle; }
    bool confirming() const noexcept { return m_state == State::Confirming; }
    const LanePolicy& policy() const noexcept { return m_policy; }

    // Events from the PAM session.
    void onMessage(const std::string& text, bool isError);
    void onPrompt(const std::string& text, bool echo);
    /// `serviceUnavailable`: PAM reported PAM_AUTHINFO_UNAVAIL, a stack problem rather
    /// than a face decision.
    void onFinished(bool success, bool pamStarted, bool serviceUnavailable = false);

  private:
    enum class State : std::uint8_t { Idle, Probing, Delayed, Scanning, Confirming };

    void begin(std::chrono::milliseconds delay);
    void handleProbe(std::uint64_t attempt, std::chrono::milliseconds delay, const Readiness& readiness);
    void launch();
    void armTimeout();
    void expireConfirmation();
    void finish(Outcome outcome, bool announced);
    void cancel();
    void emit(StatusKind kind, std::string text = {}, bool isError = false);
    void clearStatus();

    LaneDriver& m_driver;
    LanePolicy m_policy;
    AuthenticatedCallback m_onAuthenticated;
    StatusCallback m_onStatus;
    State m_state = State::Idle;
    std::uint64_t m_attempt = 0;
    bool m_enabled = true;
    std::optional<Outcome> m_announced;
    // From this attempt's readiness probe; see uiTimeoutFor().
    std::chrono::milliseconds m_uiTimeout = kFallbackUiTimeout;
    bool m_promptAborted = false;
    // Evidence for this attempt; a PAM success without either is not trusted.
    bool m_verifiedSeen = false;
    bool m_confirmationSent = false;
    LanePolicy::Clock::time_point m_confirmEnteredAt;
    bool m_tokenConfirmation = false;
    bool m_rawShown = false;
    bool m_statusShown = false;
  };

} // namespace face
