#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string_view>

// Pure policy for the face lane: how pam_gaze conversation messages are read and
// when a scan may start. FaceAuthenticator owns the timers, D-Bus and the PAM session.
namespace face {

  // Gaze's machine tokens, sent instead of English text to services registered with
  // AddPamInternal. Source of truth: gaze crates/gaze-core/src/dbus.rs (GAZE_* constants).
  inline constexpr std::string_view kTokenLookCamera = "GAZE_MSG_LOOK_CAMERA";
  inline constexpr std::string_view kTokenLookOrPassword = "GAZE_MSG_LOOK_OR_PASSWORD";
  inline constexpr std::string_view kTokenFaceVerified = "GAZE_MSG_FACE_VERIFIED";
  inline constexpr std::string_view kTokenRequireConfirmation = "GAZE_REQUIRE_CONFIRMATION";
  inline constexpr std::string_view kTokenConfirmed = "GAZE_CONFIRMED";
  inline constexpr std::string_view kTokenNotRecognized = "GAZE_MSG_FACE_NOT_RECOGNIZED";
  inline constexpr std::string_view kTokenNotDetected = "GAZE_MSG_FACE_NOT_DETECTED";
  inline constexpr std::string_view kTokenTooDark = "GAZE_MSG_FACE_TOO_DARK";
  inline constexpr std::string_view kTokenTimedOut = "GAZE_MSG_FACE_TIMED_OUT";
  inline constexpr std::string_view kTokenUnavailable = "GAZE_MSG_FACE_UNAVAILABLE";
  inline constexpr std::string_view kTokenPrefix = "GAZE_";

  // Plain-mode texts, used when registration failed or raced with the scan.
  // Source of truth: gaze crates/pam-gaze/src/core/mod.rs.
  inline constexpr std::string_view kPlainLookCamera = "Please look at the camera";
  inline constexpr std::string_view kPlainLookOrPassword = "Please look at the camera or enter password";
  inline constexpr std::string_view kPlainLookAfterPassword = "Password incorrect. Please look at the camera";
  inline constexpr std::string_view kPlainFaceVerified = "Face Verified.";
  inline constexpr std::string_view kPlainNotRecognized = "Face not recognized. Enter your password.";
  inline constexpr std::string_view kPlainNotDetected = "Face not detected. Enter your password.";
  inline constexpr std::string_view kPlainTooDark = "Too dark for face authentication. Enter your password.";
  inline constexpr std::string_view kPlainTimedOut = "Face authentication timed out. Enter your password.";
  inline constexpr std::string_view kPlainUnavailable = "Face authentication unavailable. Enter your password.";
  inline constexpr std::string_view kPlainConfirmationPrompt = "Face Verified. Type 'yes' to confirm.";
  inline constexpr std::string_view kPlainConfirmed = "yes";

  enum class GazeMessage : std::uint8_t {
    Other,        // not from Gaze (another module in the stack): may be shown as-is
    UnknownToken, // starts with GAZE_ but isn't known: never shown
    LookCamera,
    Verified,
    NotDetected,
    TimedOut,
    TooDark,
    Unavailable,
    NotRecognized,
    ConfirmationPrompt,
  };

  struct ClassifiedMessage {
    GazeMessage kind = GazeMessage::Other;
    bool token = false;
  };

  /// Classifies a conversation text in either token or plain form. Plain texts match
  /// exactly after trimming surrounding whitespace.
  ClassifiedMessage classifyGazeMessage(std::string_view text);

  enum class Outcome : std::uint8_t {
    NotDetected,
    TimedOut,
    TooDark,
    Unavailable,
    Rejected,
    // A verified face nobody confirmed in time; the helper was killed, so PAM counted nothing.
    ConfirmationExpired,
    // The user dismissed the confirmation (Escape).
    Declined,
  };

  /// The attempt outcome a message announces, if it announces one.
  std::optional<Outcome> outcomeForMessage(GazeMessage kind);

  /// Outcome of a non-success finish. Without an outcome message the attempt counts
  /// as Rejected (no automatic retry), unless PAM never started or `notADecision`: a
  /// prompt was aborted, or the stack reported PAM_AUTHINFO_UNAVAIL.
  Outcome outcomeForFailure(std::optional<Outcome> announced, bool pamStarted, bool notADecision);

  // pam_gaze waits this long for the camera itself (CAMERA_AUTH_TIMEOUT_SECS).
  inline constexpr std::chrono::milliseconds kCameraBudget = std::chrono::seconds(12);
  // Slack on top of pam_gaze's own budget so its outcome arrives before the UI gives up.
  inline constexpr std::chrono::milliseconds kTimeoutMargin = std::chrono::seconds(2);
  // Used when Gaze's Config can't be read.
  inline constexpr std::chrono::milliseconds kFallbackUiTimeout = std::chrono::seconds(30);
  // Delays past this are treated as this long; the scan then ends as Unavailable.
  inline constexpr std::chrono::milliseconds kMaxStartDelay = std::chrono::minutes(10);
  static_assert(kFallbackUiTimeout > kCameraBudget + kTimeoutMargin);

  /// How long the lane waits for pam_gaze before killing it: pam_gaze's own budget
  /// (the camera budget plus its longest start delay) plus a margin.
  std::chrono::milliseconds uiTimeoutFor(std::optional<std::chrono::milliseconds> maxStartDelay);

  /// The confirmation answer must match how the prompt arrived.
  std::string_view confirmationReply(bool tokenMode);

  /// Scan-start rules: no automatic start when the lock begins, one per wake after
  /// that, no presence scan during a grace window, a first scan on presence once the
  /// lock cooldown has passed, presence
  /// retries after undecided outcomes only, and nothing at all while the screen is off.
  class LanePolicy {
  public:
    using Clock = std::chrono::steady_clock;

    static constexpr auto kPresenceRetryGap = std::chrono::seconds(3);
    static constexpr auto kDarkRetryGap = std::chrono::seconds(15);
    // Silence after which an Unavailable attempt may be retried on presence, in case
    // the screen went off without Noctalia hearing about it.
    static constexpr auto kUnavailableQuietGap = std::chrono::seconds(60);
    // After a rejected or unconfirmed face, Enter can't start another scan before this
    // much time has passed. Repeated Enter presses would otherwise feed pam_faillock.
    static constexpr auto kRejectedRetryGap = std::chrono::seconds(5);
    // Default for [lockscreen] face_lock_cooldown_ms.
    static constexpr auto kDefaultLockCooldown = std::chrono::milliseconds(5000);
    static constexpr auto kMaxLockCooldown = std::chrono::milliseconds(60000);

    /// Off blocks every start. On lifts the block, re-arms the wake attempt and forgets
    /// the last outcome.
    void setScreenOn(bool on);
    bool screenOn() const noexcept { return m_screenOn; }

    /// A lock began at `now`. Locking is not a wake: it gets no automatic scan, because
    /// the user who just locked is usually still in front of the camera. The first scan
    /// comes from a wake, Enter, or presence once the cooldown has passed.
    ///
    /// `gracePending`: the lock opened a passwordless grace window. Presence then never
    /// starts a scan until graceEnded(), and the cooldown is measured from that moment
    /// instead of from the lock, since that is when the lock really takes effect.
    void beginLock(Clock::time_point now, bool gracePending = false);
    /// The lock's grace window closed at `now` (expired or revoked): the lock cooldown
    /// starts here. No-op unless grace is pending, so only the first call counts.
    void graceEnded(Clock::time_point now);
    bool gracePending() const noexcept { return m_gracePending; }
    /// Clamped to [0, kMaxLockCooldown].
    void setLockCooldown(std::chrono::milliseconds cooldown);
    std::chrono::milliseconds lockCooldown() const noexcept { return m_lockCooldown; }

    /// Consumes this wake's automatic attempt. False if already used or the screen is off.
    [[nodiscard]] bool takeAutoStart();
    /// Manual retry (Enter on an empty field): any outcome, but never with the screen off
    /// and not within kRejectedRetryGap of a Rejected or ConfirmationExpired scan.
    bool allowsManualRetry(Clock::time_point now) const noexcept;
    /// Records user input at `now` and says whether it should start a scan.
    bool notePresence(Clock::time_point now);
    /// Records how a scan ended. Cancelled scans are not reported.
    void scanFinished(Outcome outcome, Clock::time_point now);

    std::optional<Outcome> lastOutcome() const noexcept { return m_lastOutcome; }

  private:
    bool m_screenOn = true;
    bool m_autoStartUsed = false;
    std::chrono::milliseconds m_lockCooldown = kDefaultLockCooldown;
    // Where the lock cooldown is measured from: the lock, or the end of its grace window.
    std::optional<Clock::time_point> m_cooldownFrom;
    // The lock's grace window is still open: presence never starts a scan.
    bool m_gracePending = false;
    // Whether any scan has finished since the lock began; cancelled scans don't count.
    bool m_scannedSinceLock = false;
    std::optional<Outcome> m_lastOutcome;
    std::optional<Clock::time_point> m_lastScanEnded;
    std::optional<Clock::time_point> m_lastInput;
  };

} // namespace face
