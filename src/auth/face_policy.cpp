#include "auth/face_policy.h"

#include <algorithm>
#include <array>
#include <utility>

namespace face {

  namespace {

    std::string_view trim(std::string_view text) {
      constexpr std::string_view kSpace = " \t\r\n\v\f";
      const auto first = text.find_first_not_of(kSpace);
      if (first == std::string_view::npos) {
        return {};
      }
      const auto last = text.find_last_not_of(kSpace);
      return text.substr(first, last - first + 1);
    }

  } // namespace

  ClassifiedMessage classifyGazeMessage(std::string_view text) {
    static constexpr std::array<std::pair<std::string_view, GazeMessage>, 9> kTokens = {{
        {kTokenLookCamera, GazeMessage::LookCamera},
        {kTokenLookOrPassword, GazeMessage::LookCamera},
        {kTokenFaceVerified, GazeMessage::Verified},
        {kTokenRequireConfirmation, GazeMessage::ConfirmationPrompt},
        {kTokenNotRecognized, GazeMessage::NotRecognized},
        {kTokenNotDetected, GazeMessage::NotDetected},
        {kTokenTooDark, GazeMessage::TooDark},
        {kTokenTimedOut, GazeMessage::TimedOut},
        {kTokenUnavailable, GazeMessage::Unavailable},
    }};
    static constexpr std::array<std::pair<std::string_view, GazeMessage>, 10> kPlain = {{
        {kPlainLookCamera, GazeMessage::LookCamera},
        {kPlainLookOrPassword, GazeMessage::LookCamera},
        {kPlainLookAfterPassword, GazeMessage::LookCamera},
        {kPlainFaceVerified, GazeMessage::Verified},
        {kPlainConfirmationPrompt, GazeMessage::ConfirmationPrompt},
        {kPlainNotRecognized, GazeMessage::NotRecognized},
        {kPlainNotDetected, GazeMessage::NotDetected},
        {kPlainTooDark, GazeMessage::TooDark},
        {kPlainTimedOut, GazeMessage::TimedOut},
        {kPlainUnavailable, GazeMessage::Unavailable},
    }};

    const std::string_view trimmed = trim(text);
    for (const auto& [token, kind] : kTokens) {
      if (trimmed == token) {
        return ClassifiedMessage{.kind = kind, .token = true};
      }
    }
    if (trimmed.starts_with(kTokenPrefix)) {
      return ClassifiedMessage{.kind = GazeMessage::UnknownToken, .token = true};
    }
    for (const auto& [plain, kind] : kPlain) {
      if (trimmed == plain) {
        return ClassifiedMessage{.kind = kind, .token = false};
      }
    }
    return ClassifiedMessage{.kind = GazeMessage::Other, .token = false};
  }

  std::optional<Outcome> outcomeForMessage(GazeMessage kind) {
    switch (kind) {
    case GazeMessage::NotDetected:
      return Outcome::NotDetected;
    case GazeMessage::TimedOut:
      return Outcome::TimedOut;
    case GazeMessage::TooDark:
      return Outcome::TooDark;
    case GazeMessage::Unavailable:
      return Outcome::Unavailable;
    case GazeMessage::NotRecognized:
      return Outcome::Rejected;
    case GazeMessage::Other:
    case GazeMessage::UnknownToken:
    case GazeMessage::LookCamera:
    case GazeMessage::Verified:
    case GazeMessage::ConfirmationPrompt:
      break;
    }
    return std::nullopt;
  }

  Outcome outcomeForFailure(std::optional<Outcome> announced, bool pamStarted, bool notADecision) {
    if (announced.has_value()) {
      return *announced;
    }
    if (!pamStarted || notADecision) {
      return Outcome::Unavailable;
    }
    return Outcome::Rejected;
  }

  std::chrono::milliseconds uiTimeoutFor(std::optional<std::chrono::milliseconds> maxStartDelay) {
    if (!maxStartDelay.has_value()) {
      return kFallbackUiTimeout;
    }
    const auto delay = std::clamp(*maxStartDelay, std::chrono::milliseconds(0), kMaxStartDelay);
    return kCameraBudget + delay + kTimeoutMargin;
  }

  std::string_view confirmationReply(bool tokenMode) { return tokenMode ? kTokenConfirmed : kPlainConfirmed; }

  void LanePolicy::setScreenOn(bool on) {
    m_screenOn = on;
    if (on) {
      m_autoStartUsed = false;
      m_lastOutcome.reset();
      m_lastScanEnded.reset();
    }
  }

  void LanePolicy::beginLock(Clock::time_point now, bool gracePending) {
    m_cooldownFrom = now;
    m_gracePending = gracePending;
    m_scannedSinceLock = false;
    m_autoStartUsed = true;
    m_lastOutcome.reset();
    m_lastScanEnded.reset();
  }

  void LanePolicy::graceEnded(Clock::time_point now) {
    if (!m_gracePending) {
      return;
    }
    m_gracePending = false;
    m_cooldownFrom = now;
  }

  void LanePolicy::setLockCooldown(std::chrono::milliseconds cooldown) {
    m_lockCooldown = std::clamp(cooldown, std::chrono::milliseconds(0), std::chrono::milliseconds(kMaxLockCooldown));
  }

  bool LanePolicy::takeAutoStart() {
    if (!m_screenOn || m_autoStartUsed) {
      return false;
    }
    m_autoStartUsed = true;
    return true;
  }

  bool LanePolicy::notePresence(Clock::time_point now) {
    const std::optional<Clock::time_point> previousInput = m_lastInput;
    m_lastInput = now;
    if (!m_screenOn) {
      return false;
    }
    if (m_gracePending) {
      // The user who just locked may still be at the keyboard; the cooldown hasn't
      // even started yet.
      return false;
    }
    if (!m_scannedSinceLock && m_cooldownFrom.has_value()) {
      // Nothing has been scanned since the lock: input after the cooldown is someone
      // coming back, not the user who just locked.
      return now - *m_cooldownFrom >= m_lockCooldown;
    }
    if (!m_lastOutcome.has_value() || !m_lastScanEnded.has_value()) {
      return false;
    }
    const auto sinceScan = now - *m_lastScanEnded;
    switch (*m_lastOutcome) {
    case Outcome::NotDetected:
    case Outcome::TimedOut:
      return sinceScan >= kPresenceRetryGap;
    case Outcome::TooDark:
      return sinceScan >= kDarkRetryGap;
    case Outcome::Unavailable: {
      const auto lastActivity =
          previousInput.has_value() ? std::max(*previousInput, *m_lastScanEnded) : *m_lastScanEnded;
      return now - lastActivity >= kUnavailableQuietGap;
    }
    case Outcome::Rejected:
    case Outcome::ConfirmationExpired:
    case Outcome::Declined:
      return false;
    }
    return false;
  }

  bool LanePolicy::allowsManualRetry(Clock::time_point now) const noexcept {
    if (!m_screenOn) {
      return false;
    }
    const bool gated = m_lastOutcome == Outcome::Rejected || m_lastOutcome == Outcome::ConfirmationExpired;
    return !gated || !m_lastScanEnded.has_value() || now - *m_lastScanEnded >= kRejectedRetryGap;
  }

  void LanePolicy::scanFinished(Outcome outcome, Clock::time_point now) {
    m_scannedSinceLock = true;
    m_lastOutcome = outcome;
    m_lastScanEnded = now;
  }

} // namespace face
