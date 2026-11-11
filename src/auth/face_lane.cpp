#include "auth/face_lane.h"

#include "core/log.h"

#include <utility>

namespace face {

  namespace {
    constexpr Logger kLog("face");
  } // namespace

  Lane::Lane(LaneDriver& driver) : m_driver(driver) {}

  void Lane::setAuthenticatedCallback(AuthenticatedCallback callback) { m_onAuthenticated = std::move(callback); }

  void Lane::setStatusCallback(StatusCallback callback) { m_onStatus = std::move(callback); }

  void Lane::setEnabled(bool enabled) {
    if (!enabled) {
      cancel();
      clearStatus();
    }
    m_enabled = enabled;
  }

  void Lane::setLockCooldown(std::chrono::milliseconds cooldown) { m_policy.setLockCooldown(cooldown); }

  void Lane::beginLock(bool gracePending) {
    cancel();
    clearStatus();
    m_policy.beginLock(m_driver.now(), gracePending);
  }

  void Lane::graceEnded() {
    if (m_policy.gracePending()) {
      kLog.debug("grace period ended; starting the face lock cooldown");
    }
    m_policy.graceEnded(m_driver.now());
  }

  void Lane::start() {
    if (!m_enabled || busy() || !m_policy.takeAutoStart()) {
      return;
    }
    begin(kAutoDelay);
  }

  void Lane::stop() { cancel(); }

  void Lane::retry() {
    if (!m_enabled || busy()) {
      return;
    }
    if (!m_policy.allowsManualRetry(m_driver.now())) {
      kLog.debug("manual face retry refused (screen off or too soon after a rejection)");
      return;
    }
    kLog.debug("manual face retry");
    begin(std::chrono::milliseconds(0));
  }

  void Lane::noteUserPresence() {
    // Always record the input: the quiet-period rule needs every presence signal.
    const bool wanted = m_policy.notePresence(m_driver.now());
    if (!wanted || !m_enabled || busy()) {
      return;
    }
    kLog.debug("user presence; starting a face scan");
    begin(std::chrono::milliseconds(0));
  }

  void Lane::setScreenOn(bool on) {
    if (!on) {
      // Not an attempt outcome: nothing is classified and no error is shown.
      if (busy()) {
        kLog.debug("screen off; cancelling face scan");
      }
      cancel();
      clearStatus();
    }
    m_policy.setScreenOn(on);
  }

  void Lane::confirm(LanePolicy::Clock::time_point pressedAt) {
    if (m_state != State::Confirming) {
      return;
    }
    if (pressedAt < m_confirmEnteredAt) {
      kLog.debug("ignoring a face confirmation from a key pressed before the prompt");
      return;
    }
    // Checked here too: the timer may fire late, but an old confirmation must never pass.
    if (m_driver.now() - m_confirmEnteredAt > kConfirmWindow) {
      expireConfirmation();
      return;
    }
    m_driver.stopTimer(LaneDriver::TimerSlot::Confirm);
    m_state = State::Scanning;
    if (!m_driver.respond(confirmationReply(m_tokenConfirmation))) {
      kLog.warn("could not send the face confirmation");
      m_driver.cancelSession();
      finish(Outcome::Unavailable, false);
      return;
    }
    m_confirmationSent = true;
    armTimeout();
  }

  void Lane::declineConfirmation() {
    if (m_state != State::Confirming) {
      return;
    }
    kLog.debug("face confirmation declined");
    m_driver.stopTimer(LaneDriver::TimerSlot::Confirm);
    // Kill rather than abort: an aborted confirmation becomes PAM_AUTH_ERR, which
    // pam_faillock would count against the owner's own face.
    m_driver.cancelSession();
    finish(Outcome::Declined, false);
  }

  void Lane::expireConfirmation() {
    kLog.info("face confirmation expired");
    m_driver.stopTimer(LaneDriver::TimerSlot::Confirm);
    m_driver.cancelSession();
    finish(Outcome::ConfirmationExpired, false);
  }

  void Lane::begin(std::chrono::milliseconds delay) {
    if (!m_driver.faceServiceInstalled()) {
      return;
    }
    m_driver.ensureTokenMode();
    const std::uint64_t attempt = ++m_attempt;
    m_state = State::Probing;
    m_driver.probeReadiness([this, attempt, delay](const Readiness& readiness) {
      handleProbe(attempt, delay, readiness);
    });
  }

  void Lane::handleProbe(std::uint64_t attempt, std::chrono::milliseconds delay, const Readiness& readiness) {
    if (attempt != m_attempt || m_state != State::Probing) {
      return;
    }
    // Only a definite "no faces" keeps the lane idle; a failed probe lets PAM decide.
    if (readiness.enrolled.has_value() && !*readiness.enrolled) {
      kLog.debug("no enrolled faces; face lane idle");
      m_state = State::Idle;
      return;
    }
    m_uiTimeout = uiTimeoutFor(readiness.maxStartDelay);
    if (!readiness.maxStartDelay.has_value()) {
      kLog.debug("could not read Gaze's start delay; face scans time out after {} ms", m_uiTimeout.count());
    }
    if (delay.count() <= 0) {
      launch();
      return;
    }
    m_state = State::Delayed;
    m_driver.startTimer(LaneDriver::TimerSlot::Delay, delay, [this, attempt] {
      if (attempt == m_attempt && m_state == State::Delayed) {
        launch();
      }
    });
  }

  void Lane::launch() {
    m_state = State::Scanning;
    m_announced.reset();
    m_promptAborted = false;
    m_verifiedSeen = false;
    m_confirmationSent = false;
    m_rawShown = false;
    if (!m_driver.startSession()) {
      kLog.warn("could not start the face PAM helper");
      finish(Outcome::Unavailable, false);
      return;
    }
    armTimeout();
  }

  void Lane::armTimeout() {
    const std::uint64_t attempt = m_attempt;
    m_driver.startTimer(LaneDriver::TimerSlot::Timeout, m_uiTimeout, [this, attempt] {
      if (attempt != m_attempt || m_state != State::Scanning) {
        return;
      }
      kLog.info("face scan timed out");
      m_driver.cancelSession();
      finish(Outcome::Unavailable, false);
    });
  }

  void Lane::onMessage(const std::string& text, bool isError) {
    if (m_state != State::Scanning && m_state != State::Confirming) {
      return;
    }
    const ClassifiedMessage message = classifyGazeMessage(text);
    if (const auto outcome = outcomeForMessage(message.kind)) {
      // Outcome statuses are shown when the session finishes.
      m_announced = outcome;
      return;
    }
    switch (message.kind) {
    case GazeMessage::LookCamera:
      emit(StatusKind::Look);
      break;
    case GazeMessage::Verified:
      m_verifiedSeen = true;
      break;
    case GazeMessage::UnknownToken:
      kLog.debug("unknown Gaze token {}", text);
      emit(StatusKind::Failed, {}, true);
      break;
    case GazeMessage::Other:
      if (!text.empty()) {
        m_rawShown = true;
        emit(StatusKind::Raw, text, isError);
      }
      break;
    default:
      break;
    }
  }

  void Lane::onPrompt(const std::string& text, bool /*echo*/) {
    const ClassifiedMessage message = classifyGazeMessage(text);
    if (m_state == State::Scanning && message.kind == GazeMessage::ConfirmationPrompt) {
      m_state = State::Confirming;
      m_tokenConfirmation = message.token;
      m_confirmEnteredAt = m_driver.now();
      m_driver.stopTimer(LaneDriver::TimerSlot::Timeout);
      const std::uint64_t attempt = m_attempt;
      m_driver.startTimer(LaneDriver::TimerSlot::Confirm, kConfirmWindow, [this, attempt] {
        if (attempt == m_attempt && m_state == State::Confirming) {
          expireConfirmation();
        }
      });
      emit(StatusKind::Confirm);
      return;
    }
    // Never answer anything else: this conversation must not receive a password.
    kLog.warn("aborting unexpected prompt in the face conversation");
    m_promptAborted = true;
    if (!m_driver.abortPrompt() && (m_state == State::Scanning || m_state == State::Confirming)) {
      // The helper would wait on this prompt until the UI timeout; end it now.
      kLog.warn("could not abort the prompt; stopping the face helper");
      m_driver.cancelSession();
      finish(Outcome::Unavailable, false);
    }
  }

  void Lane::onFinished(bool success, bool pamStarted, bool serviceUnavailable) {
    if (m_state != State::Scanning && m_state != State::Confirming) {
      return;
    }
    m_driver.stopTimer(LaneDriver::TimerSlot::Timeout);
    m_driver.stopTimer(LaneDriver::TimerSlot::Confirm);
    if (success && !m_verifiedSeen && !m_confirmationSent) {
      // Only pam_gaze's own verdict may unlock. A stack that succeeds without it
      // (pam_permit, a misordered file) is treated as a rejection.
      kLog.warn("noctalia-face reported success without a Gaze verification; not unlocking");
      finish(Outcome::Rejected, false);
      return;
    }
    if (success) {
      kLog.info("face authentication succeeded");
      m_state = State::Idle;
      ++m_attempt;
      if (m_onAuthenticated) {
        m_onAuthenticated();
      }
      return;
    }
    finish(outcomeForFailure(m_announced, pamStarted, m_promptAborted || serviceUnavailable), m_announced.has_value());
  }

  void Lane::finish(Outcome outcome, bool announced) {
    m_state = State::Idle;
    ++m_attempt;
    m_policy.scanFinished(outcome, m_driver.now());
    kLog.debug("face attempt finished outcome={} announced={}", static_cast<int>(outcome), announced);

    switch (outcome) {
    case Outcome::NotDetected:
    case Outcome::TimedOut:
      emit(StatusKind::NotDetected);
      break;
    case Outcome::TooDark:
      emit(StatusKind::TooDark);
      break;
    case Outcome::Unavailable:
      emit(StatusKind::Unavailable, {}, true);
      break;
    case Outcome::ConfirmationExpired:
      emit(StatusKind::ConfirmExpired);
      break;
    case Outcome::Declined:
      clearStatus();
      break;
    case Outcome::Rejected:
      if (announced) {
        emit(StatusKind::NotRecognized, {}, true);
      } else if (!m_rawShown) {
        // Keep another module's message (e.g. a faillock notice); otherwise say it failed.
        emit(StatusKind::Failed, {}, true);
      }
      break;
    }
  }

  void Lane::cancel() {
    ++m_attempt;
    m_driver.stopTimer(LaneDriver::TimerSlot::Delay);
    m_driver.stopTimer(LaneDriver::TimerSlot::Timeout);
    m_driver.stopTimer(LaneDriver::TimerSlot::Confirm);
    if (m_state == State::Scanning || m_state == State::Confirming) {
      m_driver.cancelSession();
    }
    m_state = State::Idle;
  }

  void Lane::emit(StatusKind kind, std::string text, bool isError) {
    m_statusShown = kind != StatusKind::Clear;
    if (m_onStatus) {
      m_onStatus(Status{.kind = kind, .text = std::move(text), .isError = isError});
    }
  }

  void Lane::clearStatus() {
    if (m_statusShown) {
      emit(StatusKind::Clear);
    }
  }

} // namespace face
