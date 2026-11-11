#include "auth/face_lane.h"
#include "auth/face_policy.h"
#include "tests/test_check.h"

#include <chrono>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace {

  using face::GazeMessage;
  using face::LanePolicy;
  using face::Outcome;
  using namespace std::chrono_literals;

  void checkClassified(std::string_view text, GazeMessage kind, bool token) {
    const auto message = face::classifyGazeMessage(text);
    TEST_CHECK(message.kind == kind);
    TEST_CHECK(message.token == token);
  }

  void testClassifyTokens() {
    checkClassified("GAZE_MSG_LOOK_CAMERA", GazeMessage::LookCamera, true);
    checkClassified("GAZE_MSG_LOOK_OR_PASSWORD", GazeMessage::LookCamera, true);
    checkClassified("GAZE_MSG_FACE_VERIFIED", GazeMessage::Verified, true);
    checkClassified("GAZE_REQUIRE_CONFIRMATION", GazeMessage::ConfirmationPrompt, true);
    checkClassified("GAZE_MSG_FACE_NOT_RECOGNIZED", GazeMessage::NotRecognized, true);
    checkClassified("GAZE_MSG_FACE_NOT_DETECTED", GazeMessage::NotDetected, true);
    checkClassified("GAZE_MSG_FACE_TOO_DARK", GazeMessage::TooDark, true);
    checkClassified("GAZE_MSG_FACE_TIMED_OUT", GazeMessage::TimedOut, true);
    checkClassified("GAZE_MSG_FACE_UNAVAILABLE", GazeMessage::Unavailable, true);
    checkClassified("GAZE_MSG_SOMETHING_NEW", GazeMessage::UnknownToken, true);
    checkClassified("GAZE_CONFIRMED", GazeMessage::UnknownToken, true);
    checkClassified("  GAZE_MSG_FACE_TOO_DARK\n", GazeMessage::TooDark, true);
  }

  void testClassifyPlain() {
    // Pinned to gaze crates/pam-gaze/src/core/mod.rs: a wording change there must fail here.
    checkClassified("Please look at the camera", GazeMessage::LookCamera, false);
    checkClassified("Please look at the camera or enter password", GazeMessage::LookCamera, false);
    checkClassified("Password incorrect. Please look at the camera", GazeMessage::LookCamera, false);
    checkClassified("Face Verified.", GazeMessage::Verified, false);
    checkClassified("Face not recognized. Enter your password.", GazeMessage::NotRecognized, false);
    checkClassified("Face not detected. Enter your password.", GazeMessage::NotDetected, false);
    checkClassified("Too dark for face authentication. Enter your password.", GazeMessage::TooDark, false);
    checkClassified("Face authentication timed out. Enter your password.", GazeMessage::TimedOut, false);
    checkClassified("Face authentication unavailable. Enter your password.", GazeMessage::Unavailable, false);
    checkClassified("Face Verified. Type 'yes' to confirm.", GazeMessage::ConfirmationPrompt, false);

    // Whitespace is trimmed; everything else must match exactly.
    checkClassified("\t Face not detected. Enter your password. \n", GazeMessage::NotDetected, false);
    checkClassified("face not detected. enter your password.", GazeMessage::Other, false);
    checkClassified("Face not detected.", GazeMessage::Other, false);
    checkClassified("Face Verified. Press Enter to confirm.", GazeMessage::Other, false);
    checkClassified("The account is locked due to 3 failed logins.", GazeMessage::Other, false);
    checkClassified("", GazeMessage::Other, false);
  }

  void testOutcomes() {
    TEST_CHECK(face::outcomeForMessage(GazeMessage::NotDetected) == Outcome::NotDetected);
    TEST_CHECK(face::outcomeForMessage(GazeMessage::TimedOut) == Outcome::TimedOut);
    TEST_CHECK(face::outcomeForMessage(GazeMessage::TooDark) == Outcome::TooDark);
    TEST_CHECK(face::outcomeForMessage(GazeMessage::Unavailable) == Outcome::Unavailable);
    TEST_CHECK(face::outcomeForMessage(GazeMessage::NotRecognized) == Outcome::Rejected);
    TEST_CHECK(!face::outcomeForMessage(GazeMessage::LookCamera).has_value());
    TEST_CHECK(!face::outcomeForMessage(GazeMessage::Verified).has_value());
    TEST_CHECK(!face::outcomeForMessage(GazeMessage::Other).has_value());
    TEST_CHECK(!face::outcomeForMessage(GazeMessage::UnknownToken).has_value());

    // A failure without an outcome message is a rejection: safe, never auto-retried.
    TEST_CHECK(face::outcomeForFailure(std::nullopt, true, false) == Outcome::Rejected);
    TEST_CHECK(face::outcomeForFailure(Outcome::NotDetected, true, false) == Outcome::NotDetected);
    TEST_CHECK(face::outcomeForFailure(Outcome::Rejected, true, true) == Outcome::Rejected);
    TEST_CHECK(face::outcomeForFailure(std::nullopt, false, false) == Outcome::Unavailable);
    TEST_CHECK(face::outcomeForFailure(std::nullopt, true, true) == Outcome::Unavailable);

    TEST_CHECK(face::confirmationReply(true) == "GAZE_CONFIRMED");
    TEST_CHECK(face::confirmationReply(false) == "yes");
  }

  void testPolicyRetries() {
    const auto t0 = LanePolicy::Clock::time_point{} + 1000s;

    // NotDetected / TimedOut: presence retries after the 3 s gap, with no cap.
    for (const Outcome outcome : {Outcome::NotDetected, Outcome::TimedOut}) {
      LanePolicy policy;
      policy.scanFinished(outcome, t0);
      TEST_CHECK(!policy.notePresence(t0 + 1s));
      TEST_CHECK(!policy.notePresence(t0 + 2999ms));
      TEST_CHECK(policy.notePresence(t0 + 3s));
      policy.scanFinished(outcome, t0 + 10s);
      TEST_CHECK(!policy.notePresence(t0 + 11s));
      TEST_CHECK(policy.notePresence(t0 + 13s));
    }

    // TooDark waits 15 s.
    {
      LanePolicy policy;
      policy.scanFinished(Outcome::TooDark, t0);
      TEST_CHECK(!policy.notePresence(t0 + 3s));
      TEST_CHECK(!policy.notePresence(t0 + 14s));
      TEST_CHECK(policy.notePresence(t0 + 15s));
    }

    // Rejected never retries on presence; manual retry is still allowed.
    {
      LanePolicy policy;
      policy.scanFinished(Outcome::Rejected, t0);
      TEST_CHECK(!policy.notePresence(t0 + 3s));
      TEST_CHECK(!policy.notePresence(t0 + 1h));
      TEST_CHECK(policy.allowsManualRetry(t0 + 1h));
    }

    // Manual retry waits kRejectedRetryGap after a rejected or unconfirmed face only.
    for (const Outcome outcome : {Outcome::Rejected, Outcome::ConfirmationExpired}) {
      LanePolicy policy;
      policy.scanFinished(outcome, t0);
      TEST_CHECK(!policy.allowsManualRetry(t0));
      TEST_CHECK(!policy.allowsManualRetry(t0 + 4999ms));
      TEST_CHECK(policy.allowsManualRetry(t0 + 5s));
      TEST_CHECK(!policy.notePresence(t0 + 1h));
    }
    for (const Outcome outcome :
         {Outcome::NotDetected, Outcome::TimedOut, Outcome::TooDark, Outcome::Unavailable, Outcome::Declined}) {
      LanePolicy policy;
      policy.scanFinished(outcome, t0);
      TEST_CHECK(policy.allowsManualRetry(t0));
    }
    {
      LanePolicy policy;
      TEST_CHECK(policy.allowsManualRetry(t0));
      // Declined (Escape) never retries on presence either.
      policy.scanFinished(Outcome::Declined, t0);
      TEST_CHECK(!policy.notePresence(t0 + 1h));
    }

    // Unavailable retries only after 60 s with no input.
    {
      LanePolicy policy;
      policy.scanFinished(Outcome::Unavailable, t0);
      TEST_CHECK(!policy.notePresence(t0 + 5s));
      TEST_CHECK(!policy.notePresence(t0 + 50s));  // input 45 s after the last one
      TEST_CHECK(!policy.notePresence(t0 + 100s)); // 50 s of quiet
      TEST_CHECK(policy.notePresence(t0 + 161s));  // 61 s of quiet
    }
    {
      LanePolicy policy;
      policy.scanFinished(Outcome::Unavailable, t0);
      TEST_CHECK(policy.notePresence(t0 + 60s));
    }

    // Nothing before any scan finished.
    {
      LanePolicy policy;
      TEST_CHECK(!policy.notePresence(t0 + 1h));
    }
  }

  void testPolicyLockCooldown() {
    const auto t0 = LanePolicy::Clock::time_point{} + 1000s;
    {
      LanePolicy policy;
      TEST_CHECK(policy.lockCooldown() == LanePolicy::kDefaultLockCooldown);
      TEST_CHECK(LanePolicy::kDefaultLockCooldown == 5s);
      policy.beginLock(t0);
      // Locking is not a wake: no automatic scan.
      TEST_CHECK(!policy.takeAutoStart());
      // Presence starts the first scan only once the cooldown has passed.
      TEST_CHECK(!policy.notePresence(t0 + 1s));
      TEST_CHECK(!policy.notePresence(t0 + 4999ms));
      TEST_CHECK(policy.notePresence(t0 + 5s));
      // Enter is deliberate: allowed during the cooldown.
      TEST_CHECK(policy.allowsManualRetry(t0 + 1s));
      // A finished scan hands over to the usual outcome rules.
      policy.scanFinished(Outcome::Rejected, t0 + 6s);
      TEST_CHECK(!policy.notePresence(t0 + 1h));
    }
    {
      // A wake after the lock still gets its automatic scan.
      LanePolicy policy;
      policy.beginLock(t0);
      policy.setScreenOn(false);
      TEST_CHECK(!policy.notePresence(t0 + 1h));
      policy.setScreenOn(true);
      TEST_CHECK(policy.takeAutoStart());
      // If that scan was cancelled (typing), presence may still start the first one.
      TEST_CHECK(policy.notePresence(t0 + 1h));
    }
    {
      // A wake does not reopen the first-scan rule after a scan finished.
      LanePolicy policy;
      policy.beginLock(t0);
      policy.scanFinished(Outcome::Rejected, t0 + 10s);
      policy.setScreenOn(false);
      policy.setScreenOn(true);
      TEST_CHECK(!policy.notePresence(t0 + 1h));
    }
    {
      // A new lock resets everything from the previous one.
      LanePolicy policy;
      policy.beginLock(t0);
      policy.scanFinished(Outcome::Rejected, t0 + 10s);
      policy.beginLock(t0 + 1h);
      TEST_CHECK(!policy.lastOutcome().has_value());
      TEST_CHECK(!policy.notePresence(t0 + 1h + 1s));
      TEST_CHECK(policy.notePresence(t0 + 1h + 5s));
    }
    {
      // Configurable and clamped.
      LanePolicy policy;
      policy.setLockCooldown(0ms);
      policy.beginLock(t0);
      TEST_CHECK(policy.notePresence(t0));
      policy.setLockCooldown(-3s);
      TEST_CHECK(policy.lockCooldown() == 0ms);
      policy.setLockCooldown(10min);
      TEST_CHECK(policy.lockCooldown() == LanePolicy::kMaxLockCooldown);
      policy.setLockCooldown(12s);
      policy.beginLock(t0);
      TEST_CHECK(!policy.notePresence(t0 + 11s));
      TEST_CHECK(policy.notePresence(t0 + 12s));
    }
  }

  void testPolicyLockCooldownAfterGrace() {
    const auto t0 = LanePolicy::Clock::time_point{} + 1000s;
    {
      // While grace is pending, presence never scans, however long it lasts.
      LanePolicy policy;
      policy.beginLock(t0, true);
      TEST_CHECK(policy.gracePending());
      TEST_CHECK(!policy.takeAutoStart());
      TEST_CHECK(!policy.notePresence(t0 + 5s));
      TEST_CHECK(!policy.notePresence(t0 + 1h));
      // Grace ends at T: the cooldown runs from T, not from the lock.
      const auto graceEnd = t0 + 1h + 10s;
      policy.graceEnded(graceEnd);
      TEST_CHECK(!policy.gracePending());
      TEST_CHECK(!policy.notePresence(graceEnd));
      TEST_CHECK(!policy.notePresence(graceEnd + 4999ms));
      TEST_CHECK(policy.notePresence(graceEnd + 5s));
    }
    {
      // A second graceEnded doesn't move the origin.
      LanePolicy policy;
      policy.beginLock(t0, true);
      policy.graceEnded(t0 + 10s);
      policy.graceEnded(t0 + 14s);
      TEST_CHECK(!policy.notePresence(t0 + 14999ms));
      TEST_CHECK(policy.notePresence(t0 + 15s));
    }
    {
      // Without grace, graceEnded is a no-op and the cooldown runs from the lock.
      LanePolicy policy;
      policy.beginLock(t0, false);
      TEST_CHECK(!policy.gracePending());
      policy.graceEnded(t0 + 4s);
      TEST_CHECK(!policy.notePresence(t0 + 4999ms));
      TEST_CHECK(policy.notePresence(t0 + 5s));
    }
    {
      // A zero cooldown with grace: presence may scan right at the end of grace.
      LanePolicy policy;
      policy.setLockCooldown(0ms);
      policy.beginLock(t0, true);
      TEST_CHECK(!policy.notePresence(t0 + 30s));
      policy.graceEnded(t0 + 30s);
      TEST_CHECK(policy.notePresence(t0 + 30s));
    }
    {
      // A new lock forgets a previous lock's pending grace.
      LanePolicy policy;
      policy.beginLock(t0, true);
      policy.beginLock(t0 + 1h, false);
      TEST_CHECK(!policy.gracePending());
      TEST_CHECK(policy.notePresence(t0 + 1h + 5s));
    }
    {
      // A wake scan during grace hands over to the outcome rules, but presence still
      // waits for grace to end.
      LanePolicy policy;
      policy.beginLock(t0, true);
      policy.setScreenOn(false);
      policy.setScreenOn(true);
      TEST_CHECK(policy.takeAutoStart());
      policy.scanFinished(Outcome::NotDetected, t0 + 2s);
      TEST_CHECK(!policy.notePresence(t0 + 10s));
      policy.graceEnded(t0 + 20s);
      TEST_CHECK(policy.notePresence(t0 + 20s));
    }
    {
      // Input during grace is still recorded: the Unavailable quiet gap counts from it.
      LanePolicy policy;
      policy.beginLock(t0, true);
      policy.setScreenOn(false);
      policy.setScreenOn(true);
      TEST_CHECK(policy.takeAutoStart());
      policy.scanFinished(Outcome::Unavailable, t0);
      TEST_CHECK(!policy.notePresence(t0 + 50s)); // during grace
      policy.graceEnded(t0 + 55s);
      TEST_CHECK(!policy.notePresence(t0 + 100s)); // 50 s after the input during grace
      TEST_CHECK(policy.notePresence(t0 + 161s));  // 61 s of quiet
    }
  }

  void testUiTimeout() {
    // pam_gaze's budget is 12 s plus its longest start delay; the lane adds 2 s.
    TEST_CHECK(face::uiTimeoutFor(0ms) == 14s);
    TEST_CHECK(face::uiTimeoutFor(9s) == 23s);
    TEST_CHECK(face::uiTimeoutFor(std::nullopt) == 30s);
    TEST_CHECK(face::uiTimeoutFor(-5s) == 14s);
    TEST_CHECK(face::uiTimeoutFor(24h) == face::kCameraBudget + face::kMaxStartDelay + face::kTimeoutMargin);
  }

  void testPolicyScreen() {
    const auto t0 = LanePolicy::Clock::time_point{} + 1000s;
    LanePolicy policy;
    TEST_CHECK(policy.takeAutoStart());
    TEST_CHECK(!policy.takeAutoStart()); // one automatic start per wake

    // Screen off blocks everything.
    policy.scanFinished(Outcome::NotDetected, t0);
    policy.setScreenOn(false);
    TEST_CHECK(!policy.takeAutoStart());
    TEST_CHECK(!policy.allowsManualRetry(t0 + 10s));
    TEST_CHECK(!policy.notePresence(t0 + 10s));

    // Screen on re-arms the wake attempt and forgets the last outcome.
    policy.setScreenOn(true);
    TEST_CHECK(policy.allowsManualRetry(t0 + 10s));
    TEST_CHECK(!policy.lastOutcome().has_value());
    TEST_CHECK(!policy.notePresence(t0 + 20s));
    TEST_CHECK(policy.takeAutoStart());
    TEST_CHECK(!policy.takeAutoStart());

    // Rejected is forgotten by a new wake, so the wake scan may run again.
    policy.scanFinished(Outcome::Rejected, t0 + 30s);
    policy.setScreenOn(false);
    policy.setScreenOn(true);
    TEST_CHECK(policy.takeAutoStart());
  }

  // ---- Lane with a fake driver ----

  using Slot = face::LaneDriver::TimerSlot;

  class FakeDriver final : public face::LaneDriver {
  public:
    bool installed = true;
    std::optional<bool> enrolled = true;
    std::optional<std::chrono::milliseconds> maxStartDelay;
    bool deferProbe = false;
    std::function<void(face::Readiness)> pendingProbe;
    int probes = 0;
    int sessionsStarted = 0;
    int sessionsCancelled = 0;
    bool sessionRunning = false;
    std::vector<std::string> responses;
    bool respondOk = true;
    bool abortOk = true;
    int aborts = 0;
    std::map<Slot, std::pair<std::chrono::milliseconds, std::function<void()>>> timers;
    LanePolicy::Clock::time_point clock = LanePolicy::Clock::time_point{} + 1000s;

    int tokenModeRequests = 0;
    bool faceServiceInstalled() override { return installed; }
    void ensureTokenMode() override { ++tokenModeRequests; }
    void probeReadiness(std::function<void(face::Readiness)> done) override {
      ++probes;
      if (deferProbe) {
        pendingProbe = std::move(done);
        return;
      }
      done(face::Readiness{.enrolled = enrolled, .maxStartDelay = maxStartDelay});
    }
    bool startSession() override {
      ++sessionsStarted;
      sessionRunning = true;
      return true;
    }
    void cancelSession() override {
      ++sessionsCancelled;
      sessionRunning = false;
    }
    bool respond(std::string_view text) override {
      responses.emplace_back(text);
      return respondOk;
    }
    bool abortPrompt() override {
      ++aborts;
      return abortOk;
    }
    void startTimer(Slot slot, std::chrono::milliseconds delay, std::function<void()> callback) override {
      timers[slot] = {delay, std::move(callback)};
    }
    void stopTimer(Slot slot) override { timers.erase(slot); }
    LanePolicy::Clock::time_point now() override { return clock; }

    bool timerArmed(Slot slot) const { return timers.contains(slot); }
    void fire(Slot slot) {
      TEST_CHECK(timers.contains(slot));
      auto callback = std::move(timers[slot].second);
      timers.erase(slot);
      callback();
    }
  };

  struct LaneHarness {
    FakeDriver driver;
    face::Lane lane{driver};
    int unlocks = 0;
    std::vector<face::Status> statuses;

    LaneHarness() {
      lane.setAuthenticatedCallback([this] { ++unlocks; });
      lane.setStatusCallback([this](const face::Status& status) { statuses.push_back(status); });
    }

    // Runs an automatic start through the delay into a running session.
    void startScan() {
      lane.start();
      TEST_CHECK(driver.timerArmed(Slot::Delay));
      TEST_CHECK(driver.timers[Slot::Delay].first == face::Lane::kAutoDelay);
      driver.fire(Slot::Delay);
      TEST_CHECK(driver.sessionRunning);
      TEST_CHECK(driver.timerArmed(Slot::Timeout));
    }

    void endSession(bool success, bool started = true) {
      driver.sessionRunning = false;
      lane.onFinished(success, started);
    }

    face::StatusKind lastStatus() const { return statuses.empty() ? face::StatusKind::Clear : statuses.back().kind; }
  };

  void testLaneSuccessAndTokenConfirmation() {
    LaneHarness h;
    h.startScan();
    h.lane.onMessage("GAZE_MSG_LOOK_CAMERA", false);
    TEST_CHECK(h.lastStatus() == face::StatusKind::Look);
    h.lane.onPrompt("GAZE_REQUIRE_CONFIRMATION", true);
    TEST_CHECK(h.lane.confirming());
    TEST_CHECK(!h.driver.timerArmed(Slot::Timeout));
    TEST_CHECK(h.driver.timerArmed(Slot::Confirm));
    TEST_CHECK(h.driver.timers[Slot::Confirm].first == face::Lane::kConfirmWindow);
    TEST_CHECK(h.lastStatus() == face::StatusKind::Confirm);
    h.driver.clock += 9s;
    h.lane.confirm(h.driver.clock);
    TEST_CHECK(h.driver.responses == std::vector<std::string>{"GAZE_CONFIRMED"});
    TEST_CHECK(h.driver.timerArmed(Slot::Timeout));
    TEST_CHECK(!h.driver.timerArmed(Slot::Confirm));
    h.endSession(true);
    TEST_CHECK(h.unlocks == 1);
    TEST_CHECK(!h.lane.busy());
  }

  void testLanePlainConfirmation() {
    LaneHarness h;
    h.startScan();
    h.lane.onPrompt("Face Verified. Type 'yes' to confirm.", true);
    TEST_CHECK(h.lane.confirming());
    h.lane.confirm(h.driver.clock);
    TEST_CHECK(h.driver.responses == std::vector<std::string>{"yes"});
  }

  void testLaneAbortsOtherPrompts() {
    LaneHarness h;
    h.startScan();
    h.lane.onPrompt("Password: ", false);
    TEST_CHECK(h.driver.aborts == 1);
    TEST_CHECK(h.driver.responses.empty());
    TEST_CHECK(!h.lane.confirming());
    h.lane.confirm(h.driver.clock); // nothing pending: must not answer
    TEST_CHECK(h.driver.responses.empty());
    h.endSession(false);
    TEST_CHECK(h.unlocks == 0);
    TEST_CHECK(h.lane.policy().lastOutcome() == Outcome::Unavailable);
    TEST_CHECK(h.lastStatus() == face::StatusKind::Unavailable);
  }

  void testLaneConfirmNeedsFreshPress() {
    LaneHarness h;
    h.startScan();
    // The Enter that started the scan is still held when Gaze asks to confirm.
    const auto heldSince = h.driver.clock;
    h.driver.clock += 2s;
    h.lane.onPrompt("GAZE_REQUIRE_CONFIRMATION", true);
    h.driver.clock += 500ms;
    h.lane.confirm(heldSince);
    TEST_CHECK(h.driver.responses.empty());
    TEST_CHECK(h.lane.confirming());
    TEST_CHECK(h.driver.timerArmed(Slot::Confirm));
    TEST_CHECK(h.driver.sessionsCancelled == 0);
    // A press at the moment the prompt appeared counts; so does any later one.
    h.lane.confirm(h.driver.clock - 500ms);
    TEST_CHECK(h.driver.responses == std::vector<std::string>{"GAZE_CONFIRMED"});
    h.endSession(true);
    TEST_CHECK(h.unlocks == 1);
  }

  void testLaneTimeoutFollowsGazeDelay() {
    LaneHarness h;
    h.driver.maxStartDelay = 9s;
    h.startScan();
    // A 9 s Gaze delay outlasts the old fixed 14 s: the UI waits 23 s instead.
    TEST_CHECK(h.driver.timers[Slot::Timeout].first == 23s);
    h.lane.onMessage("GAZE_MSG_FACE_NOT_DETECTED", false);
    h.endSession(false);
    TEST_CHECK(h.lane.policy().lastOutcome() == Outcome::NotDetected);

    // The next probe can't read the Config: the fallback applies, not the stale value.
    h.driver.maxStartDelay.reset();
    h.driver.clock += 1h;
    h.lane.retry();
    TEST_CHECK(h.driver.timers[Slot::Timeout].first == face::kFallbackUiTimeout);
    // After a confirmation the same budget is re-armed.
    h.lane.onPrompt("GAZE_REQUIRE_CONFIRMATION", true);
    h.lane.confirm(h.driver.clock);
    TEST_CHECK(h.driver.timers[Slot::Timeout].first == face::kFallbackUiTimeout);
  }

  void testLaneLockDoesNotScan() {
    LaneHarness h;
    h.lane.beginLock();
    h.lane.start();
    TEST_CHECK(h.driver.probes == 0);
    TEST_CHECK(h.driver.timers.empty());
    // Presence during the cooldown does nothing; after it, the first scan starts at once.
    h.driver.clock += 2s;
    h.lane.noteUserPresence();
    TEST_CHECK(h.driver.sessionsStarted == 0);
    h.driver.clock += 3s;
    h.lane.noteUserPresence();
    TEST_CHECK(h.driver.sessionsStarted == 1);
    TEST_CHECK(!h.driver.timerArmed(Slot::Delay));
  }

  void testLaneRetryDuringCooldownAndWake() {
    {
      LaneHarness h;
      h.lane.beginLock();
      h.lane.retry();
      TEST_CHECK(h.driver.sessionsStarted == 1);
    }
    {
      // A wake after the lock scans after the usual short delay.
      LaneHarness h;
      h.lane.beginLock();
      h.lane.setScreenOn(false);
      h.lane.setScreenOn(true);
      h.startScan();
      TEST_CHECK(h.driver.sessionsStarted == 1);
    }
    {
      // A new lock cancels a scan left over from before and clears its status.
      LaneHarness h;
      h.startScan();
      h.lane.onMessage("GAZE_MSG_LOOK_CAMERA", false);
      h.lane.beginLock();
      TEST_CHECK(!h.lane.busy());
      TEST_CHECK(h.driver.sessionsCancelled == 1);
      TEST_CHECK(h.lastStatus() == face::StatusKind::Clear);
      // The lane's cooldown follows the setting.
      h.lane.setLockCooldown(0ms);
      h.lane.beginLock();
      h.lane.noteUserPresence();
      TEST_CHECK(h.driver.sessionsStarted == 2);
    }
  }

  void testLaneCooldownAfterGrace() {
    {
      LaneHarness h;
      h.lane.beginLock(true);
      h.lane.start();
      TEST_CHECK(h.driver.probes == 0);
      // Presence long after the cooldown would have ended does nothing during grace.
      h.driver.clock += 30s;
      h.lane.noteUserPresence();
      TEST_CHECK(h.driver.sessionsStarted == 0);
      // Grace ends: the cooldown starts now.
      h.lane.graceEnded();
      h.driver.clock += 4999ms;
      h.lane.noteUserPresence();
      TEST_CHECK(h.driver.sessionsStarted == 0);
      // A late second notice doesn't push the origin back.
      h.lane.graceEnded();
      h.driver.clock += 1ms;
      h.lane.noteUserPresence();
      TEST_CHECK(h.driver.sessionsStarted == 1);
    }
    {
      // Enter on an empty field still scans once while grace is pending.
      LaneHarness h;
      h.lane.beginLock(true);
      h.lane.retry();
      TEST_CHECK(h.driver.sessionsStarted == 1);
      h.lane.retry(); // busy: no second session
      TEST_CHECK(h.driver.sessionsStarted == 1);
    }
    {
      // A wake during grace still scans after the usual short delay.
      LaneHarness h;
      h.lane.beginLock(true);
      h.lane.setScreenOn(false);
      h.lane.setScreenOn(true);
      h.startScan();
      TEST_CHECK(h.driver.sessionsStarted == 1);
    }
    {
      // No grace: unchanged, and graceEnded does nothing.
      LaneHarness h;
      h.lane.beginLock(false);
      h.driver.clock += 4s;
      h.lane.graceEnded();
      h.driver.clock += 1s;
      h.lane.noteUserPresence();
      TEST_CHECK(h.driver.sessionsStarted == 1);
    }
  }

  void testLaneAbortFailureEndsAttempt() {
    LaneHarness h;
    h.driver.abortOk = false;
    h.startScan();
    h.lane.onPrompt("Password: ", false);
    TEST_CHECK(!h.lane.busy());
    TEST_CHECK(h.driver.sessionsCancelled == 1);
    TEST_CHECK(h.lane.policy().lastOutcome() == Outcome::Unavailable);
    TEST_CHECK(h.driver.responses.empty());
  }

  void testLaneOutcomesAndStatuses() {
    {
      LaneHarness h;
      h.startScan();
      h.lane.onMessage("Face not detected. Enter your password.", false);
      h.endSession(false);
      TEST_CHECK(h.lane.policy().lastOutcome() == Outcome::NotDetected);
      TEST_CHECK(h.lastStatus() == face::StatusKind::NotDetected);
      TEST_CHECK(!h.statuses.back().isError);
      TEST_CHECK(h.unlocks == 0);
    }
    {
      LaneHarness h;
      h.startScan();
      h.lane.onMessage("GAZE_MSG_FACE_NOT_RECOGNIZED", false);
      h.endSession(false);
      TEST_CHECK(h.lane.policy().lastOutcome() == Outcome::Rejected);
      TEST_CHECK(h.lastStatus() == face::StatusKind::NotRecognized);
      TEST_CHECK(h.statuses.back().isError);
    }
    {
      // No outcome message: Rejected, shown as a generic failure.
      LaneHarness h;
      h.startScan();
      h.endSession(false);
      TEST_CHECK(h.lane.policy().lastOutcome() == Outcome::Rejected);
      TEST_CHECK(h.lastStatus() == face::StatusKind::Failed);
    }
    {
      // Another module's message (faillock) stays on screen.
      LaneHarness h;
      h.startScan();
      h.lane.onMessage("The account is locked due to 3 failed logins.", true);
      TEST_CHECK(h.lastStatus() == face::StatusKind::Raw);
      TEST_CHECK(h.statuses.back().text == "The account is locked due to 3 failed logins.");
      h.endSession(false);
      TEST_CHECK(h.lastStatus() == face::StatusKind::Raw);
      TEST_CHECK(h.lane.policy().lastOutcome() == Outcome::Rejected);
    }
    {
      // Unknown tokens are never shown raw; pam_start failure is Unavailable.
      LaneHarness h;
      h.startScan();
      h.lane.onMessage("GAZE_MSG_NEW_THING", false);
      TEST_CHECK(h.lastStatus() == face::StatusKind::Failed);
      TEST_CHECK(h.statuses.back().text.empty());
      h.endSession(false, false);
      TEST_CHECK(h.lane.policy().lastOutcome() == Outcome::Unavailable);
    }
    {
      // PAM_AUTHINFO_UNAVAIL (e.g. the strict account check) is a stack problem, not a rejection.
      LaneHarness h;
      h.startScan();
      h.lane.onMessage("GAZE_MSG_FACE_VERIFIED", false);
      h.driver.sessionRunning = false;
      h.lane.onFinished(false, true, true);
      TEST_CHECK(h.unlocks == 0);
      TEST_CHECK(h.lane.policy().lastOutcome() == Outcome::Unavailable);
      TEST_CHECK(h.lastStatus() == face::StatusKind::Unavailable);
    }
    {
      // A helper failure (no Result, protocol error, setup failure) is not a decision:
      // Unavailable, and Enter can retry at once instead of waiting out the rejection gap.
      LaneHarness h;
      h.startScan();
      h.driver.sessionRunning = false;
      h.lane.onFinished(false, true, true);
      TEST_CHECK(h.lane.policy().lastOutcome() == Outcome::Unavailable);
      h.driver.clock += 1s;
      h.lane.retry();
      TEST_CHECK(h.driver.sessionsStarted == 2);
      // What Gaze announced still wins: a rejection followed by a helper failure stays one.
      h.lane.onMessage("GAZE_MSG_FACE_NOT_RECOGNIZED", false);
      h.driver.sessionRunning = false;
      h.lane.onFinished(false, true, true);
      TEST_CHECK(h.lane.policy().lastOutcome() == Outcome::Rejected);
    }
    {
      // UI timeout cancels the helper and counts as Unavailable.
      LaneHarness h;
      h.startScan();
      TEST_CHECK(h.driver.timers[Slot::Timeout].first == face::kFallbackUiTimeout);
      h.driver.fire(Slot::Timeout);
      TEST_CHECK(h.driver.sessionsCancelled == 1);
      TEST_CHECK(!h.lane.busy());
      TEST_CHECK(h.lane.policy().lastOutcome() == Outcome::Unavailable);
      // A late finish from the killed helper is ignored.
      h.lane.onFinished(true, true);
      TEST_CHECK(h.unlocks == 0);
    }
  }

  void testLaneSuccessNeedsEvidence() {
    {
      // A bare PAM success (pam_permit, a misordered stack) never unlocks.
      LaneHarness h;
      h.startScan();
      h.endSession(true);
      TEST_CHECK(h.unlocks == 0);
      TEST_CHECK(h.lane.policy().lastOutcome() == Outcome::Rejected);
      TEST_CHECK(h.lastStatus() == face::StatusKind::Failed);
    }
    {
      // "Look at the camera" alone is not evidence.
      LaneHarness h;
      h.startScan();
      h.lane.onMessage("GAZE_MSG_LOOK_CAMERA", false);
      h.endSession(true);
      TEST_CHECK(h.unlocks == 0);
    }
    for (const char* verified : {"GAZE_MSG_FACE_VERIFIED", "Face Verified."}) {
      LaneHarness h;
      h.startScan();
      h.lane.onMessage(verified, false);
      h.endSession(true);
      TEST_CHECK(h.unlocks == 1);
    }
    {
      // Evidence belongs to one attempt: the next scan starts without it.
      LaneHarness h;
      h.startScan();
      h.lane.onMessage("GAZE_MSG_FACE_VERIFIED", false);
      h.lane.onMessage("GAZE_MSG_FACE_NOT_RECOGNIZED", false);
      h.endSession(false);
      h.driver.clock += 1h;
      h.lane.retry();
      TEST_CHECK(h.driver.sessionsStarted == 2);
      h.endSession(true);
      TEST_CHECK(h.unlocks == 0);
    }
  }

  void testLaneConfirmationWindow() {
    {
      // The window expires: the helper is killed without an answer.
      LaneHarness h;
      h.startScan();
      h.lane.onPrompt("GAZE_REQUIRE_CONFIRMATION", true);
      h.driver.fire(Slot::Confirm);
      TEST_CHECK(!h.lane.busy());
      TEST_CHECK(h.driver.sessionsCancelled == 1);
      TEST_CHECK(h.driver.aborts == 0);
      TEST_CHECK(h.driver.responses.empty());
      TEST_CHECK(h.lane.policy().lastOutcome() == Outcome::ConfirmationExpired);
      TEST_CHECK(h.lastStatus() == face::StatusKind::ConfirmExpired);
      TEST_CHECK(!h.statuses.back().isError);
      h.lane.confirm(h.driver.clock);
      TEST_CHECK(h.driver.responses.empty());
      h.lane.onFinished(true, true); // late finish from the killed helper
      TEST_CHECK(h.unlocks == 0);

      // No presence retry; Enter works after the retry gap.
      h.driver.clock += 1h;
      h.lane.noteUserPresence();
      TEST_CHECK(h.driver.sessionsStarted == 1);
      h.lane.retry();
      TEST_CHECK(h.driver.sessionsStarted == 2);
    }
    {
      // A late timer can't stretch the window: Enter after it checks the clock.
      LaneHarness h;
      h.startScan();
      h.lane.onPrompt("GAZE_REQUIRE_CONFIRMATION", true);
      h.driver.clock += face::Lane::kConfirmWindow + 1ms;
      h.lane.confirm(h.driver.clock);
      TEST_CHECK(h.driver.responses.empty());
      TEST_CHECK(h.driver.sessionsCancelled == 1);
      TEST_CHECK(h.lane.policy().lastOutcome() == Outcome::ConfirmationExpired);
      TEST_CHECK(h.unlocks == 0);
      // Retry within the gap is refused.
      h.driver.clock += 4s;
      h.lane.retry();
      TEST_CHECK(h.driver.sessionsStarted == 1);
      h.driver.clock += 1s;
      h.lane.retry();
      TEST_CHECK(h.driver.sessionsStarted == 2);
    }
    {
      // Pointer movement while confirming changes nothing; Escape declines.
      LaneHarness h;
      h.startScan();
      h.lane.onPrompt("GAZE_REQUIRE_CONFIRMATION", true);
      h.driver.clock += 1s;
      h.lane.noteUserPresence();
      TEST_CHECK(h.lane.confirming());
      TEST_CHECK(h.driver.sessionsCancelled == 0);
      h.lane.declineConfirmation();
      TEST_CHECK(!h.lane.busy());
      TEST_CHECK(h.driver.sessionsCancelled == 1);
      TEST_CHECK(h.driver.aborts == 0);
      TEST_CHECK(h.driver.responses.empty());
      TEST_CHECK(!h.driver.timerArmed(Slot::Confirm));
      TEST_CHECK(h.lane.policy().lastOutcome() == Outcome::Declined);
      TEST_CHECK(h.lastStatus() == face::StatusKind::Clear);
      h.driver.clock += 1h;
      h.lane.noteUserPresence();
      TEST_CHECK(h.driver.sessionsStarted == 1);
      h.lane.retry(); // no gap after a decline
      TEST_CHECK(h.driver.sessionsStarted == 2);
    }
    {
      // declineConfirmation() outside a confirmation does nothing.
      LaneHarness h;
      h.startScan();
      h.lane.declineConfirmation();
      TEST_CHECK(h.lane.busy());
      TEST_CHECK(h.driver.sessionsCancelled == 0);
    }
    {
      // A confirmation that can't be written ends the attempt instead of waiting.
      LaneHarness h;
      h.driver.respondOk = false;
      h.startScan();
      h.lane.onPrompt("GAZE_REQUIRE_CONFIRMATION", true);
      h.lane.confirm(h.driver.clock);
      TEST_CHECK(!h.lane.busy());
      TEST_CHECK(h.driver.sessionsCancelled == 1);
      TEST_CHECK(h.lane.policy().lastOutcome() == Outcome::Unavailable);
      h.lane.onFinished(true, true);
      TEST_CHECK(h.unlocks == 0);
    }
  }

  void testLaneScreenOff() {
    LaneHarness h;
    h.startScan();
    h.lane.onMessage("GAZE_MSG_LOOK_CAMERA", false);
    h.lane.setScreenOn(false);
    TEST_CHECK(h.driver.sessionsCancelled == 1);
    TEST_CHECK(!h.lane.busy());
    // Not classified: no outcome, and only the hint is cleared, never an error.
    TEST_CHECK(!h.lane.policy().lastOutcome().has_value());
    TEST_CHECK(h.lastStatus() == face::StatusKind::Clear);
    for (const auto& status : h.statuses) {
      TEST_CHECK(!status.isError);
    }

    // Everything is blocked while off.
    const int started = h.driver.sessionsStarted;
    h.lane.start();
    h.lane.retry();
    h.driver.clock += 1h;
    h.lane.noteUserPresence();
    TEST_CHECK(h.driver.timers.empty());
    TEST_CHECK(h.driver.probes == 1);
    TEST_CHECK(h.driver.sessionsStarted == started);

    // Screen on re-arms one automatic start.
    h.lane.setScreenOn(true);
    h.startScan();
    TEST_CHECK(h.driver.sessionsStarted == started + 1);
    h.endSession(false);
    h.lane.start();
    TEST_CHECK(!h.lane.busy());
  }

  void testLaneScreenOffDuringDelayAndProbe() {
    LaneHarness h;
    h.lane.start();
    TEST_CHECK(h.driver.timerArmed(Slot::Delay));
    h.lane.setScreenOn(false);
    TEST_CHECK(!h.driver.timerArmed(Slot::Delay));
    TEST_CHECK(h.driver.sessionsStarted == 0);

    LaneHarness p;
    p.driver.deferProbe = true;
    p.lane.start();
    p.lane.setScreenOn(false);
    p.driver.pendingProbe(face::Readiness{.enrolled = true, .maxStartDelay = std::nullopt}); // late reply
    TEST_CHECK(!p.driver.timerArmed(Slot::Delay));
    TEST_CHECK(p.driver.sessionsStarted == 0);
  }

  void testLanePresenceRetries() {
    LaneHarness h;
    h.startScan();
    h.lane.onMessage("GAZE_MSG_FACE_NOT_DETECTED", false);
    h.endSession(false);
    h.driver.clock += 1s;
    h.lane.noteUserPresence();
    TEST_CHECK(!h.lane.busy());
    h.driver.clock += 2s;
    h.lane.noteUserPresence();
    // Presence skips the start delay.
    TEST_CHECK(h.driver.sessionsStarted == 2);
    TEST_CHECK(!h.driver.timerArmed(Slot::Delay));

    // Rejected: presence never retries, Enter does.
    h.lane.onMessage("GAZE_MSG_FACE_NOT_RECOGNIZED", false);
    h.endSession(false);
    h.driver.clock += 1h;
    h.lane.noteUserPresence();
    TEST_CHECK(h.driver.sessionsStarted == 2);
    h.lane.retry();
    TEST_CHECK(h.driver.sessionsStarted == 3);
  }

  void testLaneStopAndDisable() {
    LaneHarness h;
    h.startScan();
    h.lane.onMessage("GAZE_MSG_FACE_NOT_DETECTED", false);
    h.lane.stop(); // typing
    TEST_CHECK(h.driver.sessionsCancelled == 1);
    TEST_CHECK(!h.lane.policy().lastOutcome().has_value());
    h.lane.onFinished(false, true); // late finish is ignored
    TEST_CHECK(!h.lane.policy().lastOutcome().has_value());

    h.lane.setEnabled(false);
    h.lane.retry();
    h.lane.start();
    TEST_CHECK(h.driver.sessionsStarted == 1);
    h.lane.setEnabled(true);
    h.lane.retry();
    TEST_CHECK(h.driver.sessionsStarted == 2);
  }

  void testLaneReadiness() {
    {
      LaneHarness h;
      h.driver.enrolled = false;
      h.lane.start();
      TEST_CHECK(!h.lane.busy());
      TEST_CHECK(h.driver.timers.empty());
      TEST_CHECK(h.statuses.empty()); // not enrolled: show nothing
    }
    {
      LaneHarness h;
      h.driver.enrolled = std::nullopt; // probe failed: let PAM decide
      h.startScan();
    }
    {
      LaneHarness h;
      h.driver.installed = false;
      h.lane.start();
      h.lane.retry();
      TEST_CHECK(h.driver.probes == 0);
      // A system without the face service (or with an untrusted file) never wakes gazed.
      TEST_CHECK(h.driver.tokenModeRequests == 0);
      TEST_CHECK(!h.lane.busy());
    }
    {
      // Token mode is requested before each probe, never before the service check.
      LaneHarness h;
      h.startScan();
      TEST_CHECK(h.driver.tokenModeRequests == 1);
      TEST_CHECK(h.driver.probes == 1);
    }
  }

} // namespace

int main() {
  testClassifyTokens();
  testClassifyPlain();
  testOutcomes();
  testPolicyRetries();
  testPolicyLockCooldown();
  testPolicyLockCooldownAfterGrace();
  testUiTimeout();
  testPolicyScreen();
  testLaneSuccessAndTokenConfirmation();
  testLanePlainConfirmation();
  testLaneAbortsOtherPrompts();
  testLaneLockDoesNotScan();
  testLaneRetryDuringCooldownAndWake();
  testLaneCooldownAfterGrace();
  testLaneAbortFailureEndsAttempt();
  testLaneConfirmNeedsFreshPress();
  testLaneTimeoutFollowsGazeDelay();
  testLaneOutcomesAndStatuses();
  testLaneSuccessNeedsEvidence();
  testLaneConfirmationWindow();
  testLaneScreenOff();
  testLaneScreenOffDuringDelayAndProbe();
  testLanePresenceRetries();
  testLaneStopAndDisable();
  testLaneReadiness();
  return 0;
}
