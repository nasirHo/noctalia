#include "shell/lockscreen/lockscreen_face_keys.h"
#include "tests/test_check.h"

using lockscreen::FaceKeyAction;
using lockscreen::faceKeyAction;
using lockscreen::FaceKeyContext;
using lockscreen::faceRetryAfterPasswordFailure;
using lockscreen::FaceRetryContext;

namespace {

  constexpr FaceKeyContext kConfirming{.passwordEmpty = true, .confirming = true, .retryOnEmptyEnter = true};
  constexpr FaceKeyContext kIdle{.passwordEmpty = true, .confirming = false, .retryOnEmptyEnter = true};

  void testEnterWhileConfirming() {
    TEST_CHECK(faceKeyAction(kConfirming, true, false, false) == FaceKeyAction::Confirm);
    // A held Enter (the press that started the scan) never confirms.
    TEST_CHECK(faceKeyAction(kConfirming, true, false, true) == FaceKeyAction::Ignore);
    // Confirming doesn't depend on whether Enter would otherwise rescan.
    constexpr FaceKeyContext noRetry{.passwordEmpty = true, .confirming = true, .retryOnEmptyEnter = false};
    TEST_CHECK(faceKeyAction(noRetry, true, false, false) == FaceKeyAction::Confirm);
    TEST_CHECK(faceKeyAction(noRetry, true, false, true) == FaceKeyAction::Ignore);
  }

  void testEnterOnIdleField() {
    TEST_CHECK(faceKeyAction(kIdle, true, false, false) == FaceKeyAction::Retry);
    TEST_CHECK(faceKeyAction(kIdle, true, false, true) == FaceKeyAction::Ignore);
    // Face off, or empty passwords allowed: the password path decides, repeat or not.
    constexpr FaceKeyContext noFace{.passwordEmpty = true, .confirming = false, .retryOnEmptyEnter = false};
    TEST_CHECK(faceKeyAction(noFace, true, false, false) == FaceKeyAction::None);
    TEST_CHECK(faceKeyAction(noFace, true, false, true) == FaceKeyAction::None);
  }

  void testTypedPasswordIsNeverAFaceKey() {
    constexpr FaceKeyContext typed{.passwordEmpty = false, .confirming = true, .retryOnEmptyEnter = true};
    TEST_CHECK(faceKeyAction(typed, true, false, false) == FaceKeyAction::None);
    TEST_CHECK(faceKeyAction(typed, true, false, true) == FaceKeyAction::None);
    // Escape clears the password first.
    TEST_CHECK(faceKeyAction(typed, false, true, false) == FaceKeyAction::None);
  }

  void testEscape() {
    TEST_CHECK(faceKeyAction(kConfirming, false, true, false) == FaceKeyAction::Decline);
    TEST_CHECK(faceKeyAction(kConfirming, false, true, true) == FaceKeyAction::Decline);
    TEST_CHECK(faceKeyAction(kIdle, false, true, false) == FaceKeyAction::None);
  }

  void testOtherKeys() {
    TEST_CHECK(faceKeyAction(kConfirming, false, false, false) == FaceKeyAction::None);
    TEST_CHECK(faceKeyAction(kIdle, false, false, true) == FaceKeyAction::None);
  }

  constexpr FaceRetryContext kFailedEmpty{
      .submittedEmpty = true, .passwordEmpty = true, .locked = true, .faceEnabled = true
  };

  void testFailedEmptyAttemptScansForFace() { TEST_CHECK(faceRetryAfterPasswordFailure(kFailedEmpty)); }

  void testFailedTypedPasswordDoesNotScan() {
    FaceRetryContext typed = kFailedEmpty;
    typed.submittedEmpty = false;
    TEST_CHECK(!faceRetryAfterPasswordFailure(typed));
  }

  void testTypingDuringAttemptWins() {
    FaceRetryContext typing = kFailedEmpty;
    typing.passwordEmpty = false;
    TEST_CHECK(!faceRetryAfterPasswordFailure(typing));
  }

  void testFaceDisabledDoesNotScan() {
    FaceRetryContext disabled = kFailedEmpty;
    disabled.faceEnabled = false;
    TEST_CHECK(!faceRetryAfterPasswordFailure(disabled));
  }

  void testUnlockingDoesNotScan() {
    FaceRetryContext unlocking = kFailedEmpty;
    unlocking.locked = false;
    TEST_CHECK(!faceRetryAfterPasswordFailure(unlocking));
  }

  static_assert(faceKeyAction(kConfirming, true, false, true) == FaceKeyAction::Ignore);

} // namespace

int main() {
  testEnterWhileConfirming();
  testEnterOnIdleField();
  testTypedPasswordIsNeverAFaceKey();
  testEscape();
  testOtherKeys();
  testFailedEmptyAttemptScansForFace();
  testFailedTypedPasswordDoesNotScan();
  testTypingDuringAttemptWins();
  testFaceDisabledDoesNotScan();
  testUnlockingDoesNotScan();
  return 0;
}
