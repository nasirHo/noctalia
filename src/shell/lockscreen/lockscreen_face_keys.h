#pragma once

#include <cstdint>

namespace lockscreen {

  /// What Enter (Validate, or the login button) or Escape (Cancel) does to the face lane.
  enum class FaceKeyAction : std::uint8_t {
    /// Not a face key: the password path handles it as before.
    None,
    /// Answer Gaze's confirmation prompt.
    Confirm,
    /// Start a face scan now.
    Retry,
    /// Dismiss a verified face waiting for confirmation.
    Decline,
    /// A held Enter's autorepeat: neither confirms nor rescans.
    Ignore,
  };

  struct FaceKeyContext {
    bool passwordEmpty = true;
    bool confirming = false;
    /// Enter on an empty field rescans: face unlock is on and empty passwords are not allowed.
    bool retryOnEmptyEnter = false;
  };

  /// Only a fresh press may confirm or rescan. Otherwise the press that started a scan,
  /// held down, would also answer the confirmation that scan asks for.
  constexpr FaceKeyAction
  faceKeyAction(const FaceKeyContext& context, bool validate, bool cancel, bool repeat) noexcept {
    if (!context.passwordEmpty) {
      return FaceKeyAction::None;
    }
    if (validate) {
      if (!context.confirming && !context.retryOnEmptyEnter) {
        return FaceKeyAction::None;
      }
      if (repeat) {
        return FaceKeyAction::Ignore;
      }
      return context.confirming ? FaceKeyAction::Confirm : FaceKeyAction::Retry;
    }
    if (cancel && context.confirming) {
      return FaceKeyAction::Decline;
    }
    return FaceKeyAction::None;
  }

  struct FaceRetryContext {
    /// The failed attempt was an empty password (allow_empty_password, e.g. a pam_u2f touch).
    bool submittedEmpty = false;
    /// The field is still empty when the result arrives.
    bool passwordEmpty = true;
    /// Locked and not unlocking.
    bool locked = true;
    /// The face lane exists and face unlock is on.
    bool faceEnabled = false;
  };

  /// After a failed empty-password attempt, the face lane gets its turn: the password stack
  /// (a security key) goes first, then face. Typing during the attempt always wins.
  constexpr bool faceRetryAfterPasswordFailure(const FaceRetryContext& context) noexcept {
    return context.submittedEmpty && context.passwordEmpty && context.locked && context.faceEnabled;
  }

} // namespace lockscreen
