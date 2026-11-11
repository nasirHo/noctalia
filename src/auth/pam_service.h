#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <sys/types.h>

namespace pam_service {

  // Face-only service driven by the face lane (pam_gaze); never used for passwords.
  inline constexpr std::string_view kFace = "noctalia-face";

  enum class FileTrust : std::uint8_t {
    Missing,
    Trusted,
    // Exists, but isn't a regular file owned by `owner` that only the owner can write.
    Untrusted,
  };

  /// Checks the file libpam would load for `service` (the first of /etc/pam.d and
  /// /usr/lib/pam.d that has it). The face lane can unlock on this stack's word, so it
  /// must be a regular, root-owned file that neither group nor others can write.
  FileTrust inspectServiceFile(std::string_view service, uid_t owner = 0);

  /// The same check for one path. Symlinks are followed: NixOS links /etc/pam.d into
  /// the read-only store.
  FileTrust inspectFile(const std::string& path, uid_t owner);

  /// How pam_start → pam_authenticate → pam_acct_mgmt (→ pam_setcred) runs for a lane.
  struct PamSequencePolicy {
    // pam_setcred(PAM_REFRESH_CRED) after success, e.g. to renew Kerberos tickets.
    bool refreshCredentials = false;
    // Treat PAM_AUTHINFO_UNAVAIL from pam_acct_mgmt as success: an unprivileged locker
    // may be unable to read /etc/shadow for the account stack.
    bool tolerateAuthinfoUnavail = false;
  };

  // The password lane keeps the established login behavior.
  inline constexpr PamSequencePolicy kPasswordPolicy{.refreshCredentials = true, .tolerateAuthinfoUnavail = true};
  // The face lane is a passive factor, so its account check fails closed. It skips
  // pam_setcred: the face stack carries no credential modules, and running it would
  // only log pam_deny noise.
  inline constexpr PamSequencePolicy kFacePolicy{.refreshCredentials = false, .tolerateAuthinfoUnavail = false};

  /// Whether a pam_acct_mgmt result lets an authenticated user in under `policy`.
  bool acctResultAccepted(int rc, PamSequencePolicy policy) noexcept;

} // namespace pam_service
