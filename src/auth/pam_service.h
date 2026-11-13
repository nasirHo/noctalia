#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <sys/types.h>

namespace pam_service {

  // Face-only service run by noctalia-face-pam-helper (pam_gaze); never used for passwords.
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

} // namespace pam_service
