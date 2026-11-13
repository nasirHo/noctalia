#pragma once

#include <string>

namespace pam_helper_path {

  struct HelperLocation {
    // File name looked up next to the running binary.
    const char* name = nullptr;
    // Environment variable that, when set, names the helper's absolute path.
    const char* environmentVariable = nullptr;
    // Compiled install path, <prefix>/<libexecdir>/noctalia/<name>.
    const char* installedPath = nullptr;
  };

  /// The helper's environment variable replaces the lookup, so a shell built
  /// elsewhere (e.g. by Nix on another distribution) can pair with a helper built
  /// against the host's libpam. Otherwise a helper next to the binary (build tree,
  /// bundle) wins over the installed one, so a dev build never talks to an older
  /// installed helper. Returns an empty path, and logs why, when nothing is found.
  [[nodiscard]] std::string resolve(const HelperLocation& helper);

} // namespace pam_helper_path
