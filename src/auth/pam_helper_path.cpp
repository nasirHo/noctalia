#include "auth/pam_helper_path.h"

#include "core/log.h"

#include <array>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

namespace pam_helper_path {

  namespace {

    constexpr Logger kLog("pam");

  } // namespace

  std::string resolve(const HelperLocation& helper) {
    if (const char* envPath = std::getenv(helper.environmentVariable); envPath != nullptr) {
      if (*envPath != '/') {
        kLog.error("{} must be an absolute path, got {}", helper.environmentVariable, envPath);
        return {};
      }
      if (::access(envPath, X_OK) != 0) {
        kLog.error("{}={} is not executable: {}", helper.environmentVariable, envPath, std::strerror(errno));
        return {};
      }
      return envPath;
    }

    std::array<char, PATH_MAX> exe{};
    const ssize_t n = ::readlink("/proc/self/exe", exe.data(), exe.size() - 1);
    if (n > 0) {
      std::string path(exe.data(), static_cast<std::size_t>(n));
      const auto slash = path.rfind('/');
      if (slash != std::string::npos) {
        path.resize(slash + 1);
        path += helper.name;
        if (::access(path.c_str(), X_OK) == 0) {
          return path;
        }
      }
    }
    if (::access(helper.installedPath, X_OK) == 0) {
      return helper.installedPath;
    }
    kLog.error("{} not found (expected at {})", helper.name, helper.installedPath);
    return {};
  }

} // namespace pam_helper_path
