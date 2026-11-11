#include "auth/pam_service.h"

#include "auth/posix_io.h"

#include <array>
#include <cerrno>
#include <fcntl.h>
#include <security/pam_appl.h>
#include <string>
#include <sys/stat.h>

namespace pam_service {

  namespace {

    // libpam's search order: the admin's directory, then the vendor one.
    constexpr std::array<std::string_view, 2> kDirs = {"/etc/pam.d/", "/usr/lib/pam.d/"};

    bool validServiceName(std::string_view service) {
      return !service.empty() && !service.contains('/') && service != "." && service != "..";
    }

  } // namespace

  FileTrust inspectFile(const std::string& path, uid_t owner) {
    // O_NONBLOCK: a FIFO planted at the path must not block the shell.
    posix_io::UniqueFd fd(::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK));
    if (!fd.valid()) {
      return errno == ENOENT ? FileTrust::Missing : FileTrust::Untrusted;
    }
    struct stat st{};
    if (::fstat(fd.get(), &st) != 0) {
      return FileTrust::Untrusted;
    }
    const bool trusted = S_ISREG(st.st_mode) && st.st_uid == owner && (st.st_mode & (S_IWGRP | S_IWOTH)) == 0;
    return trusted ? FileTrust::Trusted : FileTrust::Untrusted;
  }

  FileTrust inspectServiceFile(std::string_view service, uid_t owner) {
    if (!validServiceName(service)) {
      return FileTrust::Missing;
    }
    for (const auto dir : kDirs) {
      std::string path(dir);
      path.append(service);
      const FileTrust trust = inspectFile(path, owner);
      if (trust != FileTrust::Missing) {
        return trust;
      }
    }
    return FileTrust::Missing;
  }

  bool acctResultAccepted(int rc, PamSequencePolicy policy) noexcept {
    return rc == PAM_SUCCESS || (rc == PAM_AUTHINFO_UNAVAIL && policy.tolerateAuthinfoUnavail);
  }

} // namespace pam_service
