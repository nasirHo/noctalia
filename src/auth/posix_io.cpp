#include "auth/posix_io.h"

#include <cerrno>
#include <cstdint>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

namespace posix_io {

  void UniqueFd::reset(int fd) noexcept {
    if (m_fd >= 0 && m_fd != fd) {
      (void)::close(m_fd);
    }
    m_fd = fd;
  }

  bool moveAboveStdio(UniqueFd& fd) {
    if (!fd.valid()) {
      return false;
    }
    if (fd.get() > STDERR_FILENO) {
      return true;
    }
    int movedFd = -1;
    do {
      movedFd = ::fcntl(fd.get(), F_DUPFD_CLOEXEC, STDERR_FILENO + 1);
    } while (movedFd < 0 && errno == EINTR);
    if (movedFd < 0) {
      return false;
    }
    fd.reset(movedFd);
    return true;
  }

  bool readAll(int fd, void* data, std::size_t len) {
    auto* bytes = static_cast<std::uint8_t*>(data);
    while (len > 0) {
      const ssize_t n = ::read(fd, bytes, len);
      if (n > 0) {
        bytes += n;
        len -= static_cast<std::size_t>(n);
      } else if (n < 0 && errno == EINTR) {
        continue;
      } else {
        return false;
      }
    }
    return true;
  }

  bool writeAll(int fd, const void* data, std::size_t len) {
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    while (len > 0) {
      ssize_t n = ::send(fd, bytes, len, MSG_NOSIGNAL);
      if (n < 0 && errno == ENOTSOCK) {
        n = ::write(fd, bytes, len);
      }
      if (n > 0) {
        bytes += n;
        len -= static_cast<std::size_t>(n);
      } else if (n < 0 && errno == EINTR) {
        continue;
      } else {
        return false;
      }
    }
    return true;
  }

  void secureClear(std::string& value) noexcept {
    volatile char* ptr = value.empty() ? nullptr : value.data();
    for (std::size_t i = 0; i < value.size(); ++i) {
      ptr[i] = '\0';
    }
    value.clear();
  }

} // namespace posix_io
