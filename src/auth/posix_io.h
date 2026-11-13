#pragma once

#include <cstddef>
#include <string>

// Small POSIX helpers shared by the PAM helpers and the sessions that drive them.
namespace posix_io {

  /// Owns one file descriptor and closes it on destruction.
  class UniqueFd {
  public:
    UniqueFd() = default;
    explicit UniqueFd(int fd) noexcept : m_fd(fd) {}
    ~UniqueFd() { reset(); }

    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;
    UniqueFd(UniqueFd&& other) noexcept : m_fd(other.release()) {}
    UniqueFd& operator=(UniqueFd&& other) noexcept {
      if (this != &other) {
        reset(other.release());
      }
      return *this;
    }

    int get() const noexcept { return m_fd; }
    bool valid() const noexcept { return m_fd >= 0; }
    /// Gives up ownership without closing.
    [[nodiscard]] int release() noexcept {
      const int fd = m_fd;
      m_fd = -1;
      return fd;
    }
    void reset(int fd = -1) noexcept;

  private:
    int m_fd = -1;
  };

  /// Re-homes `fd` above stderr (keeping CLOEXEC) so dup2() onto stdio never clobbers it.
  [[nodiscard]] bool moveAboveStdio(UniqueFd& fd);

  /// Blocking read of exactly `len` bytes; false on EOF or error.
  [[nodiscard]] bool readAll(int fd, void* data, std::size_t len);
  /// Blocking write of `len` bytes. On a socket it never raises SIGPIPE.
  [[nodiscard]] bool writeAll(int fd, const void* data, std::size_t len);

  /// Overwrites the string's bytes before clearing it.
  void secureClear(std::string& value) noexcept;

} // namespace posix_io
