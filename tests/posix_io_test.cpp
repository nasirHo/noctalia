#include "auth/posix_io.h"
#include "tests/test_check.h"

#include <cerrno>
#include <fcntl.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <utility>

namespace {

  using posix_io::UniqueFd;

  bool isOpen(int fd) { return ::fcntl(fd, F_GETFD) >= 0 || errno != EBADF; }

  void testUniqueFd() {
    int fds[2] = {-1, -1};
    TEST_CHECK(::pipe2(fds, O_CLOEXEC) == 0);
    const int readFd = fds[0];
    const int writeFd = fds[1];
    {
      UniqueFd read(readFd);
      UniqueFd write(writeFd);
      TEST_CHECK(read.valid());
      TEST_CHECK(read.get() == readFd);

      // Moving transfers ownership; the source no longer closes anything.
      UniqueFd moved(std::move(read));
      TEST_CHECK(!read.valid()); // NOLINT(bugprone-use-after-move)
      TEST_CHECK(moved.get() == readFd);

      // release() hands the fd back without closing it.
      const int released = write.release();
      TEST_CHECK(released == writeFd);
      TEST_CHECK(!write.valid());
      TEST_CHECK(isOpen(writeFd));
      write.reset(released);
    }
    TEST_CHECK(!isOpen(readFd));
    TEST_CHECK(!isOpen(writeFd));
  }

  void testMoveAboveStdio() {
    UniqueFd invalid;
    TEST_CHECK(!posix_io::moveAboveStdio(invalid));

    int fds[2] = {-1, -1};
    TEST_CHECK(::pipe2(fds, O_CLOEXEC) == 0);
    UniqueFd high(fds[0]);
    UniqueFd other(fds[1]);
    const int before = high.get();
    TEST_CHECK(posix_io::moveAboveStdio(high));
    TEST_CHECK(high.get() == before); // already above stderr: untouched
    TEST_CHECK(high.get() > STDERR_FILENO);
  }

  void testReadWriteAll() {
    int sockets[2] = {-1, -1};
    TEST_CHECK(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == 0);
    UniqueFd a(sockets[0]);
    UniqueFd b(sockets[1]);
    const std::string payload = "hello";
    TEST_CHECK(posix_io::writeAll(a.get(), payload.data(), payload.size()));
    std::string received(payload.size(), '\0');
    TEST_CHECK(posix_io::readAll(b.get(), received.data(), received.size()));
    TEST_CHECK(received == payload);

    // EOF before the requested length is a failure.
    a.reset();
    char byte = 0;
    TEST_CHECK(!posix_io::readAll(b.get(), &byte, 1));
    // Writing to a closed peer fails instead of raising SIGPIPE.
    TEST_CHECK(!posix_io::writeAll(b.get(), payload.data(), payload.size()));
  }

  void testSecureClear() {
    std::string secret = "hunter2";
    posix_io::secureClear(secret);
    TEST_CHECK(secret.empty());
  }

} // namespace

int main() {
  testUniqueFd();
  testMoveAboveStdio();
  testReadWriteAll();
  testSecureClear();
  return 0;
}
