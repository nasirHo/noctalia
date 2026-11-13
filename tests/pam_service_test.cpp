#include "auth/pam_service.h"
#include "tests/test_check.h"

#include <cstdlib>
#include <fcntl.h>
#include <filesystem>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace {

  void testInspectFile() {
    using pam_service::FileTrust;
    using pam_service::inspectFile;

    std::string templ = (std::filesystem::temp_directory_path() / "noctalia-pam-service-XXXXXX").string();
    TEST_CHECK(::mkdtemp(templ.data()) != nullptr);
    const std::filesystem::path dir = templ;
    const uid_t me = ::getuid();
    // Root never matches an ownership check against another uid, so pick one that differs.
    const uid_t someoneElse = me == 0 ? 1 : 0;

    const auto make = [&](const std::string& name, mode_t mode) {
      const std::string path = (dir / name).string();
      const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
      TEST_CHECK(fd >= 0);
      (void)::close(fd);
      TEST_CHECK(::chmod(path.c_str(), mode) == 0);
      return path;
    };

    const std::string good = make("good", 0644);
    TEST_CHECK(inspectFile(good, me) == FileTrust::Trusted);
    TEST_CHECK(inspectFile(make("readonly", 0444), me) == FileTrust::Trusted);
    // Wrong owner.
    TEST_CHECK(inspectFile(good, someoneElse) == FileTrust::Untrusted);
    // Group- or world-writable.
    TEST_CHECK(inspectFile(make("world", 0666), me) == FileTrust::Untrusted);
    TEST_CHECK(inspectFile(make("group", 0620), me) == FileTrust::Untrusted);
    TEST_CHECK(inspectFile(make("other", 0602), me) == FileTrust::Untrusted);
    // Symlinks are followed (NixOS); the target is what counts.
    const std::string link = (dir / "link").string();
    TEST_CHECK(::symlink(good.c_str(), link.c_str()) == 0);
    TEST_CHECK(inspectFile(link, me) == FileTrust::Trusted);
    const std::string badLink = (dir / "bad-link").string();
    TEST_CHECK(::symlink((dir / "world").c_str(), badLink.c_str()) == 0);
    TEST_CHECK(inspectFile(badLink, me) == FileTrust::Untrusted);
    // Not a regular file: a directory, a FIFO (must not block).
    const std::string subdir = (dir / "subdir").string();
    TEST_CHECK(::mkdir(subdir.c_str(), 0755) == 0);
    TEST_CHECK(inspectFile(subdir, me) == FileTrust::Untrusted);
    const std::string fifo = (dir / "fifo").string();
    TEST_CHECK(::mkfifo(fifo.c_str(), 0644) == 0);
    TEST_CHECK(inspectFile(fifo, me) == FileTrust::Untrusted);
    // Missing, including a dangling link.
    TEST_CHECK(inspectFile((dir / "absent").string(), me) == FileTrust::Missing);
    const std::string dangling = (dir / "dangling").string();
    TEST_CHECK(::symlink((dir / "absent").c_str(), dangling.c_str()) == 0);
    TEST_CHECK(inspectFile(dangling, me) == FileTrust::Missing);

    std::filesystem::remove_all(dir);

    TEST_CHECK(pam_service::inspectServiceFile("") == FileTrust::Missing);
    TEST_CHECK(pam_service::inspectServiceFile("..") == FileTrust::Missing);
    TEST_CHECK(pam_service::inspectServiceFile("../pam.d/login") == FileTrust::Missing);
    TEST_CHECK(pam_service::inspectServiceFile("noctalia-test-service-that-does-not-exist") == FileTrust::Missing);
  }

} // namespace

int main() {
  testInspectFile();
  return 0;
}
