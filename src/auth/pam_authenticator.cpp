#include "auth/pam_authenticator.h"

#include "auth/pam_helper_protocol.h"
#include "auth/pam_service.h"
#include "auth/posix_io.h"
#include "core/log.h"
#include "i18n/i18n.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <exception>
#include <fcntl.h>
#include <pthread.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace {

  constexpr Logger kLog("pam");

  // Runs inside a helper entry point's catch block: a throw from the logger there would
  // escape into main() instead of the documented exit status 2.
  void logHelperFailure(const char* helper, const char* what) noexcept {
    try {
      kLog.error("{} failed: {}", helper, what);
    } catch (...) {
      // Exit status 2 still reports the failure.
    }
  }

  constexpr std::size_t kMaxPamMessageBytes = 4096;
  constexpr std::size_t kMaxPasswordBytes = 64 * 1024;

  using posix_io::readAll;
  using posix_io::secureClear;
  using posix_io::UniqueFd;
  using posix_io::writeAll;

  struct PamConversationData {
    const char* password = nullptr;
    bool passwordSent = false;
  };

  struct PamHandle {
    pam_handle_t* h = nullptr;
    int lastRc = PAM_SUCCESS;

    PamHandle() = default;
    PamHandle(const PamHandle&) = delete;
    PamHandle& operator=(const PamHandle&) = delete;

    ~PamHandle() {
      if (h != nullptr) {
        pam_end(h, lastRc);
      }
    }
  };

  // Only C calls (calloc, strdup): nothing here can throw into libpam.
  int pamConversation(int numMsg, const pam_message** msg, pam_response** response, void* appdataPtr) noexcept {
    if (numMsg <= 0 || msg == nullptr || response == nullptr || appdataPtr == nullptr) {
      return PAM_CONV_ERR;
    }

    auto* data = static_cast<PamConversationData*>(appdataPtr);
    auto* replies = static_cast<pam_response*>(std::calloc(static_cast<std::size_t>(numMsg), sizeof(pam_response)));
    if (replies == nullptr) {
      return PAM_BUF_ERR;
    }

    for (int i = 0; i < numMsg; ++i) {
      if (msg[i] == nullptr) {
        std::free(replies);
        return PAM_CONV_ERR;
      }

      switch (msg[i]->msg_style) {
      case PAM_PROMPT_ECHO_OFF:
        if (data->passwordSent) {
          for (int j = 0; j < i; ++j) {
            if (replies[j].resp != nullptr) {
              std::free(replies[j].resp);
            }
          }
          std::free(replies);
          return PAM_CONV_ERR;
        }
        replies[i].resp = ::strdup(data->password != nullptr ? data->password : "");
        data->passwordSent = true;
        break;
      case PAM_PROMPT_ECHO_ON:
        replies[i].resp = ::strdup("");
        break;
      case PAM_ERROR_MSG:
      case PAM_TEXT_INFO:
        replies[i].resp = nullptr;
        break;
      default:
        for (int j = 0; j <= i; ++j) {
          if (replies[j].resp != nullptr) {
            std::free(replies[j].resp);
          }
        }
        std::free(replies);
        return PAM_CONV_ERR;
      }

      if ((msg[i]->msg_style == PAM_PROMPT_ECHO_OFF || msg[i]->msg_style == PAM_PROMPT_ECHO_ON)
          && replies[i].resp == nullptr) {
        for (int j = 0; j <= i; ++j) {
          if (replies[j].resp != nullptr) {
            std::free(replies[j].resp);
          }
        }
        std::free(replies);
        return PAM_BUF_ERR;
      }
    }

    *response = replies;
    return PAM_SUCCESS;
  }

  struct Pipe {
    UniqueFd read;
    UniqueFd write;
  };

  [[nodiscard]] bool createPipe(Pipe& pipe) {
    int fds[2] = {-1, -1};
    if (::pipe2(fds, O_CLOEXEC) != 0) {
      return false;
    }
    pipe.read.reset(fds[0]);
    pipe.write.reset(fds[1]);
    return posix_io::moveAboveStdio(pipe.read) && posix_io::moveAboveStdio(pipe.write);
  }

  // Both conversation functions run under libpam (C) and its modules: unwinding into
  // them is undefined behavior.
  static_assert(noexcept(pamConversation(0, nullptr, nullptr, nullptr)));
  static_assert(noexcept(pam_protocol::interactiveConversation(0, nullptr, nullptr, nullptr)));

  [[nodiscard]] bool sendPassword(int fd, std::string_view password) {
    sigset_t pipeMask;
    sigset_t previousMask;
    sigset_t pendingMask;
    if (::sigemptyset(&pipeMask) != 0
        || ::sigaddset(&pipeMask, SIGPIPE) != 0
        || ::pthread_sigmask(SIG_BLOCK, &pipeMask, &previousMask) != 0) {
      return false;
    }

    if (::sigpending(&pendingMask) != 0) {
      (void)::pthread_sigmask(SIG_SETMASK, &previousMask, nullptr);
      return false;
    }
    const int wasPending = ::sigismember(&pendingMask, SIGPIPE);
    if (wasPending < 0) {
      (void)::pthread_sigmask(SIG_SETMASK, &previousMask, nullptr);
      return false;
    }

    const auto len = static_cast<std::uint32_t>(password.size());
    errno = 0;
    const bool sent = writeAll(fd, &len, sizeof(len)) && (len == 0 || writeAll(fd, password.data(), len));
    const int writeError = errno;

    bool restoreSafe = true;
    if (!sent && writeError == EPIPE && wasPending == 0) {
      const timespec timeout{};
      int receivedSignal = -1;
      do {
        receivedSignal = ::sigtimedwait(&pipeMask, nullptr, &timeout);
      } while (receivedSignal < 0 && errno == EINTR);
      restoreSafe = receivedSignal == SIGPIPE || (receivedSignal < 0 && errno == EAGAIN);
    }

    if (!restoreSafe || ::pthread_sigmask(SIG_SETMASK, &previousMask, nullptr) != 0) {
      return false;
    }
    return sent;
  }

  [[nodiscard]] bool writeResult(int fd, const PamAuthenticator::Result& result) {
    const std::uint8_t success = result.success ? 1 : 0;
    if (!writeAll(fd, &success, sizeof(success))) {
      return false;
    }
    const std::uint32_t len = static_cast<std::uint32_t>(std::min(result.message.size(), kMaxPamMessageBytes));
    if (!writeAll(fd, &len, sizeof(len))) {
      return false;
    }
    if (len > 0 && !writeAll(fd, result.message.data(), len)) {
      return false;
    }
    return true;
  }

  [[nodiscard]] bool readResult(int fd, PamAuthenticator::Result& result) {
    std::uint8_t success = 0;
    if (!readAll(fd, &success, sizeof(success)) || success > 1) {
      return false;
    }
    std::uint32_t len = 0;
    if (!readAll(fd, &len, sizeof(len))) {
      return false;
    }
    if (len > kMaxPamMessageBytes) {
      return false;
    }
    result.success = success != 0;
    result.message.clear();
    if (len > 0) {
      result.message.resize(len);
      if (!readAll(fd, result.message.data(), len)) {
        return false;
      }
    }
    return true;
  }

  struct [[nodiscard]] PamSequenceResult {
    int rc = PAM_SYSTEM_ERR;
    bool started = false;
    std::string message;
  };

  // pam_start → pam_authenticate → pam_acct_mgmt (→ pam_setcred), shared by the
  // one-shot password helper and the interactive helper.
  PamSequenceResult runPamSequence(
      std::string_view service, const std::string& user, const pam_conv& conv, pam_service::PamSequencePolicy policy
  ) {
    kLog.debug("authenticating user='{}' service='{}'", user, service);

    PamHandle pamh;
    const std::string serviceName(service);
    const int startRc = pam_start(serviceName.c_str(), user.c_str(), &conv, &pamh.h);
    if (startRc != PAM_SUCCESS || pamh.h == nullptr) {
      kLog.error(
          "pam_start failed rc={} ({})", startRc, pamh.h != nullptr ? pam_strerror(pamh.h, startRc) : "no handle"
      );
      return PamSequenceResult{
          .rc = startRc != PAM_SUCCESS ? startRc : PAM_SYSTEM_ERR,
          .started = false,
          .message = i18n::tr("auth.pam.start-failed"),
      };
    }

    int rc = pam_authenticate(pamh.h, 0);
    kLog.debug("pam_authenticate rc={} ({})", rc, pam_strerror(pamh.h, rc));
    if (rc == PAM_SUCCESS) {
      const int acctRc = pam_acct_mgmt(pamh.h, 0);
      kLog.debug("pam_acct_mgmt rc={} ({})", acctRc, pam_strerror(pamh.h, acctRc));
      if (!pam_service::acctResultAccepted(acctRc, policy)) {
        if (acctRc == PAM_AUTHINFO_UNAVAIL) {
          kLog.warn(
              "pam_acct_mgmt for service '{}' could not read account data (PAM_AUTHINFO_UNAVAIL); this service needs "
              "an account stack that works without root",
              service
          );
        }
        rc = acctRc;
      }
    }
    const char* err = pam_strerror(pamh.h, rc);
    const std::string errStr = err != nullptr ? err : i18n::tr("auth.pam.authentication-failed");
    pamh.lastRc = rc;

    if (rc == PAM_SUCCESS && policy.refreshCredentials) {
      // A credential-provider failure must not reject an otherwise valid unlock.
      const int credRc = pam_setcred(pamh.h, PAM_REFRESH_CRED);
      kLog.debug("pam_setcred PAM_REFRESH_CRED rc={} ({})", credRc, pam_strerror(pamh.h, credRc));
      pamh.lastRc = credRc;
      if (credRc != PAM_SUCCESS) {
        kLog.warn("credential refresh failed for user='{}' rc={} ({})", user, credRc, pam_strerror(pamh.h, credRc));
      }
    }

    if (rc == PAM_SUCCESS) {
      kLog.debug("authentication succeeded for user='{}'", user);
      return PamSequenceResult{.rc = rc, .started = true, .message = {}};
    }

    kLog.warn("authentication failed for user='{}' rc={} ({})", user, rc, errStr);
    return PamSequenceResult{.rc = rc, .started = true, .message = errStr};
  }

  PamAuthenticator::Result authenticateDirect(std::string_view password, std::string_view service) {
    std::string user = PamAuthenticator::currentUsername();
    if (user.empty()) {
      return PamAuthenticator::Result{.success = false, .message = i18n::tr("auth.pam.user-unavailable")};
    }

    std::string passwordCopy(password);
    PamConversationData convData{.password = passwordCopy.c_str()};
    const pam_conv conv = {
        .conv = &pamConversation,
        .appdata_ptr = &convData,
    };

    PamSequenceResult result = runPamSequence(service, user, conv, pam_service::kPasswordPolicy);
    secureClear(passwordCopy);
    return PamAuthenticator::Result{.success = result.rc == PAM_SUCCESS, .message = std::move(result.message)};
  }

} // namespace

PamAuthenticator::Result PamAuthenticator::authenticateCurrentUser(
    std::string_view password, std::string_view service, std::string_view language, std::string_view startFailureMessage
) const {
  // Re-exec before invoking PAM so the helper cannot inherit locked library
  // state from the shell's other threads.
  const auto fail = [startFailureMessage] {
    return Result{.success = false, .message = std::string(startFailureMessage)};
  };

  if (password.size() > kMaxPasswordBytes || service.empty() || language.empty()) {
    return fail();
  }

  // Owned, writable argument buffers: execv() takes char* const*.
  std::array<std::string, 4> args = {"noctalia", "pam-helper", std::string(service), std::string(language)};
  std::array<char*, 5> helperArgv = {args[0].data(), args[1].data(), args[2].data(), args[3].data(), nullptr};

  Pipe inPipe;
  Pipe outPipe;
  if (!createPipe(inPipe) || !createPipe(outPipe)) {
    return fail();
  }

  const pid_t pid = ::fork();
  if (pid < 0) {
    return fail();
  }

  if (pid == 0) {
    // Keep this path async-signal-safe until execv(). Every pipe end is CLOEXEC.
    if (::dup2(inPipe.read.get(), STDIN_FILENO) < 0 || ::dup2(outPipe.write.get(), STDOUT_FILENO) < 0) {
      ::_exit(127);
    }
    ::execv("/proc/self/exe", helperArgv.data());
    ::_exit(127);
  }

  inPipe.read.reset();
  outPipe.write.reset();

  const bool sentOk = sendPassword(inPipe.write.get(), password);
  inPipe.write.reset();

  Result result;
  const bool readOk = sentOk && readResult(outPipe.read.get(), result);
  outPipe.read.reset();

  int status = 0;
  pid_t waitResult = -1;
  do {
    waitResult = ::waitpid(pid, &status, 0);
  } while (waitResult < 0 && errno == EINTR);

  const bool exited = waitResult == pid && WIFEXITED(status);
  const int exitCode = exited ? WEXITSTATUS(status) : -1;
  const bool statusOk = readOk && (exitCode == 0 || exitCode == 1) && ((exitCode == 0) == result.success);
  if (!sentOk || !statusOk) {
    kLog.warn(
        "pam helper failed (sent={} read={} waited={} exited={} status={})", sentOk, readOk, waitResult == pid, exited,
        exitCode
    );
    return fail();
  }

  return result;
}

int PamAuthenticator::runHelperMode(int argc, char* argv[]) {
  pam_protocol::hardenHelperProcess();
  // No exception may escape into main(): exit 2 is "helper failed", which the parent
  // treats as an authentication failure.
  try {
    return runHelperModeUnguarded(argc, argv);
  } catch (const std::exception& e) {
    logHelperFailure("pam helper", e.what());
  } catch (...) {
    logHelperFailure("pam helper", "unknown exception");
  }
  return 2;
}

int PamAuthenticator::runInteractiveHelperMode(int argc, char* argv[]) {
  pam_protocol::hardenHelperProcess();
  // Exit 2 without a Result frame: the parent reports PAM_SYSTEM_ERR, never success.
  try {
    return runInteractiveHelperModeUnguarded(argc, argv);
  } catch (const std::exception& e) {
    logHelperFailure("interactive pam helper", e.what());
  } catch (...) {
    logHelperFailure("interactive pam helper", "unknown exception");
  }
  return 2;
}

int PamAuthenticator::runHelperModeUnguarded(int argc, char* argv[]) {
  if (argc != 4 || argv[2][0] == '\0' || argv[3][0] == '\0') {
    return 2;
  }

  const std::string_view service = argv[2];
  const std::string_view language = argv[3];
  i18n::Service::instance().init(language);
  if (i18n::Service::instance().language() != language) {
    return 2;
  }

  std::uint32_t len = 0;
  if (!readAll(STDIN_FILENO, &len, sizeof(len)) || len > kMaxPasswordBytes) {
    return 2;
  }
  std::string password(len, '\0');
  if (len > 0 && !readAll(STDIN_FILENO, password.data(), len)) {
    secureClear(password);
    return 2;
  }

  Result result = authenticateDirect(password, service);
  secureClear(password);

  if (!writeResult(STDOUT_FILENO, result)) {
    return 2;
  }
  return result.success ? 0 : 1;
}

int PamAuthenticator::runInteractiveHelperModeUnguarded(int argc, char* argv[]) {
  if (argc != 4 || argv[2][0] == '\0' || argv[3][0] == '\0') {
    return 2;
  }

  const std::string_view service = argv[2];
  const std::string_view language = argv[3];
  i18n::Service::instance().init(language);
  if (i18n::Service::instance().language() != language) {
    return 2;
  }

  // Each prompt is relayed to the parent, which answers with a reply or an abort.
  pam_protocol::ConversationChannel channel{.inFd = STDIN_FILENO, .outFd = STDOUT_FILENO};
  const pam_conv conv = {
      .conv = &pam_protocol::interactiveConversation,
      .appdata_ptr = &channel,
  };

  PamSequenceResult result;
  const std::string user = currentUsername();
  if (user.empty()) {
    result =
        PamSequenceResult{.rc = PAM_USER_UNKNOWN, .started = false, .message = i18n::tr("auth.pam.user-unavailable")};
  } else {
    // The interactive helper only serves the face lane.
    result = runPamSequence(service, user, conv, pam_service::kFacePolicy);
  }

  const pam_protocol::Frame frame{
      .type = pam_protocol::FrameType::Result,
      .rc = result.rc,
      .started = result.started,
      .text = result.message,
  };
  if (!pam_protocol::writeFrame(STDOUT_FILENO, frame)) {
    return 2;
  }
  return result.rc == PAM_SUCCESS ? 0 : 1;
}

std::string PamAuthenticator::currentUsername() {
  const uid_t uid = getuid();
  passwd pwd{};
  passwd* result = nullptr;
  std::vector<char> buf(4096);

  while (true) {
    const int rc = getpwuid_r(uid, &pwd, buf.data(), buf.size(), &result);
    if (rc == 0 && result != nullptr) {
      return std::string(result->pw_name != nullptr ? result->pw_name : "");
    }
    if (rc != ERANGE) {
      return {};
    }
    buf.resize(buf.size() * 2);
    if (buf.size() > 1 << 20) {
      return {};
    }
  }
}
