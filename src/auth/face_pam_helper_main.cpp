// noctalia-face-pam-helper: runs the face unlock PAM conversation (pam_gaze in
// the noctalia-face service) for the lock screen.
//
// It needs no privileges and must not be given any: the face stack talks to a
// daemon and must never run with the rights a distribution may grant to
// noctalia-pam-helper. It takes no arguments, only authenticates the invoking
// user, and relays every PAM message and prompt to the shell over stdin and
// stdout (auth/face_helper_protocol.h).

#include "auth/face_helper_protocol.h"
#include "auth/pam_service.h"

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <pwd.h>
#include <security/pam_appl.h>
#include <string>
#include <unistd.h>
#include <vector>

namespace {

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

  // Called from libpam (C), then pam_gaze (Rust): unwinding into them is undefined behavior.
  static_assert(noexcept(face_helper::interactiveConversation(0, nullptr, nullptr, nullptr)));

  [[nodiscard]] std::string currentUsername() {
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

  struct [[nodiscard]] Outcome {
    int rc = PAM_SYSTEM_ERR;
    // False when the session never reached pam_authenticate.
    bool started = false;
  };

  Outcome authenticate(const pam_conv& conv) {
    const std::string user = currentUsername();
    if (user.empty()) {
      return Outcome{.rc = PAM_USER_UNKNOWN, .started = false};
    }

    const std::string service(pam_service::kFace);
    PamHandle pamh;
    const int startRc = pam_start(service.c_str(), user.c_str(), &conv, &pamh.h);
    if (startRc != PAM_SUCCESS || pamh.h == nullptr) {
      return Outcome{.rc = startRc != PAM_SUCCESS ? startRc : PAM_SYSTEM_ERR, .started = false};
    }

    int rc = pam_authenticate(pamh.h, 0);
    if (rc == PAM_SUCCESS) {
      // Face is a passive factor, so the account check fails closed: any result
      // but PAM_SUCCESS, PAM_AUTHINFO_UNAVAIL and PAM_CRED_INSUFFICIENT included,
      // rejects. The face stack carries no credential modules, so there is no
      // pam_setcred.
      const int acctRc = pam_acct_mgmt(pamh.h, 0);
      if (acctRc != PAM_SUCCESS) {
        rc = acctRc;
      }
    }
    pamh.lastRc = rc;
    return Outcome{.rc = rc, .started = true};
  }

  int run(int argc) {
    if (argc != 1) {
      return face_helper::kExitProtocolError;
    }
    if (!face_helper::exchangeVersions(STDIN_FILENO, STDOUT_FILENO)) {
      return face_helper::kExitProtocolError;
    }

    // Each prompt is relayed to the shell, which answers with a Reply or an Abort.
    face_helper::ConversationChannel channel{.inFd = STDIN_FILENO, .outFd = STDOUT_FILENO};
    const pam_conv conv = {
        .conv = &face_helper::interactiveConversation,
        .appdata_ptr = &channel,
    };
    const Outcome outcome = authenticate(conv);

    const face_helper::Frame frame{
        .type = face_helper::FrameType::Result,
        .rc = outcome.rc,
        .started = outcome.started,
        .text = {},
    };
    if (!face_helper::writeFrame(STDOUT_FILENO, frame)) {
      return face_helper::kExitProtocolError;
    }
    return outcome.rc == PAM_SUCCESS ? face_helper::kExitSuccess : face_helper::kExitFailure;
  }

  void reportFailure(const char* what) noexcept {
    (void)std::fprintf(stderr, "noctalia-face-pam-helper failed: %s\n", what);
  }

} // namespace

int main(int argc, char* /*argv*/[]) {
  face_helper::hardenHelperProcess();
  // No exception may escape main(): exit 2 without a Result frame is "helper failed",
  // which the shell treats as unavailable, never as a rejection or a success.
  try {
    return run(argc);
  } catch (const std::exception& e) {
    reportFailure(e.what());
  } catch (...) {
    reportFailure("unknown exception");
  }
  return face_helper::kExitProtocolError;
}
