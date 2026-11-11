#include "auth/interactive_pam_session.h"
#include "auth/pam_helper_protocol.h"
#include "core/deferred_call.h"
#include "tests/test_check.h"

#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <functional>
#include <optional>
#include <poll.h>
#include <security/pam_appl.h>
#include <string>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace {

  using pam_protocol::Frame;
  using pam_protocol::FrameDecoder;
  using pam_protocol::FrameType;

  std::string u32le(std::uint32_t value) {
    std::string out;
    for (int i = 0; i < 4; ++i) {
      out.push_back(static_cast<char>((value >> (8 * i)) & 0xFFU));
    }
    return out;
  }

  Frame roundTrip(const Frame& frame) {
    FrameDecoder decoder;
    decoder.feed(pam_protocol::encodeFrame(frame));
    auto decoded = decoder.next();
    TEST_CHECK(decoded.has_value());
    TEST_CHECK(!decoder.failed());
    TEST_CHECK(!decoder.next().has_value());
    return *decoded;
  }

  bool rejects(const std::string& bytes) {
    FrameDecoder decoder;
    decoder.feed(bytes);
    const auto frame = decoder.next();
    return !frame.has_value() && decoder.failed();
  }

  void testFraming() {
    const Frame message = roundTrip(Frame{.type = FrameType::Message, .style = PAM_TEXT_INFO, .text = "hello"});
    TEST_CHECK(message.type == FrameType::Message);
    TEST_CHECK(message.style == PAM_TEXT_INFO);
    TEST_CHECK(message.text == "hello");

    const Frame error = roundTrip(Frame{.type = FrameType::Message, .style = PAM_ERROR_MSG, .text = ""});
    TEST_CHECK(error.style == PAM_ERROR_MSG);
    TEST_CHECK(error.text.empty());

    const Frame prompt = roundTrip(Frame{.type = FrameType::Prompt, .style = PAM_PROMPT_ECHO_ON, .text = "confirm?"});
    TEST_CHECK(prompt.type == FrameType::Prompt);
    TEST_CHECK(prompt.style == PAM_PROMPT_ECHO_ON);
    TEST_CHECK(prompt.text == "confirm?");

    const Frame result =
        roundTrip(Frame{.type = FrameType::Result, .rc = PAM_AUTH_ERR, .started = true, .text = "nope"});
    TEST_CHECK(result.type == FrameType::Result);
    TEST_CHECK(result.rc == PAM_AUTH_ERR);
    TEST_CHECK(result.started);
    TEST_CHECK(result.text == "nope");

    const Frame negative = roundTrip(Frame{.type = FrameType::Result, .rc = -7, .started = false});
    TEST_CHECK(negative.rc == -7);
    TEST_CHECK(!negative.started);

    TEST_CHECK(roundTrip(Frame{.type = FrameType::Reply, .text = "yes"}).text == "yes");
    TEST_CHECK(roundTrip(Frame{.type = FrameType::Abort}).type == FrameType::Abort);

    // Little-endian length prefix that counts the body only.
    const std::string encoded = pam_protocol::encodeFrame(Frame{.type = FrameType::Reply, .text = "ab"});
    TEST_CHECK(
        encoded
        == u32le(3)
            + std::string(
                "\x04"
                "ab"
            )
    );

    // Oversized text is truncated to the limit rather than rejected.
    const Frame truncated =
        roundTrip(Frame{.type = FrameType::Message, .style = PAM_TEXT_INFO, .text = std::string(5000, 'x')});
    TEST_CHECK(truncated.text.size() == pam_protocol::kMaxTextBytes);

    // Byte-at-a-time delivery and several frames in one buffer.
    const std::string stream =
        pam_protocol::encodeFrame(Frame{.type = FrameType::Message, .style = PAM_TEXT_INFO, .text = "a"})
        + pam_protocol::encodeFrame(Frame{.type = FrameType::Result, .rc = 0, .started = true});
    FrameDecoder decoder;
    std::vector<Frame> frames;
    for (char c : stream) {
      decoder.feed(std::string_view(&c, 1));
      while (auto frame = decoder.next()) {
        frames.push_back(*frame);
      }
    }
    TEST_CHECK(frames.size() == 2);
    TEST_CHECK(frames[0].text == "a");
    TEST_CHECK(frames[1].type == FrameType::Result);

    // Malformed frames.
    TEST_CHECK(rejects(u32le(0)));
    TEST_CHECK(rejects(u32le(1 << 20)));
    TEST_CHECK(rejects(u32le(1) + "\x09"));                                     // unknown type
    TEST_CHECK(rejects(u32le(2) + std::string("\x01\x01")));                    // message with a prompt style
    TEST_CHECK(rejects(u32le(2) + std::string("\x02\x04")));                    // prompt with a message style
    TEST_CHECK(rejects(u32le(1) + "\x01"));                                     // message without style
    TEST_CHECK(rejects(u32le(2) + std::string("\x05x")));                       // abort with payload
    TEST_CHECK(rejects(u32le(3) + std::string("\x03\x00\x00", 3)));             // short result
    TEST_CHECK(rejects(u32le(6) + std::string("\x03\x00\x00\x00\x00\x02", 6))); // started > 1
    TEST_CHECK(rejects(u32le(5000 + 6) + std::string(5006, '\x04')));
    // The largest valid body passes; one byte more is rejected.
    TEST_CHECK(pam_protocol::kMaxBodyBytes == 1 + 4 + 1 + pam_protocol::kMaxTextBytes);
    {
      FrameDecoder largest;
      largest.feed(
          u32le(static_cast<std::uint32_t>(pam_protocol::kMaxBodyBytes))
          + std::string("\x03\x00\x00\x00\x00\x01", 6)
          + std::string(pam_protocol::kMaxTextBytes, 'r')
      );
      const auto frame = largest.next();
      TEST_CHECK(frame.has_value());
      TEST_CHECK(frame->type == FrameType::Result);
      TEST_CHECK(frame->started);
    }
    TEST_CHECK(rejects(u32le(static_cast<std::uint32_t>(pam_protocol::kMaxBodyBytes + 1))));

    // A failed decoder stays failed even if valid bytes follow.
    FrameDecoder broken;
    broken.feed(u32le(0));
    TEST_CHECK(!broken.next().has_value());
    broken.feed(pam_protocol::encodeFrame(Frame{.type = FrameType::Abort}));
    TEST_CHECK(!broken.next().has_value());
    TEST_CHECK(broken.failed());

    // An incomplete frame is not a failure.
    FrameDecoder partial;
    partial.feed(u32le(4));
    TEST_CHECK(!partial.next().has_value());
    TEST_CHECK(!partial.failed());
  }

  struct ConversationRun {
    int rc = PAM_SUCCESS;
    std::vector<std::string> responses;
    std::vector<Frame> seen;
  };

  // Runs the helper's conversation function against a scripted parent on the other
  // end of a socket. `answer` decides the parent's frame for each prompt (nullopt closes the socket).
  ConversationRun runConversation(
      const std::vector<std::pair<int, std::string>>& messages,
      const std::function<std::optional<Frame>(const Frame&)>& answer
  ) {
    int sockets[2] = {-1, -1};
    TEST_CHECK(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == 0);

    ConversationRun run;
    std::thread parent([&] {
      while (true) {
        auto frame = pam_protocol::readFrame(sockets[1]);
        if (!frame.has_value()) {
          break;
        }
        run.seen.push_back(*frame);
        if (frame->type == FrameType::Prompt) {
          const auto reply = answer(*frame);
          if (!reply.has_value()) {
            ::shutdown(sockets[1], SHUT_RDWR);
            break;
          }
          TEST_CHECK(pam_protocol::writeFrame(sockets[1], *reply));
        }
      }
    });

    std::vector<pam_message> storage(messages.size());
    std::vector<const pam_message*> pointers;
    for (std::size_t i = 0; i < messages.size(); ++i) {
      storage[i].msg_style = messages[i].first;
      storage[i].msg = messages[i].second.c_str();
      pointers.push_back(&storage[i]);
    }
    pam_protocol::ConversationChannel channel{.inFd = sockets[0], .outFd = sockets[0]};
    pam_response* responses = nullptr;
    run.rc =
        pam_protocol::interactiveConversation(static_cast<int>(pointers.size()), pointers.data(), &responses, &channel);
    if (run.rc == PAM_SUCCESS) {
      for (std::size_t i = 0; i < messages.size(); ++i) {
        run.responses.emplace_back(responses[i].resp != nullptr ? responses[i].resp : "<null>");
        std::free(responses[i].resp);
      }
      std::free(responses);
    } else {
      TEST_CHECK(responses == nullptr);
    }
    ::shutdown(sockets[0], SHUT_RDWR);
    parent.join();
    ::close(sockets[0]);
    ::close(sockets[1]);
    return run;
  }

  // Called from libpam: no exception may unwind out of it.
  static_assert(noexcept(pam_protocol::interactiveConversation(0, nullptr, nullptr, nullptr)));

  void testConversation() {
    const auto reply = [](const std::string& text) {
      return [text](const Frame&) { return std::optional<Frame>(Frame{.type = FrameType::Reply, .text = text}); };
    };

    // Info and error messages are forwarded without waiting; prompts wait for the reply.
    auto ok = runConversation(
        {{PAM_TEXT_INFO, "look"}, {PAM_ERROR_MSG, "oops"}, {PAM_PROMPT_ECHO_ON, "confirm"}}, reply("yes")
    );
    TEST_CHECK(ok.rc == PAM_SUCCESS);
    TEST_CHECK(ok.seen.size() == 3);
    TEST_CHECK(ok.seen[0].type == FrameType::Message);
    TEST_CHECK(ok.seen[0].style == PAM_TEXT_INFO);
    TEST_CHECK(ok.seen[0].text == "look");
    TEST_CHECK(ok.seen[1].type == FrameType::Message);
    TEST_CHECK(ok.seen[1].style == PAM_ERROR_MSG);
    TEST_CHECK(ok.seen[2].type == FrameType::Prompt);
    TEST_CHECK(ok.seen[2].style == PAM_PROMPT_ECHO_ON);
    TEST_CHECK(ok.responses.size() == 3);
    TEST_CHECK(ok.responses[0] == "<null>");
    TEST_CHECK(ok.responses[2] == "yes");

    // ABORT fails the conversation.
    auto aborted = runConversation({{PAM_PROMPT_ECHO_OFF, "Password:"}}, [](const Frame&) {
      return std::optional<Frame>(Frame{.type = FrameType::Abort});
    });
    TEST_CHECK(aborted.rc == PAM_CONV_ERR);

    // A parent that goes away fails the conversation.
    auto closed = runConversation({{PAM_PROMPT_ECHO_ON, "x"}}, [](const Frame&) { return std::optional<Frame>{}; });
    TEST_CHECK(closed.rc == PAM_CONV_ERR);

    // Unknown styles fail without contacting the parent.
    auto unknown = runConversation({{99, "binary"}}, reply("x"));
    TEST_CHECK(unknown.rc == PAM_CONV_ERR);
    TEST_CHECK(unknown.seen.empty());

    // An oversized message is truncated on the wire; a bad style after it still fails
    // the conversation cleanly instead of terminating.
    auto oversized = runConversation({{PAM_TEXT_INFO, std::string(10000, 'x')}, {99, "binary"}}, reply("x"));
    TEST_CHECK(oversized.rc == PAM_CONV_ERR);
    TEST_CHECK(oversized.seen.size() == 1);
    TEST_CHECK(oversized.seen[0].text.size() == pam_protocol::kMaxTextBytes);

    // A prompt answered, then a bad style: the earlier answer is freed, nothing is returned.
    auto partial = runConversation({{PAM_PROMPT_ECHO_ON, "confirm"}, {99, "binary"}}, reply("yes"));
    TEST_CHECK(partial.rc == PAM_CONV_ERR);
    TEST_CHECK(partial.seen.size() == 1);
  }

  // ---- End-to-end through a re-executed helper (this binary in fake-helper mode) ----

  // Emulates `pam-helper-interactive` without PAM: the "service" names a script.
  int runFakeHelper(const std::string& script) {
    pam_protocol::ConversationChannel channel{.inFd = STDIN_FILENO, .outFd = STDOUT_FILENO};
    const auto ask = [&](int style, const char* text) {
      pam_message message{.msg_style = style, .msg = text};
      const pam_message* messages[] = {&message};
      pam_response* responses = nullptr;
      const int rc = pam_protocol::interactiveConversation(1, messages, &responses, &channel);
      std::string answer;
      if (rc == PAM_SUCCESS) {
        answer = responses[0].resp != nullptr ? responses[0].resp : "";
        std::free(responses[0].resp);
        std::free(responses);
      }
      return std::pair{rc, answer};
    };
    const auto finish = [](int rc, bool started) {
      (void)pam_protocol::writeFrame(STDOUT_FILENO, Frame{.type = FrameType::Result, .rc = rc, .started = started});
      return rc == PAM_SUCCESS ? 0 : 1;
    };

    if (script == "confirm") {
      (void)ask(PAM_TEXT_INFO, "GAZE_MSG_LOOK_CAMERA");
      const auto [rc, answer] = ask(PAM_PROMPT_ECHO_ON, "GAZE_REQUIRE_CONFIRMATION");
      return finish(rc == PAM_SUCCESS && answer == "GAZE_CONFIRMED" ? PAM_SUCCESS : PAM_AUTH_ERR, true);
    }
    if (script == "abort") {
      const auto [rc, answer] = ask(PAM_PROMPT_ECHO_OFF, "Password:");
      return finish(rc == PAM_CONV_ERR ? PAM_AUTH_ERR : PAM_SUCCESS, true);
    }
    if (script == "start-failed") {
      return finish(PAM_ABORT, false);
    }
    if (script == "lying") {
      (void)finish(PAM_SUCCESS, true);
      return 1;
    }
    if (script == "garbage") {
      const std::string junk = u32le(3) + "\x09xy";
      (void)::write(STDOUT_FILENO, junk.data(), junk.size());
      ::pause();
      return 2;
    }
    if (script == "eof-no-result") {
      // Closes the channel without a Result and lingers: must fail, and soon.
      (void)ask(PAM_TEXT_INFO, "scanning");
      (void)::close(STDOUT_FILENO);
      (void)::close(STDIN_FILENO);
      ::sleep(10);
      return 0;
    }
    if (script == "success-then-sigkill") {
      (void)finish(PAM_SUCCESS, true);
      ::raise(SIGKILL);
      return 0;
    }
    if (script == "send-reply") {
      // Protocol inversion: only the parent may send replies.
      (void)pam_protocol::writeFrame(STDOUT_FILENO, Frame{.type = FrameType::Reply, .text = "yes"});
      ::pause();
      return 0;
    }
    if (script == "double-result") {
      // Only the first Result counts; this one matches the exit status.
      (void)pam_protocol::writeFrame(
          STDOUT_FILENO, Frame{.type = FrameType::Result, .rc = PAM_AUTH_ERR, .started = true}
      );
      (void)pam_protocol::writeFrame(
          STDOUT_FILENO, Frame{.type = FrameType::Result, .rc = PAM_SUCCESS, .started = true}
      );
      return 1;
    }
    if (script == "oversize-len") {
      const std::string junk = u32le(static_cast<std::uint32_t>(pam_protocol::kMaxBodyBytes + 1)) + "\x01\x04";
      (void)::write(STDOUT_FILENO, junk.data(), junk.size());
      ::pause();
      return 2;
    }
    if (script == "result-then-linger" || script == "exit-no-eof") {
      // A grandchild keeps the socket open after the helper exits.
      if (script == "result-then-linger") {
        (void)finish(PAM_SUCCESS, true);
      }
      // It lingers far longer than any bound the tests allow the reader. Only the socket
      // matters; stderr goes, so the test runner doesn't wait for it.
      if (::fork() == 0) {
        const int devNull = ::open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (devNull >= 0) {
          (void)::dup2(devNull, STDERR_FILENO);
        }
        ::sleep(10);
        ::_exit(0);
      }
      return script == "result-then-linger" ? 0 : 1;
    }
    if (script == "inspect") {
      // Reports what the helper inherited: session leadership, a controlling terminal,
      // open fds (beyond the one listing them) and the dumpable flag.
      const bool sessionLeader = ::getsid(0) == ::getpid();
      const int tty = ::open("/dev/tty", O_RDWR | O_CLOEXEC);
      const bool hasTty = tty >= 0;
      if (hasTty) {
        (void)::close(tty);
      }
      std::string fds;
      if (DIR* dir = ::opendir("/proc/self/fd")) {
        while (const dirent* entry = ::readdir(dir)) {
          const std::string name = entry->d_name;
          if (name == "." || name == ".." || name == std::to_string(::dirfd(dir))) {
            continue;
          }
          fds += fds.empty() ? name : "," + name;
        }
        ::closedir(dir);
      }
      const std::string report = std::string("leader=")
          + (sessionLeader ? "1" : "0")
          + " tty="
          + (hasTty ? "1" : "0")
          + " fds="
          + fds
          + " dumpable="
          + std::to_string(::prctl(PR_GET_DUMPABLE));
      (void)ask(PAM_TEXT_INFO, report.c_str());
      return finish(PAM_SUCCESS, true);
    }
    if (script == "report-pid") {
      (void)ask(PAM_TEXT_INFO, std::to_string(::getpid()).c_str());
      while (true) {
        ::pause();
      }
    }
    if (script == "hang") {
      // Ignore SIGTERM so cancel() has to escalate to SIGKILL.
      std::signal(SIGTERM, SIG_IGN);
      (void)ask(PAM_TEXT_INFO, "scanning");
      while (true) {
        ::pause();
      }
    }
    return 2;
  }

  bool pumpUntil(const std::function<bool()>& done, std::chrono::milliseconds timeout = std::chrono::seconds(5)) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
      for (auto& fn : DeferredCall::takePending()) {
        fn();
      }
      if (done()) {
        return true;
      }
      pollfd fd{.fd = DeferredCall::wakeFd(), .events = POLLIN, .revents = 0};
      (void)::poll(&fd, 1, 20);
      DeferredCall::drainWakeFd();
    }
    return done();
  }

  struct Recorder {
    std::vector<std::pair<std::string, bool>> messages;
    std::vector<std::pair<std::string, bool>> prompts;
    std::optional<InteractivePamSession::Finished> finished;

    void attach(InteractivePamSession& session) {
      session.setMessageCallback([this](const std::string& text, bool isError) {
        messages.emplace_back(text, isError);
      });
      session.setPromptCallback([this](const std::string& text, bool echo) { prompts.emplace_back(text, echo); });
      session.setFinishedCallback([this](const InteractivePamSession::Finished& result) { finished = result; });
    }
  };

  void testSessionConfirm() {
    InteractivePamSession session;
    Recorder recorder;
    recorder.attach(session);
    TEST_CHECK(session.start("confirm", "en"));
    TEST_CHECK(session.running());
    TEST_CHECK(pumpUntil([&] { return !recorder.prompts.empty(); }));
    TEST_CHECK(recorder.messages.size() == 1);
    TEST_CHECK(recorder.messages[0].first == "GAZE_MSG_LOOK_CAMERA");
    TEST_CHECK(!recorder.messages[0].second);
    TEST_CHECK(recorder.prompts[0].first == "GAZE_REQUIRE_CONFIRMATION");
    TEST_CHECK(recorder.prompts[0].second);
    TEST_CHECK(session.promptPending());
    TEST_CHECK(session.respond("GAZE_CONFIRMED"));
    TEST_CHECK(!session.respond("again")); // only one answer per prompt
    TEST_CHECK(pumpUntil([&] { return recorder.finished.has_value(); }));
    TEST_CHECK(recorder.finished->rc == PAM_SUCCESS);
    TEST_CHECK(recorder.finished->started);
    TEST_CHECK(!recorder.finished->infrastructureFailure);
    TEST_CHECK(!session.running());
  }

  void testSessionAbort() {
    InteractivePamSession session;
    Recorder recorder;
    recorder.attach(session);
    TEST_CHECK(session.start("abort", "en"));
    TEST_CHECK(pumpUntil([&] { return !recorder.prompts.empty(); }));
    TEST_CHECK(!recorder.prompts[0].second);
    TEST_CHECK(session.abort());
    TEST_CHECK(pumpUntil([&] { return recorder.finished.has_value(); }));
    TEST_CHECK(recorder.finished->rc == PAM_AUTH_ERR);
  }

  void testSessionStartFailedAndLyingHelper() {
    InteractivePamSession session;
    Recorder recorder;
    recorder.attach(session);
    TEST_CHECK(session.start("start-failed", "en"));
    TEST_CHECK(pumpUntil([&] { return recorder.finished.has_value(); }));
    TEST_CHECK(recorder.finished->rc == PAM_ABORT);
    TEST_CHECK(!recorder.finished->started);
    // pam_start failing is PAM's own answer, reported in a valid Result.
    TEST_CHECK(!recorder.finished->infrastructureFailure);

    // A success frame contradicted by the exit status is never a success, and not a
    // PAM decision either.
    recorder.finished.reset();
    TEST_CHECK(session.start("lying", "en"));
    TEST_CHECK(pumpUntil([&] { return recorder.finished.has_value(); }));
    TEST_CHECK(recorder.finished->rc != PAM_SUCCESS);
    TEST_CHECK(recorder.finished->infrastructureFailure);
  }

  void testSessionGarbage() {
    InteractivePamSession session;
    Recorder recorder;
    recorder.attach(session);
    TEST_CHECK(session.start("garbage", "en"));
    TEST_CHECK(pumpUntil([&] { return recorder.finished.has_value(); }));
    TEST_CHECK(recorder.finished->rc != PAM_SUCCESS);
    TEST_CHECK(recorder.finished->infrastructureFailure);
    TEST_CHECK(recorder.messages.empty());
  }

  void testSessionCancelBeforeFinish() {
    InteractivePamSession session;
    Recorder recorder;
    recorder.attach(session);
    TEST_CHECK(session.start("hang", "en"));
    TEST_CHECK(pumpUntil([&] { return !recorder.messages.empty(); }));
    session.cancel();
    TEST_CHECK(!session.running());
    TEST_CHECK(!session.respond("x"));
    // The helper ignores SIGTERM; the reader escalates and reaps without reporting anything.
    (void)pumpUntil([] { return false; }, std::chrono::milliseconds(1000));
    TEST_CHECK(!recorder.finished.has_value());
    TEST_CHECK(recorder.messages.size() == 1);

    // Restarting drops callbacks from the previous helper.
    TEST_CHECK(session.start("hang", "en"));
    TEST_CHECK(session.start("confirm", "en"));
    TEST_CHECK(pumpUntil([&] { return !recorder.prompts.empty(); }));
    TEST_CHECK(recorder.messages.back().first == "GAZE_MSG_LOOK_CAMERA");
    TEST_CHECK(session.respond("no"));
    TEST_CHECK(pumpUntil([&] { return recorder.finished.has_value(); }));
    TEST_CHECK(recorder.finished->rc == PAM_AUTH_ERR);
  }

  void testSessionDestroyedWhileRunning() {
    Recorder recorder;
    {
      InteractivePamSession session;
      recorder.attach(session);
      TEST_CHECK(session.start("hang", "en"));
      TEST_CHECK(pumpUntil([&] { return !recorder.messages.empty(); }));
    }
    // The reader is bounded after a cancel (SIGTERM is ignored, so it escalates), and
    // teardown can join it.
    const auto joinStart = std::chrono::steady_clock::now();
    InteractivePamSession::joinAllReaders();
    TEST_CHECK(std::chrono::steady_clock::now() - joinStart < std::chrono::seconds(2));
    // Posts queued before destruction must be dropped safely.
    (void)pumpUntil([] { return false; }, std::chrono::milliseconds(200));
    TEST_CHECK(!recorder.finished.has_value());
  }

  // Runs `script` to completion and returns how it finished, within `limit`.
  std::optional<InteractivePamSession::Finished>
  runToFinish(const std::string& script, Recorder& recorder, std::chrono::milliseconds limit) {
    InteractivePamSession session;
    recorder.attach(session);
    TEST_CHECK(session.start(script, "en"));
    (void)pumpUntil([&] { return recorder.finished.has_value(); }, limit);
    return recorder.finished;
  }

  void testSessionAdversarialHelpers() {
    using namespace std::chrono_literals;
    // Room for a slow (sanitized, loaded) helper start on top of the reader's own bounds.
    constexpr auto kBound = InteractivePamSession::kExitGrace + InteractivePamSession::kKillWait + 3s;
    {
      // EOF without a Result fails within the exit grace, though the helper lingers.
      Recorder recorder;
      const auto finished = runToFinish("eof-no-result", recorder, kBound);
      TEST_CHECK(finished.has_value());
      TEST_CHECK(finished->rc != PAM_SUCCESS);
      TEST_CHECK(finished->infrastructureFailure);
    }
    {
      // A success Result followed by a signal death is not a success.
      Recorder recorder;
      const auto finished = runToFinish("success-then-sigkill", recorder, kBound);
      TEST_CHECK(finished.has_value());
      TEST_CHECK(finished->rc != PAM_SUCCESS);
      TEST_CHECK(finished->infrastructureFailure);
    }
    {
      // A Reply from the helper is a protocol error.
      Recorder recorder;
      const auto finished = runToFinish("send-reply", recorder, kBound);
      TEST_CHECK(finished.has_value());
      TEST_CHECK(finished->rc != PAM_SUCCESS);
      TEST_CHECK(finished->infrastructureFailure);
      TEST_CHECK(recorder.messages.empty());
    }
    {
      // Only the first Result counts.
      Recorder recorder;
      const auto finished = runToFinish("double-result", recorder, kBound);
      TEST_CHECK(finished.has_value());
      TEST_CHECK(finished->rc == PAM_AUTH_ERR);
      TEST_CHECK(!finished->infrastructureFailure);
    }
    {
      // A length one past the maximum body fails the session.
      Recorder recorder;
      const auto finished = runToFinish("oversize-len", recorder, kBound);
      TEST_CHECK(finished.has_value());
      TEST_CHECK(finished->rc != PAM_SUCCESS);
      TEST_CHECK(finished->infrastructureFailure);
    }
    {
      // A grandchild holding the socket can't stall the reader once the helper exits.
      // The bound stays well under the grandchild's 10 s, which a stalled reader would wait for.
      Recorder recorder;
      const auto started = std::chrono::steady_clock::now();
      const auto finished = runToFinish("result-then-linger", recorder, kBound);
      TEST_CHECK(finished.has_value());
      TEST_CHECK(finished->rc == PAM_SUCCESS);
      TEST_CHECK(std::chrono::steady_clock::now() - started < kBound);
    }
    {
      Recorder recorder;
      const auto finished = runToFinish("exit-no-eof", recorder, kBound);
      TEST_CHECK(finished.has_value());
      TEST_CHECK(finished->rc != PAM_SUCCESS);
      TEST_CHECK(finished->infrastructureFailure);
    }
    InteractivePamSession::joinAllReaders();
  }

  void testSessionStaleGeneration() {
    // Nothing else may post while this test holds the queue.
    InteractivePamSession::joinAllReaders();
    (void)pumpUntil([] { return false; }, std::chrono::milliseconds(50));
    InteractivePamSession session;
    Recorder recorder;
    recorder.attach(session);
    TEST_CHECK(session.start("confirm", "en"));
    // Collect the first helper's message and prompt posts without running them, however
    // long the helper takes to start.
    std::vector<std::function<void()>> stale;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (stale.size() < 2 && std::chrono::steady_clock::now() < deadline) {
      pollfd fd{.fd = DeferredCall::wakeFd(), .events = POLLIN, .revents = 0};
      (void)::poll(&fd, 1, 20);
      DeferredCall::drainWakeFd();
      for (auto& fn : DeferredCall::takePending()) {
        stale.push_back(std::move(fn));
      }
    }
    TEST_CHECK(stale.size() == 2);
    TEST_CHECK(session.start("start-failed", "en"));
    // Delivered after the restart, they belong to an old generation and must be dropped.
    for (auto& fn : stale) {
      fn();
    }
    TEST_CHECK(pumpUntil([&] { return recorder.finished.has_value(); }));
    TEST_CHECK(recorder.messages.empty());
    TEST_CHECK(recorder.prompts.empty());
    TEST_CHECK(!session.promptPending());
    TEST_CHECK(recorder.finished->rc == PAM_ABORT);
  }

  int countOpenFds() {
    int count = 0;
    if (DIR* dir = ::opendir("/proc/self/fd")) {
      while (const dirent* entry = ::readdir(dir)) {
        if (entry->d_name[0] != '.') {
          ++count;
        }
      }
      ::closedir(dir);
    }
    return count;
  }

  void testSessionReaderStartFailure() {
    InteractivePamSession::joinAllReaders();
    const int fdsBefore = countOpenFds();
    InteractivePamSession session;
    InteractivePamSession::failNextReaderStartForTesting();
    TEST_CHECK(!session.start("hang", "en"));
    TEST_CHECK(!session.running());
    TEST_CHECK(countOpenFds() == fdsBefore);
    // The helper was killed and reaped: this process has no children left.
    errno = 0;
    TEST_CHECK(::waitpid(-1, nullptr, WNOHANG) < 0);
    TEST_CHECK(errno == ECHILD);
    // The hook is one-shot.
    TEST_CHECK(session.start("start-failed", "en"));
    session.cancel();
    InteractivePamSession::joinAllReaders();
  }

  void testSessionReaderThrows() {
    InteractivePamSession::joinAllReaders();
    const int fdsBefore = countOpenFds();
    {
      InteractivePamSession session;
      Recorder recorder;
      recorder.attach(session);
      InteractivePamSession::throwInNextReaderForTesting();
      // "hang" ignores SIGTERM and never finishes by itself.
      TEST_CHECK(session.start("hang", "en"));
      const auto started = std::chrono::steady_clock::now();
      TEST_CHECK(pumpUntil([&] { return recorder.finished.has_value(); }));
      TEST_CHECK(std::chrono::steady_clock::now() - started < std::chrono::seconds(3));
      TEST_CHECK(recorder.finished->rc == PAM_SYSTEM_ERR);
      TEST_CHECK(recorder.finished->infrastructureFailure);
      TEST_CHECK(!session.running());
    }
    InteractivePamSession::joinAllReaders();
    // The helper was killed and reaped, and every descriptor closed.
    errno = 0;
    TEST_CHECK(::waitpid(-1, nullptr, WNOHANG) < 0);
    TEST_CHECK(errno == ECHILD);
    TEST_CHECK(countOpenFds() == fdsBefore);
  }

  void testHelperProcessHardening() {
    // A descriptor leaked without CLOEXEC must not reach the helper.
    const int leaked = ::open("/dev/null", O_RDONLY);
    TEST_CHECK(leaked > STDERR_FILENO);
    Recorder recorder;
    const auto finished = runToFinish("inspect", recorder, std::chrono::seconds(3));
    (void)::close(leaked);
    TEST_CHECK(finished.has_value());
    TEST_CHECK(recorder.messages.size() == 1);
    TEST_CHECK(recorder.messages[0].first == "leader=1 tty=0 fds=0,1,2 dumpable=0");
    InteractivePamSession::joinAllReaders();
  }

  // /proc state of `pid`: true while it runs (a zombie counts as gone).
  bool processAlive(pid_t pid) {
    std::ifstream stat("/proc/" + std::to_string(pid) + "/stat");
    std::string line;
    if (!std::getline(stat, line)) {
      return false;
    }
    const auto close = line.rfind(')');
    return close != std::string::npos && close + 2 < line.size() && line[close + 2] != 'Z';
  }

  void testHelperDiesWithParent() {
    int pipeFds[2] = {-1, -1};
    TEST_CHECK(::pipe2(pipeFds, O_CLOEXEC) == 0);
    const pid_t middle = ::fork();
    TEST_CHECK(middle >= 0);
    if (middle == 0) {
      (void)::close(pipeFds[0]);
      InteractivePamSession session;
      Recorder recorder;
      recorder.attach(session);
      if (!session.start("report-pid", "en") || !pumpUntil([&] { return !recorder.messages.empty(); })) {
        ::_exit(3);
      }
      const auto helper = static_cast<pid_t>(std::strtol(recorder.messages[0].first.c_str(), nullptr, 10));
      (void)::write(pipeFds[1], &helper, sizeof(helper));
      // Exit without any cleanup: only PR_SET_PDEATHSIG can end the helper now.
      ::_exit(0);
    }
    (void)::close(pipeFds[1]);
    pid_t helper = -1;
    TEST_CHECK(::read(pipeFds[0], &helper, sizeof(helper)) == static_cast<ssize_t>(sizeof(helper)));
    (void)::close(pipeFds[0]);
    int status = 0;
    TEST_CHECK(::waitpid(middle, &status, 0) == middle);
    TEST_CHECK(WIFEXITED(status));
    TEST_CHECK(WEXITSTATUS(status) == 0);
    TEST_CHECK(helper > 0);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (processAlive(helper) && std::chrono::steady_clock::now() < deadline) {
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    const bool survived = processAlive(helper);
    if (survived) {
      (void)::kill(helper, SIGKILL);
    }
    TEST_CHECK(!survived);
  }

} // namespace

int main(int argc, char* argv[]) {
  if (argc == 4 && std::strcmp(argv[1], "pam-helper-interactive") == 0) {
    // Same first step as the real helper entry points.
    pam_protocol::hardenHelperProcess();
    return runFakeHelper(argv[2]);
  }

  testFraming();
  testConversation();
  testSessionConfirm();
  testSessionAbort();
  testSessionStartFailedAndLyingHelper();
  testSessionGarbage();
  testSessionCancelBeforeFinish();
  testSessionDestroyedWhileRunning();
  testSessionAdversarialHelpers();
  testSessionStaleGeneration();
  testSessionReaderStartFailure();
  testSessionReaderThrows();
  testHelperProcessHardening();
  testHelperDiesWithParent();
  InteractivePamSession::joinAllReaders();
  return 0;
}
