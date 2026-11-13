#pragma once

#include "auth/posix_io.h"

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace face_helper {
  struct Frame;
}

/// One PAM conversation run in a helper process (noctalia-face-pam-helper) that
/// speaks the protocol in auth/face_helper_protocol.h. Unlike PamAuthenticator, it
/// streams every conversation message to the shell and lets the shell answer
/// prompts. All callbacks run on the main thread.
///
/// Each helper gets a reader thread that never outlives a bounded wait: it stops
/// reading after the Result frame, notices the helper's exit through a pidfd (so a
/// grandchild holding the socket can't stall it), and escalates to SIGKILL. The
/// helper dies with the shell (PR_SET_PDEATHSIG), runs in its own session without a
/// controlling terminal, and inherits only stdin, stdout and stderr.
class InteractivePamSession {
public:
  struct Finished {
    int rc = 0;
    // False when the helper reported that pam_start failed or the helper could not start.
    bool started = false;
    // True when the helper, not PAM, failed: no valid Result frame, a protocol error or
    // version mismatch, a setup failure in the child, or an exit status that contradicts
    // the Result. PAM made no decision, so this must never count as a rejection.
    bool infrastructureFailure = false;
  };

  /// The helper to execute: its path and its full argv, argv[0] included.
  struct Command {
    std::string path;
    std::vector<std::string> argv;
  };

  /// How long the helper gets to exit after SIGTERM, after its Result frame, or after
  /// closing its output, before SIGKILL.
  static constexpr std::chrono::milliseconds kExitGrace{500};
  /// How long to wait for a SIGKILLed helper before giving up on reaping it (a process in
  /// uninterruptible sleep can't die yet). This keeps every reader thread bounded.
  static constexpr std::chrono::milliseconds kKillWait{1000};

  using MessageCallback = std::function<void(const std::string& text, bool isError)>;
  using PromptCallback = std::function<void(const std::string& text, bool echo)>;
  using FinishedCallback = std::function<void(const Finished& result)>;

  InteractivePamSession();
  ~InteractivePamSession();

  InteractivePamSession(const InteractivePamSession&) = delete;
  InteractivePamSession& operator=(const InteractivePamSession&) = delete;

  void setMessageCallback(MessageCallback callback);
  void setPromptCallback(PromptCallback callback);
  void setFinishedCallback(FinishedCallback callback);

  /// Runs `command` and starts its conversation. Cancels any running session first.
  [[nodiscard]] bool start(const Command& command);
  /// Answers the pending prompt.
  bool respond(std::string_view text);
  /// Fails the pending prompt; the helper's conversation returns PAM_CONV_ERR.
  bool abort();
  /// Kills the helper (SIGTERM, then SIGKILL after kExitGrace) and drops its callbacks.
  /// Never blocks: the reader thread does the waiting.
  void cancel();

  bool running() const noexcept { return m_running; }
  bool promptPending() const noexcept { return m_promptPending; }

  /// Joins every reader thread, finished or not. Each is bounded (about 1.5 s after a
  /// cancel), so this returns promptly once their sessions are cancelled. Call it
  /// at teardown while the main loop's DeferredCall queue and logging still exist.
  static void joinAllReaders();

  /// Test hook: the next start() fails as if the reader thread could not be created.
  static void failNextReaderStartForTesting();
  /// Test hook: the next reader thread throws once the helper is running.
  static void throwInNextReaderForTesting();

private:
  struct ReaderArgs;
  static void runReader(ReaderArgs& args) noexcept;
  static void readHelper(ReaderArgs& args);
  void handleFrame(std::uint64_t generation, const face_helper::Frame& frame);
  void handleFinished(std::uint64_t generation, const Finished& result);
  void closeChannel() noexcept;

  MessageCallback m_onMessage;
  PromptCallback m_onPrompt;
  FinishedCallback m_onFinished;

  posix_io::UniqueFd m_fd;
  // Closing this wakes the reader thread, which then kills and reaps the helper.
  posix_io::UniqueFd m_cancelFd;
  bool m_running = false;
  bool m_promptPending = false;
  std::uint64_t m_generation = 0;
  std::shared_ptr<void> m_aliveGuard = std::make_shared<int>(0);
};
