#include "auth/interactive_pam_session.h"

#include "auth/pam_helper_protocol.h"
#include "core/deferred_call.h"
#include "core/log.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <exception>
#include <fcntl.h>
#include <mutex>
#include <optional>
#include <poll.h>
#include <security/pam_appl.h>
#include <stdexcept>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <system_error>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

namespace {

  constexpr Logger kLog("pam");

  using posix_io::UniqueFd;
  using Clock = std::chrono::steady_clock;

  constexpr auto kExitGrace = InteractivePamSession::kExitGrace;
  constexpr auto kKillWait = InteractivePamSession::kKillWait;
  // Poll slice when there is no pidfd to wait on.
  constexpr auto kPollSlice = std::chrono::milliseconds(10);

  std::atomic<bool> g_failNextReaderStart{false};
  std::atomic<bool> g_throwInNextReader{false};

  // Exit codes of the forked child when it fails before execv(). 127 stays "exec failed".
  constexpr int kChildDeathSignalFailed = 121;
  constexpr int kChildSetsidFailed = 122;
  constexpr int kChildStdioFailed = 123;
  constexpr int kChildCloseRangeFailed = 124;
  constexpr int kChildExecFailed = 127;

  const char* childSetupFailure(int exitCode) noexcept {
    switch (exitCode) {
    case kChildDeathSignalFailed:
      return "PR_SET_PDEATHSIG";
    case kChildSetsidFailed:
      return "setsid";
    case kChildStdioFailed:
      return "dup2";
    case kChildCloseRangeFailed:
      return "close_range";
    case kChildExecFailed:
      return "execv";
    default:
      return nullptr;
    }
  }

  [[nodiscard]] UniqueFd openPidfd(pid_t pid) {
    // pidfd_open(2) through syscall(): older glibc has no wrapper. The fd is CLOEXEC.
    return UniqueFd(static_cast<int>(::syscall(SYS_pidfd_open, pid, 0)));
  }

  // Waits up to `timeout` for the helper to exit and reaps it. nullopt while it still
  // runs; -1 when it can't be reaped (not our child any more).
  [[nodiscard]] std::optional<int> waitForExit(int pidfd, pid_t pid, std::chrono::milliseconds timeout) noexcept {
    const auto deadline = Clock::now() + timeout;
    while (true) {
      int status = 0;
      const pid_t rc = ::waitpid(pid, &status, WNOHANG);
      if (rc == pid) {
        return status;
      }
      if (rc < 0 && errno != EINTR) {
        return -1;
      }
      auto remaining = std::chrono::ceil<std::chrono::milliseconds>(deadline - Clock::now());
      if (remaining.count() <= 0) {
        return std::nullopt;
      }
      if (pidfd < 0) {
        remaining = std::min(remaining, kPollSlice);
      }
      pollfd fd{.fd = pidfd, .events = POLLIN, .revents = 0};
      (void)::poll(&fd, 1, static_cast<int>(remaining.count()));
    }
  }

  // Ends the helper, with SIGTERM first when `graceful`. Returns the wait status, or -1
  // if it could not be reaped in time. Runs while a failed reader unwinds, so never throws.
  int stopHelper(int pidfd, pid_t pid, bool graceful) noexcept {
    if (graceful) {
      (void)::kill(pid, SIGTERM);
      if (const auto status = waitForExit(pidfd, pid, kExitGrace)) {
        return *status;
      }
    }
    (void)::kill(pid, SIGKILL);
    if (const auto status = waitForExit(pidfd, pid, kKillWait)) {
      return *status;
    }
    try {
      kLog.warn("interactive pam helper pid={} did not exit after SIGKILL", pid);
    } catch (...) {
      // Logging is best effort here.
    }
    return -1;
  }

  // Owns every reader thread, so teardown can join them while the DeferredCall queue
  // and the logger still exist.
  class ReaderRegistry {
  public:
    ReaderRegistry() = default;
    ReaderRegistry(const ReaderRegistry&) = delete;
    ReaderRegistry& operator=(const ReaderRegistry&) = delete;

    ~ReaderRegistry() {
      // joinAll() should already have run. If not, don't let a static destructor block
      // on a helper that is still scanning.
      std::scoped_lock lock(m_mutex);
      for (auto& reader : m_readers) {
        if (reader.thread.joinable()) {
          reader.thread.detach();
        }
      }
    }

    /// Starts `fn` on a new thread. Throws (with nothing started) if it can't.
    void spawn(std::function<void()> fn) {
      std::scoped_lock lock(m_mutex);
      std::erase_if(m_readers, [](const Reader& reader) { return reader.done->load(); });
      // Reserve first so that once the thread runs, storing it can't fail.
      m_readers.reserve(m_readers.size() + 1);
      auto done = std::make_shared<std::atomic<bool>>(false);
      std::jthread thread([fn = std::move(fn), done] {
        try {
          fn();
        } catch (...) {
          // The session's UI timeout still ends the attempt.
        }
        done->store(true);
      });
      m_readers.push_back(Reader{.thread = std::move(thread), .done = std::move(done)});
    }

    void joinAll() {
      std::vector<Reader> readers;
      {
        std::scoped_lock lock(m_mutex);
        readers.swap(m_readers);
      }
      // std::jthread joins on destruction; readers never take m_mutex.
      readers.clear();
    }

  private:
    struct Reader {
      std::jthread thread;
      std::shared_ptr<std::atomic<bool>> done;
    };

    std::mutex m_mutex;
    std::vector<Reader> m_readers;
  };

  ReaderRegistry& readers() {
    static ReaderRegistry registry;
    return registry;
  }

} // namespace

struct InteractivePamSession::ReaderArgs {
  UniqueFd fd;
  UniqueFd cancelFd;
  UniqueFd pidfd;
  pid_t pid = -1;
  InteractivePamSession* self = nullptr;
  std::weak_ptr<void> guard;
  std::uint64_t generation = 0;
};

InteractivePamSession::InteractivePamSession() = default;

InteractivePamSession::~InteractivePamSession() {
  // cancel() without its log line: a throwing logger would terminate here.
  ++m_generation;
  closeChannel();
  m_aliveGuard.reset();
}

void InteractivePamSession::setMessageCallback(MessageCallback callback) { m_onMessage = std::move(callback); }

void InteractivePamSession::setPromptCallback(PromptCallback callback) { m_onPrompt = std::move(callback); }

void InteractivePamSession::setFinishedCallback(FinishedCallback callback) { m_onFinished = std::move(callback); }

void InteractivePamSession::joinAllReaders() { readers().joinAll(); }

void InteractivePamSession::failNextReaderStartForTesting() { g_failNextReaderStart.store(true); }

void InteractivePamSession::throwInNextReaderForTesting() { g_throwInNextReader.store(true); }

bool InteractivePamSession::start(std::string_view service, std::string_view language) {
  cancel();
  if (service.empty() || language.empty()) {
    return false;
  }

  // Owned, writable argument buffers: execv() takes char* const*.
  std::array<std::string, 4> args = {
      "noctalia",
      "pam-helper-interactive",
      std::string(service),
      std::string(language),
  };
  std::array<char*, 5> helperArgv = {args[0].data(), args[1].data(), args[2].data(), args[3].data(), nullptr};

  // One socket carries both directions; send() with MSG_NOSIGNAL means a dead helper
  // can never raise SIGPIPE in the shell.
  int sockets[2] = {-1, -1};
  if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) != 0) {
    return false;
  }
  UniqueFd parentFd(sockets[0]);
  UniqueFd childFd(sockets[1]);
  int cancelPipe[2] = {-1, -1};
  if (!posix_io::moveAboveStdio(parentFd)
      || !posix_io::moveAboveStdio(childFd)
      || ::pipe2(cancelPipe, O_CLOEXEC) != 0) {
    return false;
  }
  UniqueFd cancelRead(cancelPipe[0]);
  UniqueFd cancelWrite(cancelPipe[1]);
  // The reader thread gets its own descriptor so cancel() can close ours without racing its poll().
  UniqueFd readerFd(::fcntl(parentFd.get(), F_DUPFD_CLOEXEC, STDERR_FILENO + 1));
  if (!readerFd.valid()) {
    return false;
  }

  const pid_t parentPid = ::getpid();
  const int childSocket = childFd.get();
  const pid_t pid = ::fork();
  if (pid < 0) {
    return false;
  }

  if (pid == 0) {
    // Only async-signal-safe calls until execv().
    // Die with the shell. The signal follows the forking thread, which is the main thread;
    // the getppid() check covers a parent that died before prctl().
    if (::prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || ::getppid() != parentPid) {
      ::_exit(kChildDeathSignalFailed);
    }
    // A new session has no controlling terminal, so PAM modules can't open /dev/tty.
    if (::setsid() < 0) {
      ::_exit(kChildSetsidFailed);
    }
    if (::dup2(childSocket, STDIN_FILENO) < 0 || ::dup2(childSocket, STDOUT_FILENO) < 0) {
      ::_exit(kChildStdioFailed);
    }
    // Inherit only stdio (stderr stays for the helper's log), whatever the shell leaked
    // without CLOEXEC. close_range() needs Linux 5.9.
    if (::syscall(SYS_close_range, STDERR_FILENO + 1, ~0U, 0) != 0) {
      ::_exit(kChildCloseRangeFailed);
    }
    ::execv("/proc/self/exe", helperArgv.data());
    ::_exit(kChildExecFailed);
  }

  childFd.reset();

  auto reader = std::make_shared<ReaderArgs>();
  reader->fd = std::move(readerFd);
  reader->cancelFd = std::move(cancelRead);
  reader->pidfd = openPidfd(pid);
  reader->pid = pid;
  reader->self = this;
  reader->guard = m_aliveGuard;
  reader->generation = m_generation + 1;
  if (!reader->pidfd.valid()) {
    kLog.warn("could not open a pidfd for the interactive pam helper (errno={})", errno);
    (void)stopHelper(-1, pid, false);
    return false;
  }

  // Start the reader before publishing any state, so a failure leaves nothing behind.
  try {
    if (g_failNextReaderStart.exchange(false)) {
      throw std::system_error(std::make_error_code(std::errc::resource_unavailable_try_again));
    }
    readers().spawn([reader] { runReader(*reader); });
  } catch (const std::exception& e) {
    kLog.warn("could not start the interactive pam reader: {}", e.what());
    (void)stopHelper(reader->pidfd.get(), pid, false);
    return false;
  }

  m_fd = std::move(parentFd);
  m_cancelFd = std::move(cancelWrite);
  m_running = true;
  m_promptPending = false;
  m_generation = reader->generation;
  kLog.debug("started interactive pam helper pid={} service='{}'", pid, args[2]);
  return true;
}

bool InteractivePamSession::respond(std::string_view text) {
  if (!m_running || !m_promptPending || !m_fd.valid()) {
    return false;
  }
  m_promptPending = false;
  pam_protocol::Frame frame{.type = pam_protocol::FrameType::Reply, .text = std::string(text)};
  const bool ok = pam_protocol::writeFrame(m_fd.get(), frame);
  posix_io::secureClear(frame.text);
  return ok;
}

bool InteractivePamSession::abort() {
  if (!m_running || !m_promptPending || !m_fd.valid()) {
    return false;
  }
  m_promptPending = false;
  return pam_protocol::writeFrame(m_fd.get(), pam_protocol::Frame{.type = pam_protocol::FrameType::Abort});
}

void InteractivePamSession::cancel() {
  ++m_generation;
  if (m_running) {
    kLog.debug("cancelling interactive pam helper");
  }
  closeChannel();
  m_running = false;
  m_promptPending = false;
}

void InteractivePamSession::closeChannel() noexcept {
  m_cancelFd.reset();
  m_fd.reset();
}

void InteractivePamSession::runReader(ReaderArgs& args) noexcept {
  try {
    readHelper(args);
  } catch (...) {
    // Something threw mid-read (bad_alloc while posting, say). The helper must not run on
    // unsupervised with the camera on, nor stay a zombie: kill and reap it, then end the
    // session as a helper failure if that can still be posted. A stale post is dropped by
    // the generation check; if none can be posted, the lane's UI timeout ends the attempt.
    if (args.pid > 0) {
      (void)stopHelper(args.pidfd.get(), args.pid, false);
      args.pid = -1;
    }
    args.fd.reset();
    args.cancelFd.reset();
    args.pidfd.reset();
    try {
      kLog.warn("interactive pam reader failed; helper stopped");
      DeferredCall::callLater([self = args.self, guard = args.guard, generation = args.generation] {
        if (!guard.expired()) {
          self->handleFinished(
              generation, Finished{.rc = PAM_SYSTEM_ERR, .started = true, .infrastructureFailure = true, .message = {}}
          );
        }
      });
    } catch (...) {
      // Nothing more can be done without memory.
    }
  }
}

void InteractivePamSession::readHelper(ReaderArgs& args) {
  // Never touches the session directly, only posts to the main thread, where the
  // alive guard and generation decide whether the session still wants it.
  InteractivePamSession* self = args.self;
  const std::weak_ptr<void> guard = args.guard;
  const std::uint64_t generation = args.generation;
  const auto post = [&](pam_protocol::Frame frame) {
    DeferredCall::callLater([self, guard, generation, frame = std::move(frame)] {
      if (!guard.expired()) {
        self->handleFrame(generation, frame);
      }
    });
  };

  pam_protocol::FrameDecoder decoder;
  std::optional<pam_protocol::Frame> result;
  bool reading = true;
  bool cancelled = false;
  bool protocolError = false;
  bool exited = false;
  // Set once the helper has nothing more to say (Result or EOF): it must exit by then.
  std::optional<Clock::time_point> deadline;
  std::array<char, 4096> buffer{};

  // Feeds `n` bytes from `buffer`. False on a protocol error. Stops at the Result
  // frame: nothing after it is read.
  const auto consume = [&](std::size_t n) {
    decoder.feed(std::string_view(buffer.data(), n));
    while (auto frame = decoder.next()) {
      switch (frame->type) {
      case pam_protocol::FrameType::Message:
      case pam_protocol::FrameType::Prompt:
        post(std::move(*frame));
        break;
      case pam_protocol::FrameType::Result:
        result = std::move(*frame);
        return true;
      case pam_protocol::FrameType::Reply:
      case pam_protocol::FrameType::Abort:
        return false;
      }
    }
    return !decoder.failed();
  };
  const auto stopReading = [&] {
    reading = false;
    deadline = Clock::now() + kExitGrace;
  };

  if (g_throwInNextReader.exchange(false)) {
    throw std::runtime_error("reader failure injected for testing");
  }

  while (true) {
    int timeoutMs = -1;
    if (deadline.has_value()) {
      const auto remaining = std::chrono::ceil<std::chrono::milliseconds>(*deadline - Clock::now());
      if (remaining.count() <= 0) {
        break;
      }
      timeoutMs = static_cast<int>(remaining.count());
    }
    std::array<pollfd, 3> fds{{
        {.fd = args.cancelFd.get(), .events = POLLIN, .revents = 0},
        {.fd = args.pidfd.get(), .events = POLLIN, .revents = 0},
        {.fd = reading ? args.fd.get() : -1, .events = POLLIN, .revents = 0},
    }};
    if (::poll(fds.data(), fds.size(), timeoutMs) < 0) {
      if (errno == EINTR) {
        continue;
      }
      protocolError = true;
      break;
    }
    if (fds[0].revents != 0) {
      cancelled = true;
      break;
    }
    if (fds[2].revents != 0) {
      const ssize_t n = ::read(args.fd.get(), buffer.data(), buffer.size());
      if (n < 0 && (errno == EINTR || errno == EAGAIN)) {
        continue;
      }
      if (n <= 0) {
        stopReading();
      } else if (!consume(static_cast<std::size_t>(n))) {
        protocolError = true;
        break;
      } else if (result.has_value()) {
        stopReading();
      }
      // Read everything buffered before acting on the helper's exit.
      continue;
    }
    if (fds[1].revents != 0) {
      // The helper exited. What it wrote is already buffered, so drain without
      // blocking: a grandchild may still hold the socket open.
      while (reading && !result.has_value()) {
        const ssize_t n = ::recv(args.fd.get(), buffer.data(), buffer.size(), MSG_DONTWAIT);
        if (n < 0 && errno == EINTR) {
          continue;
        }
        if (n <= 0) {
          break;
        }
        if (!consume(static_cast<std::size_t>(n))) {
          protocolError = true;
          break;
        }
      }
      exited = !protocolError;
      break;
    }
  }
  buffer.fill('\0');
  args.fd.reset();

  int status = -1;
  if (exited) {
    status = waitForExit(args.pidfd.get(), args.pid, kExitGrace).value_or(-1);
  } else {
    // Cancelled or a protocol error: SIGTERM first. A helper still alive after its
    // grace period (it went quiet but didn't exit) gets SIGKILL straight away.
    status = stopHelper(args.pidfd.get(), args.pid, cancelled || protocolError);
  }
  // Reaped, or given up on: the unwinding path must never signal this pid again.
  args.pid = -1;
  args.cancelFd.reset();
  args.pidfd.reset();
  if (cancelled) {
    return;
  }

  const bool exitedNormally = status >= 0 && WIFEXITED(status);
  const int exitCode = exitedNormally ? WEXITSTATUS(status) : -1;
  // Anything short of a Result that matches the exit status is the helper failing, not PAM.
  Finished finished{.rc = PAM_SYSTEM_ERR, .started = true, .infrastructureFailure = true, .message = {}};
  if (protocolError || !result.has_value()) {
    if (const char* step = exitedNormally && !protocolError ? childSetupFailure(exitCode) : nullptr) {
      kLog.warn("interactive pam helper could not start: {} failed (exit status {})", step, exitCode);
    } else {
      kLog.warn(
          "interactive pam helper failed (protocol={} exited={} status={})", protocolError, exitedNormally, exitCode
      );
    }
  } else if ((result->rc == PAM_SUCCESS) != (exitCode == 0) || (exitCode != 0 && exitCode != 1)) {
    kLog.warn("interactive pam helper result rc={} disagrees with exit status {}", result->rc, exitCode);
    finished.started = result->started;
  } else {
    finished = Finished{
        .rc = result->rc, .started = result->started, .infrastructureFailure = false, .message = std::move(result->text)
    };
  }

  DeferredCall::callLater([self, guard, generation, finished = std::move(finished)] {
    if (!guard.expired()) {
      self->handleFinished(generation, finished);
    }
  });
}

void InteractivePamSession::handleFrame(std::uint64_t generation, const pam_protocol::Frame& frame) {
  if (generation != m_generation || !m_running) {
    return;
  }
  if (frame.type == pam_protocol::FrameType::Prompt) {
    m_promptPending = true;
    if (m_onPrompt) {
      m_onPrompt(frame.text, frame.style == PAM_PROMPT_ECHO_ON);
    }
    return;
  }
  if (m_onMessage) {
    m_onMessage(frame.text, frame.style == PAM_ERROR_MSG);
  }
}

void InteractivePamSession::handleFinished(std::uint64_t generation, const Finished& result) {
  if (generation != m_generation || !m_running) {
    return;
  }
  closeChannel();
  m_running = false;
  m_promptPending = false;
  kLog.debug("interactive pam helper finished rc={} started={}", result.rc, result.started);
  if (m_onFinished) {
    m_onFinished(result);
  }
}
