#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

struct pam_message;
struct pam_response;

// Wire protocol between the shell and noctalia-face-pam-helper, over one socket
// that is the helper's stdin and stdout.
//
// Each side first sends kProtocolVersion as one byte, so a running shell and a
// helper from a newer package fail cleanly instead of misreading each other. The
// helper sends its version before it checks the shell's, and exits on a mismatch.
// Then every frame is `[len:u32][type:u8][fields…]`, little-endian, where len
// counts the bytes after the length prefix.
//
// The helper exits 0 after a Result with PAM_SUCCESS, 1 after any other Result,
// and 2 on a protocol or setup error, with no Result.
namespace face_helper {

  inline constexpr std::uint8_t kProtocolVersion = 1;

  inline constexpr int kExitSuccess = 0;
  inline constexpr int kExitFailure = 1;
  inline constexpr int kExitProtocolError = 2;

  enum class FrameType : std::uint8_t {
    Message = 1, // helper → parent: {style:u8, text}, PAM_TEXT_INFO or PAM_ERROR_MSG
    Prompt = 2,  // helper → parent: {style:u8, text}, PAM_PROMPT_ECHO_ON/OFF; a Reply or Abort follows
    Result = 3,  // helper → parent: {rc:i32, started:u8, text}; always the last frame
    Reply = 4,   // parent → helper: {text}
    Abort = 5,   // parent → helper: the pending prompt fails with PAM_CONV_ERR
  };

  struct Frame {
    FrameType type = FrameType::Abort;
    int style = 0;
    std::int32_t rc = 0;
    // Result only: false when the session never reached pam_authenticate (pam_start failed).
    bool started = false;
    std::string text;
  };

  inline constexpr std::size_t kMaxTextBytes = 4096;
  // Bytes of the u32 length prefix in front of every frame body.
  inline constexpr std::size_t kLengthPrefixBytes = 4;
  // Bytes of the type byte that starts every frame body.
  inline constexpr std::size_t kTypeBytes = 1;
  // Message and Prompt: style:u8 before the text.
  inline constexpr std::size_t kMessageHeaderBytes = 1;
  // Result: rc:i32 and started:u8 before the text.
  inline constexpr std::size_t kResultHeaderBytes = 4 + 1;
  // Largest valid body: type, the larger header, and the longest text.
  inline constexpr std::size_t kMaxBodyBytes = kTypeBytes + kResultHeaderBytes + kMaxTextBytes;

  /// Encodes one frame. Text longer than kMaxTextBytes is truncated.
  std::string encodeFrame(const Frame& frame);

  /// Incremental decoder for a byte stream of frames. Any malformed frame puts it
  /// into a permanent failed state.
  class FrameDecoder {
  public:
    FrameDecoder() = default;
    ~FrameDecoder();
    FrameDecoder(const FrameDecoder&) = delete;
    FrameDecoder& operator=(const FrameDecoder&) = delete;

    void feed(std::string_view bytes);
    [[nodiscard]] std::optional<Frame> next();
    bool failed() const noexcept { return m_failed; }

  private:
    std::string m_buffer;
    bool m_failed = false;
  };

  /// Blocking write of a whole frame. Never raises SIGPIPE on a socket.
  [[nodiscard]] bool writeFrame(int fd, const Frame& frame);
  /// Blocking read of exactly one frame; nullopt on EOF, I/O error or a malformed frame.
  [[nodiscard]] std::optional<Frame> readFrame(int fd);

  /// Helper side of the version exchange: sends kProtocolVersion on `outFd`, then
  /// reads the shell's from `inFd`. False on an I/O error or a different version.
  [[nodiscard]] bool exchangeVersions(int inFd, int outFd);

  /// First call of the helper's main(): no core dumps and no same-user ptrace or
  /// /proc/<pid>/mem access while the process holds PAM state. Must run
  /// after exec, which resets the flag.
  void hardenHelperProcess() noexcept;

  /// The helper's channel to the parent, passed as the PAM conversation appdata.
  struct ConversationChannel {
    int inFd = -1;
    int outFd = -1;
  };

  /// PAM conversation function for the face helper: forwards info and error
  /// messages, asks the parent for every prompt, and fails the conversation with
  /// PAM_CONV_ERR when the parent aborts or the channel breaks. It is called from C
  /// (libpam, then pam_gaze in Rust), so no exception may leave it: an allocation
  /// failure becomes PAM_BUF_ERR.
  int interactiveConversation(int numMsg, const pam_message** msg, pam_response** response, void* appdataPtr) noexcept;

} // namespace face_helper
