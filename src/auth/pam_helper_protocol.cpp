#include "auth/pam_helper_protocol.h"

#include "auth/posix_io.h"

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <security/pam_appl.h>
#include <sys/prctl.h>

namespace pam_protocol {

  namespace {

    using posix_io::secureClear;

    void putU32(std::string& out, std::uint32_t value) {
      for (int i = 0; i < 4; ++i) {
        out.push_back(static_cast<char>((value >> (8 * i)) & 0xFFU));
      }
    }

    std::uint32_t getU32(std::string_view in) {
      std::uint32_t value = 0;
      for (int i = 0; i < 4; ++i) {
        value |= static_cast<std::uint32_t>(static_cast<std::uint8_t>(in[static_cast<std::size_t>(i)])) << (8 * i);
      }
      return value;
    }

    bool isMessageStyle(int style) { return style == PAM_ERROR_MSG || style == PAM_TEXT_INFO; }

    bool isPromptStyle(int style) { return style == PAM_PROMPT_ECHO_OFF || style == PAM_PROMPT_ECHO_ON; }

    std::optional<Frame> decodeBody(std::string_view body) {
      if (body.empty()) {
        return std::nullopt;
      }
      Frame frame;
      const auto type = static_cast<std::uint8_t>(body[0]);
      body.remove_prefix(1);
      switch (type) {
      case static_cast<std::uint8_t>(FrameType::Message):
      case static_cast<std::uint8_t>(FrameType::Prompt): {
        frame.type = static_cast<FrameType>(type);
        if (body.empty()) {
          return std::nullopt;
        }
        frame.style = static_cast<std::uint8_t>(body[0]);
        const bool validStyle =
            frame.type == FrameType::Message ? isMessageStyle(frame.style) : isPromptStyle(frame.style);
        if (!validStyle) {
          return std::nullopt;
        }
        body.remove_prefix(kMessageHeaderBytes);
        break;
      }
      case static_cast<std::uint8_t>(FrameType::Result): {
        frame.type = FrameType::Result;
        if (body.size() < kResultHeaderBytes) {
          return std::nullopt;
        }
        frame.rc = static_cast<std::int32_t>(getU32(body));
        const auto started = static_cast<std::uint8_t>(body[kResultHeaderBytes - 1]);
        if (started > 1) {
          return std::nullopt;
        }
        frame.started = started != 0;
        body.remove_prefix(kResultHeaderBytes);
        break;
      }
      case static_cast<std::uint8_t>(FrameType::Reply):
        frame.type = FrameType::Reply;
        break;
      case static_cast<std::uint8_t>(FrameType::Abort):
        frame.type = FrameType::Abort;
        if (!body.empty()) {
          return std::nullopt;
        }
        return frame;
      default:
        return std::nullopt;
      }
      if (body.size() > kMaxTextBytes) {
        return std::nullopt;
      }
      frame.text.assign(body);
      return frame;
    }

    void freeResponses(pam_response* replies, int count) noexcept {
      for (int i = 0; i < count; ++i) {
        if (replies[i].resp != nullptr) {
          volatile char* ptr = replies[i].resp;
          for (std::size_t j = 0; ptr[j] != '\0'; ++j) {
            ptr[j] = '\0';
          }
          std::free(replies[i].resp);
        }
      }
      std::free(replies);
    }

  } // namespace

  std::string encodeFrame(const Frame& frame) {
    const std::string_view text = std::string_view(frame.text).substr(0, std::min(frame.text.size(), kMaxTextBytes));
    std::string body;
    body.reserve(kTypeBytes + kResultHeaderBytes + text.size());
    body.push_back(static_cast<char>(frame.type));
    switch (frame.type) {
    case FrameType::Message:
    case FrameType::Prompt:
      body.push_back(static_cast<char>(static_cast<std::uint8_t>(frame.style)));
      body.append(text);
      break;
    case FrameType::Result:
      putU32(body, static_cast<std::uint32_t>(frame.rc));
      body.push_back(static_cast<char>(frame.started ? 1 : 0));
      body.append(text);
      break;
    case FrameType::Reply:
      body.append(text);
      break;
    case FrameType::Abort:
      break;
    }
    std::string out;
    out.reserve(kLengthPrefixBytes + body.size());
    putU32(out, static_cast<std::uint32_t>(body.size()));
    out.append(body);
    secureClear(body);
    return out;
  }

  FrameDecoder::~FrameDecoder() { secureClear(m_buffer); }

  void FrameDecoder::feed(std::string_view bytes) {
    if (!m_failed) {
      m_buffer.append(bytes);
    }
  }

  std::optional<Frame> FrameDecoder::next() {
    if (m_failed || m_buffer.size() < kLengthPrefixBytes) {
      return std::nullopt;
    }
    const std::uint32_t len = getU32(m_buffer);
    if (len == 0 || len > kMaxBodyBytes) {
      m_failed = true;
      secureClear(m_buffer);
      return std::nullopt;
    }
    if (m_buffer.size() < kLengthPrefixBytes + static_cast<std::size_t>(len)) {
      return std::nullopt;
    }
    auto frame = decodeBody(std::string_view(m_buffer).substr(kLengthPrefixBytes, len));
    // Shift the remainder down in place so consumed bytes are overwritten, not left in freed memory.
    const std::size_t consumed = kLengthPrefixBytes + static_cast<std::size_t>(len);
    std::copy(m_buffer.begin() + static_cast<std::ptrdiff_t>(consumed), m_buffer.end(), m_buffer.begin());
    const std::size_t remaining = m_buffer.size() - consumed;
    std::fill(m_buffer.begin() + static_cast<std::ptrdiff_t>(remaining), m_buffer.end(), '\0');
    m_buffer.resize(remaining);
    if (!frame.has_value()) {
      m_failed = true;
      secureClear(m_buffer);
    }
    return frame;
  }

  bool writeFrame(int fd, const Frame& frame) {
    std::string bytes = encodeFrame(frame);
    const bool ok = posix_io::writeAll(fd, bytes.data(), bytes.size());
    secureClear(bytes);
    return ok;
  }

  std::optional<Frame> readFrame(int fd) {
    char header[kLengthPrefixBytes];
    if (!posix_io::readAll(fd, header, sizeof(header))) {
      return std::nullopt;
    }
    const std::uint32_t len = getU32(std::string_view(header, sizeof(header)));
    if (len == 0 || len > kMaxBodyBytes) {
      return std::nullopt;
    }
    std::string body(len, '\0');
    if (!posix_io::readAll(fd, body.data(), len)) {
      secureClear(body);
      return std::nullopt;
    }
    auto frame = decodeBody(body);
    secureClear(body);
    return frame;
  }

  void hardenHelperProcess() noexcept { (void)::prctl(PR_SET_DUMPABLE, 0); }

  int interactiveConversation(int numMsg, const pam_message** msg, pam_response** response, void* appdataPtr) noexcept {
    if (numMsg <= 0 || msg == nullptr || response == nullptr || appdataPtr == nullptr) {
      return PAM_CONV_ERR;
    }

    const auto* channel = static_cast<const ConversationChannel*>(appdataPtr);
    auto* replies = static_cast<pam_response*>(std::calloc(static_cast<std::size_t>(numMsg), sizeof(pam_response)));
    if (replies == nullptr) {
      return PAM_BUF_ERR;
    }

    int i = 0;
    try {
      for (; i < numMsg; ++i) {
        if (msg[i] == nullptr) {
          freeResponses(replies, i);
          return PAM_CONV_ERR;
        }
        const int style = msg[i]->msg_style;
        const std::string text = msg[i]->msg != nullptr ? msg[i]->msg : "";

        if (isMessageStyle(style)) {
          if (!writeFrame(channel->outFd, Frame{.type = FrameType::Message, .style = style, .text = text})) {
            freeResponses(replies, i);
            return PAM_CONV_ERR;
          }
          continue;
        }
        if (!isPromptStyle(style)
            || !writeFrame(channel->outFd, Frame{.type = FrameType::Prompt, .style = style, .text = text})) {
          freeResponses(replies, i);
          return PAM_CONV_ERR;
        }

        auto answer = readFrame(channel->inFd);
        if (!answer.has_value() || answer->type != FrameType::Reply) {
          if (answer.has_value()) {
            secureClear(answer->text);
          }
          freeResponses(replies, i);
          return PAM_CONV_ERR;
        }
        replies[i].resp = ::strdup(answer->text.c_str());
        secureClear(answer->text);
        if (replies[i].resp == nullptr) {
          freeResponses(replies, i);
          return PAM_BUF_ERR;
        }
      }
    } catch (...) {
      // Replies up to and including message i may hold strdup()ed answers.
      freeResponses(replies, std::min(i + 1, numMsg));
      return PAM_BUF_ERR;
    }

    *response = replies;
    return PAM_SUCCESS;
  }

} // namespace pam_protocol
