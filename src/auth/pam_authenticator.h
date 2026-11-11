#pragma once

#include <string>
#include <string_view>

class PamAuthenticator {
public:
  struct [[nodiscard]] Result {
    bool success = false;
    std::string message;
  };

  Result authenticateCurrentUser(
      std::string_view password, std::string_view service, std::string_view language,
      std::string_view startFailureMessage
  ) const;
  static std::string currentUsername();
  [[nodiscard]] static int runHelperMode(int argc, char* argv[]);
  /// `pam-helper-interactive <service> <language>`: relays the PAM conversation over
  /// stdin/stdout using the frames in auth/pam_helper_protocol.h.
  [[nodiscard]] static int runInteractiveHelperMode(int argc, char* argv[]);

private:
  [[nodiscard]] static int runHelperModeUnguarded(int argc, char* argv[]);
  [[nodiscard]] static int runInteractiveHelperModeUnguarded(int argc, char* argv[]);
};
