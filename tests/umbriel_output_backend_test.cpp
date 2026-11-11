#include "compositors/output_power_state.h"
#include "compositors/umbriel/umbriel_output_backend.h"
#include "compositors/umbriel/umbriel_runtime.h"
#include "test_check.h"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <nlohmann/json.hpp>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <unordered_map>

using compositors::umbriel::UmbrielRuntime;

namespace {

  // A listening socket at UMBRIEL_SOCKET that never replies; it only counts how many
  // connections reached it. Each request is a fresh connection; the event stream is one
  // more, opened when the backend registers.
  class CountingServer {
  public:
    CountingServer() {
      char directory[] = "/tmp/noctalia-umbriel-output-test-XXXXXX";
      const auto* created = mkdtemp(directory);
      TEST_CHECK(created != nullptr);
      m_directory = created;
      m_path = m_directory + "/umbriel.sock";
      TEST_CHECK(setenv("UMBRIEL_SOCKET", m_path.c_str(), 1) == 0);
      m_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
      TEST_CHECK(m_fd >= 0);
      sockaddr_un address{};
      address.sun_family = AF_UNIX;
      std::memcpy(address.sun_path, m_path.c_str(), m_path.size() + 1);
      TEST_CHECK(bind(m_fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0);
      TEST_CHECK(listen(m_fd, 8) == 0);
    }
    ~CountingServer() {
      close(m_fd);
      unlink(m_path.c_str());
      rmdir(m_directory.c_str());
      unsetenv("UMBRIEL_SOCKET");
    }
    CountingServer(const CountingServer&) = delete;
    CountingServer& operator=(const CountingServer&) = delete;

    // Accepts (and closes) every pending connection; returns how many there were.
    int takeConnections() const {
      int count = 0;
      while (true) {
        const int client = accept4(m_fd, nullptr, nullptr, SOCK_CLOEXEC);
        if (client < 0) {
          TEST_CHECK(errno == EAGAIN);
          return count;
        }
        close(client);
        ++count;
      }
    }

  private:
    int m_fd = -1;
    std::string m_directory;
    std::string m_path;
  };

  // Answers power states only by query, like the Hyprland, Niri and Sway backends.
  struct QueryOnlyBackend {
    mutable int queries = 0;
    std::unordered_map<std::string, bool> outputPowerStates() const {
      ++queries;
      return {{"DP-1", false}};
    }
  };
  static_assert(!compositors::CachesPushedOutputPower<QueryOnlyBackend>);

  // Pushes changes and can also be queried, like Umbriel: only the cache may be read.
  struct PushingBackend : QueryOnlyBackend {
    std::unordered_map<std::string, bool> cache{{"DP-1", true}};
    void setOutputPowerChangeCallback(const std::function<void()>& /*callback*/) {}
    const std::unordered_map<std::string, bool>& cachedOutputPowerStates() const noexcept { return cache; }
  };
  static_assert(compositors::CachesPushedOutputPower<PushingBackend>);

  nlohmann::json outputs(bool dp1, bool edp1) {
    return nlohmann::json::array({
        {{"name", "DP-1"}, {"powered", dp1}},
        {{"name", "eDP-1"}, {"powered", edp1}},
    });
  }

  void testCachedStatesNeverQuery() {
    CountingServer server;
    UmbrielRuntime runtime;
    UmbrielOutputBackend backend(runtime);
    // The event stream.
    TEST_CHECK(server.takeConnections() == 1);
    int changes = 0;
    backend.setOutputPowerChangeCallback([&changes] { ++changes; });

    TEST_CHECK(backend.cachedOutputPowerStates().empty());

    // The snapshot Umbriel sends right after subscribing fills the cache.
    backend.handleEvent("outputs", outputs(true, true));
    TEST_CHECK(changes == 1);
    TEST_CHECK(backend.cachedOutputPowerStates().size() == 2);
    TEST_CHECK(backend.cachedOutputPowerStates().at("DP-1"));
    // What the lock path reads.
    TEST_CHECK(compositors::pushedOutputPowerStates(backend) == backend.cachedOutputPowerStates());

    backend.handleEvent("outputs", outputs(false, false));
    TEST_CHECK(changes == 2);
    TEST_CHECK(!backend.cachedOutputPowerStates().at("DP-1"));
    TEST_CHECK(!backend.cachedOutputPowerStates().at("eDP-1"));

    // An unchanged snapshot is not a change.
    backend.handleEvent("outputs", outputs(false, false));
    TEST_CHECK(changes == 2);

    // A dropped stream forgets what it reported.
    backend.handleStreamReset();
    TEST_CHECK(changes == 3);
    TEST_CHECK(backend.cachedOutputPowerStates().empty());

    TEST_CHECK(server.takeConnections() == 0);
  }

  void testQueryOnlyBackendIsNotAsked() {
    const QueryOnlyBackend backend;
    TEST_CHECK(compositors::pushedOutputPowerStates(backend).empty());
    TEST_CHECK(backend.queries == 0);

    const PushingBackend pushing;
    TEST_CHECK(compositors::pushedOutputPowerStates(pushing) == pushing.cache);
    TEST_CHECK(pushing.queries == 0);
  }

  void testQueryUsesTheSocket() {
    // Control for the counter: outputPowerStates() is a real request.
    CountingServer server;
    UmbrielRuntime runtime;
    UmbrielOutputBackend backend(runtime);
    TEST_CHECK(server.takeConnections() == 1);
    TEST_CHECK(backend.outputPowerStates().empty());
    TEST_CHECK(server.takeConnections() == 1);
  }

} // namespace

int main() {
  testCachedStatesNeverQuery();
  testQueryOnlyBackendIsNotAsked();
  testQueryUsesTheSocket();
  return 0;
}
