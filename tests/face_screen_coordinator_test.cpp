#include "auth/face_screen_coordinator.h"
#include "tests/test_check.h"

#include <string>
#include <vector>

namespace {

  class FakeTarget final : public face::ScreenTarget {
  public:
    std::vector<std::string> calls;
    void setScreenOn(bool on) override { calls.emplace_back(on ? "on" : "off"); }
    void start() override { calls.emplace_back("start"); }
    void beginLock() override { calls.emplace_back("lock"); }
  };

  struct Harness {
    FakeTarget target;
    bool knownOff = false;
    int queries = 0;
    face::ScreenCoordinator coordinator{target, [this] {
                                          ++queries;
                                          return knownOff;
                                        }};

    std::vector<std::string> take() {
      auto calls = std::move(target.calls);
      target.calls.clear();
      return calls;
    }
  };

  using Calls = std::vector<std::string>;

  void testLockDoesNotScan() {
    // Screen on at lock: unblocked and the cooldown starts, but nothing scans.
    Harness h;
    h.coordinator.locked();
    TEST_CHECK(h.take() == (Calls{"on", "lock"}));
    TEST_CHECK(!h.coordinator.screenOff());
    // Only the cheap known-off check runs at lock, once.
    TEST_CHECK(h.queries == 1);
  }

  void testLockWithScreenKnownOff() {
    // A pending power-off (or every output reported off) blocks until a wake.
    Harness h;
    h.knownOff = true;
    h.coordinator.locked();
    TEST_CHECK(h.take() == (Calls{"off", "lock"}));
    TEST_CHECK(h.coordinator.screenOff());
    h.coordinator.outputsPoweredOn();
    TEST_CHECK(h.take() == (Calls{"on", "start"}));
    TEST_CHECK(!h.coordinator.screenOff());
  }

  void testPowerOnWhileOnIsNotAWake() {
    // `ipc dpms-on` (or an idle resume action) right after locking in front of the
    // camera: the screen never went off, so this must not scan inside the cooldown.
    Harness h;
    h.coordinator.locked();
    h.take();
    h.coordinator.outputsPoweredOn();
    TEST_CHECK(h.take().empty());
    TEST_CHECK(!h.coordinator.screenOff());
    // After an aborted power-off the screen is still on: no wake either.
    h.coordinator.powerOffPrepared();
    h.coordinator.powerOffAborted();
    h.take();
    h.coordinator.outputsPoweredOn();
    TEST_CHECK(h.take().empty());
  }

  void testStalePowerOffBeforeLockDoesNotBlock() {
    // Noctalia powered off, the compositor woke the outputs without telling Noctalia,
    // then the user locked: the old power-off must not block this lock.
    Harness h;
    h.coordinator.powerOffPrepared();
    TEST_CHECK(h.coordinator.screenOff());
    h.take();
    h.knownOff = false;
    h.coordinator.locked();
    TEST_CHECK(h.take() == (Calls{"on", "lock"}));
    TEST_CHECK(!h.coordinator.screenOff());
  }

  void testPowerOffDuringLock() {
    Harness h;
    h.coordinator.locked();
    h.take();
    const int queries = h.queries;
    // Noctalia's own power-off blocks at once, without asking the compositor.
    h.coordinator.powerOffPrepared();
    TEST_CHECK(h.take() == (Calls{"off"}));
    TEST_CHECK(h.queries == queries);
    // Aborted: the screen never went dark. Unblock, but no scan.
    h.coordinator.powerOffAborted();
    TEST_CHECK(h.take() == (Calls{"on"}));
    // An abort with nothing blocked changes nothing.
    h.coordinator.powerOffAborted();
    TEST_CHECK(h.take().empty());
    // Off again, then powered on: a wake scans.
    h.coordinator.powerOffPrepared();
    h.coordinator.outputsPoweredOn();
    TEST_CHECK(h.take() == (Calls{"off", "on", "start"}));
  }

  void testCompositorReports() {
    Harness h;
    h.coordinator.locked();
    h.take();
    // Reported all off: block. Repeated reports don't repeat actions.
    h.knownOff = true;
    h.coordinator.powerStateReported();
    h.coordinator.powerStateReported();
    TEST_CHECK(h.take() == (Calls{"off"}));
    // Reported on: a wake, once.
    h.knownOff = false;
    h.coordinator.powerStateReported();
    h.coordinator.powerStateReported();
    TEST_CHECK(h.take() == (Calls{"on", "start"}));
    // A report that some output is on never blocks a running lock.
    h.coordinator.powerStateReported();
    TEST_CHECK(h.take().empty());
  }

  void testResume() {
    // Resume drops whatever was in flight, then counts as a wake.
    Harness h;
    h.coordinator.locked();
    h.take();
    h.coordinator.resumed();
    TEST_CHECK(h.take() == (Calls{"off", "on", "start"}));
    TEST_CHECK(!h.coordinator.screenOff());
  }

  void testWithoutQuery() {
    // No compositor: nothing is ever known to be off.
    FakeTarget target;
    face::ScreenCoordinator coordinator(target, {});
    coordinator.locked();
    TEST_CHECK(target.calls == (Calls{"on", "lock"}));
    coordinator.powerStateReported();
    TEST_CHECK(target.calls.size() == 2);
  }

} // namespace

int main() {
  testLockDoesNotScan();
  testLockWithScreenKnownOff();
  testPowerOnWhileOnIsNotAWake();
  testStalePowerOffBeforeLockDoesNotBlock();
  testPowerOffDuringLock();
  testCompositorReports();
  testResume();
  testWithoutQuery();
  return 0;
}
