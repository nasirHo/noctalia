#pragma once

#include <functional>

namespace face {

  /// What the coordinator drives: the face lane, behind LockScreen's own gates.
  class ScreenTarget {
  public:
    virtual ~ScreenTarget() = default;
    virtual void setScreenOn(bool on) = 0;
    /// This wake's automatic scan.
    virtual void start() = 0;
    virtual void beginLock() = 0;
  };

  /// Decides, from lock and output-power events, when the face lane may scan. It keeps
  /// the camera off while the screen is known to be dark and treats only real wakes as
  /// reasons to scan. Locking is not a wake.
  ///
  /// It knows the screen is off from Noctalia's own power-off, a pending power-off,
  /// or outputs a compositor reported as off (only push-capable backends report).
  /// A compositor that powers outputs off by itself without telling Noctalia can't be
  /// seen, so a scan may run on a dark screen there.
  class ScreenCoordinator {
  public:
    /// `outputsKnownOff` must be cheap: a pending Noctalia power-off, or every output
    /// reported off by a compositor that pushes power changes. Never compositor IPC.
    ScreenCoordinator(ScreenTarget& target, std::function<bool()> outputsKnownOff);

    /// The session lock is up. The screen state is taken fresh from known reports, so
    /// a power-off from before the lock that the compositor undid can't block face
    /// unlock for this lock.
    void locked();
    /// Noctalia is about to power the outputs off.
    void powerOffPrepared();
    /// That power-off was abandoned; the screen never went dark. No scan.
    void powerOffAborted();
    /// Noctalia powered the outputs on: a wake, if the screen was known to be off.
    void outputsPoweredOn();
    /// A compositor pushed an output power change.
    void powerStateReported();
    /// The system resumed: anything in flight is stale, and this is a wake.
    void resumed();

    bool screenOff() const noexcept { return m_screenOff; }

  private:
    void block();
    void wake();

    ScreenTarget& m_target;
    std::function<bool()> m_outputsKnownOff;
    bool m_screenOff = false;
  };

} // namespace face
