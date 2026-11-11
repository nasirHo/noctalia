#include "auth/face_screen_coordinator.h"

#include <utility>

namespace face {

  ScreenCoordinator::ScreenCoordinator(ScreenTarget& target, std::function<bool()> outputsKnownOff)
      : m_target(target), m_outputsKnownOff(std::move(outputsKnownOff)) {}

  void ScreenCoordinator::locked() {
    m_screenOff = m_outputsKnownOff && m_outputsKnownOff();
    // Screen state first: turning it on re-arms the wake scan, which beginLock() then spends.
    m_target.setScreenOn(!m_screenOff);
    m_target.beginLock();
  }

  void ScreenCoordinator::powerOffPrepared() { block(); }

  void ScreenCoordinator::powerOffAborted() {
    if (!m_screenOff) {
      return;
    }
    m_screenOff = false;
    m_target.setScreenOn(true);
  }

  void ScreenCoordinator::outputsPoweredOn() {
    // A power-on request while the screen is already on (`ipc dpms-on`, an idle resume
    // action) is not a wake: scanning then would skip the lock cooldown.
    if (m_screenOff) {
      wake();
    }
  }

  void ScreenCoordinator::powerStateReported() {
    const bool off = m_outputsKnownOff && m_outputsKnownOff();
    if (off && !m_screenOff) {
      block();
    } else if (!off && m_screenOff) {
      wake();
    }
  }

  void ScreenCoordinator::resumed() {
    block();
    wake();
  }

  void ScreenCoordinator::block() {
    m_screenOff = true;
    m_target.setScreenOn(false);
  }

  void ScreenCoordinator::wake() {
    m_screenOff = false;
    m_target.setScreenOn(true);
    m_target.start();
  }

} // namespace face
