#include "auth/face_authenticator.h"

#include "auth/gaze_config.h"
#include "auth/pam_authenticator.h"
#include "auth/pam_service.h"
#include "core/log.h"
#include "dbus/system_bus.h"
#include "i18n/i18n.h"

#include <chrono>
#include <optional>
#include <sdbus-c++/Error.h>
#include <sdbus-c++/IConnection.h>
#include <sdbus-c++/IProxy.h>
#include <sdbus-c++/Message.h>
#include <sdbus-c++/Types.h>
#include <security/pam_appl.h>
#include <string>
#include <utility>

namespace {
  constexpr Logger kLog("face");

  const sdbus::ServiceName kGazeBusName{"com.gundulabs.Gaze"};
  const sdbus::ObjectPath kGazePath{"/com/gundulabs/Gaze"};
  constexpr auto kGazeInterface = "com.gundulabs.Gaze";

  const sdbus::ServiceName kBusDaemonName{"org.freedesktop.DBus"};
  const sdbus::ObjectPath kBusDaemonPath{"/org/freedesktop/DBus"};
  constexpr auto kBusDaemonInterface = "org.freedesktop.DBus";

  constexpr auto kPropertiesInterface = "org.freedesktop.DBus.Properties";

  constexpr auto kProbeTimeout = std::chrono::seconds(3);
  constexpr auto kConfigTimeout = std::chrono::seconds(1);
} // namespace

// Registers "noctalia-face" in gazed's PamInternal list so pam_gaze sends machine
// tokens instead of English text. gazed forgets the entry when the registering
// connection closes, so this uses the shell's long-lived system bus connection and
// registers again whenever gazed reappears. The lane reads both forms regardless,
// because registration can race with a scan. Nothing here contacts gazed until the
// lane asks for token mode.
class GazePamInternalRegistration {
public:
  explicit GazePamInternalRegistration(SystemBus& bus) {
    try {
      m_gaze = sdbus::createProxy(bus.connection(), kGazeBusName, kGazePath);
      // arg0 filter: the bus daemon delivers only Gaze's owner changes, not every
      // client joining or leaving the system bus.
      const std::string match = std::string("type='signal',sender='")
          + kBusDaemonName.c_str()
          + "',path='"
          + kBusDaemonPath.c_str()
          + "',interface='"
          + kBusDaemonInterface
          + "',member='NameOwnerChanged',arg0='"
          + kGazeBusName.c_str()
          + "'";
      m_ownerWatch = bus.connection().addMatchAsync(
          match,
          [this](sdbus::Message message) {
            std::string name;
            std::string oldOwner;
            std::string newOwner;
            message >> name >> oldOwner >> newOwner;
            if (name != kGazeBusName) {
              return;
            }
            m_registered = false;
            if (!newOwner.empty() && m_wanted) {
              kLog.debug("gazed appeared; registering face token mode");
              add();
            }
          },
          // A non-empty install callback: the default one closes the connection on failure.
          [](const sdbus::Message& /*reply*/) {}, sdbus::return_slot
      );
    } catch (const sdbus::Error& e) {
      kLog.debug("could not watch gazed: {}", e.what());
      m_gaze.reset();
      m_ownerWatch.reset();
    }
  }

  // gazed drops the registration when the shell's connection closes, so teardown
  // needs no D-Bus call.
  ~GazePamInternalRegistration() = default;

  GazePamInternalRegistration(const GazePamInternalRegistration&) = delete;
  GazePamInternalRegistration& operator=(const GazePamInternalRegistration&) = delete;

  void ensureRegistered() {
    m_wanted = true;
    if (!m_registered && !m_pending) {
      add();
    }
  }

  void unregister() {
    const bool hadRegistration = m_registered || m_pending;
    m_wanted = false;
    m_registered = false;
    m_pending = false;
    ++m_generation;
    if (!hadRegistration || m_gaze == nullptr) {
      return;
    }
    // Asynchronous: the main thread never waits on gazed. Messages on one connection
    // stay ordered, so a later AddPamInternal still lands after this.
    m_gaze->callMethodAsync("RemovePamInternal")
        .onInterface(kGazeInterface)
        .withArguments(std::string(pam_service::kFace))
        .uponReplyInvoke([](std::optional<sdbus::Error> e) {
          if (e.has_value()) {
            kLog.debug("could not unregister face token mode: {}", e->what());
          } else {
            kLog.debug("unregistered face token mode");
          }
        });
  }

private:
  void add() {
    if (m_gaze == nullptr) {
      return;
    }
    m_pending = true;
    const std::uint64_t generation = ++m_generation;
    m_gaze->callMethodAsync("AddPamInternal")
        .onInterface(kGazeInterface)
        .withArguments(std::string(pam_service::kFace))
        .uponReplyInvoke([this, generation](std::optional<sdbus::Error> e) {
          if (generation != m_generation) {
            return;
          }
          m_pending = false;
          if (e.has_value()) {
            // Plain mode still works; this only loses translated outcomes.
            kLog.debug("could not register face token mode: {}", e->what());
            return;
          }
          m_registered = true;
          kLog.debug("registered face token mode");
        });
  }

  std::unique_ptr<sdbus::IProxy> m_gaze;
  sdbus::Slot m_ownerWatch;
  bool m_wanted = false;
  bool m_registered = false;
  bool m_pending = false;
  std::uint64_t m_generation = 0;
};

FaceAuthenticator::FaceAuthenticator(SystemBus& bus)
    : m_bus(bus), m_registration(std::make_unique<GazePamInternalRegistration>(bus)),
      m_user(PamAuthenticator::currentUsername()) {
  try {
    m_gaze = sdbus::createProxy(m_bus.connection(), kGazeBusName, kGazePath);
  } catch (const sdbus::Error& e) {
    kLog.debug("could not create Gaze proxy: {}", e.what());
  }

  m_session.setMessageCallback([this](const std::string& text, bool isError) { m_lane.onMessage(text, isError); });
  m_session.setPromptCallback([this](const std::string& text, bool echo) { m_lane.onPrompt(text, echo); });
  m_session.setFinishedCallback([this](const InteractivePamSession::Finished& result) {
    // A helper failure is no more a PAM decision than a missing service.
    m_lane.onFinished(
        result.rc == PAM_SUCCESS, result.started, result.rc == PAM_AUTHINFO_UNAVAIL || result.infrastructureFailure
    );
  });
  m_lane.setAuthenticatedCallback([this] {
    if (m_onAuthenticated) {
      m_onAuthenticated();
    }
  });
  m_lane.setStatusCallback([this](const face::Status& status) { handleStatus(status); });
}

FaceAuthenticator::~FaceAuthenticator() {
  m_lane.stop();
  m_session.cancel();
  // Reader threads are bounded after a cancel; join them while the main loop and
  // logging still exist.
  InteractivePamSession::joinAllReaders();
  m_registration.reset();
}

void FaceAuthenticator::setAuthenticatedCallback(AuthenticatedCallback callback) {
  m_onAuthenticated = std::move(callback);
}

void FaceAuthenticator::setStatusCallback(StatusCallback callback) { m_onStatus = std::move(callback); }

void FaceAuthenticator::setEnabled(bool enabled) {
  if (enabled == m_enabled) {
    return;
  }
  m_enabled = enabled;
  m_lane.setEnabled(enabled);
  if (!enabled) {
    m_registration->unregister();
  }
}

void FaceAuthenticator::setLockCooldown(std::chrono::milliseconds cooldown) { m_lane.setLockCooldown(cooldown); }

void FaceAuthenticator::beginLock(bool gracePending) { m_lane.beginLock(gracePending); }

void FaceAuthenticator::graceEnded() { m_lane.graceEnded(); }

void FaceAuthenticator::start() {
  if (!m_enabled) {
    return;
  }
  m_lane.start();
}

void FaceAuthenticator::stop() { m_lane.stop(); }

void FaceAuthenticator::retry() { m_lane.retry(); }

void FaceAuthenticator::confirm(face::LanePolicy::Clock::time_point pressedAt) { m_lane.confirm(pressedAt); }

void FaceAuthenticator::declineConfirmation() { m_lane.declineConfirmation(); }

void FaceAuthenticator::noteUserPresence() { m_lane.noteUserPresence(); }

void FaceAuthenticator::setScreenOn(bool on) { m_lane.setScreenOn(on); }

bool FaceAuthenticator::faceServiceInstalled() {
  switch (pam_service::inspectServiceFile(pam_service::kFace)) {
  case pam_service::FileTrust::Trusted:
    m_untrustedServiceReported = false;
    return true;
  case pam_service::FileTrust::Missing:
    kLog.debug("PAM service '{}' is not installed; face lane idle", pam_service::kFace);
    return false;
  case pam_service::FileTrust::Untrusted:
    if (!m_untrustedServiceReported) {
      m_untrustedServiceReported = true;
      kLog.warn(
          "PAM service file for '{}' must be a regular file owned by root and not writable by group or others; "
          "face unlock is off",
          pam_service::kFace
      );
    }
    return false;
  }
  return false;
}

void FaceAuthenticator::ensureTokenMode() {
  if (m_enabled) {
    m_registration->ensureRegistered();
  }
}

void FaceAuthenticator::probeReadiness(std::function<void(face::Readiness readiness)> done) {
  if (m_gaze == nullptr || m_user.empty()) {
    done(face::Readiness{});
    return;
  }
  // Neither call opens the camera. Errors (gazed missing, access denied) leave the
  // decision to PAM, and the lane falls back to a fixed timeout.
  m_gaze->callMethodAsync("HasEnrolledFaces")
      .onInterface(kGazeInterface)
      .withTimeout(kProbeTimeout)
      .withArguments(m_user)
      .uponReplyInvoke([this, done = std::move(done)](std::optional<sdbus::Error> e, bool enrolled) {
        std::optional<bool> hasFaces;
        if (e.has_value()) {
          kLog.debug("HasEnrolledFaces failed: {}", e->what());
        } else {
          hasFaces = enrolled;
        }
        if (hasFaces == false) {
          done(face::Readiness{.enrolled = false, .maxStartDelay = std::nullopt});
          return;
        }
        readStartDelay([done, hasFaces](std::optional<std::chrono::milliseconds> delay) {
          done(face::Readiness{.enrolled = hasFaces, .maxStartDelay = delay});
        });
      });
}

void FaceAuthenticator::readStartDelay(std::function<void(std::optional<std::chrono::milliseconds>)> done) {
  // Config is readable by the active session; its wire layout is frozen by Gaze.
  m_gaze->callMethodAsync("Get")
      .onInterface(kPropertiesInterface)
      .withTimeout(kConfigTimeout)
      .withArguments(std::string(kGazeInterface), std::string("Config"))
      .uponReplyInvoke([done = std::move(done)](std::optional<sdbus::Error> e, const sdbus::Variant& config) {
        if (e.has_value()) {
          kLog.debug("reading Gaze's Config failed: {}", e->what());
          done(std::nullopt);
          return;
        }
        const auto delay = gaze_config::maxStartDelay(config);
        if (!delay.has_value()) {
          kLog.debug("Gaze's Config has an unexpected layout");
        }
        done(delay);
      });
}

bool FaceAuthenticator::startSession() {
  return m_session.start(pam_service::kFace, i18n::Service::instance().language());
}

void FaceAuthenticator::cancelSession() { m_session.cancel(); }

bool FaceAuthenticator::respond(std::string_view text) { return m_session.respond(text); }

bool FaceAuthenticator::abortPrompt() { return m_session.abort(); }

Timer& FaceAuthenticator::timer(TimerSlot slot) {
  switch (slot) {
  case TimerSlot::Delay:
    return m_delayTimer;
  case TimerSlot::Timeout:
    return m_timeoutTimer;
  case TimerSlot::Confirm:
    return m_confirmTimer;
  }
  return m_timeoutTimer;
}

void FaceAuthenticator::startTimer(TimerSlot slot, std::chrono::milliseconds delay, std::function<void()> callback) {
  timer(slot).start(delay, std::move(callback));
}

void FaceAuthenticator::stopTimer(TimerSlot slot) { timer(slot).stop(); }

face::LanePolicy::Clock::time_point FaceAuthenticator::now() { return face::LanePolicy::Clock::now(); }

void FaceAuthenticator::handleStatus(const face::Status& status) {
  if (!m_onStatus) {
    return;
  }
  // Tokens never reach the UI: every Gaze outcome maps to a translated string.
  switch (status.kind) {
  case face::StatusKind::Clear:
    m_onStatus({}, false);
    break;
  case face::StatusKind::Look:
    m_onStatus(i18n::tr("auth.face.look"), false);
    break;
  case face::StatusKind::NotDetected:
    m_onStatus(i18n::tr("auth.face.not-detected"), false);
    break;
  case face::StatusKind::TooDark:
    m_onStatus(i18n::tr("auth.face.too-dark"), false);
    break;
  case face::StatusKind::Unavailable:
    m_onStatus(i18n::tr("auth.face.unavailable"), true);
    break;
  case face::StatusKind::NotRecognized:
    m_onStatus(i18n::tr("auth.face.not-recognized"), true);
    break;
  case face::StatusKind::Failed:
    m_onStatus(i18n::tr("auth.face.failed"), true);
    break;
  case face::StatusKind::Confirm:
    m_onStatus(i18n::tr("lockscreen.face.confirm"), false);
    break;
  case face::StatusKind::ConfirmExpired:
    m_onStatus(i18n::tr("auth.face.confirm-expired"), false);
    break;
  case face::StatusKind::Raw:
    m_onStatus(status.text, status.isError);
    break;
  }
}
