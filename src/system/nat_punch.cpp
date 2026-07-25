/**
 * @file        system/nat_punch.cpp
 * @brief       WAN UDP hole-punch coordinator (see nat_punch.h).
 *
 * @modified    2026 - ReXGlue netplay
 */

#include <rex/system/nat_punch.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <rex/cvar.h>
#include <rex/logging.h>
#include <rex/platform.h>
#include <rex/system/xlive_web_client.h>
#include <rex/system/xsocket.h>

// Declared in xlive_flags.cpp
REXCVAR_DECLARE(bool, xlive_web_enabled);
REXCVAR_DECLARE(int32_t, systemlink_base_port);
REXCVAR_DECLARE(int32_t, systemlink_port_offset);

#if REX_PLATFORM_WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

namespace rex::system {

#define NATP_LOG(...) REXSYS_INFO("[NATPunch] " __VA_ARGS__)

namespace {

// How often to fire punches while peers are present. Tighter than typical NAT
// UDP timeouts (~30s) so mappings never lapse mid-session; also doubles as a
// keepalive.
constexpr int kActiveIntervalMs = 2000;
// When no peers are visible, back off so we're not searching the backend
// constantly during single-player / idle time.
constexpr int kIdleIntervalMs = 8000;

class Impl {
 public:
  static Impl& Get() {
    static Impl instance;
    return instance;
  }

  void Start(uint32_t title_id) {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      title_id_ = title_id;
      if (running_) return;
      running_ = true;
      stop_ = false;
      worker_ = std::thread([this] { Loop(); });
      static std::once_flag atexit_once;
      std::call_once(atexit_once, [] { std::atexit([] { Impl::Get().Stop(); }); });
    }
    NATP_LOG("hole-punch coordinator started for title {:08X}", title_id);
  }

  void Stop() {
    std::thread worker;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (!running_) return;
      stop_ = true;
      worker = std::move(worker_);
      running_ = false;
    }
    cv_.notify_all();
    if (worker.joinable()) worker.join();
  }

 private:
  Impl() = default;
  ~Impl() { Stop(); }

  uint32_t MyPublicNet() {
#if REX_PLATFORM_WIN32
    return XLiveWebClient::Get().public_address_net();
#else
    return 0;
#endif
  }

  static uint32_t ParseIpv4(const std::string& ip) {
#if REX_PLATFORM_WIN32
    return inet_addr(ip.c_str());  // returns network byte order; INADDR_NONE on error
#else
    uint32_t addr = 0;
    inet_pton(AF_INET, ip.c_str(), &addr);
    return addr;
#endif
  }

  void Loop() {
    for (;;) {
      int wait_ms = kIdleIntervalMs;
      if (REXCVAR_GET(xlive_web_enabled)) {
        wait_ms = PunchOnce() ? kActiveIntervalMs : kIdleIntervalMs;
      }

      std::unique_lock<std::mutex> lock(mutex_);
      if (stop_) break;
      cv_.wait_for(lock, std::chrono::milliseconds(wait_ms),
                   [this] { return stop_.load(); });
      if (stop_) break;
    }
  }

  // Returns true if at least one peer was punched (used to pace the loop).
  bool PunchOnce() {
    uint32_t title_id;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      title_id = title_id_;
    }
    if (!title_id) return false;

    auto& wc = XLiveWebClient::Get();
    if (!wc.EnsureReady()) return false;

    // Make THIS instance discoverable so the peer's SearchSessions finds us and
    // punches back. Without this, a joiner (which has no session of its own)
    // is invisible to the host, so the host never punches the joiner and its
    // NAT never opens — hole-punching only works if BOTH sides punch. The stub
    // is property-less, so the game's own lobby search filters it out; only the
    // punch coordinators use it. Idempotent (registers once per lifetime).
    const uint16_t sl_port = static_cast<uint16_t>(REXCVAR_GET(systemlink_base_port) +
                                                   REXCVAR_GET(systemlink_port_offset));
    wc.EnsureHostSession(title_id, sl_port);

    std::vector<WebSession> sessions;
    if (!wc.SearchSessions(title_id, sessions) || sessions.empty()) {
      return false;
    }

    const uint32_t my_pub = MyPublicNet();
    int punched = 0;
    for (const auto& s : sessions) {
      if (s.host_address.empty()) continue;
      const uint32_t peer_ip = ParseIpv4(s.host_address);
      if (peer_ip == 0 || peer_ip == 0xFFFFFFFFu) continue;  // 0 / INADDR_NONE
      // Skip our own session and any peer sharing our public IP: same-public-IP
      // peers are reached over the LAN/loopback path, not by punching our own
      // NAT's external address (which home routers don't hairpin).
      if (my_pub != 0 && peer_ip == my_pub) continue;

      XSocket::PunchAllBoundUdpSockets(peer_ip);
      ++punched;
    }
    return punched > 0;
  }

  std::mutex mutex_;
  std::condition_variable cv_;
  std::thread worker_;
  std::atomic<bool> stop_{false};
  bool running_ = false;
  uint32_t title_id_ = 0;
};

}  // namespace

NatPunchCoordinator& NatPunchCoordinator::Get() {
  static NatPunchCoordinator instance;
  return instance;
}

void NatPunchCoordinator::Start(uint32_t title_id) { Impl::Get().Start(title_id); }

void NatPunchCoordinator::Stop() { Impl::Get().Stop(); }

}  // namespace rex::system
