#pragma once
/**
 * @file        system/upnp.h
 * @brief       Automatic NAT traversal via UPnP IGD port forwarding.
 *
 *   ~60% of players can't or won't set up manual port forwarding, which is the
 *   single most common reason a hosted System Link/XLink session is
 *   unreachable from the internet. This manager asks the home router (an
 *   InternetGatewayDevice) to forward the netplay UDP ports to this machine
 *   automatically, replicating what a manual port-forward rule does.
 *
 *   Discovery (SSDP) and the SOAP AddPortMapping/DeletePortMapping calls run on
 *   a background worker so the guest's bind() path never blocks. Mappings are
 *   created with a finite lease and periodically renewed; they are also deleted
 *   on clean shutdown. Should the process crash, the lease guarantees the
 *   router eventually reclaims the mapping on its own.
 *
 * @modified    2026 - ReXGlue netplay
 */

#include <cstdint>

namespace rex::system {

class UpnpManager {
 public:
  static UpnpManager& Get();

  // Request that {port, UDP or TCP} be forwarded from the router's WAN side to
  // this machine's LAN address. Non-blocking and idempotent: the port is queued
  // and the background worker performs discovery (once) and the SOAP call, then
  // keeps the mapping's lease renewed for the lifetime of the process. Safe to
  // call before the router has been discovered and safe to call repeatedly for
  // the same port. Does nothing when the upnp_enabled cvar is false.
  void RequestMapping(uint16_t port, bool udp = true);

  // True once an InternetGatewayDevice has been found and its control endpoint
  // resolved. Purely informational (e.g. for an overlay status line).
  bool is_available() const;

  // Best-effort synchronous teardown of every mapping we created, then stop the
  // worker thread. Called on clean shutdown; also runs via atexit so callers
  // don't strictly have to invoke it.
  void Shutdown();

 private:
  UpnpManager() = default;
  ~UpnpManager() = default;
  UpnpManager(const UpnpManager&) = delete;
  UpnpManager& operator=(const UpnpManager&) = delete;
};

}  // namespace rex::system
