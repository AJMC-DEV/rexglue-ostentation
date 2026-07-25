#pragma once
/**
 * @file        system/nat_punch.h
 * @brief       WAN UDP hole-punch coordinator for zero-config internet netplay.
 *
 *   Home routers drop unsolicited inbound UDP, which is why a hosted session is
 *   unreachable without port forwarding or UPnP. Hole punching sidesteps that:
 *   if BOTH peers send UDP to each other's public endpoint at about the same
 *   time, each side's NAT opens a mapping for the other and traffic flows — no
 *   router configuration at all.
 *
 *   The backend session registry is the rendezvous: both host and joiner
 *   register discoverable sessions, so SearchSessions() hands each peer the
 *   other's public IP. This coordinator runs a background loop that repeatedly
 *   fires punch datagrams at every discovered peer from the title's bound UDP
 *   sockets, keeping both NAT mappings open for the life of the session.
 *
 *   Covers the common home-router case (endpoint-independent / port-preserving
 *   NAT). Symmetric NAT and CGNAT still can't be punched — those need a relay.
 *
 * @modified    2026 - ReXGlue netplay
 */

#include <cstdint>

namespace rex::system {

class NatPunchCoordinator {
 public:
  static NatPunchCoordinator& Get();

  // Begin (or keep) hole-punching toward peers of this title's sessions.
  // Idempotent and cheap to call on every socket bind / session create. Does
  // nothing while the upnp/web netplay path is disabled.
  void Start(uint32_t title_id);

  // Stop the background loop. Called on clean shutdown; also runs via atexit.
  void Stop();

 private:
  NatPunchCoordinator() = default;
  ~NatPunchCoordinator() = default;
  NatPunchCoordinator(const NatPunchCoordinator&) = delete;
  NatPunchCoordinator& operator=(const NatPunchCoordinator&) = delete;
};

}  // namespace rex::system
