/**
 * @file        system/xlive_commands.cpp
 * @brief       Console commands for maintaining XLive web sessions.
 *
 *   A crashed or force-closed instance leaves its session registered on the
 *   backend, where it keeps showing up in other players' searches and absorbs
 *   join attempts that can never succeed. These commands clear that state by
 *   hand.
 *
 * @modified    2026 - ReXGlue netplay
 */

#include <string>

#include <rex/cvar.h>
#include <rex/logging.h>
#include <rex/system/xlive_web_client.h>

// Declared in xlive_flags.cpp
REXCVAR_DECLARE(bool, xlive_web_enabled);

namespace {

#define XLIVE_LOG(...) REXSYS_INFO("[XLive] " __VA_ARGS__)
#define XLIVE_WARN(...) REXSYS_WARN("[XLive] " __VA_ARGS__)

// Both commands run on the caller's thread (console/UI) and issue a blocking
// HTTP DELETE bounded by the xlive_web_timeout_ms cvar. That is fine for a
// manual command but is why neither is wired into any automatic path.
bool PruneReady(rex::system::XLiveWebClient*& out) {
  if (!REXCVAR_GET(xlive_web_enabled)) {
    XLIVE_WARN("prune: xlive_web_enabled is false, nothing to do");
    return false;
  }
  auto& wc = rex::system::XLiveWebClient::Get();
  if (!wc.EnsureReady()) {
    XLIVE_WARN("prune: web client not ready (backend unreachable?)");
    return false;
  }
  out = &wc;
  return true;
}

}  // namespace

// Deletes every session the backend associates with this public IP. The backend
// infers the address from the request itself, so no argument is needed.
//
// Behind NAT this covers every console sharing the connection -- it will also
// delete a session someone else on the same network is legitimately hosting.
// Prefer xlive_web_prune_my_sessions when that matters.
REXCVAR_DEFINE_COMMAND(
    xlive_web_prune_sessions,
    []() {
      rex::system::XLiveWebClient* wc = nullptr;
      if (!PruneReady(wc)) return;
      const bool ok = wc->DeleteStaleSessions(/*by_mac=*/false, "");
      XLIVE_LOG("prune sessions for public IP {} -> {}", wc->public_address(),
                ok ? "ok" : "FAILED");
    },
    "XLive",
    "Delete stale XLive web sessions created from this public IP");

// Deletes only the sessions registered to this machine's synthetic MAC, leaving
// other consoles behind the same NAT alone.
REXCVAR_DEFINE_COMMAND(
    xlive_web_prune_my_sessions,
    []() {
      rex::system::XLiveWebClient* wc = nullptr;
      if (!PruneReady(wc)) return;
      const std::string& mac = wc->registered_mac();
      if (mac.empty()) {
        XLIVE_WARN("prune: no registered MAC yet");
        return;
      }
      const bool ok = wc->DeleteStaleSessions(/*by_mac=*/true, mac);
      XLIVE_LOG("prune sessions for MAC {} -> {}", mac, ok ? "ok" : "FAILED");
    },
    "XLive",
    "Delete stale XLive web sessions created by this machine only");
