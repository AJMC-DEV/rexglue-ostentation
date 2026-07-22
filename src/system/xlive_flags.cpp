/**
 * @file        xlive_flags.cpp
 * @brief       CVars for the XLive web netplay system.
 *
 * @modified    2026 - ReXGlue NX1-style netplay port
 */

#include <rex/cvar.h>

// ---------------------------------------------------------------------------
// User identity
// ---------------------------------------------------------------------------
REXCVAR_DEFINE_STRING(user_gamertag, "Player", "XLive", "Gamertag shown to other players.");
REXCVAR_DEFINE_STRING(user_xuid, "", "XLive",
                      "64-bit XUID in hex (e.g. B13EBABEBABEBABE). "
                      "Leave empty to derive from gamertag + machine ID.")
    .lifecycle(rex::cvar::Lifecycle::kInitOnly);

// ---------------------------------------------------------------------------
// Web client
// ---------------------------------------------------------------------------
REXCVAR_DEFINE_BOOL(xlive_web_enabled, false, "XLive",
                    "Enable XLive web netplay (requires internet access).")
    .lifecycle(rex::cvar::Lifecycle::kInitOnly);

REXCVAR_DEFINE_STRING(xlive_web_api_address,
                      "https://xenia-netplay-2a0298c0e3f4.herokuapp.com/", "XLive",
                      "Base URL for the XLive web API.");

REXCVAR_DEFINE_INT32(xlive_web_timeout_ms, 3000, "XLive", "HTTP request timeout in milliseconds.")
    .range(500, 30000);

REXCVAR_DEFINE_BOOL(xlive_web_log_requests, false, "XLive",
                    "Log all HTTP requests and responses.");

REXCVAR_DEFINE_BOOL(xlive_web_probe_on_startup, true, "XLive",
                    "Call /whoami and register player on first use.");

REXCVAR_DEFINE_BOOL(xlive_web_advertise_systemlink, true, "XLive",
                    "Post hosted sessions to the web API.");

// ---------------------------------------------------------------------------
// Session cleanup
// ---------------------------------------------------------------------------
REXCVAR_DEFINE_BOOL(xlive_web_delete_stale_on_startup, true, "XLive",
                    "Delete stale sessions for this profile at startup.");

REXCVAR_DEFINE_BOOL(xlive_web_delete_session_on_end, true, "XLive",
                    "Delete the hosted session when XSessionEnd is called.");

REXCVAR_DEFINE_BOOL(xlive_web_prune_profile_on_session_end, true, "XLive",
                    "Prune stale sessions for this profile when a session ends.");

REXCVAR_DEFINE_BOOL(xlive_web_delete_stale_for_public_ip, false, "XLive",
                    "Delete stale sessions from any profile sharing this public IP at startup.");

REXCVAR_DEFINE_BOOL(xlive_web_prune_public_ip_on_shutdown, true, "XLive",
                    "Prune all sessions from this public IP on clean shutdown.");

// ---------------------------------------------------------------------------
// LAN bridge / broadcast synthesis
// ---------------------------------------------------------------------------
REXCVAR_DEFINE_BOOL(xlive_web_bridge_systemlink_broadcast, true, "XLive",
                    "Intercept System Link broadcast probes and query the web API.");

REXCVAR_DEFINE_INT32(xlive_web_bridge_broadcast_cache_ms, 2000, "XLive",
                     "How long (ms) to cache web session search results.")
    .range(500, 10000);

REXCVAR_DEFINE_INT32(xlive_web_bridge_broadcast_max_hosts, 32, "XLive",
                     "Maximum number of remote sessions to synthesize.")
    .range(1, 64);

REXCVAR_DEFINE_BOOL(xlive_web_bridge_log_packets, false, "XLive",
                    "Log synthesized LAN packets. Keep off during real play.");

REXCVAR_DEFINE_BOOL(xlive_web_bridge_synthesize_lan_info, true, "XLive",
                    "Build fake infoResponse packets from web sessions.");

REXCVAR_DEFINE_BOOL(xlive_web_bridge_loopback_same_public_ip, true, "XLive",
                    "Rewrite same-public-IP joins to loopback (127.0.0.1).");

// ---------------------------------------------------------------------------
// LAN awareness
// ---------------------------------------------------------------------------
REXCVAR_DEFINE_STRING(lan_ip, "", "XLive",
                      "LAN IPv4 address advertised to same-subnet System Link peers. "
                      "Empty = auto-detect from the default-route interface.");

REXCVAR_DEFINE_BOOL(systemlink_lan_discovery, true, "XLive",
                    "Also emit System Link discovery probes as real UDP broadcasts so "
                    "peers on the same LAN (sharing one public IP) can hear them.");

// ---------------------------------------------------------------------------
// System Link ports
// ---------------------------------------------------------------------------
REXCVAR_DEFINE_INT32(systemlink_base_port, 1001, "XLive",
                     "Base UDP port for System Link traffic.")
    .range(1024, 65000)
    .lifecycle(rex::cvar::Lifecycle::kInitOnly);

REXCVAR_DEFINE_INT32(systemlink_port_offset, 0, "XLive",
                     "Port offset added to the base port (use different values for "
                     "multiple local instances).")
    .range(0, 60000)
    .lifecycle(rex::cvar::Lifecycle::kInitOnly);

// ---------------------------------------------------------------------------
// QoS tuning
// ---------------------------------------------------------------------------
REXCVAR_DEFINE_INT32(xlive_web_qos_rtt_min_ms, 35, "XLive",
                     "Minimum RTT reported to the game via QoS.")
    .range(1, 1000);

REXCVAR_DEFINE_INT32(xlive_web_qos_rtt_median_ms, 70, "XLive",
                     "Median RTT reported to the game via QoS. "
                     "Increase to 100-120 for WAN to avoid rubber-banding.")
    .range(1, 2000);

REXCVAR_DEFINE_INT32(xlive_web_qos_up_bits_per_second, 8388608, "XLive",
                     "Upstream bandwidth reported via QoS.")
    .range(1024, 1000000000);

REXCVAR_DEFINE_INT32(xlive_web_qos_down_bits_per_second, 8388608, "XLive",
                     "Downstream bandwidth reported via QoS.")
    .range(1024, 1000000000);
