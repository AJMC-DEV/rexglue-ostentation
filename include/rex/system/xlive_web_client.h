#pragma once
/**
 * @file        system/xlive_web_client.h
 * @brief       HTTP REST client for the XLive web netplay API.
 *
 *   Control plane:   discovery, session create/search/join/leave/delete, QoS.
 *   Data plane:      direct UDP between players (unchanged – XSocket layer).
 *
 * @modified    2026 - ReXGlue NX1-style netplay port
 */

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace rex::system {

// ---------------------------------------------------------------------------
// Lightweight JSON helpers (no external dependency)
// ---------------------------------------------------------------------------
namespace json {
/// Extract a string value for a given key from a flat JSON object.
/// Returns empty string if not found.
std::string GetString(const std::string& json, const std::string& key);

/// Extract a uint32 / uint64 value for a given key.
uint64_t GetUInt64(const std::string& json, const std::string& key);
uint32_t GetUInt32(const std::string& json, const std::string& key);

/// Extract an array of JSON objects (one-level deep).
std::vector<std::string> GetArray(const std::string& json, const std::string& key);
}  // namespace json

// ---------------------------------------------------------------------------
// Session descriptor returned by /sessions/search
// ---------------------------------------------------------------------------
struct WebSession {
  std::string session_id;      ///< Web UUID
  std::string host_address;    ///< Public IPv4 string
  uint16_t    port      = 0;
  std::string mac_address;     ///< Hex string
  std::string xnkid_hex;       ///< 16 hex chars (8 bytes)
  std::string xnkey_hex;       ///< 32 hex chars (16 bytes)
  uint32_t    slots_public  = 0;
  uint32_t    slots_private = 0;
  uint32_t    open_public    = 0;  ///< openPublicSlotsCount
  uint32_t    open_private   = 0;  ///< openPrivateSlotsCount
  uint32_t    filled_public  = 0;  ///< filledPublicSlotsCount
  uint32_t    filled_private = 0;  ///< filledPrivateSlotsCount
  uint64_t    host_xuid   = 0;
  uint32_t    port_offset = 0;
  uint64_t    nonce       = 0;
};

// ---------------------------------------------------------------------------
// XLiveWebClient
// ---------------------------------------------------------------------------
class XLiveWebClient {
 public:
  /// Singleton accessor.
  static XLiveWebClient& Get();

  // -------------------------------------------------------------------------
  // Initialisation
  // -------------------------------------------------------------------------

  /// Perform startup probes (whoami, register player).
  /// Called lazily on first netplay operation. Thread-safe.
  bool EnsureReady();

  /// True once EnsureReady() has succeeded.
  bool is_ready() const { return ready_; }

  /// True once the player has been successfully registered on the backend.
  bool is_registered() const { return registered_ok_; }

  /// Identity used for the last registration (empty until EnsureReady()).
  const std::string& registered_xuid() const { return registered_xuid_; }
  const std::string& registered_mac() const { return registered_mac_; }

  /// Public IPv4 address (dotted decimal) from /whoami.
  const std::string& public_address() const { return public_address_; }
  uint32_t           public_address_net() const;  ///< network byte order

  // -------------------------------------------------------------------------
  // Players
  // -------------------------------------------------------------------------
  bool RegisterPlayer(uint64_t xuid, const std::string& gamertag,
                      const std::string& machine_id);

  // -------------------------------------------------------------------------
  // Sessions
  // -------------------------------------------------------------------------
  bool CreateSession(uint32_t title_id, const WebSession& info,
                     std::string& out_session_id);

  bool SearchSessions(uint32_t title_id,
                      std::vector<WebSession>& out_sessions);

  bool FetchSession(uint32_t title_id, const std::string& session_id,
                    WebSession& out);

  /// Fetch a session's advertised properties/contexts. Each returned blob is a
  /// base64-decoded serialized property: [property_id LE u32 (4)]
  /// [X_USER_DATA (16): type@0, union@8 big-endian][extended string/blob bytes].
  /// A context is just a property whose X_USER_DATA type == 0 (CONTEXT).
  bool GetSessionProperties(uint32_t title_id, const std::string& session_id,
                            std::vector<std::vector<uint8_t>>& out);

  bool JoinSession(uint32_t title_id, const std::string& session_id,
                   uint64_t xuid);

  bool PrejoinSession(uint32_t title_id, const std::string& session_id,
                      uint64_t xuid);

  bool LeaveSession(uint32_t title_id, const std::string& session_id,
                    uint64_t xuid);

  bool DeleteSession(uint32_t title_id, const std::string& session_id);

  bool DeleteStaleSessions(bool by_mac, const std::string& mac_or_empty);

  // -------------------------------------------------------------------------
  // QoS
  // -------------------------------------------------------------------------
  bool UploadQos(uint32_t title_id, const std::string& session_id,
                 const std::vector<uint8_t>& data);

  bool DownloadQos(uint32_t title_id, const std::string& session_id,
                   std::vector<uint8_t>& out_data);

  // -------------------------------------------------------------------------
  // Players/find
  // -------------------------------------------------------------------------
  bool FindPlayerByIp(const std::string& ip, WebSession& out_info);

  // Auto-register this instance as a discoverable host session so the
  // broadcast bridge can forward discovery probes from other instances.
  // Safe to call repeatedly – only registers once per lifetime.
  bool EnsureHostSession(uint32_t title_id, uint16_t port);

 public:
  XLiveWebClient() = default;
  ~XLiveWebClient() = default;

 private:
  // Internal HTTP helpers
  bool HttpGet(const std::string& path, std::string& out_body);
  bool HttpPost(const std::string& path, const std::string& body, std::string& out_body);
  bool HttpDelete(const std::string& path, std::string& out_body);

  bool ParseWebSession(const std::string& json_obj, WebSession& out);

  std::string BaseUrl() const;
  std::string SessionsPath(uint32_t title_id) const;
  std::string SessionPath(uint32_t title_id, const std::string& id) const;

  mutable std::mutex mtx_;
  bool ready_         = false;
  bool startup_tried_ = false;
  bool registered_ok_ = false;

  std::string public_address_;
  std::string registered_xuid_;
  std::string registered_mac_;

  // Auto-hosted session (registered from broadcast bridge, not from XGI)
  bool        auto_host_tried_      = false;
  std::string auto_host_session_id_;
};

}  // namespace rex::system
