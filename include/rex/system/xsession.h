#pragma once
/**
 * @file        system/xsession.h
 * @brief       Local XSession state - mirrors the Xbox 360 XSESSION_INFO that
 *              the game fills when it calls XSessionCreate through XGI.
 *
 * @modified    2026 - ReXGlue NX1-style netplay port
 */

#include <array>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>

namespace rex::system {

// ---------------------------------------------------------------------------
// Xbox 360 XNet key / address types (host byte order unless noted)
// ---------------------------------------------------------------------------

/// 8-byte System Link session identifier.
struct XNKID {
  uint8_t ab[8];
  bool operator==(const XNKID& o) const { return std::memcmp(ab, o.ab, 8) == 0; }
  bool operator!=(const XNKID& o) const { return !(*this == o); }
  bool IsZero() const {
    for (auto b : ab) if (b) return false;
    return true;
  }
};

/// 16-byte exchange key.
struct XNKEY {
  uint8_t ab[16];
};

/// Xbox Network Address (36 bytes, host layout matching guest memory).
/// Fields stored in network byte order where the 360 stores them that way.
struct XNADDR {
  uint32_t ina;        ///< Local IP (network byte order)
  uint32_t inaOnline;  ///< Public/online IP (network byte order)
  uint16_t wPortOnline;
  uint8_t  abEnet[6];
  uint8_t  abOnline[20];
};

/// XSESSION_INFO as laid out in guest memory (big-endian fields).
/// Matches the 360 SDK XSessionCreate output buffer.
struct XSESSION_INFO {
  XNKID  sessionID;    ///< 8 bytes
  XNADDR hostAddress;  ///< 36 bytes
  XNKEY  exchangeKey;  ///< 16 bytes
};
static_assert(sizeof(XSESSION_INFO) == 60, "XSESSION_INFO size mismatch");

// ---------------------------------------------------------------------------
// XSession – local session state
// ---------------------------------------------------------------------------

class XSession {
 public:
  XSession() = default;
  ~XSession() = default;

  // Non-copyable
  XSession(const XSession&) = delete;
  XSession& operator=(const XSession&) = delete;

  // -------------------------------------------------------------------------
  // State
  // -------------------------------------------------------------------------

  bool is_host()    const { return is_host_; }
  bool is_active()  const { return active_; }

  uint64_t xuid()         const { return host_xuid_; }
  uint32_t flags()        const { return flags_; }
  uint32_t slots_public() const { return slots_public_; }
  uint32_t slots_private()const { return slots_private_; }
  uint16_t advertised_port() const { return advertised_port_; }
  uint64_t nonce()        const { return nonce_; }

  const XNKID& session_id()   const { return session_info_.sessionID; }
  const XNKEY& exchange_key() const { return session_info_.exchangeKey; }
  const XSESSION_INFO& session_info() const { return session_info_; }

  /// Web-side UUID string returned by POST /sessions (empty until posted).
  const std::string& web_session_id() const { return web_session_id_; }
  void set_web_session_id(std::string id)   { web_session_id_ = std::move(id); }

  // -------------------------------------------------------------------------
  // Init helpers
  // -------------------------------------------------------------------------

  /// Initialise as a host session.  Fills session_info with generated IDs.
  void CreateHostSession(uint64_t host_xuid, uint32_t flags,
                         uint32_t slots_public, uint32_t slots_private,
                         uint32_t public_ip_net,   ///< network byte order
                         uint16_t port);

  /// Initialise from a remote infoResponse (join path).
  void CreateClientSession(const XSESSION_INFO& info, uint64_t host_xuid,
                           uint32_t flags, uint32_t slots_public,
                           uint32_t slots_private);

  void Destroy();

 private:
  bool     active_        = false;
  bool     is_host_       = false;
  uint64_t host_xuid_     = 0;
  uint32_t flags_         = 0;
  uint32_t slots_public_  = 8;
  uint32_t slots_private_ = 0;
  uint16_t advertised_port_ = 1001;
  uint64_t nonce_         = 0;

  XSESSION_INFO session_info_{};
  std::string   web_session_id_;
};

// ---------------------------------------------------------------------------
// XNetKeyRegistry – maps active XNKID ↔ XNKEY for System Link
// ---------------------------------------------------------------------------

class XNetKeyRegistry {
 public:
  static XNetKeyRegistry& Get();

  /// Generate a new XNKID+XNKEY pair derived from XUID and a nonce.
  static void GenerateKey(uint64_t xuid, uint64_t nonce,
                          XNKID& out_id, XNKEY& out_key);

  /// Register a key. Returns false if the registry is full.
  bool Register(const XNKID& id, const XNKEY& key);
  bool Unregister(const XNKID& id);
  bool Lookup(const XNKID& id, XNKEY& out_key) const;

  /// The most recently registered key (used as the active System Link session).
  const XNKID& active_id() const { return active_id_; }

 private:
  mutable std::mutex          mtx_;
  std::unordered_map<uint64_t, XNKEY> table_;  // key = first 8 bytes as u64
  XNKID                       active_id_{};

  static uint64_t KeyOf(const XNKID& id);
};

// ---------------------------------------------------------------------------
// XNetAddrCache – maps synthetic IN_ADDR tokens ↔ XNADDR/XNKID
// ---------------------------------------------------------------------------

struct XNetAddrEntry {
  XNADDR xn_addr;
  XNKID  xn_kid;
};

class XNetAddrCache {
 public:
  static XNetAddrCache& Get();

  /// Store a mapping and return the synthetic IN_ADDR token (host byte order).
  uint32_t Store(const XNADDR& addr, const XNKID& kid);

  /// Retrieve the entry for a given IN_ADDR token. Returns false if not found.
  bool Lookup(uint32_t in_addr_token, XNetAddrEntry& out) const;

  /// Attempt to find an entry by public IP (for /players/find path).
  bool FindByPublicIp(uint32_t public_ip_net, XNetAddrEntry& out) const;

 private:
  mutable std::mutex                     mtx_;
  std::unordered_map<uint32_t, XNetAddrEntry> table_;
  uint32_t next_token_ = 0xAB000001;  ///< Synthetic handle counter
};

}  // namespace rex::system

namespace rex::system {
/// The single active session for this process (host or client).
XSession& GetActiveSession();
}  // namespace rex::system
