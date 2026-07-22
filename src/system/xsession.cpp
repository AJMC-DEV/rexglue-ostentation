/**
 * @file        system/xsession.cpp
 * @brief       XSession state and XNet key/address registries.
 *
 * @modified    2026 - ReXGlue NX1-style netplay port
 */

#include <rex/system/xsession.h>

#include <algorithm>
#include <cstring>
#include <random>

#include <rex/platform.h>

#if REX_PLATFORM_WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

namespace rex::system {

// ---------------------------------------------------------------------------
// XSession
// ---------------------------------------------------------------------------

void XSession::CreateHostSession(uint64_t host_xuid, uint32_t flags,
                                 uint32_t slots_public, uint32_t slots_private,
                                 uint32_t public_ip_net, uint16_t port) {
  is_host_        = true;
  active_         = true;
  host_xuid_      = host_xuid;
  flags_          = flags;
  slots_public_   = slots_public;
  slots_private_  = slots_private;
  advertised_port_= port;

  // Generate nonce
  std::random_device rd;
  std::mt19937_64 eng(rd());
  nonce_ = eng();

  // Generate session ID and exchange key from XUID + nonce
  XNetKeyRegistry::GenerateKey(host_xuid, nonce_,
                               session_info_.sessionID,
                               session_info_.exchangeKey);

  // Fill host address: public IP, port, synthetic MAC from XUID
  session_info_.hostAddress.ina       = 0;             // local: unknown
  session_info_.hostAddress.inaOnline = public_ip_net; // set by web client later
  session_info_.hostAddress.wPortOnline = htons(port);
  // Synthetic MAC: low 6 bytes of XUID
  for (int i = 0; i < 6; ++i)
    session_info_.hostAddress.abEnet[i] = static_cast<uint8_t>(host_xuid >> (i * 8));
  std::memset(session_info_.hostAddress.abOnline, 0, 20);
}

void XSession::CreateClientSession(const XSESSION_INFO& info, uint64_t host_xuid,
                                   uint32_t flags, uint32_t slots_public,
                                   uint32_t slots_private) {
  is_host_        = false;
  active_         = true;
  host_xuid_      = host_xuid;
  flags_          = flags;
  slots_public_   = slots_public;
  slots_private_  = slots_private;
  session_info_   = info;
  nonce_          = 0;
}

void XSession::Destroy() {
  active_          = false;
  is_host_         = false;
  web_session_id_.clear();
}

// ---------------------------------------------------------------------------
// XNetKeyRegistry
// ---------------------------------------------------------------------------

static XNetKeyRegistry g_net_key_registry;
XNetKeyRegistry& XNetKeyRegistry::Get() { return g_net_key_registry; }

uint64_t XNetKeyRegistry::KeyOf(const XNKID& id) {
  uint64_t v = 0;
  std::memcpy(&v, id.ab, 8);
  return v;
}

void XNetKeyRegistry::GenerateKey(uint64_t xuid, uint64_t nonce,
                                  XNKID& out_id, XNKEY& out_key) {
  // Mix XUID and nonce into the 8-byte session ID.
  // The XNKID high nibble of ab[0] must be 0x31–0x3F for system link sessions
  // (bit pattern: 0x3x where x is 1-F per Xbox 360 docs).
  uint64_t raw = xuid ^ (nonce * 0x9e3779b97f4a7c15ULL);
  std::memcpy(out_id.ab, &raw, 8);
  out_id.ab[0] = 0x31u | (out_id.ab[0] & 0x0Fu);  // force System Link ID flag

  // Exchange key: expand to 16 bytes using a simple scramble.
  uint64_t k0 = nonce ^ 0xDEADBEEFCAFEBABEULL;
  uint64_t k1 = xuid  ^ 0x0123456789ABCDEFULL;
  std::memcpy(out_key.ab + 0, &k0, 8);
  std::memcpy(out_key.ab + 8, &k1, 8);
}

bool XNetKeyRegistry::Register(const XNKID& id, const XNKEY& key) {
  std::lock_guard<std::mutex> lk(mtx_);
  table_[KeyOf(id)] = key;
  active_id_        = id;
  return true;
}

bool XNetKeyRegistry::Unregister(const XNKID& id) {
  std::lock_guard<std::mutex> lk(mtx_);
  auto it = table_.find(KeyOf(id));
  if (it == table_.end()) return false;
  table_.erase(it);
  if (active_id_ == id)
    std::memset(active_id_.ab, 0, 8);
  return true;
}

bool XNetKeyRegistry::Lookup(const XNKID& id, XNKEY& out_key) const {
  std::lock_guard<std::mutex> lk(mtx_);
  auto it = table_.find(KeyOf(id));
  if (it == table_.end()) return false;
  out_key = it->second;
  return true;
}

// ---------------------------------------------------------------------------
// XNetAddrCache
// ---------------------------------------------------------------------------

static XNetAddrCache g_addr_cache;
XNetAddrCache& XNetAddrCache::Get() { return g_addr_cache; }

uint32_t XNetAddrCache::Store(const XNADDR& addr, const XNKID& kid) {
  std::lock_guard<std::mutex> lk(mtx_);

  // Check if already cached by public IP
  for (auto& [tok, entry] : table_) {
    if (entry.xn_addr.inaOnline == addr.inaOnline &&
        entry.xn_addr.ina == addr.ina &&
        entry.xn_addr.wPortOnline == addr.wPortOnline) {
      return tok;
    }
  }

  uint32_t token = next_token_++;
  table_[token]  = {addr, kid};
  return token;
}

bool XNetAddrCache::Lookup(uint32_t in_addr_token, XNetAddrEntry& out) const {
  std::lock_guard<std::mutex> lk(mtx_);
  auto it = table_.find(in_addr_token);
  if (it == table_.end()) return false;
  out = it->second;
  return true;
}

bool XNetAddrCache::FindByPublicIp(uint32_t public_ip_net, XNetAddrEntry& out) const {
  std::lock_guard<std::mutex> lk(mtx_);
  for (auto& [tok, entry] : table_) {
    if (entry.xn_addr.inaOnline == public_ip_net) {
      out = entry;
      return true;
    }
  }
  return false;
}

}  // namespace rex::system

namespace rex::system {
static XSession g_active_session;
XSession& GetActiveSession() { return g_active_session; }
}
