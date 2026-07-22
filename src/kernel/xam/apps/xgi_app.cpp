/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2021 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 *
 * @modified    Tom Clay, 2026 - Adapted for ReXGlue runtime
 */

#include <rex/kernel/xam/apps/xgi_app.h>

#include <fmt/format.h>

#include <rex/cvar.h>
#include <rex/logging.h>
#include <rex/system/xlive_web_client.h>
#include <rex/system/xsession.h>
#include <rex/thread.h>

#include <cstdio>
#include <cstring>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

#if REX_PLATFORM_WIN32
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

REXCVAR_DECLARE(bool,    xlive_web_enabled);
REXCVAR_DECLARE(int32_t, systemlink_base_port);
REXCVAR_DECLARE(int32_t, systemlink_port_offset);

namespace rex {
namespace kernel {
namespace xam {
using namespace rex::system;
using namespace rex::system::xam;
namespace apps {
using namespace rex::system;

// Parse a hex string (must be exactly 2*out_len chars) into raw bytes.
static bool HexToBytes(const std::string& hex, uint8_t* out, size_t out_len) {
  if (hex.size() != out_len * 2) return false;
  for (size_t i = 0; i < out_len; ++i) {
    unsigned byte = 0;
    if (std::sscanf(hex.c_str() + i * 2, "%02x", &byte) != 1) return false;
    out[i] = static_cast<uint8_t>(byte);
  }
  return true;
}

static std::string ToHex(const uint8_t* data, size_t len) {
  std::string out;
  out.reserve(len * 2);
  static const char hex_digits[] = "0123456789abcdef";
  for (size_t i = 0; i < len; ++i) {
    out += hex_digits[(data[i] >> 4) & 0xF];
    out += hex_digits[data[i] & 0xF];
  }
  return out;
}

// Write an IPv4 address string to 4 bytes in network byte order (big-endian).
static void WriteIPNBO(uint8_t* dst, const std::string& ip_str) {
  unsigned a = 0, b = 0, c = 0, d = 0;
  if (std::sscanf(ip_str.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
    dst[0] = static_cast<uint8_t>(a);
    dst[1] = static_cast<uint8_t>(b);
    dst[2] = static_cast<uint8_t>(c);
    dst[3] = static_cast<uint8_t>(d);
  } else {
    std::memset(dst, 0, 4);
  }
}

// Fetch the session's advertised properties/contexts from the backend and write
// them into the XSESSION_SEARCHRESULT (contexts_count @0x50, contexts_ptr @0x58,
// properties_count @0x4C, properties_ptr @0x54). This is REQUIRED, not cosmetic:
// titles look up specific advertised properties by id (e.g. Viva Piñata reads
// property 0x40000809, a unicode string) and dereference the returned pointer;
// if the property is absent the lookup returns 0 and the guest faults reading
// NULL+0xC. Mirrors netplay GetSessions -> FillSessionContext/FillSessionProperties.
//
// Each backend blob is a serialized xam::Property:
//   [property_id LE u32 (4)][X_USER_DATA (16): type@0, pad, union@8 big-endian]
//   [extended bytes]  (extended present only for WSTRING/BINARY)
// A context is a property whose X_USER_DATA type == 0 (CONTEXT).
//
// Guest XUSER_PROPERTY (0x18): property_id(be)@0, pad@4, X_USER_DATA@8
//   (type@8, union@0x10: {size@0x10, ptr@0x14} for string/blob).
// Guest XUSER_CONTEXT (0x8): context_id(be)@0, value(be)@4.
// Defined below in the host-advertised-attributes section.
namespace {
constexpr uint32_t kPropGamerHostname = 0x40008109;  // XPROPERTY_GAMER_HOSTNAME
constexpr uint32_t kPropGamerPuid     = 0x20008107;  // XPROPERTY_GAMER_PUID
std::vector<uint8_t> BuildContextBlob(uint32_t id, uint32_t value);
std::vector<uint8_t> BuildPropertyBlob(uint32_t id, const uint8_t* val,
                                       uint32_t val_size);
std::vector<uint8_t> BuildHostnameBlob(const std::string& tag);
std::vector<uint8_t> BuildPuidBlob(uint64_t xuid);
}  // namespace

// Writes the session's advertised properties/contexts into the search result.
// `blobs` is the pre-fetched property set from GetSessionProperties — fetched by
// the caller so it can SKIP sessions with no properties before writing anything.
static void WriteSessionAttrs(memory::Memory* mem, uint8_t* r,
                              std::vector<std::vector<uint8_t>> blobs,
                              uint32_t ctx_ptr, uint32_t num_ctx,
                              uint32_t props_ptr, uint32_t num_props) {
  enum : uint8_t { kTypeContext = 0, kTypeWString = 4, kTypeBinary = 6 };

  auto rd_le32 = [](const uint8_t* p) -> uint32_t {
    return p[0] | (p[1] << 8) | (p[2] << 16) | (uint32_t(p[3]) << 24);
  };

  // --- Joiner-side safety net -----------------------------------------------
  // Titles dereference specific attribute lookups from the result without a
  // null check. If the host never advertised them (stale session, old build),
  // synthesize placeholders so the guest doesn't fault:
  //  1. System props netplay always uploads (GAMER_HOSTNAME wstring, GAMER_PUID
  //     int64) — Viva Piñata wcsncpy's the hostname string (NULL+0xC crash).
  //  2. The game's own search-filter contexts/properties — titles read back the
  //     ids they filtered by.
  auto has_id = [&](uint32_t id) {
    for (const auto& b : blobs) {
      if (b.size() >= 20 && rd_le32(b.data()) == id) return true;
    }
    return false;
  };

  uint32_t synth_count = 0;
  if (!has_id(kPropGamerHostname)) {
    blobs.push_back(BuildHostnameBlob("Player"));
    ++synth_count;
  }
  if (!has_id(kPropGamerPuid)) {
    blobs.push_back(BuildPuidBlob(0));
    ++synth_count;
  }
  if (props_ptr && num_props) {
    const uint8_t* fp = mem->TranslateVirtual(props_ptr);
    for (uint32_t i = 0; fp && i < num_props && i < 32; ++i) {
      const uint8_t* p = fp + i * 0x18;  // guest XUSER_PROPERTY
      uint32_t id = memory::load_and_swap<uint32_t>(p + 0);
      if (!id || has_id(id)) continue;
      uint8_t type = p[8];
      if (type == kTypeWString || type == kTypeBinary) {
        uint32_t size = memory::load_and_swap<uint32_t>(p + 0x10);
        uint32_t gptr = memory::load_and_swap<uint32_t>(p + 0x14);
        if (size > 0x400) size = 0x400;
        const uint8_t* ext = gptr ? mem->TranslateVirtual(gptr) : nullptr;
        blobs.push_back(BuildPropertyBlob(id, ext, ext ? size : 0));
      } else {
        blobs.push_back(BuildPropertyBlob(id, p + 0x10, 8));
      }
      ++synth_count;
    }
  }
  if (ctx_ptr && num_ctx) {
    const uint8_t* fc = mem->TranslateVirtual(ctx_ptr);
    for (uint32_t i = 0; fc && i < num_ctx && i < 32; ++i) {
      const uint8_t* c = fc + i * 0x8;  // guest XUSER_CONTEXT
      uint32_t id = memory::load_and_swap<uint32_t>(c + 0);
      uint32_t value = memory::load_and_swap<uint32_t>(c + 4);
      if (!id || has_id(id)) continue;
      blobs.push_back(BuildContextBlob(id, value));
      ++synth_count;
    }
  }
  if (synth_count) {
    REXKRNL_INFO("  session attrs: synthesized {} missing attrs for joiner safety",
                 synth_count);
  }

  // Split contexts vs properties by X_USER_DATA type (blob[4]). Done after all
  // appends — pushing to `blobs` would invalidate these pointers.
  std::vector<const std::vector<uint8_t>*> contexts, properties;
  for (const auto& b : blobs) {
    if (b.size() < 4 + 16) continue;
    if (b[4] == kTypeContext) contexts.push_back(&b);
    else properties.push_back(&b);
  }

  uint32_t ctx_g = 0, props_g = 0;

  if (!contexts.empty()) {
    uint32_t g = mem->SystemHeapAlloc(static_cast<uint32_t>(contexts.size()) * 0x8);
    if (g) {
      uint8_t* base = mem->TranslateVirtual(g);
      for (size_t i = 0; i < contexts.size(); ++i) {
        const auto& b = *contexts[i];
        uint8_t* c = base + i * 0x8;
        memory::store_and_swap<uint32_t>(c + 0, rd_le32(b.data()));  // context_id
        std::memcpy(c + 4, b.data() + 12, 4);  // value (union.u32, already be)
      }
      memory::store_and_swap<uint32_t>(r + 0x50, static_cast<uint32_t>(contexts.size()));
      memory::store_and_swap<uint32_t>(r + 0x58, g);
      ctx_g = g;
    }
  }

  if (!properties.empty()) {
    uint32_t g = mem->SystemHeapAlloc(static_cast<uint32_t>(properties.size()) * 0x18);
    if (g) {
      uint8_t* base = mem->TranslateVirtual(g);
      for (size_t i = 0; i < properties.size(); ++i) {
        const auto& b = *properties[i];
        uint8_t* p = base + i * 0x18;
        std::memset(p, 0, 0x18);
        memory::store_and_swap<uint32_t>(p + 0x00, rd_le32(b.data()));  // property_id
        uint8_t type = b[4];
        p[0x08] = type;  // X_USER_DATA.type
        if (type == kTypeWString || type == kTypeBinary) {
          uint32_t ext_size = static_cast<uint32_t>(b.size() - 20);
          uint32_t data_g = mem->SystemHeapAlloc(ext_size ? ext_size : 1);
          if (data_g && ext_size) {
            std::memcpy(mem->TranslateVirtual(data_g), b.data() + 20, ext_size);
          }
          memory::store_and_swap<uint32_t>(p + 0x10, ext_size);  // union.size
          memory::store_and_swap<uint32_t>(p + 0x14, data_g);    // union.ptr
        } else {
          std::memcpy(p + 0x10, b.data() + 12, 8);  // union value (already be)
        }
      }
      memory::store_and_swap<uint32_t>(r + 0x4C, static_cast<uint32_t>(properties.size()));
      memory::store_and_swap<uint32_t>(r + 0x54, g);
      props_g = g;
    }
  }

  REXKRNL_INFO("  session attrs: contexts_ptr=0x{:08X} (n={}) properties_ptr=0x{:08X} (n={})",
               ctx_g, contexts.size(), props_g, properties.size());
}

// Hex-dump `len` bytes of guest memory `r` for diagnostics.
static void DumpResultBytes(const uint8_t* r, uint32_t len) {
  std::string hex;
  hex.reserve(len * 3);
  static const char d[] = "0123456789abcdef";
  for (uint32_t i = 0; i < len; ++i) {
    hex += d[(r[i] >> 4) & 0xF];
    hex += d[r[i] & 0xF];
    if ((i & 0xF) == 0xF) hex += '\n';
    else hex += ' ';
  }
  REXKRNL_INFO("  result bytes:\n{}", hex);
}

// Shared result-writer for XSessionSearch (0x000B0016) and XSessionSearchEx
// (0x000B001C). Writes netplay's SEARCH_RESULTS layout (0x0C header, result
// array at +0x0C) and returns how many results were written.
//
// Sessions whose backend /properties fetch comes back EMPTY are SKIPPED:
// titles dereference specific advertised attributes from the result with no
// null checks (Viva Piñata reads five), so a property-less session — hosted by
// an old build or left stale on the web service — is unjoinable and would
// crash the guest. Filtering them out mirrors what a real xenia-only list
// looks like, since xenia hosts always upload their properties.
static uint32_t WriteSearchResults(memory::Memory* mem, KernelState* kernel_state,
                                   const char* tag,
                                   const std::vector<system::WebSession>& sessions,
                                   uint8_t* out, uint32_t search_results_ptr,
                                   uint32_t max_results,
                                   uint32_t ctx_ptr, uint32_t num_ctx,
                                   uint32_t props_ptr, uint32_t num_props) {
  constexpr uint32_t kResultSize = 92;    // sizeof(XSESSION_SEARCHRESULT)
  constexpr uint32_t kHeaderSize = 0x0C;  // header(8) + results_ptr field(4)
  auto& wc = system::XLiveWebClient::Get();
  const uint32_t results_guest_ptr = search_results_ptr + kHeaderSize;

  uint32_t out_index = 0;
  for (const auto& ws : sessions) {
    if (out_index >= max_results) break;

    // Fetch the host's advertised properties BEFORE writing anything so an
    // unjoinable session can be dropped entirely.
    std::vector<std::vector<uint8_t>> blobs;
    wc.GetSessionProperties(kernel_state->title_id(), ws.session_id, blobs);
    if (blobs.empty()) {
      REXKRNL_WARN("{}: skipping session {} (host {}) — no advertised properties "
                   "(stale or old-build host, unjoinable)",
                   tag, ws.session_id, ws.host_address);
      continue;
    }

    uint8_t* r = out + kHeaderSize + out_index * kResultSize;
    std::memset(r, 0, kResultSize);

    // --- XNKID (session id) @ 0x00 ---
    system::XNKID kid{};
    if (!HexToBytes(ws.xnkid_hex, kid.ab, 8)) {
      REXKRNL_WARN("{}: bad xnkid_hex '{}' for session {}", tag, ws.xnkid_hex,
                   ws.session_id);
    }
    std::memcpy(r + 0x00, kid.ab, 8);

    // --- XNADDR (hostAddress) @ 0x08 — mirrors netplay
    // GetXnAddrFromSessionObject: ina AND inaOnline = public IP, port,
    // abEnet = host MAC, abOnline zeroed except platform_type @0x28.
    WriteIPNBO(r + 0x08, ws.host_address);
    WriteIPNBO(r + 0x0C, ws.host_address);
    memory::store_and_swap<uint16_t>(r + 0x10, ws.port);

    uint8_t mac[6] = {};
    bool have_mac = ws.mac_address.size() == 12 &&
                    HexToBytes(ws.mac_address, mac, 6);
    if (!have_mac && ws.host_xuid) {
      for (int b = 0; b < 6; ++b) {
        mac[b] = static_cast<uint8_t>(ws.host_xuid >> ((5 - b) * 8));
      }
    }
    std::memcpy(r + 0x12, mac, 6);
    r[0x28] = 1;  // SGADDR.platform_type = PLATFORM_TYPE::Xbox360

    // --- XNKEY @ 0x2C: netplay's fixed identity key {0,1,...,15} ---
    system::XNKEY key{};
    for (uint8_t b = 0; b < 16; ++b) key.ab[b] = b;
    std::memcpy(r + 0x2C, key.ab, 16);

    // --- Slot counts (all four, like netplay FillSessionSearchResult) ---
    uint32_t open_pub = ws.open_public;
    if (!open_pub && !ws.filled_public) open_pub = ws.slots_public;
    memory::store_and_swap<uint32_t>(r + 0x3C, open_pub);
    memory::store_and_swap<uint32_t>(r + 0x40, ws.open_private);
    memory::store_and_swap<uint32_t>(r + 0x44, ws.filled_public);
    memory::store_and_swap<uint32_t>(r + 0x48, ws.filled_private);

    // --- Advertised properties/contexts ---
    WriteSessionAttrs(mem, r, std::move(blobs), ctx_ptr, num_ctx, props_ptr,
                      num_props);

    // Pre-register so the joiner's XNetXnAddrToInAddr / XNetRegisterKey
    // resolve this host instead of missing.
    if (!kid.IsZero()) {
      system::XNADDR addr{};
      {
        unsigned a = 0, bb = 0, c = 0, d = 0;
        if (std::sscanf(ws.host_address.c_str(), "%u.%u.%u.%u", &a, &bb, &c, &d) == 4) {
          uint32_t ip = htonl((a << 24) | (bb << 16) | (c << 8) | d);
          addr.ina = ip;
          addr.inaOnline = ip;
        }
      }
      addr.wPortOnline = htons(ws.port);
      std::memcpy(addr.abEnet, mac, 6);
      std::memset(addr.abOnline, 0, sizeof(addr.abOnline));
      addr.abOnline[0x10] = 1;
      system::XNetKeyRegistry::Get().Register(kid, key);
      system::XNetAddrCache::Get().Store(addr, kid);
    }

    REXKRNL_INFO("{}: result[{}] xnkid={} host={} port={} mac={} pub={} priv={}",
                 tag, out_index, ws.xnkid_hex, ws.host_address, ws.port,
                 ws.mac_address, ws.slots_public, ws.slots_private);
    DumpResultBytes(r, kResultSize);
    ++out_index;
  }

  // Header last, with the count of results actually written.
  memory::store_and_swap<uint32_t>(out + 0, out_index);
  memory::store_and_swap<uint32_t>(out + 4, out_index ? results_guest_ptr : 0u);
  memory::store_and_swap<uint32_t>(out + 8, out_index ? results_guest_ptr : 0u);
  return out_index;
}

// Resolves explicit session IDs (XNKIDs) into search results. This is how a
// title joins from a friends list: it holds only the friend's session id and
// needs the host's XNADDR/XNKEY/port to build a client session. Returning
// success with an empty results buffer is what makes a title report a generic
// "connection problem" — the join never gets an address to reach.
static X_RESULT ResolveSessionsById(memory::Memory* mem,
                                    KernelState* kernel_state, const char* tag,
                                    const std::vector<std::string>& id_hexes,
                                    uint32_t results_buffer_size,
                                    uint32_t search_results_ptr) {
  if (!search_results_ptr) {
    return X_E_SUCCESS;
  }
  auto* out = mem->TranslateVirtual(search_results_ptr);
  if (!out) {
    REXKRNL_WARN("{}: search_results_ptr {:08X} unmapped", tag, search_results_ptr);
    return X_E_SUCCESS;
  }

  constexpr uint32_t kResultSize = 92;
  constexpr uint32_t kHeaderSize = 0x0C;
  uint32_t max_results = static_cast<uint32_t>(id_hexes.size());
  if (results_buffer_size >= kHeaderSize) {
    const uint32_t by_buf = (results_buffer_size - kHeaderSize) / kResultSize;
    if (by_buf < max_results) max_results = by_buf;
  }

  if (!REXCVAR_GET(xlive_web_enabled) || id_hexes.empty()) {
    memory::store_and_swap<uint32_t>(out + 0, 0);
    memory::store_and_swap<uint32_t>(out + 4, 0);
    memory::store_and_swap<uint32_t>(out + 8, 0);
    return X_E_SUCCESS;
  }

  auto& wc = system::XLiveWebClient::Get();
  wc.EnsureReady();

  std::vector<system::WebSession> sessions;
  for (const auto& id_hex : id_hexes) {
    // An all-zero XNKID means "no session" (a friend who isn't hosting).
    if (id_hex.find_first_not_of('0') == std::string::npos) {
      REXKRNL_INFO("{}: skipping null session id", tag);
      continue;
    }
    system::WebSession ws;
    if (wc.FetchSession(kernel_state->title_id(), id_hex, ws)) {
      sessions.push_back(std::move(ws));
    } else {
      REXKRNL_WARN("{}: session {} not found on backend", tag, id_hex);
    }
  }

  const uint32_t written =
      WriteSearchResults(mem, kernel_state, tag, sessions, out,
                         search_results_ptr, max_results, 0, 0, 0, 0);
  REXKRNL_INFO("{}: resolved {}/{} session(s), wrote {}", tag, sessions.size(),
               id_hexes.size(), written);
  return X_E_SUCCESS;
}

// --- Host-advertised session attributes -----------------------------------
// The game sets matchmaking contexts/properties via XGIUserSetContextEx /
// XGIUserSetPropertyEx before hosting. We capture them here and, on session
// create, upload them to the backend so joiners fetch them (otherwise a
// rexglue-hosted session returns {"properties":[]} and the joiner faults on the
// game's property lookup, exactly like a xenia host that never advertised).
// Each stored blob is the serialized xam::Property format WriteSessionAttrs /
// GetSessionProperties consume: [id LE u32][X_USER_DATA 16: type@0, union@8 BE]
// [ext bytes].
namespace {
struct SessionAttrStore {
  std::mutex mtx;
  std::vector<std::pair<uint32_t, std::vector<uint8_t>>> items;
  // Returns true if this changed the stored set (new id or different value).
  bool Set(uint32_t id, std::vector<uint8_t> blob) {
    std::lock_guard<std::mutex> lk(mtx);
    for (auto& it : items) {
      if (it.first == id) {
        if (it.second == blob) return false;
        it.second = std::move(blob);
        return true;
      }
    }
    items.emplace_back(id, std::move(blob));
    return true;
  }
  std::vector<std::vector<uint8_t>> All() {
    std::lock_guard<std::mutex> lk(mtx);
    std::vector<std::vector<uint8_t>> out;
    out.reserve(items.size());
    for (auto& it : items) out.push_back(it.second);
    return out;
  }
};

SessionAttrStore& AttrStore() {
  static SessionAttrStore s;
  return s;
}

// The web session this console currently hosts (set on create). Property/context
// sets after create re-upload so the backend always has the latest advertised
// attributes — mirrors netplay's change-driven UserTracker maintenance upload.
std::mutex g_host_mtx;
std::string g_host_web_id;
uint32_t g_host_title_id = 0;

void SetHostedSession(uint32_t title_id, const std::string& web_id,
                      const std::string& gamertag, uint64_t online_xuid) {
  {
    std::lock_guard<std::mutex> lk(g_host_mtx);
    g_host_title_id = title_id;
    g_host_web_id = web_id;
  }
  // Seed the system matchmaking properties netplay synthesizes host-side
  // (SessionPropertiesSet): GAMER_HOSTNAME + GAMER_PUID. The game never sets
  // these itself but joiners dereference them from the search result.
  AttrStore().Set(kPropGamerHostname, BuildHostnameBlob(gamertag));
  AttrStore().Set(kPropGamerPuid, BuildPuidBlob(online_xuid));
}

// Upload the current attribute set if we are hosting a web session. Runs on a
// detached thread so a synchronous HTTP POST never stalls the guest thread that
// is busy setting properties.
void UploadAttrsIfHosting() {
  std::string web_id;
  uint32_t title_id;
  {
    std::lock_guard<std::mutex> lk(g_host_mtx);
    web_id = g_host_web_id;
    title_id = g_host_title_id;
  }
  if (web_id.empty()) return;
  auto blobs = AttrStore().All();
  if (blobs.empty()) return;
  std::thread([title_id, web_id, blobs = std::move(blobs)]() {
    system::XLiveWebClient::Get().SetSessionProperties(title_id, web_id, blobs);
  }).detach();
}

void PutLE32(uint8_t* p, uint32_t v) {
  p[0] = v & 0xFF; p[1] = (v >> 8) & 0xFF; p[2] = (v >> 16) & 0xFF; p[3] = (v >> 24) & 0xFF;
}
void PutBE32(uint8_t* p, uint32_t v) {
  p[0] = (v >> 24) & 0xFF; p[1] = (v >> 16) & 0xFF; p[2] = (v >> 8) & 0xFF; p[3] = v & 0xFF;
}

// Context: X_USER_DATA.type == CONTEXT(0), value in union.u32.
std::vector<uint8_t> BuildContextBlob(uint32_t id, uint32_t value) {
  std::vector<uint8_t> b(20, 0);
  PutLE32(b.data() + 0, id);
  b[4] = 0;  // X_USER_DATA_TYPE::CONTEXT
  PutBE32(b.data() + 12, value);  // union @ blob[12]
  return b;
}

// Property: type = id >> 28. Non-string types store the raw big-endian guest
// value in the union; WSTRING/BINARY append the bytes as extended data.
std::vector<uint8_t> BuildPropertyBlob(uint32_t id, const uint8_t* val, uint32_t val_size) {
  uint8_t type = static_cast<uint8_t>((id >> 28) & 0xF);
  bool ext = (type == 4 /*WSTRING*/ || type == 6 /*BINARY*/);
  std::vector<uint8_t> b(20 + (ext ? val_size : 0), 0);
  PutLE32(b.data() + 0, id);
  b[4] = type;
  if (ext) {
    PutBE32(b.data() + 12, val_size);  // union.size
    if (val && val_size) std::memcpy(b.data() + 20, val, val_size);
  } else {
    uint32_t n = val_size > 8 ? 8 : val_size;
    if (val && n) std::memcpy(b.data() + 12, val, n);  // union value (BE guest bytes)
  }
  return b;
}

// System matchmaking properties netplay synthesizes from the profile in
// SessionPropertiesSet (default_system_matchmaking_properties) — the GAME never
// sets these via XGIUserSetPropertyEx, yet titles dereference them from search
// results (Viva Piñata wcsncpy's GAMER_HOSTNAME's string: the NULL+0xC crash).
// kPropGamerHostname / kPropGamerPuid are defined with the forward declarations
// above WriteSessionAttrs.

// WSTRING property: UTF-16BE chars + null terminator as extended data.
std::vector<uint8_t> BuildHostnameBlob(const std::string& tag) {
  std::vector<uint8_t> ext;
  ext.reserve(tag.size() * 2 + 2);
  for (char c : tag) {
    ext.push_back(0);
    ext.push_back(static_cast<uint8_t>(c));
  }
  ext.push_back(0);
  ext.push_back(0);
  std::vector<uint8_t> b(20 + ext.size(), 0);
  PutLE32(b.data() + 0, kPropGamerHostname);
  b[4] = 4;  // WSTRING
  PutBE32(b.data() + 12, static_cast<uint32_t>(ext.size()));  // union.size
  std::memcpy(b.data() + 20, ext.data(), ext.size());
  return b;
}

// INT64 property: 8-byte big-endian value in the union.
std::vector<uint8_t> BuildPuidBlob(uint64_t xuid) {
  std::vector<uint8_t> b(20, 0);
  PutLE32(b.data() + 0, kPropGamerPuid);
  b[4] = 2;  // INT64
  for (int i = 0; i < 8; ++i) {
    b[12 + i] = static_cast<uint8_t>(xuid >> (56 - 8 * i));
  }
  return b;
}
}  // namespace

XgiApp::XgiApp(KernelState* kernel_state) : App(kernel_state, 0xFB) {}

// http://mb.mirage.org/bugzilla/xliveless/main.c

X_HRESULT XgiApp::DispatchMessageSync(uint32_t message, uint32_t buffer_ptr,
                                      uint32_t buffer_length) {
  // NOTE: buffer_length may be zero or valid.
  auto buffer = memory_->TranslateVirtual(buffer_ptr);
  REXKRNL_INFO("XGI dispatch: msg={:08X} buffer_ptr={:08X} buffer_length={}", message, buffer_ptr, buffer_length);
  switch (message) {
    case 0x000B0006: {
      assert_true(!buffer_length || buffer_length == 24);
      // dword r3 user index
      // dword (unwritten?)
      // qword 0
      // dword r4 context enum
      // dword r5 value
      uint32_t user_index = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t context_id = memory::load_and_swap<uint32_t>(buffer + 16);
      uint32_t context_value = memory::load_and_swap<uint32_t>(buffer + 20);
      REXKRNL_DEBUG("XGIUserSetContextEx({:08X}, {:08X}, {:08X})", user_index, context_id,
                    context_value);
      // Capture for advertising when this console hosts a session; re-upload if
      // it changed and we are already hosting (game may set attrs post-create).
      if (AttrStore().Set(context_id, BuildContextBlob(context_id, context_value))) {
        UploadAttrsIfHosting();
      }
      return X_E_SUCCESS;
    }
    case 0x000B0007: {
      uint32_t user_index = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t property_id = memory::load_and_swap<uint32_t>(buffer + 16);
      uint32_t value_size = memory::load_and_swap<uint32_t>(buffer + 20);
      uint32_t value_ptr = memory::load_and_swap<uint32_t>(buffer + 24);
      REXKRNL_DEBUG("XGIUserSetPropertyEx({:08X}, {:08X}, {}, {:08X})", user_index, property_id,
                    value_size, value_ptr);
      // Capture for advertising when this console hosts a session; re-upload if
      // it changed and we are already hosting (game may set attrs post-create).
      const uint8_t* pval = value_ptr ? memory_->TranslateVirtual(value_ptr) : nullptr;
      if (AttrStore().Set(property_id, BuildPropertyBlob(property_id, pval, value_size))) {
        UploadAttrsIfHosting();
      }
      return X_E_SUCCESS;
    }
    case 0x000B0008: {
      // Raw dump so we can confirm the actual buffer layout the game sends.
      uint32_t raw0 = buffer_length >= 4 ? memory::load_and_swap<uint32_t>(buffer + 0) : 0;
      uint32_t raw4 = buffer_length >= 8 ? memory::load_and_swap<uint32_t>(buffer + 4) : 0;
      REXKRNL_INFO("XGIUserWriteAchievements called: buf_len={} raw[0]={:08X} raw[4]={:08X}",
                   buffer_length, raw0, raw4);

      assert_true(!buffer_length || buffer_length == 8);
      uint32_t achievement_count = raw0;
      uint32_t achievements_ptr = raw4;

      // Empirically confirmed from log: each entry is {u32 padding/user_index, u32 id, ...}.
      // The achievement ID sits at offset 4, not 0. Stride 8 covers the observed fields.
      constexpr uint32_t kEntryIdOffset = 4;
      constexpr uint32_t kEntryStride = 8;
      constexpr uint32_t kMaxAchievements = 1000;

      if (achievements_ptr && achievement_count > 0) {
        if (achievement_count > kMaxAchievements) {
          REXKRNL_WARN("XGIUserWriteAchievements: count={} unreasonable, ignoring",
                       achievement_count);
          return X_E_FAIL;
        }
        uint32_t span_end = achievements_ptr + achievement_count * kEntryStride - 1;
        if (!memory_->LookupHeap(achievements_ptr) || !memory_->LookupHeap(span_end)) {
          REXKRNL_WARN("XGIUserWriteAchievements: ptr {:08X} OOB", achievements_ptr);
          return X_E_FAIL;
        }
        auto* base = memory_->TranslateVirtual(achievements_ptr);
        for (uint32_t i = 0; i < achievement_count; ++i) {
          uint32_t id = memory::load_and_swap<uint32_t>(base + i * kEntryStride + kEntryIdOffset);
          REXKRNL_INFO("XGIUserWriteAchievements: id={} ({})", id, i);
          kernel_state_->UnlockAchievement(id);
        }
      } else {
        REXKRNL_INFO("XGIUserWriteAchievements: skipped (count={} ptr={:08X})", achievement_count,
                     achievements_ptr);
      }
      return X_E_SUCCESS;
    }
    case 0x000B0010: {
      REXKRNL_INFO("XGISessionCreateImpl: buffer_length={} buffer_ptr={:08X}",
                   buffer_length, buffer_ptr);
      if (buffer_length && buffer_length != 28) {
        REXKRNL_WARN("XGISessionCreateImpl: unexpected buffer_length={}", buffer_length);
      }
      if (buffer_length < 0x1C) {
        REXKRNL_ERROR("XGISessionCreateImpl: buffer too small ({}), returning early", buffer_length);
        return X_E_SUCCESS;
      }
      uint32_t session_ptr      = memory::load_and_swap<uint32_t>(buffer + 0x0);
      uint32_t flags            = memory::load_and_swap<uint32_t>(buffer + 0x4);
      uint32_t num_slots_public = memory::load_and_swap<uint32_t>(buffer + 0x8);
      uint32_t num_slots_private= memory::load_and_swap<uint32_t>(buffer + 0xC);
      uint32_t user_xuid_lo     = memory::load_and_swap<uint32_t>(buffer + 0x10);
      uint32_t session_info_ptr = memory::load_and_swap<uint32_t>(buffer + 0x14);
      uint32_t nonce_ptr        = memory::load_and_swap<uint32_t>(buffer + 0x18);

      REXKRNL_DEBUG(
          "XGISessionCreateImpl({:08X}, {:08X}, {}, {}, {:08X}, {:08X}, {:08X})",
          session_ptr, flags, num_slots_public, num_slots_private,
          user_xuid_lo, session_info_ptr, nonce_ptr);

      // HOST flag (0x01) distinguishes session creator from joiner.
      // SYSTEMLINK_FEATURES = HOST | PEER_NETWORK. Clients joining an existing
      // session do NOT set HOST, so we must not overwrite their XSESSION_INFO.
      constexpr uint32_t XSESSION_CREATE_HOST = 0x00000001;
      const bool is_host_session = (flags & XSESSION_CREATE_HOST) != 0;

      if (session_info_ptr && REXCVAR_GET(xlive_web_enabled)) {
        if (is_host_session) {
          REXKRNL_INFO("XGISessionCreateImpl: web enabled (HOST), EnsureReady...");
          auto& wc = system::XLiveWebClient::Get();
          wc.EnsureReady();
          REXKRNL_INFO("XGISessionCreateImpl: wc.is_ready()={}", wc.is_ready());
          if (!wc.is_ready()) {
            REXKRNL_ERROR("XGISessionCreateImpl: web client not ready, skipping web session");
            return X_E_SUCCESS;
          }

          // Host under the SAME xuid the web client registered the player with
          // (the online 0x0009... xuid when LIVE-enabled). Using the offline
          // xuid makes the backend reject the session with 403 "Player not
          // found" (it only knows the registered online xuid).
          uint64_t host_xuid = kernel_state_->user_profile()->GetLogonXUID();
          uint16_t port = static_cast<uint16_t>(
              REXCVAR_GET(systemlink_base_port) + REXCVAR_GET(systemlink_port_offset));
          REXKRNL_INFO("XGISessionCreateImpl: host_xuid={:016X} port={} public_ip={}",
                       host_xuid, port, wc.public_address());

          auto& session = system::GetActiveSession();
          session.CreateHostSession(host_xuid, flags, num_slots_public, num_slots_private,
                                    wc.public_address_net(), port);
          REXKRNL_INFO("XGISessionCreateImpl: local host session created");

          system::WebSession ws_info;
          ws_info.host_xuid     = host_xuid;
          ws_info.slots_public  = num_slots_public;
          ws_info.slots_private = num_slots_private;
          ws_info.port          = port;
          ws_info.host_address  = wc.public_address();
          ws_info.xnkid_hex     = ToHex(session.session_id().ab, 8);
          ws_info.xnkey_hex     = ToHex(session.exchange_key().ab, 16);
          // Media id/version so the web UI doesn't show "Media ID: N/A"
          // (netplay XSessionCreate sends both from the XEX execution info).
          ws_info.media_id      = fmt::format("{:08X}", kernel_state_->media_id());
          ws_info.version       = kernel_state_->title_version();
          REXKRNL_INFO("XGISessionCreateImpl: calling wc.CreateSession title_id={:08X}",
                       kernel_state_->title_id());
          std::string web_id;
          bool create_ok = wc.CreateSession(kernel_state_->title_id(), ws_info, web_id);
          REXKRNL_INFO("XGISessionCreateImpl: CreateSession ok={} web_id='{}'", create_ok, web_id);
          if (create_ok && !web_id.empty()) {
            session.set_web_session_id(web_id);
            // Advertise the matchmaking contexts/properties the game set so
            // joiners can fetch them (else they fault on the missing-property
            // lookup). Mirrors xenia SessionPropertiesSet. Register as the hosted
            // session first so any attrs set AFTER create also get re-uploaded.
            auto* profile = kernel_state_->user_profile();
            SetHostedSession(kernel_state_->title_id(), web_id,
                             profile ? profile->name() : "Player", host_xuid);
            UploadAttrsIfHosting();
          }

          auto* info_raw = memory_->TranslateVirtual(session_info_ptr);
          REXKRNL_INFO("XGISessionCreateImpl: info_raw={} session_info_ptr={:08X}",
                       (void*)info_raw, session_info_ptr);
          if (info_raw) {
            const auto& si = session.session_info();
            std::memcpy(info_raw, &si, sizeof(system::XSESSION_INFO));
            REXKRNL_INFO("XGISessionCreateImpl: XSESSION_INFO written ({} bytes)",
                         sizeof(system::XSESSION_INFO));
          }

          // Games pass the nonce back to XSessionStart/arbitration; without
          // it hosts and joiners disagree on the session identity (netplay
          // writes it in XSession::CreateSession).
          if (nonce_ptr) {
            memory::store_and_swap<uint64_t>(memory_->TranslateVirtual(nonce_ptr),
                                             session.nonce());
            REXKRNL_INFO("XGISessionCreateImpl: nonce {:016X} written",
                         session.nonce());
          }
        } else {
          // Client joining an existing session.
          // The game already populated session_info_ptr with the host's XSESSION_INFO
          // (received via broadcast or session search). Read it and initialise a
          // client-side session without touching guest memory or the web API.
          REXKRNL_INFO("XGISessionCreateImpl: client join path (no HOST flag), flags={:08X}", flags);
          auto* info_raw = memory_->TranslateVirtual(session_info_ptr);
          if (info_raw) {
            system::XSESSION_INFO host_si{};
            std::memcpy(&host_si, info_raw, sizeof(system::XSESSION_INFO));

            auto& session = system::GetActiveSession();
            session.CreateClientSession(host_si, 0 /*host_xuid unknown*/, flags,
                                         num_slots_public, num_slots_private);

            // Cache the host's XNADDR so XNetXnAddrToInAddr can resolve it.
            system::XNetAddrCache::Get().Store(host_si.hostAddress, host_si.sessionID);

            REXKRNL_INFO("XGISessionCreateImpl: client session ready, host inaOnline={:08X}",
                         host_si.hostAddress.inaOnline);
          }
        }
      }
      return X_E_SUCCESS;
    }
    case 0x000B0011: {
      REXKRNL_INFO("XGISessionDelete");
      if (REXCVAR_GET(xlive_web_enabled)) {
        auto& session = system::GetActiveSession();
        if (!session.web_session_id().empty()) {
          system::XLiveWebClient::Get().DeleteSession(kernel_state_->title_id(),
                                                      session.web_session_id());
        }
        session.Destroy();
      }
      return X_STATUS_SUCCESS;
    }
    case 0x000B0012: {
      // XSessionJoin. One opcode serves both variants, distinguished by
      // xuid_array_ptr: null => local users joining (indices_array holds user
      // indices), non-null => remote members (xuid_array holds online XUIDs).
      // Mirrors xenia XSession::JoinSession.
      assert_true(!buffer_length || buffer_length == 20);
      uint32_t session_ptr        = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t array_count        = memory::load_and_swap<uint32_t>(buffer + 4);
      uint32_t xuid_array_ptr     = memory::load_and_swap<uint32_t>(buffer + 8);
      uint32_t indices_array_ptr  = memory::load_and_swap<uint32_t>(buffer + 12);
      uint32_t private_slots_ptr  = memory::load_and_swap<uint32_t>(buffer + 16);

      const bool join_local = (xuid_array_ptr == 0);
      REXKRNL_INFO("{}({:08X}, {}, {:08X}, {:08X}, {:08X})",
                   join_local ? "XGISessionJoinLocal" : "XGISessionJoinRemote",
                   session_ptr, array_count, xuid_array_ptr, indices_array_ptr,
                   private_slots_ptr);

      if (!REXCVAR_GET(xlive_web_enabled)) {
        return X_E_SUCCESS;
      }

      std::vector<uint64_t> xuids;
      std::vector<bool> private_slots;
      for (uint32_t i = 0; i < array_count; ++i) {
        uint64_t xuid = 0;
        if (join_local) {
          // The guest names a local user index; resolve it to that profile's
          // online XUID, which is the identity the backend knows us by.
          uint32_t user_index = 0;
          if (indices_array_ptr) {
            user_index = memory::load_and_swap<uint32_t>(
                memory_->TranslateVirtual(indices_array_ptr + i * 4));
          }
          auto* profile = kernel_state_->profile_manager()->GetProfile(
              static_cast<uint8_t>(user_index));
          if (!profile) {
            REXKRNL_WARN("XSessionJoin: no profile at user index {}", user_index);
            continue;
          }
          xuid = profile->GetOnlineXUID();
        } else {
          xuid = memory::load_and_swap<uint64_t>(
              memory_->TranslateVirtual(xuid_array_ptr + i * 8));
        }
        if (!xuid) continue;

        bool is_private = false;
        if (private_slots_ptr) {
          is_private = memory::load_and_swap<uint32_t>(
                           memory_->TranslateVirtual(private_slots_ptr + i * 4)) != 0;
        }
        xuids.push_back(xuid);
        private_slots.push_back(is_private);
        REXKRNL_INFO("XSessionJoin: XUID {:016X} occupying {} slot", xuid,
                     is_private ? "private" : "public");
      }

      if (xuids.empty()) {
        return X_E_SUCCESS;
      }

      auto& session = system::GetActiveSession();
      // The backend keys sessions by the host's XNKID, which the client-join
      // path already holds even though it never received a web session id.
      std::string web_id = session.web_session_id();
      if (web_id.empty()) web_id = ToHex(session.session_id().ab, 8);
      const bool is_host = session.is_host();
      uint32_t title_id = kernel_state_->title_id();

      // Detached: these are synchronous HTTP posts and the guest thread is
      // mid-join. Host publishes the member set, joiners announce themselves.
      std::thread([title_id, web_id, is_host, xuids, private_slots]() {
        auto& wc = system::XLiveWebClient::Get();
        wc.EnsureReady();
        if (is_host) {
          wc.JoinSession(title_id, web_id, xuids, private_slots);
        } else {
          wc.PrejoinSession(title_id, web_id, xuids);
        }
      }).detach();

      return X_E_SUCCESS;
    }
    case 0x000B0013: {
      // XSessionLeave (local variant of 0x000B0012's leave path); netplay
      // routes this to XSession::LeaveSession. We track a single session so
      // just report success.
      REXKRNL_INFO("XSessionLeave({:08X}, {:08X})", buffer_ptr, buffer_length);
      return X_E_SUCCESS;
    }
    case 0x000B0014: {
      assert_true(!buffer_length || buffer_length == 16);

      uint32_t obj_ptr = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t flags = memory::load_and_swap<uint32_t>(buffer + 4);
      uint64_t session_nonce = memory::load_and_swap<uint64_t>(buffer + 8);

      REXKRNL_DEBUG("XSessionStart({:08X}, {:08X}, {:016X})", obj_ptr, flags, session_nonce);

      return X_STATUS_SUCCESS;
    }
    case 0x000B0015: {
      // send high scores?
      assert_true(!buffer_length || buffer_length == 16);

      uint32_t obj_ptr = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t flags = memory::load_and_swap<uint32_t>(buffer + 4);
      uint64_t session_nonce = memory::load_and_swap<uint64_t>(buffer + 8);

      REXKRNL_DEBUG("XSessionEnd({:08X}, {:08X}, {:016X})", obj_ptr, flags, session_nonce);

      return X_E_SUCCESS;
    }
    case 0x000B0016: {
      assert_true(!buffer_length || buffer_length == 32);

      uint32_t proc_index          = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t user_index          = memory::load_and_swap<uint32_t>(buffer + 4);
      uint32_t num_results         = memory::load_and_swap<uint32_t>(buffer + 8);
      uint16_t num_props           = memory::load_and_swap<uint16_t>(buffer + 12);
      uint16_t num_ctx             = memory::load_and_swap<uint16_t>(buffer + 14);
      uint32_t props_ptr           = memory::load_and_swap<uint32_t>(buffer + 16);
      uint32_t ctx_ptr             = memory::load_and_swap<uint32_t>(buffer + 20);
      uint32_t results_buffer_size = memory::load_and_swap<uint32_t>(buffer + 24);
      uint32_t search_results_ptr  = memory::load_and_swap<uint32_t>(buffer + 28);

      REXKRNL_INFO("XSessionSearch({}, {}, {}, {}, {}, {:08X}, {:08X}, {}, {:08X})", proc_index,
                   user_index, num_results, num_props, num_ctx, props_ptr, ctx_ptr,
                   results_buffer_size, search_results_ptr);

      if (!REXCVAR_GET(xlive_web_enabled) || !search_results_ptr) {
        return X_E_SUCCESS;
      }

      auto& wc = system::XLiveWebClient::Get();
      wc.EnsureReady();
      std::vector<system::WebSession> sessions;
      bool ok = wc.SearchSessions(kernel_state_->title_id(), sessions);
      REXKRNL_INFO("XSessionSearch: SearchSessions ok={} count={}", ok, sessions.size());
      if (!ok) {
        return X_E_SUCCESS;
      }

      // Cap to what the game allocated for and what fits in the results buffer.
      constexpr uint32_t kResultSize = 92;
      constexpr uint32_t kHeaderSize = 0x0C;
      uint32_t max_by_alloc = num_results;
      if (results_buffer_size >= kHeaderSize) {
        uint32_t max_by_buf = (results_buffer_size - kHeaderSize) / kResultSize;
        if (max_by_buf < max_by_alloc) max_by_alloc = max_by_buf;
      }

      auto* out = memory_->TranslateVirtual(search_results_ptr);
      if (!out) {
        REXKRNL_WARN("XSessionSearch: search_results_ptr {:08X} unmapped", search_results_ptr);
        return X_E_SUCCESS;
      }

      uint32_t written = WriteSearchResults(
          memory_, kernel_state_, "XSessionSearch", sessions, out,
          search_results_ptr, max_by_alloc, ctx_ptr, num_ctx, props_ptr, num_props);

      REXKRNL_INFO("XSessionSearch: wrote {} results to {:08X}", written, search_results_ptr);
      return X_E_SUCCESS;
    }
    case 0x000B0018: {
      assert_true(!buffer_length || buffer_length == 16);

      uint32_t obj_ptr = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t flags = memory::load_and_swap<uint32_t>(buffer + 4);
      uint32_t maxPublicSlots = memory::load_and_swap<uint32_t>(buffer + 8);
      uint16_t maxPrivateSlots = memory::load_and_swap<uint16_t>(buffer + 12);

      REXKRNL_DEBUG("XSessionModify({:08X}, {:08X}, {:08X}, {:08X})", obj_ptr, flags,
                    maxPublicSlots, maxPrivateSlots);

      return X_E_SUCCESS;
    }
    case 0x000B001C: {
      assert_true(!buffer_length || buffer_length == 36);

      uint32_t proc_index          = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t user_index          = memory::load_and_swap<uint32_t>(buffer + 4);
      uint32_t num_results         = memory::load_and_swap<uint32_t>(buffer + 8);
      uint16_t num_props           = memory::load_and_swap<uint16_t>(buffer + 12);
      uint16_t num_ctx             = memory::load_and_swap<uint16_t>(buffer + 14);
      uint32_t props_ptr           = memory::load_and_swap<uint32_t>(buffer + 16);
      uint32_t ctx_ptr             = memory::load_and_swap<uint32_t>(buffer + 20);
      uint32_t results_buffer_size = memory::load_and_swap<uint32_t>(buffer + 24);
      uint32_t search_results_ptr  = memory::load_and_swap<uint32_t>(buffer + 28);
      uint32_t num_users           = memory::load_and_swap<uint32_t>(buffer + 32);

      REXKRNL_INFO("XSessionSearchEx({}, {}, {}, {}, {}, {:08X}, {:08X}, {}, {:08X}, {})",
                   proc_index, user_index, num_results, num_props, num_ctx, props_ptr, ctx_ptr,
                   results_buffer_size, search_results_ptr, num_users);

      if (!REXCVAR_GET(xlive_web_enabled) || !search_results_ptr) {
        return X_E_SUCCESS;
      }

      auto& wc = system::XLiveWebClient::Get();
      wc.EnsureReady();
      std::vector<system::WebSession> sessions;
      bool ok = wc.SearchSessions(kernel_state_->title_id(), sessions);
      REXKRNL_INFO("XSessionSearchEx: SearchSessions ok={} count={}", ok, sessions.size());
      if (!ok) {
        return X_E_SUCCESS;
      }

      constexpr uint32_t kResultSize = 92;    // sizeof(XSESSION_SEARCHRESULT)
      constexpr uint32_t kHeaderSize = 0x0C;  // header(8) + results_ptr field(4)
      uint32_t max_by_alloc = num_results;
      if (results_buffer_size >= kHeaderSize) {
        uint32_t max_by_buf = (results_buffer_size - kHeaderSize) / kResultSize;
        if (max_by_buf < max_by_alloc) max_by_alloc = max_by_buf;
      }

      auto* out = memory_->TranslateVirtual(search_results_ptr);
      if (!out) {
        REXKRNL_WARN("XSessionSearchEx: search_results_ptr {:08X} unmapped", search_results_ptr);
        return X_E_SUCCESS;
      }

      uint32_t written = WriteSearchResults(
          memory_, kernel_state_, "XSessionSearchEx", sessions, out,
          search_results_ptr, max_by_alloc, ctx_ptr, num_ctx, props_ptr, num_props);

      REXKRNL_INFO("XSessionSearchEx: wrote {} results to {:08X}", written, search_results_ptr);
      return X_E_SUCCESS;
    }
    case 0x000B001D: {
      assert_true(!buffer_length || buffer_length == 24);

      uint32_t obj_ptr = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t details_buffer_size = memory::load_and_swap<uint32_t>(buffer + 4);
      uint32_t session_details_ptr = memory::load_and_swap<uint32_t>(buffer + 8);
      uint32_t reserved1 = memory::load_and_swap<uint32_t>(buffer + 12);
      uint32_t reserved2 = memory::load_and_swap<uint32_t>(buffer + 16);
      uint32_t reserved3 = memory::load_and_swap<uint32_t>(buffer + 20);

      REXKRNL_DEBUG("XSessionGetDetails({:08X}, {}, {:08X}, {}, {}, {})", obj_ptr,
                    details_buffer_size, session_details_ptr, reserved1, reserved2, reserved3);

      return X_E_SUCCESS;
    }
    case 0x000B001E: {
      assert_true(!buffer_length || buffer_length == 24);

      uint32_t obj_ptr = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t session_info_ptr = memory::load_and_swap<uint32_t>(buffer + 4);
      uint32_t user_index = memory::load_and_swap<uint32_t>(buffer + 8);
      uint32_t reserved1 = memory::load_and_swap<uint32_t>(buffer + 12);
      uint32_t reserved2 = memory::load_and_swap<uint32_t>(buffer + 16);
      uint32_t reserved3 = memory::load_and_swap<uint32_t>(buffer + 20);

      REXKRNL_DEBUG("XSessionMigrateHost({:08X}, {:08X}, {}, {}, {}, {})", obj_ptr,
                    session_info_ptr, user_index, reserved1, reserved2, reserved3);

      return X_E_SUCCESS;
    }
    case 0x000B0019: {
      assert_true(!buffer_length || buffer_length == 8);

      uint32_t user_index = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t session_info_ptr = memory::load_and_swap<uint32_t>(buffer + 4);

      REXKRNL_DEBUG("XSessionGetInvitationData - unimplemented({}, {:08X})", user_index,
                    session_info_ptr);

      return X_E_SUCCESS;
    }
    case 0x000B001A: {
      assert_true(!buffer_length || buffer_length == 28);

      uint32_t obj_ptr = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t flags = memory::load_and_swap<uint32_t>(buffer + 4);
      uint64_t session_nonce = memory::load_and_swap<uint64_t>(buffer + 8);
      uint32_t session_duration_sec = memory::load_and_swap<uint32_t>(buffer + 16);  // 300
      uint32_t results_buffer_size = memory::load_and_swap<uint32_t>(buffer + 20);
      uint32_t results_ptr = memory::load_and_swap<uint32_t>(buffer + 24);

      REXKRNL_DEBUG("XSessionArbitrationRegister({:08X}, {:08X}, {:016X}, {:08X}, {:08X}, {:08X})",
                    obj_ptr, flags, session_nonce, session_duration_sec, results_buffer_size,
                    results_ptr);

      return X_E_SUCCESS;
    }
    case 0x000B001B: {
      // XSessionSearchByID — XGI_SESSION_SEARCH_BYID is 0x14, NOT the 0x20
      // ByIds layout: the XNKID sits inline at +4, so the two are not
      // interchangeable.
      assert_true(!buffer_length || buffer_length == 20);

      uint32_t user_index = memory::load_and_swap<uint32_t>(buffer + 0);
      uint8_t session_id[8] = {};
      std::memcpy(session_id, buffer + 4, sizeof(session_id));
      uint32_t results_buffer_size = memory::load_and_swap<uint32_t>(buffer + 12);
      uint32_t search_results_ptr = memory::load_and_swap<uint32_t>(buffer + 16);

      const std::string id_hex = ToHex(session_id, sizeof(session_id));
      REXKRNL_INFO("XSessionSearchByID(user={}, id={}, buf_size={}, results={:08X})",
                   user_index, id_hex, results_buffer_size, search_results_ptr);

      return ResolveSessionsById(memory_, kernel_state_, "XSessionSearchByID",
                                 {id_hex}, results_buffer_size,
                                 search_results_ptr);
    }
    case 0x000B001F: {
      assert_true(!buffer_length || buffer_length == 24);

      uint32_t obj_ptr = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t array_count = memory::load_and_swap<uint32_t>(buffer + 4);
      uint32_t xuid_array_ptr = memory::load_and_swap<uint32_t>(buffer + 8);
      uint32_t reserved1 = memory::load_and_swap<uint32_t>(buffer + 12);
      uint32_t reserved2 = memory::load_and_swap<uint32_t>(buffer + 16);
      uint32_t reserved3 = memory::load_and_swap<uint32_t>(buffer + 20);

      REXKRNL_DEBUG("XSessionModifySkill({:08X}, {}, {:08X}, {}, {}, {})", obj_ptr, array_count,
                    xuid_array_ptr, reserved1, reserved2, reserved3);

      return X_E_SUCCESS;
    }
    case 0x000B0020: {
      assert_true(!buffer_length || buffer_length == 8);

      uint32_t user_index = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t view_id = memory::load_and_swap<uint32_t>(buffer + 4);

      REXKRNL_DEBUG("XUserResetStatsView({:08X}, {})", user_index, view_id);

      return X_E_SUCCESS;
    }
    case 0x000B0021: {
      assert_true(!buffer_length || buffer_length == 28);

      uint32_t title_id = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t xuids_count = memory::load_and_swap<uint32_t>(buffer + 4);
      uint32_t xuids_ptr = memory::load_and_swap<uint32_t>(buffer + 8);
      uint32_t specs_count = memory::load_and_swap<uint32_t>(buffer + 12);
      uint32_t specs_ptr = memory::load_and_swap<uint32_t>(buffer + 16);
      uint32_t results_size = memory::load_and_swap<uint32_t>(buffer + 20);
      uint32_t results_ptr = memory::load_and_swap<uint32_t>(buffer + 24);

      REXKRNL_DEBUG("XUserReadStats({}, {}, {:08X}, {}, {:08X}, {}, {:08X})", title_id, xuids_count,
                    xuids_ptr, specs_count, specs_ptr, results_size, results_ptr);

      return X_E_SUCCESS;
    }
    case 0x000B0025: {
      assert_true(!buffer_length || buffer_length == 20);

      uint32_t obj_ptr = memory::load_and_swap<uint32_t>(buffer + 0);
      uint64_t xuid = memory::load_and_swap<uint64_t>(buffer + 4);
      uint32_t num_views = memory::load_and_swap<uint32_t>(buffer + 12);
      uint32_t views_ptr = memory::load_and_swap<uint32_t>(buffer + 16);

      REXKRNL_DEBUG("XSessionWriteStats({:08X}, {:016X}, {:08X}, {:08X})", obj_ptr, xuid, num_views,
                    views_ptr);

      return X_E_SUCCESS;
    }
    case 0x000B0026: {
      assert_true(!buffer_length || buffer_length == 20);

      uint32_t obj_ptr = memory::load_and_swap<uint32_t>(buffer + 0);
      uint64_t xuid = memory::load_and_swap<uint64_t>(buffer + 4);
      uint32_t num_views = memory::load_and_swap<uint32_t>(buffer + 12);
      uint32_t views_ptr = memory::load_and_swap<uint32_t>(buffer + 16);

      REXKRNL_DEBUG("XSessionFlushStats({:08X}, {:016X}, {:08X}, {:08X})", obj_ptr, xuid, num_views,
                    views_ptr);

      return X_E_SUCCESS;
    }
    case 0x000B0036: {
      // Called after opening xbox live arcade and clicking on xbox live v5759
      // to 5787 and called after clicking xbox live in the game library from
      // v6683 to v6717
      // Does not get sent a buffer
      REXKRNL_DEBUG("XInvalidateGamerTileCache, unimplemented");
      return X_E_FAIL;
    }
    case 0x000B003D: {
      assert_true(!buffer_length || buffer_length == 16);

      uint32_t user_index = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t AnId_buffer_size = memory::load_and_swap<uint32_t>(buffer + 4);
      uint32_t AnId_buffer_ptr = memory::load_and_swap<uint32_t>(buffer + 8);
      uint32_t block = memory::load_and_swap<uint32_t>(buffer + 12);

      REXKRNL_DEBUG("XUserGetANID({:08X}, {:08X}, {:08X}, {:08X})", user_index, AnId_buffer_size,
                    AnId_buffer_ptr, block);

      return X_E_SUCCESS;
    }
    case 0x000B0041: {
      assert_true(!buffer_length || buffer_length == 32);
      // 00000000 2789fecc 00000000 00000000 200491e0 00000000 200491f0 20049340
      uint32_t user_index = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t context_ptr = memory::load_and_swap<uint32_t>(buffer + 16);
      auto context = context_ptr ? memory_->TranslateVirtual(context_ptr) : nullptr;
      uint32_t context_id = context ? memory::load_and_swap<uint32_t>(context + 0) : 0;
      REXKRNL_INFO("XGIUserGetContext({:08X}, {:08X}, {:08X}))", user_index, context_ptr,
                   context_id);
      uint32_t value = 0;
      if (context) {
        memory::store_and_swap<uint32_t>(context + 4, value);
      }
      return X_E_FAIL;
    }
    case 0x000B0060: {
      assert_true(!buffer_length || buffer_length == 32);

      uint32_t user_index = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t num_session_ids = memory::load_and_swap<uint32_t>(buffer + 4);
      uint32_t session_ids_ptr = memory::load_and_swap<uint32_t>(buffer + 8);
      uint32_t results_buffer_size = memory::load_and_swap<uint32_t>(buffer + 12);
      uint32_t search_results_ptr = memory::load_and_swap<uint32_t>(buffer + 16);
      uint32_t reserved1 = memory::load_and_swap<uint32_t>(buffer + 20);
      uint32_t reserved2 = memory::load_and_swap<uint32_t>(buffer + 24);
      uint32_t reserved3 = memory::load_and_swap<uint32_t>(buffer + 28);

      REXKRNL_INFO("XSessionSearchByIds({:08X}, {}, {:08X}, {:08X}, {:08X}, {}, {}, {})",
                   user_index, num_session_ids, session_ids_ptr, results_buffer_size,
                   search_results_ptr, reserved1, reserved2, reserved3);

      // session_ids_ptr is an array of XNKIDs (8 raw bytes each).
      std::vector<std::string> ids;
      if (session_ids_ptr) {
        auto* ids_base = memory_->TranslateVirtual(session_ids_ptr);
        if (ids_base) {
          auto* ids_bytes = static_cast<const uint8_t*>(static_cast<void*>(ids_base));
          for (uint32_t i = 0; i < num_session_ids; ++i) {
            ids.push_back(ToHex(ids_bytes + i * 8, 8));
          }
        }
      }

      return ResolveSessionsById(memory_, kernel_state_, "XSessionSearchByIds",
                                 ids, results_buffer_size, search_results_ptr);
    }
    case 0x000B0065: {
      assert_true(!buffer_length || buffer_length == 52);

      uint32_t proc_index = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t user_index = memory::load_and_swap<uint32_t>(buffer + 4);
      uint32_t num_results = memory::load_and_swap<uint32_t>(buffer + 8);
      uint16_t num_weighted_properties = memory::load_and_swap<uint16_t>(buffer + 12);
      uint16_t num_weighted_contexts = memory::load_and_swap<uint16_t>(buffer + 14);
      uint32_t weighted_search_properties_ptr = memory::load_and_swap<uint32_t>(buffer + 16);
      uint32_t weighted_search_contexts_ptr = memory::load_and_swap<uint32_t>(buffer + 20);
      uint16_t num_props = memory::load_and_swap<uint16_t>(buffer + 24);
      uint16_t num_ctx = memory::load_and_swap<uint16_t>(buffer + 26);
      uint32_t non_weighted_search_properties_ptr = memory::load_and_swap<uint32_t>(buffer + 28);
      uint32_t non_weighted_search_contexts_ptr = memory::load_and_swap<uint32_t>(buffer + 32);
      uint32_t results_buffer_size = memory::load_and_swap<uint32_t>(buffer + 36);
      uint32_t search_results_ptr = memory::load_and_swap<uint32_t>(buffer + 40);
      uint32_t num_users = memory::load_and_swap<uint32_t>(buffer + 44);
      uint32_t weighted_search = memory::load_and_swap<uint32_t>(buffer + 48);

      REXKRNL_DEBUG(
          "XSessionSearchWeighted({:08X}, {:08X}, {:08X}, {}, {}, {:08X}, {:08X}, {}, {}, {:08X}, "
          "{:08X}, {:08X}, {:08X}, {:08X}, {:08X})",
          proc_index, user_index, num_results, num_weighted_properties, num_weighted_contexts,
          weighted_search_properties_ptr, weighted_search_contexts_ptr, num_props, num_ctx,
          non_weighted_search_properties_ptr, non_weighted_search_contexts_ptr, results_buffer_size,
          search_results_ptr, num_users, weighted_search);

      return X_E_SUCCESS;
    }
    case 0x000B0071: {
      REXKRNL_INFO("XGI 0x000B0071");
      return X_E_SUCCESS;
    }
  }
  REXKRNL_ERROR(
      "Unimplemented XGI message app={:08X}, msg={:08X}, arg1={:08X}, "
      "arg2={:08X}",
      app_id(), message, buffer_ptr, buffer_length);
  return X_E_FAIL;
}

}  // namespace apps
}  // namespace xam
}  // namespace kernel
}  // namespace rex
