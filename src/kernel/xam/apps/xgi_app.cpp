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
#include <rex/cvar.h>
#include <rex/logging.h>
#include <rex/system/xlive_web_client.h>
#include <rex/system/xsession.h>
#include <rex/thread.h>

#include <cstdio>
#include <cstring>

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
static void WriteSessionAttrs(memory::Memory* mem, uint8_t* r, uint32_t title_id,
                              const std::string& session_id) {
  enum : uint8_t { kTypeContext = 0, kTypeWString = 4, kTypeBinary = 6 };

  std::vector<std::vector<uint8_t>> blobs;
  system::XLiveWebClient::Get().GetSessionProperties(title_id, session_id, blobs);

  // Split contexts vs properties by X_USER_DATA type (blob[4]).
  std::vector<const std::vector<uint8_t>*> contexts, properties;
  for (const auto& b : blobs) {
    if (b.size() < 4 + 16) continue;
    if (b[4] == kTypeContext) contexts.push_back(&b);
    else properties.push_back(&b);
  }

  auto rd_le32 = [](const uint8_t* p) -> uint32_t {
    return p[0] | (p[1] << 8) | (p[2] << 16) | (uint32_t(p[3]) << 24);
  };

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
      return X_E_SUCCESS;
    }
    case 0x000B0007: {
      uint32_t user_index = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t property_id = memory::load_and_swap<uint32_t>(buffer + 16);
      uint32_t value_size = memory::load_and_swap<uint32_t>(buffer + 20);
      uint32_t value_ptr = memory::load_and_swap<uint32_t>(buffer + 24);
      REXKRNL_DEBUG("XGIUserSetPropertyEx({:08X}, {:08X}, {}, {:08X})", user_index, property_id,
                    value_size, value_ptr);
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
          REXKRNL_INFO("XGISessionCreateImpl: calling wc.CreateSession title_id={:08X}",
                       kernel_state_->title_id());
          std::string web_id;
          bool create_ok = wc.CreateSession(kernel_state_->title_id(), ws_info, web_id);
          REXKRNL_INFO("XGISessionCreateImpl: CreateSession ok={} web_id='{}'", create_ok, web_id);
          if (create_ok && !web_id.empty()) {
            session.set_web_session_id(web_id);
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
      assert_true(!buffer_length || buffer_length == 20);
      uint32_t session_ptr = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t user_count = memory::load_and_swap<uint32_t>(buffer + 4);
      uint32_t unk_0 = memory::load_and_swap<uint32_t>(buffer + 8);
      uint32_t user_index_array = memory::load_and_swap<uint32_t>(buffer + 12);
      uint32_t private_slots_array = memory::load_and_swap<uint32_t>(buffer + 16);

      assert_zero(unk_0);
      REXKRNL_INFO("XGISessionJoinLocal({:08X}, {}, {}, {:08X}, {:08X})", session_ptr, user_count,
                   unk_0, user_index_array, private_slots_array);
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
      // Match netplay's SEARCH_RESULTS layout: 0x0C header (8-byte
      // XSESSION_SEARCHRESULT_HEADER + a 4-byte results_ptr field), then the
      // array of XSESSION_SEARCHRESULT (0x5C each) at offset 0x0C.
      constexpr uint32_t kResultSize = 92;
      constexpr uint32_t kHeaderSize = 0x0C;
      uint32_t max_by_alloc = num_results;
      if (results_buffer_size >= kHeaderSize) {
        uint32_t max_by_buf = (results_buffer_size - kHeaderSize) / kResultSize;
        if (max_by_buf < max_by_alloc) max_by_alloc = max_by_buf;
      }

      uint32_t count = static_cast<uint32_t>(sessions.size());
      if (count > max_by_alloc) count = max_by_alloc;

      auto* out = memory_->TranslateVirtual(search_results_ptr);
      if (!out) {
        REXKRNL_WARN("XSessionSearch: search_results_ptr {:08X} unmapped", search_results_ptr);
        return X_E_SUCCESS;
      }

      uint32_t results_guest_ptr = search_results_ptr + kHeaderSize;
      memory::store_and_swap<uint32_t>(out + 0, count);
      memory::store_and_swap<uint32_t>(out + 4, count > 0 ? results_guest_ptr : 0u);
      memory::store_and_swap<uint32_t>(out + 8, count > 0 ? results_guest_ptr : 0u);

      uint8_t* r = out + kHeaderSize;
      for (uint32_t i = 0; i < count; ++i, r += kResultSize) {
        const auto& ws = sessions[i];
        std::memset(r, 0, kResultSize);

        // _XSESSION_INFO starts at offset 0:
        //   XNKID  sessionID  [0x00, 8 bytes]
        //   XNADDR hostAddress[0x08, 36 bytes]
        //   XNKEY  keyExchange[0x2C, 16 bytes]

        // XNKID (8 bytes at 0x00): 16 hex chars from xnkid_hex
        system::XNKID kid{};
        if (!HexToBytes(ws.xnkid_hex, kid.ab, 8)) {
          REXKRNL_WARN("XSessionSearch: bad xnkid_hex '{}' for session {}", ws.xnkid_hex, i);
        }
        std::memcpy(r + 0x00, kid.ab, 8);

        // XNADDR (36 bytes at 0x08) — mirrors netplay GetXnAddrFromSessionObject:
        //   ina         u32   [0x08] — public IP (both ina and inaOnline set)
        //   inaOnline   u32   [0x0C] — public IP in NBO
        //   wPortOnline u16   [0x10] — port in NBO
        //   abEnet      [6]   [0x12] — host ethernet MAC
        //   abOnline  SGADDR  [0x18] — zeroed except platform_type @0x28
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

        // XNKEY (16 bytes at 0x2C): netplay's fixed identity key {0,1,...,15}
        // (GenerateIdentityExchangeKey) on both ends — a zero key faults the
        // guest when it derives a secure association.
        system::XNKEY key{};
        for (uint8_t b = 0; b < 16; ++b) key.ab[b] = b;
        std::memcpy(r + 0x2C, key.ab, 16);

        // Slot counts (all four, matching netplay FillSessionSearchResult):
        //   open_public @0x3C, open_private @0x40, filled_public @0x44,
        //   filled_private @0x48
        uint32_t open_pub = ws.open_public;
        if (!open_pub && !ws.filled_public) open_pub = ws.slots_public;
        memory::store_and_swap<uint32_t>(r + 0x3C, open_pub);
        memory::store_and_swap<uint32_t>(r + 0x40, ws.open_private);
        memory::store_and_swap<uint32_t>(r + 0x44, ws.filled_public);
        memory::store_and_swap<uint32_t>(r + 0x48, ws.filled_private);

        // Properties/contexts: fetch the session's real advertised properties
        // (required — the game looks up specific property ids and derefs the
        // result, faulting on a missing one).
        WriteSessionAttrs(memory_, r, kernel_state_->title_id(), ws.session_id);

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

        REXKRNL_INFO("XSessionSearch: result[{}] xnkid={} host={} port={} pub={} priv={}",
                     i, ws.xnkid_hex, ws.host_address, ws.port,
                     ws.slots_public, ws.slots_private);
      }

      REXKRNL_INFO("XSessionSearch: wrote {} results to {:08X}", count, search_results_ptr);
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

      // Match netplay's SEARCH_RESULTS layout exactly (xsession.cc
      // GetSessionByIDs):
      //   struct SEARCH_RESULTS {
      //     XSESSION_SEARCHRESULT_HEADER header;  // count@0x00, results_ptr@0x04
      //     XSESSION_SEARCHRESULT*       results; // guest ptr @0x08
      //   };  // = 0x0C; the result array begins right after, at offset 0x0C.
      constexpr uint32_t kResultSize = 92;    // sizeof(XSESSION_SEARCHRESULT)
      constexpr uint32_t kHeaderSize = 0x0C;  // header(8) + results_ptr field(4)
      uint32_t max_by_alloc = num_results;
      if (results_buffer_size >= kHeaderSize) {
        uint32_t max_by_buf = (results_buffer_size - kHeaderSize) / kResultSize;
        if (max_by_buf < max_by_alloc) max_by_alloc = max_by_buf;
      }

      uint32_t count = static_cast<uint32_t>(sessions.size());
      if (count > max_by_alloc) count = max_by_alloc;

      auto* out = memory_->TranslateVirtual(search_results_ptr);
      if (!out) {
        REXKRNL_WARN("XSessionSearchEx: search_results_ptr {:08X} unmapped", search_results_ptr);
        return X_E_SUCCESS;
      }

      uint32_t results_guest_ptr = search_results_ptr + kHeaderSize;
      // header.search_results_count @0x00, header.search_results_ptr @0x04, and
      // the SEARCH_RESULTS::results_ptr field @0x08 — all point at the array.
      memory::store_and_swap<uint32_t>(out + 0, count);
      memory::store_and_swap<uint32_t>(out + 4, count > 0 ? results_guest_ptr : 0u);
      memory::store_and_swap<uint32_t>(out + 8, count > 0 ? results_guest_ptr : 0u);

      uint8_t* r = out + kHeaderSize;
      for (uint32_t i = 0; i < count; ++i, r += kResultSize) {
        const auto& ws = sessions[i];
        std::memset(r, 0, kResultSize);

        // --- XNKID (session id) @ 0x00 ---
        system::XNKID kid{};
        if (!HexToBytes(ws.xnkid_hex, kid.ab, 8)) {
          REXKRNL_WARN("XSessionSearchEx: bad xnkid_hex '{}' for session {}", ws.xnkid_hex, i);
        }
        std::memcpy(r + 0x00, kid.ab, 8);

        // --- XNADDR (hostAddress) @ 0x08 --- mirrors netplay
        // XLiveAPI::GetXnAddrFromSessionObject:
        //   ina         u32   [0x08] — public IP (netplay sets BOTH ina and
        //                              inaOnline to HostAddress; leaving ina 0
        //                              makes the joiner connect to 0.0.0.0)
        //   inaOnline   u32   [0x0C] — public IP in NBO
        //   wPortOnline u16   [0x10] — port in NBO
        //   abEnet      [6]   [0x12] — host ethernet MAC
        //   abOnline  SGADDR  [0x18] — zeroed except platform_type
        //     platform_type u8 [0x28] = Xbox360 (1); a mismatched platform makes
        //                                some titles refuse to join.
        WriteIPNBO(r + 0x08, ws.host_address);
        WriteIPNBO(r + 0x0C, ws.host_address);
        memory::store_and_swap<uint16_t>(r + 0x10, ws.port);

        // The backend returns the host's real MAC (macAddress). Write that into
        // abEnet — NOT the host xuid, which the search response does not carry.
        uint8_t mac[6] = {};
        bool have_mac = ws.mac_address.size() == 12 &&
                        HexToBytes(ws.mac_address, mac, 6);
        if (!have_mac && ws.host_xuid) {
          for (int b = 0; b < 6; ++b) {
            mac[b] = static_cast<uint8_t>(ws.host_xuid >> ((5 - b) * 8));
          }
          have_mac = true;
        }
        std::memcpy(r + 0x12, mac, 6);

        // abOnline stays zero (already memset) except the platform type byte at
        // SGADDR offset 0x10 (result offset 0x28).
        constexpr uint8_t kPlatformXbox360 = 1;  // PLATFORM_TYPE::Xbox360
        r[0x28] = kPlatformXbox360;

        // --- XNKEY (exchange key) @ 0x2C ---
        // Netplay uses a FIXED identity key {0,1,...,15}
        // (GenerateIdentityExchangeKey) on BOTH host and joiner; the backend
        // does not relay a key (xnkey_hex here is all-zeros). A zero exchange
        // key makes the guest fault when it derives a secure association from
        // it, so emit the same deterministic non-zero key netplay does.
        system::XNKEY key{};
        for (uint8_t b = 0; b < 16; ++b) key.ab[b] = b;
        std::memcpy(r + 0x2C, key.ab, 16);

        // --- Slot counts (netplay FillSessionSearchResult writes all four) ---
        //   open_public @0x3C, open_private @0x40,
        //   filled_public @0x44, filled_private @0x48
        uint32_t open_pub = ws.open_public;
        if (!open_pub && !ws.filled_public) open_pub = ws.slots_public;
        memory::store_and_swap<uint32_t>(r + 0x3C, open_pub);
        memory::store_and_swap<uint32_t>(r + 0x40, ws.open_private);
        memory::store_and_swap<uint32_t>(r + 0x44, ws.filled_public);
        memory::store_and_swap<uint32_t>(r + 0x48, ws.filled_private);

        // --- Properties/contexts @0x4C..0x58 ---
        // properties_count @0x4C, contexts_count @0x50,
        // properties_ptr   @0x54, contexts_ptr   @0x58
        // Netplay always SystemHeapAllocs these buffers; some titles dereference
        // result->properties_ptr / contexts_ptr as soon as a session is found,
        // regardless of the count — a NULL there faults in pure guest code
        // (which is exactly the crash: it only happens once count goes 0->1).
        // Fetch the session's real advertised properties/contexts from the
        // backend; the game looks up specific property ids by value and
        // dereferences the result, so they must be present.
        WriteSessionAttrs(memory_, r, kernel_state_->title_id(), ws.session_id);

        // Pre-register the discovered session so a subsequent
        // XNetXnAddrToInAddr / XNetRegisterKey on the joiner resolves this host
        // instead of missing (and the game connecting to a bogus token).
        if (!kid.IsZero()) {
          system::XNADDR addr{};
          {
            unsigned a = 0, bb = 0, c = 0, d = 0;
            if (std::sscanf(ws.host_address.c_str(), "%u.%u.%u.%u", &a, &bb, &c, &d) == 4) {
              uint32_t ip = htonl((a << 24) | (bb << 16) | (c << 8) | d);
              addr.ina = ip;        // netplay sets both ina and inaOnline
              addr.inaOnline = ip;
            }
          }
          addr.wPortOnline = htons(ws.port);
          std::memcpy(addr.abEnet, mac, 6);
          // abOnline zeroed except platform_type (SGADDR offset 0x10) = Xbox360.
          std::memset(addr.abOnline, 0, sizeof(addr.abOnline));
          addr.abOnline[0x10] = 1;  // PLATFORM_TYPE::Xbox360
          system::XNetKeyRegistry::Get().Register(kid, key);
          system::XNetAddrCache::Get().Store(addr, kid);
        }

        REXKRNL_INFO("XSessionSearchEx: result[{}] xnkid={} host={} port={} mac={} pub={} priv={}",
                     i, ws.xnkid_hex, ws.host_address, ws.port,
                     ws.mac_address, ws.slots_public, ws.slots_private);
        DumpResultBytes(r, kResultSize);
      }

      REXKRNL_INFO("XSessionSearchEx: wrote {} results to {:08X}", count, search_results_ptr);
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
      assert_true(!buffer_length || buffer_length == 32);

      uint32_t user_index = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t num_session_ids = memory::load_and_swap<uint32_t>(buffer + 4);
      uint32_t session_ids_ptr = memory::load_and_swap<uint32_t>(buffer + 8);
      uint32_t results_buffer_size = memory::load_and_swap<uint32_t>(buffer + 12);
      uint32_t search_results_ptr = memory::load_and_swap<uint32_t>(buffer + 16);
      uint32_t reserved1 = memory::load_and_swap<uint32_t>(buffer + 20);
      uint32_t reserved2 = memory::load_and_swap<uint32_t>(buffer + 24);
      uint32_t reserved3 = memory::load_and_swap<uint32_t>(buffer + 28);

      REXKRNL_DEBUG("XSessionSearchByID({}, {:08X}, {:08X}, {:08X}, {:08X}, {}, {}, {})",
                    user_index, num_session_ids, session_ids_ptr, results_buffer_size,
                    search_results_ptr, reserved1, reserved2, reserved3);

      return X_E_SUCCESS;
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

      REXKRNL_DEBUG("XSessionSearchByIds({:08X}, {:08X}, {:08X}, {:08X}, {:08X}, {}, {}, {})",
                    user_index, num_session_ids, session_ids_ptr, results_buffer_size,
                    search_results_ptr, reserved1, reserved2, reserved3);

      return X_E_SUCCESS;
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
