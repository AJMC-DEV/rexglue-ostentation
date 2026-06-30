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

          uint64_t host_xuid = kernel_state_->user_profile()->xuid();
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
      // _XSESSION_SEARCHRESULT = 92 bytes; header = 8 bytes.
      constexpr uint32_t kResultSize = 92;
      constexpr uint32_t kHeaderSize = 8;
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

      // _XSESSION_SEARCHRESULT_HEADER: dwSearchResults (u32) + pResults (guest ptr, u32)
      // pResults points to the array immediately after the 8-byte header.
      uint32_t results_guest_ptr = search_results_ptr + kHeaderSize;
      memory::store_and_swap<uint32_t>(out + 0, count);
      memory::store_and_swap<uint32_t>(out + 4, count > 0 ? results_guest_ptr : 0u);

      uint8_t* r = out + kHeaderSize;
      for (uint32_t i = 0; i < count; ++i, r += kResultSize) {
        const auto& ws = sessions[i];
        std::memset(r, 0, kResultSize);

        // _XSESSION_INFO starts at offset 0:
        //   XNKID  sessionID  [0x00, 8 bytes]
        //   XNADDR hostAddress[0x08, 36 bytes]
        //   XNKEY  keyExchange[0x2C, 16 bytes]
        // Total _XSESSION_INFO = 60 bytes

        // XNKID (8 bytes at 0x00): 16 hex chars from xnkid_hex
        if (!HexToBytes(ws.xnkid_hex, r + 0x00, 8)) {
          REXKRNL_WARN("XSessionSearch: bad xnkid_hex '{}' for session {}", ws.xnkid_hex, i);
        }

        // XNADDR (36 bytes at 0x08):
        //   ina         u32  [0x08] — LAN address, unknown; leave 0
        //   inaOnline   u32  [0x0C] — public IP in NBO (written raw, no swap)
        //   wPortOnline u16  [0x10] — port in NBO
        //   abEnet      [6]  [0x12] — Ethernet MAC / pseudo-MAC from host_xuid low bytes
        //   abOnline    [20] [0x18] — zeros
        WriteIPNBO(r + 0x0C, ws.host_address);
        memory::store_and_swap<uint16_t>(r + 0x10, ws.port);
        // Use the low 6 bytes of host_xuid as a pseudo-MAC for abEnet
        uint64_t xuid = ws.host_xuid;
        r[0x12] = static_cast<uint8_t>((xuid >> 40) & 0xFF);
        r[0x13] = static_cast<uint8_t>((xuid >> 32) & 0xFF);
        r[0x14] = static_cast<uint8_t>((xuid >> 24) & 0xFF);
        r[0x15] = static_cast<uint8_t>((xuid >> 16) & 0xFF);
        r[0x16] = static_cast<uint8_t>((xuid >>  8) & 0xFF);
        r[0x17] = static_cast<uint8_t>((xuid >>  0) & 0xFF);

        // XNKEY (16 bytes at 0x2C): 32 hex chars from xnkey_hex
        if (!HexToBytes(ws.xnkey_hex, r + 0x2C, 16)) {
          REXKRNL_WARN("XSessionSearch: bad xnkey_hex '{}' for session {}", ws.xnkey_hex, i);
        }

        // Slot counts at 0x3C–0x4B (all u32 big-endian):
        //   dwOpenPublicSlots   [0x3C]
        //   dwOpenPrivateSlots  [0x40]
        //   dwFilledPublicSlots [0x44]
        //   dwFilledPrivateSlots[0x48]
        memory::store_and_swap<uint32_t>(r + 0x3C, ws.slots_public);
        memory::store_and_swap<uint32_t>(r + 0x40, ws.slots_private);
        // Filled slots unknown; leave as 0.

        // cProperties, cContexts, pProperties, pContexts at 0x4C–0x58: all 0 (no props/ctx)

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

      constexpr uint32_t kResultSize = 92;
      constexpr uint32_t kHeaderSize = 8;
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
      memory::store_and_swap<uint32_t>(out + 0, count);
      memory::store_and_swap<uint32_t>(out + 4, count > 0 ? results_guest_ptr : 0u);

      uint8_t* r = out + kHeaderSize;
      for (uint32_t i = 0; i < count; ++i, r += kResultSize) {
        const auto& ws = sessions[i];
        std::memset(r, 0, kResultSize);

        if (!HexToBytes(ws.xnkid_hex, r + 0x00, 8)) {
          REXKRNL_WARN("XSessionSearchEx: bad xnkid_hex '{}' for session {}", ws.xnkid_hex, i);
        }
        WriteIPNBO(r + 0x0C, ws.host_address);
        memory::store_and_swap<uint16_t>(r + 0x10, ws.port);
        uint64_t xuid = ws.host_xuid;
        r[0x12] = static_cast<uint8_t>((xuid >> 40) & 0xFF);
        r[0x13] = static_cast<uint8_t>((xuid >> 32) & 0xFF);
        r[0x14] = static_cast<uint8_t>((xuid >> 24) & 0xFF);
        r[0x15] = static_cast<uint8_t>((xuid >> 16) & 0xFF);
        r[0x16] = static_cast<uint8_t>((xuid >>  8) & 0xFF);
        r[0x17] = static_cast<uint8_t>((xuid >>  0) & 0xFF);
        if (!HexToBytes(ws.xnkey_hex, r + 0x2C, 16)) {
          REXKRNL_WARN("XSessionSearchEx: bad xnkey_hex '{}' for session {}", ws.xnkey_hex, i);
        }
        memory::store_and_swap<uint32_t>(r + 0x3C, ws.slots_public);
        memory::store_and_swap<uint32_t>(r + 0x40, ws.slots_private);

        REXKRNL_INFO("XSessionSearchEx: result[{}] xnkid={} host={} port={} pub={} priv={}",
                     i, ws.xnkid_hex, ws.host_address, ws.port,
                     ws.slots_public, ws.slots_private);
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
