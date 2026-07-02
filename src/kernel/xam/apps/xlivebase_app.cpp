/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2026 Xenia Canary. All rights reserved.                          *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 *
 * @modified    Tom Clay, 2026 - Adapted for ReXGlue runtime
 * @modified    2026 - Message handling ported from xenia-canary netplay
 *              (src/xenia/kernel/xam/apps/xlivebase_app.cc). Async marshaled
 *              tasks that need the web backend return zeroed results instead
 *              of failing so titles treat the service as reachable.
 */

#include <rex/kernel/xam/apps/xlivebase_app.h>

#include <fmt/format.h>

#include <rex/cvar.h>
#include <rex/logging.h>
#include <rex/string.h>
#include <rex/system/xam/account_info.h>
#include <rex/system/xam/profile_manager.h>
#include <rex/system/xenumerator.h>
#include <rex/thread.h>

REXCVAR_DECLARE(bool, xlive_web_enabled);

namespace rex {
namespace kernel {
namespace xam {
using namespace rex::system;
using namespace rex::system::xam;
namespace apps {
using namespace rex::system;

XLiveBaseApp::XLiveBaseApp(KernelState* kernel_state) : App(kernel_state, 0xFC) {}

namespace {

// Empty friends list enumerator: correct item size, zero items.
class XStaticFriendsEnumerator : public XEnumerator {
 public:
  XStaticFriendsEnumerator(KernelState* kernel_state, size_t items_per_enumerate)
      : XEnumerator(kernel_state, items_per_enumerate, sizeof(X_ONLINE_FRIEND)) {}

  uint32_t WriteItems(uint32_t buffer_ptr, uint8_t* buffer_data,
                      uint32_t* written_count) override {
    if (written_count) {
      *written_count = 0;
    }
    return X_ERROR_NO_MORE_FILES;
  }
};

}  // namespace

uint32_t XLiveBaseApp::ReadArgument32(const X_ARGUMENT_ENTRY& entry) {
  const uint32_t value_ptr = static_cast<uint32_t>(entry.argument_value_ptr);
  if (!value_ptr) {
    return 0;
  }
  return memory::load_and_swap<uint32_t>(memory_->TranslateVirtual(value_ptr));
}

// Zeroes the results buffer of a marshaled XLive async task so titles read a
// well-defined "empty" response. buffer_ptr points at XLIVEBASE_ASYNC_MESSAGE.
X_HRESULT XLiveBaseApp::ZeroAsyncTaskResults(uint32_t buffer_ptr) {
  if (!buffer_ptr) {
    return X_E_INVALIDARG;
  }

  auto* async_message =
      memory_->TranslateVirtual<XLIVEBASE_ASYNC_MESSAGE*>(buffer_ptr);
  if (!async_message->xlive_async_task_ptr) {
    return X_E_SUCCESS;
  }

  auto* task = memory_->TranslateVirtual<XLIVE_ASYNC_TASK*>(
      async_message->xlive_async_task_ptr);
  if (task->results_ptr && task->results_size) {
    uint8_t* results = memory_->TranslateVirtual(task->results_ptr);
    std::memset(results, 0, task->results_size);
  }

  return X_E_SUCCESS;
}

X_HRESULT XLiveBaseApp::XOnlineGetServiceInfo(uint32_t service_id,
                                              uint32_t service_info) {
  if (!REXCVAR_GET(xlive_web_enabled)) {
    return X_ONLINE_E_LOGON_NOT_LOGGED_ON;
  }

  if (!service_info) {
    return X_E_SUCCESS;
  }

  auto* service_info_ptr =
      memory_->TranslateVirtual<X_ONLINE_SERVICE_INFO*>(service_info);
  std::memset(service_info_ptr, 0, sizeof(X_ONLINE_SERVICE_INFO));
  service_info_ptr->id = service_id;

  return X_E_SUCCESS;
}

X_HRESULT XLiveBaseApp::XFriendsCreateEnumerator(uint32_t buffer_ptr,
                                                 uint32_t buffer_length) {
  if (!buffer_ptr || !buffer_length) {
    return X_E_INVALIDARG;
  }

  // buffer_length is actually a pointer to the marshaled argument list.
  auto* friends_enumerator =
      memory_->TranslateVirtual<X_CREATE_FRIENDS_ENUMERATOR*>(buffer_length);

  const uint32_t user_index = ReadArgument32(friends_enumerator->user_index);
  const uint32_t friends_starting_index =
      ReadArgument32(friends_enumerator->friends_starting_index);
  const uint32_t friends_amount =
      ReadArgument32(friends_enumerator->friends_amount);
  const uint32_t buffer_address =
      static_cast<uint32_t>(friends_enumerator->buffer_ptr.argument_value_ptr);
  const uint32_t handle_address =
      static_cast<uint32_t>(friends_enumerator->handle_ptr.argument_value_ptr);

  if (!handle_address) {
    return X_E_INVALIDARG;
  }

  auto* handle_ptr = memory_->TranslateVirtual<rex::be<uint32_t>*>(handle_address);

  // 41560834 and 45410923 expect invalid handle of 0 (not -1) for failure,
  // therefore set as soon as possible.
  *handle_ptr = 0;

  if (!buffer_address) {
    return X_E_INVALIDARG;
  }

  auto* buffer_size_ptr =
      memory_->TranslateVirtual<rex::be<uint32_t>*>(buffer_address);
  *buffer_size_ptr = 0;

  if (user_index >= XUserMaxUserCount) {
    return X_E_INVALIDARG;
  }

  if (friends_starting_index >= X_ONLINE_MAX_FRIENDS) {
    return X_E_INVALIDARG;
  }

  if (friends_amount > X_ONLINE_MAX_FRIENDS) {
    return X_E_INVALIDARG;
  }

  if (!kernel_state_->profile_manager()->GetProfile(
          static_cast<uint8_t>(user_index))) {
    return X_E_NO_SUCH_USER;
  }

  auto e = object_ref<XStaticFriendsEnumerator>(
      new XStaticFriendsEnumerator(kernel_state_, friends_amount));

  auto result = e->Initialize(0xFF, app_id(), 0x58021, 0x58022, 0);
  if (XFAILED(result)) {
    return result;
  }

  const uint32_t friends_buffer_size =
      static_cast<uint32_t>(e->items_per_enumerate() * e->item_size());

  *buffer_size_ptr = friends_buffer_size;
  *handle_ptr = e->handle();

  REXKRNL_DEBUG("XFriendsCreateEnumerator: user={} count={} -> empty list",
                user_index, friends_amount);
  return X_E_SUCCESS;
}

X_HRESULT XLiveBaseApp::XStorageBuildServerPath(uint32_t buffer_ptr) {
  if (!buffer_ptr) {
    return X_E_INVALIDARG;
  }

  auto* args = memory_->TranslateVirtual<X_STORAGE_BUILD_SERVER_PATH*>(buffer_ptr);

  if (args->user_index >= XUserMaxUserCount &&
      args->user_index != XUserIndexNone) {
    return X_E_INVALIDARG;
  }

  uint64_t xuid = 0;
  if (args->user_index == XUserIndexNone) {
    xuid = args->xuid;
    if (!xuid) {
      return X_E_INVALIDARG;
    }
  } else {
    auto* profile = kernel_state_->profile_manager()->GetProfile(
        static_cast<uint8_t>(args->user_index));
    if (!profile) {
      return X_E_NO_SUCH_USER;
    }
    xuid = profile->GetOnlineXUID();
  }

  if (!args->server_path_length_ptr) {
    return X_E_INVALIDARG;
  }

  auto read_filename = [args, this]() -> std::string {
    if (!args->file_name_ptr) {
      return "";
    }

    const char16_t* filename_ptr =
        memory_->TranslateVirtual<char16_t*>(args->file_name_ptr);

    std::u16string filename;
    for (const char16_t* p = filename_ptr; *p; ++p) {
      filename.push_back(rex::byte_swap(*p));
    }
    return rex::string::to_utf8(filename);
  };

  // Storage facility types (netplay X_STORAGE_FACILITY).
  constexpr uint32_t kFacilityGameClip = 1;
  constexpr uint32_t kFacilityPerTitle = 2;
  constexpr uint32_t kFacilityPerUserTitle = 3;

  std::u16string guest_path;

  switch (args->storage_location) {
    case kFacilityGameClip: {
      if (!args->storage_location_info_ptr ||
          args->storage_location_info_size != sizeof(uint32_t)) {
        return X_E_INVALIDARG;
      }

      const uint32_t leaderboard_id = memory::load_and_swap<uint32_t>(
          memory_->TranslateVirtual(args->storage_location_info_ptr));

      guest_path = rex::string::to_utf16(
          fmt::format("//xestats/u:{:016x}/{:08x}/{:08x}", xuid,
                      kernel_state_->title_id(), leaderboard_id));
    } break;
    case kFacilityPerTitle: {
      if (args->storage_location_info_ptr || args->storage_location_info_size) {
        return X_E_INVALIDARG;
      }

      const std::string filename = read_filename();
      if (filename.empty()) {
        return X_E_INVALIDARG;
      }

      guest_path = rex::string::to_utf16(
          fmt::format("//title.{:08x}/t:{:08x}/{}", kernel_state_->title_id(),
                      kernel_state_->title_id(), filename));
    } break;
    case kFacilityPerUserTitle: {
      if (args->storage_location_info_ptr || args->storage_location_info_size) {
        return X_E_INVALIDARG;
      }

      const std::string filename = read_filename();
      if (filename.empty()) {
        return X_E_INVALIDARG;
      }

      guest_path = rex::string::to_utf16(
          fmt::format("//tuser.{:08x}/u:{:016x}/{:08x}/{}",
                      kernel_state_->title_id(), xuid,
                      kernel_state_->title_id(), filename));
    } break;
    default:
      return X_ONLINE_E_STORAGE_INVALID_FACILITY;
  }

  uint32_t server_path_length = 0;

  if (args->server_path_ptr) {
    const size_t size_bytes = (guest_path.size() + 1) * sizeof(char16_t);

    // Ensure server path buffer has enough space
    server_path_length = memory::load_and_swap<uint32_t>(
        memory_->TranslateVirtual(args->server_path_length_ptr));

    if (server_path_length < size_bytes) {
      return X_E_INVALIDARG;
    }

    char16_t* server_path_ptr =
        memory_->TranslateVirtual<char16_t*>(args->server_path_ptr);

    rex::string::copy_and_swap_truncating(server_path_ptr, guest_path,
                                          server_path_length);
  }

  server_path_length = static_cast<uint32_t>(guest_path.size()) + 1;
  memory::store_and_swap<uint32_t>(
      memory_->TranslateVirtual(args->server_path_length_ptr),
      server_path_length);

  REXKRNL_DEBUG("XStorageBuildServerPath: {}",
                rex::string::to_utf8(guest_path));
  return X_E_SUCCESS;
}

// http://mb.mirage.org/bugzilla/xliveless/main.c
X_HRESULT XLiveBaseApp::DispatchMessageSync(uint32_t message, uint32_t buffer_ptr,
                                            uint32_t buffer_length) {
  // NOTE: buffer_length may be zero, valid, or a pointer to marshaled args.
  auto buffer = memory_->TranslateVirtual(buffer_ptr);
  switch (message) {
    case 0x00050002: {
      // XInviteSend - invites are not supported.
      REXKRNL_DEBUG("XInviteSend({:08X}, {:08X}) ignored", buffer_ptr,
                    buffer_length);
      return X_E_SUCCESS;
    }
    case 0x00050008: {
      REXKRNL_DEBUG("XStorageDelete({:08X})", buffer_ptr);
      return ZeroAsyncTaskResults(buffer_ptr);
    }
    case 0x00050009: {
      // 534507D4, 555307D7, 545107D1
      // No storage backend: report file not found; titles treat this as
      // "no data uploaded yet".
      REXKRNL_DEBUG("XStorageDownloadToMemory({:08X})", buffer_ptr);
      ZeroAsyncTaskResults(buffer_ptr);
      return X_ONLINE_E_STORAGE_FILE_NOT_FOUND;
    }
    case 0x0005000A: {
      // 4D5307D3, 415607F7, 584108F0, 5454082B, 545407F8, 575207FD, 555307D7
      REXKRNL_DEBUG("XStorageEnumerate({:08X}) -> empty", buffer_ptr);
      return ZeroAsyncTaskResults(buffer_ptr);
    }
    case 0x0005000B: {
      // 43430821, 4E4D07D3
      REXKRNL_DEBUG("XStorageUploadFromMemory({:08X}) -> pretend uploaded",
                    buffer_ptr);
      return ZeroAsyncTaskResults(buffer_ptr);
    }
    case 0x0005000C: {
      // 57520829, 4156081C, 415607D2
      // Zeroed STRING_VERIFY_RESPONSE result codes == 0 (no offensive text).
      REXKRNL_DEBUG("XStringVerify({:08X}, {:08X})", buffer_ptr, buffer_length);
      return ZeroAsyncTaskResults(buffer_ptr);
    }
    case 0x0005000D: {
      // 4D5307EA, 58410889
      REXKRNL_DEBUG("XUserEstimateRankForRating({:08X})", buffer_ptr);
      return ZeroAsyncTaskResults(buffer_ptr);
    }
    case 0x0005000E: {
      // 584113E8
      REXKRNL_DEBUG("XUserFindUsers({:08X}) -> none", buffer_ptr);
      return ZeroAsyncTaskResults(buffer_ptr);
    }
    case 0x0005000F:
    case 0x000500B0: {
      // 454107DB, 4D530AA5, 454107F1
      REXKRNL_DEBUG("XAccountGetUserInfo({:08X})", buffer_ptr);
      return ZeroAsyncTaskResults(buffer_ptr);
    }
    case 0x0005006E: {
      // 4D5307D3, 4D5307D1, 545407E2, 545407E3, 545407D2, 545407D3, 534507D4
      REXKRNL_DEBUG("XOnlineQuerySearch({:08X}) -> no results", buffer_ptr);
      return ZeroAsyncTaskResults(buffer_ptr);
    }
    case 0x000500C6: {
      REXKRNL_DEBUG("XAccountGetPointsBalance({:08X})", buffer_ptr);
      return ZeroAsyncTaskResults(buffer_ptr);
    }
    case 0x000500F7: {
      REXKRNL_DEBUG("XOfferingContentEnumerate({:08X}) -> empty", buffer_ptr);
      return ZeroAsyncTaskResults(buffer_ptr);
    }
    case 0x000500FE: {
      REXKRNL_DEBUG("XGetBannerList({:08X}) -> empty", buffer_ptr);
      return ZeroAsyncTaskResults(buffer_ptr);
    }
    case 0x000500FF: {
      REXKRNL_DEBUG("XGetBannerListHot({:08X}) -> empty", buffer_ptr);
      return ZeroAsyncTaskResults(buffer_ptr);
    }
    case 0x00050104: {
      REXKRNL_DEBUG("XOfferingSubscriptionEnumerate({:08X}) -> empty",
                    buffer_ptr);
      return ZeroAsyncTaskResults(buffer_ptr);
    }
    case 0x00050119: {
      REXKRNL_DEBUG("XPassportGetMemberName({:08X})", buffer_ptr);
      return ZeroAsyncTaskResults(buffer_ptr);
    }
    case 0x0005012B: {
      REXKRNL_DEBUG("XUserValidateAvatarManifest({:08X})", buffer_ptr);
      return ZeroAsyncTaskResults(buffer_ptr);
    }
    case 0x00058003: {
      // Called on startup of dashboard (and by games to check LIVE logon).
      const X_HRESULT live_connection_state =
          REXCVAR_GET(xlive_web_enabled) ? X_ONLINE_S_LOGON_CONNECTION_ESTABLISHED
                                         : X_ONLINE_S_LOGON_DISCONNECTED;
      REXKRNL_DEBUG("XLiveBaseLogonGetHR({:08X}, {:08X}) -> {:08X}", buffer_ptr,
                    buffer_length, static_cast<uint32_t>(live_connection_state));
      return live_connection_state;
    }
    case 0x00058004: {
      // Called on startup, seems to just return a bool in the buffer.
      assert_true(!buffer_length || buffer_length == 4);
      REXKRNL_DEBUG("XOnlineGetLogonID({:08X})", buffer_ptr);
      memory::store_and_swap<uint32_t>(buffer + 0, 1);
      return X_E_SUCCESS;
    }
    case 0x00058006: {
      assert_true(!buffer_length || buffer_length == 4);
      REXKRNL_DEBUG("XOnlineGetNatType({:08X})", buffer_ptr);
      memory::store_and_swap<uint32_t>(buffer + 0, NAT_OPEN);
      return X_E_SUCCESS;
    }
    case 0x00058007: {
      REXKRNL_DEBUG("XOnlineGetServiceInfo({:08X}, {:08X})", buffer_ptr,
                    buffer_length);
      return XOnlineGetServiceInfo(buffer_ptr, buffer_length);
    }
    case 0x00058009: {
      REXKRNL_DEBUG("XContentGetMarketplaceCounts({:08X}, {:08X})", buffer_ptr,
                    buffer_length);
      if (buffer_ptr && buffer_length) {
        std::memset(buffer, 0, buffer_length);
      }
      return X_E_SUCCESS;
    }
    case 0x0005800A: {
      REXKRNL_DEBUG("XUpdateAccessTimes({:08X}, {:08X})", buffer_ptr,
                    buffer_length);
      return X_E_SUCCESS;
    }
    case 0x0005800C: {
      // 464F0800
      REXKRNL_DEBUG("XUserMuteListAdd({:08X}, {:08X})", buffer_ptr,
                    buffer_length);
      return X_E_SUCCESS;
    }
    case 0x0005800D: {
      // 464F0800
      REXKRNL_DEBUG("XUserMuteListRemove({:08X}, {:08X})", buffer_ptr,
                    buffer_length);
      return X_E_SUCCESS;
    }
    case 0x0005800E: {
      // 513107D9 - buffer_length is a pointer to the result bool.
      REXKRNL_DEBUG("XUserMuteListQuery({:08X}, {:08X})", buffer_ptr,
                    buffer_length);
      if (buffer_length) {
        memory::store_and_swap<uint32_t>(memory_->TranslateVirtual(buffer_length),
                                         0);  // not muted
      }
      return X_E_SUCCESS;
    }
    case 0x00058017: {
      REXKRNL_DEBUG("GetNextSequenceMessage({:08X}, {:08X})", buffer_ptr,
                    buffer_length);
      return X_E_FAIL;  // no pending sequence messages
    }
    case 0x00058019: {
      // 54510846
      REXKRNL_DEBUG("XPresenceCreateEnumerator({:08X}, {:08X})", buffer_ptr,
                    buffer_length);
      return X_E_FAIL;
    }
    case 0x0005801C: {
      REXKRNL_DEBUG("XPresenceGetState({:08X}, {:08X})", buffer_ptr,
                    buffer_length);
      return X_E_SUCCESS;
    }
    case 0x0005801E: {
      // 54510846
      REXKRNL_DEBUG("XPresenceSubscribe({:08X}, {:08X})", buffer_ptr,
                    buffer_length);
      return X_E_SUCCESS;
    }
    case 0x0005801F: {
      // 545107D1
      REXKRNL_DEBUG("XPresenceUnsubscribe({:08X}, {:08X})", buffer_ptr,
                    buffer_length);
      return X_E_SUCCESS;
    }
    case 0x00058020: {
      REXKRNL_DEBUG("XFriendsCreateEnumerator({:08X}, {:08X})", buffer_ptr,
                    buffer_length);
      return XFriendsCreateEnumerator(buffer_ptr, buffer_length);
    }
    case 0x00058023: {
      // 584107D7
      REXKRNL_DEBUG("XInviteGetAcceptedInfo({:08X}, {:08X}) -> no invite",
                    buffer_ptr, buffer_length);
      return X_E_FAIL;
    }
    case 0x00058024: {
      REXKRNL_DEBUG("XMessageEnumerate({:08X}, {:08X}) -> none", buffer_ptr,
                    buffer_length);
      return X_E_FAIL;
    }
    case 0x00058032: {
      REXKRNL_DEBUG("XOnlineGetTaskProgress({:08X}, {:08X})", buffer_ptr,
                    buffer_length);
      return X_E_SUCCESS;
    }
    case 0x00058035: {
      REXKRNL_DEBUG("XStorageBuildServerPath({:08X}, {:08X})", buffer_ptr,
                    buffer_length);
      return XStorageBuildServerPath(buffer_ptr);
    }
    case 0x00058037: {
      // Used in older games such as Crackdown, FM2, Saints Row 1
      REXKRNL_DEBUG("XPresenceInitializeLegacy({:08X}, {:08X})", buffer_ptr,
                    buffer_length);
      return X_E_SUCCESS;
    }
    case 0x00058044: {
      REXKRNL_DEBUG("XPresenceUnsubscribe({:08X}, {:08X})", buffer_ptr,
                    buffer_length);
      return X_E_SUCCESS;
    }
    case 0x00058046: {
      // Used in newer games such as Forza 4, MW3, FH2
      // Required to be successful for 4D530910 to detect signed-in profile
      REXKRNL_DEBUG("XLiveBaseUnk58046({:08X}, {:08X})", buffer_ptr,
                    buffer_length);
      return X_E_SUCCESS;
    }
    case 0x00058056: {
      REXKRNL_DEBUG("XPresenceInitializeEx({:08X}, {:08X})", buffer_ptr,
                    buffer_length);
      return X_E_SUCCESS;
    }
    case 0x0005806A: {
      REXKRNL_DEBUG("XOnlineCallWebService({:08X}, {:08X}) unimplemented",
                    buffer_ptr, buffer_length);
      return X_E_FAIL;
    }
    case 0x00058072: {
      REXKRNL_DEBUG("XOnlineGetWebServiceTaskBufferSize({:08X}, {:08X})",
                    buffer_ptr, buffer_length);
      return X_E_FAIL;
    }
  }
  REXKRNL_ERROR(
      "Unimplemented XLIVEBASE message app={:08X}, msg={:08X}, arg1={:08X}, "
      "arg2={:08X}",
      app_id(), message, buffer_ptr, buffer_length);
  return X_E_FAIL;
}

}  // namespace apps
}  // namespace xam
}  // namespace kernel
}  // namespace rex
