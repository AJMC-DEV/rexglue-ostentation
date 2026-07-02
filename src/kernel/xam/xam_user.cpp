/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2022 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 *
 * @modified    Tom Clay, 2026 - Adapted for ReXGlue runtime
 * @modified    2026 - User/account semantics ported from xenia-canary netplay
 *              (src/xenia/kernel/xam/xam_user.cc).
 */

// Disable warnings about unused parameters for kernel functions
#pragma GCC diagnostic ignored "-Wunused-parameter"

#include <cstring>

#include <rex/cvar.h>

REXCVAR_DECLARE(bool, xlive_web_enabled);

#include <rex/kernel/xam/private.h>
#include <rex/logging.h>
#include <rex/math.h>
#include <rex/hook.h>
#include <rex/types.h>
#include <rex/string.h>
#include <rex/system/kernel_state.h>
#include <rex/system/xam/account_info.h>
#include <rex/system/xam/profile_manager.h>
#include <rex/system/xam/user_profile.h>
#include <rex/system/xenumerator.h>
#include <rex/system/xio.h>
#include <rex/system/xthread.h>
#include <rex/system/xtypes.h>

// stb_image implementation is compiled statically into this TU only; keep it
// static so WINDOWS_EXPORT_ALL_SYMBOLS doesn't export stb symbols from the
// runtime DLL (the graphics module vendors its own copy).
#define STB_IMAGE_STATIC
#define STB_IMAGE_IMPLEMENTATION
#include <stb/stb_image.h>

REXCVAR_DEFINE_UINT32(user_language, 1, "Kernel", "User's language ID");

namespace rex {
namespace kernel {
namespace xam {
using namespace rex::system;
using namespace rex::system::xam;

namespace {

UserProfile* GetUserProfile(uint32_t user_index) {
  return REX_KERNEL_STATE()->profile_manager()->GetProfile(static_cast<uint8_t>(user_index));
}

bool IsUserSignedIn(uint32_t user_index) {
  if(GetUserProfile(user_index) != nullptr) {
    return true;
  }else {
    REXKRNL_ERROR("IsUserSignedIn: user={} -> false (no profile)", (uint32_t)user_index);
    return false;
  }
}

// Looks a profile up by either its offline or online XUID.
UserProfile* GetUserProfileAny(uint64_t xuid) {
  REXKRNL_INFO("GetUserProfileAny: xuid={:016X}", (uint64_t)xuid);
  auto* profile_manager = REX_KERNEL_STATE()->profile_manager();
  UserProfile* profile = profile_manager->GetProfile(xuid);
  if (!profile) {
    REXKRNL_INFO("GetUserProfileAny: xuid={:016X} -> not found in offline profiles, checking online profiles", (uint64_t)xuid);
    profile = profile_manager->GetProfileLive(xuid);
  }else {
    REXKRNL_INFO("GetUserProfileAny: xuid={:016X} -> found in offline profiles", (uint64_t)xuid);
  }
  return profile;
}

}  // namespace

i32 XamUserGetXUID_entry(u32 user_index, u32 type_mask, mapped_u64 xuid_ptr) {
  REXKRNL_INFO("XamUserGetXUID: user={} type_mask={:08X} xuid_ptr={:08X}", (uint32_t)user_index, (uint32_t)type_mask, (uint32_t)xuid_ptr);
  if (!xuid_ptr) {
    REXKRNL_ERROR("XamUserGetXUID: X_E_INVALIDARG (null pointer to xuid_ptr)");
    return X_E_INVALIDARG;
  }

  *xuid_ptr = 0;

  if (user_index >= XUserMaxUserCount) {
    REXKRNL_ERROR("XamUserGetXUID: X_E_INVALIDARG (user_index out of range)");
    return X_E_INVALIDARG;
  }

  const auto* user_profile = GetUserProfile(user_index);
  if (!user_profile) {
    REXKRNL_ERROR("XamUserGetXUID: X_E_NO_SUCH_USER (user_index {} not signed in)", (uint32_t)user_index);
    return X_E_NO_SUCH_USER;
  }

  uint32_t result = X_E_NO_SUCH_USER;
  uint64_t xuid = 0;

  if (type_mask & X_USER_XUID_ONLINE) {
    xuid = user_profile->GetLogonXUID();
    REXKRNL_INFO("XamUserGetXUID: user={} type_mask={:08X} -> online xuid={:016X}", (uint32_t)user_index, (uint32_t)type_mask, xuid);
    result = X_E_SUCCESS;
  } else if (type_mask & X_USER_XUID_OFFLINE) {
    xuid = user_profile->xuid();
    REXKRNL_INFO("XamUserGetXUID: user={} type_mask={:08X} -> offline xuid={:016X}", (uint32_t)user_index, (uint32_t)type_mask, xuid);
    result = X_E_SUCCESS;
  }

  if (type_mask == X_USER_XUID_GUEST) {
    REXKRNL_ERROR("XamUserGetXUID: X_E_NO_SUCH_USER (guest type_mask not supported)");
    result = X_E_NO_SUCH_USER;
  }

  REXKRNL_INFO("XamUserGetXUID: user={} type_mask={:08X} -> {:016X} result={:08X}",(uint32_t)user_index, (uint32_t)type_mask, xuid, result);
  *xuid_ptr = xuid;
  return result;
}

u32 XamUserGetSigninState_entry(u32 user_index) {
  X_USER_SIGNIN_STATE signin_state = X_USER_SIGNIN_STATE::NotSignedIn;
  if (user_index >= XUserMaxUserCount) {
    REXKRNL_ERROR("XamUserGetSigninState: user={} -> NotSignedIn (user_index out of range)", (uint32_t)user_index);
    return static_cast<uint32_t>(signin_state);
  }

  const auto* user_profile = GetUserProfile(user_index);
  if (user_profile) {
    REXKRNL_INFO("XamUserGetSigninState: user={} -> {}", (uint32_t)user_index, static_cast<uint32_t>(user_profile->signin_state()));
    signin_state = user_profile->signin_state();
  } else {
    REXKRNL_INFO("XamUserGetSigninState: user={} -> NotSignedIn (no profile)", (uint32_t)user_index);
  }

  return static_cast<uint32_t>(signin_state);
}

typedef struct {
  rex::be<uint64_t> xuid;
  rex::be<uint32_t> info_flags;
  rex::be<uint32_t> signin_state;
  rex::be<uint32_t> dwGuestNumber;
  rex::be<uint32_t> dwSponsorUserIndex;
  char name[16];
} X_USER_SIGNIN_INFO;
static_assert_size(X_USER_SIGNIN_INFO, 40);

i32 XamUserGetSigninInfo_entry(u32 user_index, u32 flags, ppc_ptr_t<X_USER_SIGNIN_INFO> info) {
  if (!info) {
    REXKRNL_ERROR("XamUserGetSigninInfo: X_E_INVALIDARG (null pointer to info)");
    return X_E_INVALIDARG;
  }

  std::memset(info, 0, sizeof(X_USER_SIGNIN_INFO));

  if (user_index >= XUserMaxUserCount) {
    REXKRNL_ERROR("XamUserGetSigninInfo: X_E_INVALIDARG (user_index out of range)");
    return X_E_NO_SUCH_USER;
  }

  const auto* user_profile = GetUserProfile(user_index);
  if (!user_profile) {
    REXKRNL_ERROR("XamUserGetSigninInfo: X_E_NO_SUCH_USER (user_index {} not signed in)", (uint32_t)user_index);
    return X_E_NO_SUCH_USER;
  }

  rex::string::copy_truncating(info->name, user_profile->name(),
                               rex::countof(info->name));

  uint32_t info_flags = 0;
  if (user_profile->IsLiveEnabled()) {
    REXKRNL_INFO("XamUserGetSigninInfo: user={} -> LiveEnabled", (uint32_t)user_index);
    info_flags |= X_USER_INFO_FLAG_LIVE_ENABLED;
  }
  info->info_flags = info_flags;

  // Online XUID if connected to Xbox Live, otherwise offline XUID
  uint64_t xuid = 0;
  if (!flags) {
    REXKRNL_INFO("XamUserGetSigninInfo: user={} -> no flags, returning offline xuid={:016X}", (uint32_t)user_index, user_profile->xuid());
    xuid = user_profile->GetLogonXUID();
  }

  if (flags & X_USER_GET_SIGNIN_INFO_OFFLINE_XUID_ONLY) {
    REXKRNL_INFO("XamUserGetSigninInfo: user={} -> OFFLINE_XUID_ONLY, returning offline xuid={:016X}", (uint32_t)user_index, user_profile->xuid());
    //xuid = user_profile->xuid();
    xuid = user_profile->GetOnlineXUID();
  }

  // If both OFFLINE_XUID_ONLY and ONLINE_XUID_ONLY are provided, return the
  // online XUID.
  if (flags & X_USER_GET_SIGNIN_INFO_ONLINE_XUID_ONLY) {
    REXKRNL_INFO("XamUserGetSigninInfo: user={} -> ONLINE_XUID_ONLY, returning online xuid={:016X}", (uint32_t)user_index, user_profile->GetOnlineXUID());
    xuid = user_profile->GetOnlineXUID();
  }

  info->xuid = xuid;
  info->signin_state = static_cast<uint32_t>(user_profile->signin_state());

  REXKRNL_INFO("XamUserGetSigninInfo: user={} flags={:08X} -> state={} xuid={:016X} name='{}'", (uint32_t)user_index, (uint32_t)flags,(uint32_t)info->signin_state, xuid, info->name);
  return X_E_SUCCESS;
}

u32 XamUserGetName_entry(u32 user_index, mapped_string buffer, u32 buffer_len) {
  if (user_index >= XUserMaxUserCount) {
    REXKRNL_ERROR("XamUserGetName: user={} -> X_ERROR_INVALID_PARAMETER (user_index out of range)", (uint32_t)user_index);
    return X_ERROR_INVALID_PARAMETER;
  }

  const auto* user_profile = GetUserProfile(user_index);
  if (!user_profile) {
    REXKRNL_ERROR("XamUserGetName: user={} -> X_ERROR_NO_SUCH_USER (no profile)", (uint32_t)user_index);
    // Based on XAM only first byte is cleared in case of lack of user.
    if (buffer && buffer_len) {
      rex::string::copy_truncating(buffer, "", 1);
    }
    return X_ERROR_NO_SUCH_USER;
  }

  const auto& user_name = user_profile->name();
  rex::string::copy_truncating(buffer, user_name, std::min(buffer_len, uint32_t(16)));
  REXKRNL_INFO("XamUserGetName: user={} -> name='{}'", (uint32_t)user_index, user_name);
  return X_ERROR_SUCCESS;
}

u32 XamUserGetGamerTag_entry(u32 user_index, mapped_wstring buffer, u32 buffer_len) {
  if (user_index >= XUserMaxUserCount) {
    REXKRNL_ERROR("XamUserGetGamerTag: user={} -> X_E_INVALIDARG (user_index out of range)", (uint32_t)user_index);
    return X_E_INVALIDARG;
  }

  if (!buffer || buffer_len < 16) {
    REXKRNL_ERROR("XamUserGetGamerTag: user={} -> X_E_INVALIDARG (invalid buffer or buffer_len < 16)", (uint32_t)user_index);
    return X_E_INVALIDARG;
  }

  const auto* user_profile = GetUserProfile(user_index);
  if (!user_profile) {
    REXKRNL_ERROR("XamUserGetGamerTag: user={} -> X_E_NO_SUCH_USER (no profile)", (uint32_t)user_index);
    return X_E_NO_SUCH_USER;
  }

  auto user_name = rex::string::to_utf16(user_profile->name());
  rex::string::copy_and_swap_truncating(buffer, user_name, std::min(buffer_len, uint32_t(16)));
  REXKRNL_INFO("XamUserGetGamerTag: user={} -> gamertag='{}'", (uint32_t)user_index, user_profile->name());
  return X_E_SUCCESS;
}

typedef struct {
  rex::be<uint32_t> setting_count;
  rex::be<uint32_t> settings_ptr;
} X_USER_READ_PROFILE_SETTINGS;
static_assert_size(X_USER_READ_PROFILE_SETTINGS, 8);

// https://github.com/oukiar/freestyledash/blob/master/Freestyle/Tools/Generic/xboxtools.cpp
uint32_t XamUserReadProfileSettingsEx(uint32_t title_id, uint32_t user_index, uint32_t xuid_count,
                                      be<uint64_t>* xuids, uint32_t setting_count,
                                      be<uint32_t>* setting_ids, uint32_t unk,
                                      be<uint32_t>* buffer_size_ptr, uint8_t* buffer,
                                      XAM_OVERLAPPED* overlapped) {
  // must have at least 1 to 32 settings
  if (setting_count < 1 || setting_count > 32) {
    REXKRNL_ERROR("XamUserReadProfileSettingsEx: X_E_INVALIDARG (setting_count out of range)");
    return X_ERROR_INVALID_PARAMETER;
  }

  // buffer size pointer must be valid
  if (!buffer_size_ptr) {
    REXKRNL_ERROR("XamUserReadProfileSettingsEx: X_E_INVALIDARG (buffer_size_ptr is null)");
    return X_ERROR_INVALID_PARAMETER;
  }

  // if buffer size is non-zero, buffer pointer must be valid
  auto buffer_size = static_cast<uint32_t>(*buffer_size_ptr);
  if (buffer_size && !buffer) {
    REXKRNL_ERROR("XamUserReadProfileSettingsEx: X_E_INVALIDARG (buffer_size is non-zero but buffer is null)");
    return X_ERROR_INVALID_PARAMETER;
  }

  // Dashboard expects settings in order use vector to ensure insertion order
  // is maintained.
  const std::vector<uint32_t> settings_ids = {setting_ids, setting_ids + setting_count};
  
  // 454D07D2 reads settings from multiple XUIDs.
  const std::vector<uint64_t> profile_xuids = {xuids, xuids + xuid_count};
  
  uint32_t needed_header_size = 0;
  uint32_t needed_data_size = 0;
  for (const uint32_t setting_id : settings_ids) {
    needed_header_size += sizeof(X_USER_PROFILE_SETTING);
    UserProfile::Setting::Key setting_key;
    setting_key.value = static_cast<uint32_t>(setting_id);
    switch (static_cast<UserProfile::Setting::Type>(setting_key.type)) {
      case UserProfile::Setting::Type::WSTRING:
      case UserProfile::Setting::Type::BINARY:
        needed_data_size += setting_key.size;
        break;
      default:
        break;
    }
  }
  if (xuids) {
    needed_header_size *= xuid_count;
    needed_data_size *= xuid_count;
  }
  needed_header_size += sizeof(X_USER_READ_PROFILE_SETTINGS);

  uint32_t needed_size = needed_header_size + needed_data_size;
  if (!buffer || buffer_size < needed_size) {
    if (!buffer_size) {
      *buffer_size_ptr = needed_size;
    }
    return X_ERROR_INSUFFICIENT_BUFFER;
  }

  // Title ID = 0 means us.
  // 0xfffe07d1 = profile?

  auto* user_profile = GetUserProfile(user_index);
  if (!xuids && !user_profile) {
    REXKRNL_ERROR("XamUserReadProfileSettingsEx: X_E_NO_SUCH_USER (no profile for user_index {})", (uint32_t)user_index);
    if (overlapped) {
      REX_KERNEL_STATE()->CompleteOverlappedImmediate(REX_KERNEL_MEMORY()->HostToGuestVirtual(overlapped), X_ERROR_NO_SUCH_USER);
      return X_ERROR_IO_PENDING;
    }
    return X_ERROR_NO_SUCH_USER;
  }

  if (!user_profile) {
    // XUID-based lookup; only the signed-in user is supported.
    user_profile = GetUserProfileAny(static_cast<uint64_t>(xuids[0]));
    if (!user_profile) {
      REXKRNL_ERROR("XamUserReadProfileSettingsEx: X_E_NO_SUCH_USER (no profile for xuid {:016X})", static_cast<uint64_t>(xuids[0]));
      user_profile = GetUserProfile(0);
    }
    if (!user_profile) {
      if (overlapped) {
        REXKRNL_ERROR("XamUserReadProfileSettingsEx: X_E_NO_SUCH_USER (no profile for xuid {:016X} and no profile for user_index 0)", static_cast<uint64_t>(xuids[0]));
        REX_KERNEL_STATE()->CompleteOverlappedImmediate(REX_KERNEL_MEMORY()->HostToGuestVirtual(overlapped), X_ERROR_NO_SUCH_USER);
        return X_ERROR_IO_PENDING;
      }
      return X_ERROR_NO_SUCH_USER;
    }
  }

  // First call asks for size (fill buffer_size_ptr).
  // Second call asks for buffer contents with that size.

  // TODO(gibbed): setting validity checking without needing a user profile
  // object.
  bool any_missing = false;
  for (const uint32_t setting_id : settings_ids) {
    auto setting = user_profile->GetSetting(setting_id);
    if (!setting) {
      any_missing = true;
      REXKRNL_ERROR("XamUserReadProfileSettingsEx requested unimplemented setting {:08X}", setting_id);
    }
  }
  if (any_missing) {
    // TODO(benvanik): don't fail? most games don't even check!
    REXKRNL_ERROR("XamUserReadProfileSettingsEx: X_E_NOT_FOUND (one or more requested settings not found)");
    if (overlapped) {
      REX_KERNEL_STATE()->CompleteOverlappedImmediate(REX_KERNEL_MEMORY()->HostToGuestVirtual(overlapped), X_ERROR_INVALID_PARAMETER);
      REXKRNL_ERROR("XamUserReadProfileSettingsEx: X_E_NOT_FOUND (one or more requested settings not found)");
      return X_ERROR_IO_PENDING;
    }
    return X_ERROR_INVALID_PARAMETER;
  }

  auto out_header = reinterpret_cast<X_USER_READ_PROFILE_SETTINGS*>(buffer);
  auto out_setting = reinterpret_cast<X_USER_PROFILE_SETTING*>(&out_header[1]);
  out_header->setting_count = static_cast<uint32_t>(setting_count);
  out_header->settings_ptr = REX_KERNEL_MEMORY()->HostToGuestVirtual(out_setting);

  UserProfile::SettingByteStream out_stream(REX_KERNEL_MEMORY()->HostToGuestVirtual(buffer), buffer,
                                            buffer_size, needed_header_size);
  for (uint32_t n = 0; n < setting_count; ++n) {
    uint32_t setting_id = setting_ids[n];
    auto setting = user_profile->GetSetting(setting_id);

    std::memset(out_setting, 0, sizeof(X_USER_PROFILE_SETTING));
    out_setting->from = !setting || !setting->is_set ? 0 : setting->is_title_specific() ? 2 : 1;
    if (xuids) {
      out_setting->xuid = user_profile->xuid();
    } else {
      out_setting->user_index = static_cast<uint32_t>(user_index);
    }
    out_setting->setting_id = setting_id;

    if (setting && setting->is_set) {
      setting->Append(&out_setting->data, &out_stream);
    }
    ++out_setting;
  }

  if (overlapped) {
    REX_KERNEL_STATE()->CompleteOverlappedImmediate(REX_KERNEL_MEMORY()->HostToGuestVirtual(overlapped), X_ERROR_SUCCESS);
    return X_ERROR_IO_PENDING;
  }
  return X_ERROR_SUCCESS;
}

u32 XamUserReadProfileSettings_entry(u32 title_id, u32 user_index, u32 xuid_count, mapped_u64 xuids,
                                     u32 setting_count, mapped_u32 setting_ids,
                                     mapped_u32 buffer_size_ptr, mapped_void buffer_ptr,
                                     ppc_ptr_t<XAM_OVERLAPPED> overlapped) {
  return XamUserReadProfileSettingsEx(title_id, user_index, xuid_count, xuids, setting_count,
                                      setting_ids, 0, buffer_size_ptr, buffer_ptr, overlapped);
}

u32 XamUserReadProfileSettingsEx_entry(u32 title_id, u32 user_index, u32 xuid_count,
                                       mapped_u64 xuids, u32 setting_count, mapped_u32 setting_ids,
                                       mapped_u32 buffer_size_ptr, u32 unk_2,
                                       mapped_void buffer_ptr,
                                       ppc_ptr_t<XAM_OVERLAPPED> overlapped) {
  return XamUserReadProfileSettingsEx(title_id, user_index, xuid_count, xuids, setting_count,
                                      setting_ids, unk_2, buffer_size_ptr, buffer_ptr, overlapped);
}

u32 XamUserWriteProfileSettings_entry(u32 title_id, u32 user_index, u32 setting_count,
                                      ppc_ptr_t<X_USER_PROFILE_SETTING> settings,
                                      ppc_ptr_t<XAM_OVERLAPPED> overlapped) {
  if (!setting_count || !settings) {
    return X_ERROR_INVALID_PARAMETER;
  }

  // Update and save settings.
  auto* user_profile = GetUserProfile(user_index);
  if (!user_profile) {
    if (overlapped) {
      REX_KERNEL_STATE()->CompleteOverlappedImmediate(overlapped.guest_address(),
                                                      X_ERROR_NO_SUCH_USER);
      return X_ERROR_IO_PENDING;
    }
    return X_ERROR_NO_SUCH_USER;
  }

  for (uint32_t n = 0; n < setting_count; ++n) {
    const X_USER_PROFILE_SETTING& setting = settings[n];

    auto setting_type = static_cast<UserProfile::Setting::Type>(setting.data.type);
    if (setting_type == UserProfile::Setting::Type::UNSET) {
      continue;
    }

    REXKRNL_DEBUG(
        "XamUserWriteProfileSettings: setting index [{}]:"
        " from={} setting_id={:08X} data.type={}",
        n, (uint32_t)setting.from, (uint32_t)setting.setting_id, setting.data.type);

    switch (setting_type) {
      case UserProfile::Setting::Type::CONTENT:
      case UserProfile::Setting::Type::BINARY: {
        uint8_t* binary_ptr = REX_KERNEL_MEMORY()->TranslateVirtual(setting.data.binary.ptr);
        size_t binary_size = setting.data.binary.size;
        std::vector<uint8_t> bytes;
        if (setting.data.binary.ptr) {
          // Copy provided data
          bytes.resize(binary_size);
          std::memcpy(bytes.data(), binary_ptr, binary_size);
        } else {
          // Data pointer was NULL, so just fill with zeroes
          bytes.resize(binary_size, 0);
        }
        user_profile->AddSetting(
            std::make_unique<xam::UserProfile::BinarySetting>(setting.setting_id, bytes));
      } break;
      case UserProfile::Setting::Type::WSTRING:
      case UserProfile::Setting::Type::DOUBLE:
      case UserProfile::Setting::Type::FLOAT:
      case UserProfile::Setting::Type::INT32:
      case UserProfile::Setting::Type::INT64:
      case UserProfile::Setting::Type::DATETIME:
      default: {
        REXKRNL_ERROR("XamUserWriteProfileSettings: Unimplemented data type {}", setting_type);
      } break;
    };
  }

  if (overlapped) {
    REX_KERNEL_STATE()->CompleteOverlappedImmediate(overlapped.guest_address(), X_ERROR_SUCCESS);
    return X_ERROR_IO_PENDING;
  }
  return X_ERROR_SUCCESS;
}

u32 XamUserCheckPrivilege_entry(u32 user_index, u32 mask, mapped_u32 out_value) {
  // XPRIVILEGE_PII_ACCESS == 221
  REXKRNL_INFO("XamUserCheckPrivilege: user={} mask={:08X}", (uint32_t)user_index, (uint32_t)mask);

  *out_value = 0;

  // 0xFF means "check all signed-in users".
  if (user_index == XUserIndexAny) {
    REXKRNL_INFO("XamUserCheckPrivilege: user=ANY mask={:08X}", (uint32_t)mask);
    for (uint8_t i = 0; i < XUserMaxUserCount; ++i) {
      const auto result = XamUserCheckPrivilege_entry(i, mask, out_value);
      if (result != X_ERROR_NO_SUCH_USER) {
        return result;
      }
    }
    REXKRNL_ERROR("XamUserCheckPrivilege: user=ANY mask={:08X} -> X_ERROR_NO_SUCH_USER (no signed-in users)", (uint32_t)mask);
    return X_ERROR_NO_SUCH_USER;
  }

  if (user_index >= XUserMaxUserCount) {
    REXKRNL_ERROR("XamUserCheckPrivilege: user={} mask={:08X} -> X_ERROR_INVALID_PARAMETER (user_index out of range)", (uint32_t)user_index, (uint32_t)mask);
    return X_ERROR_INVALID_PARAMETER;
  }

  const auto* user_profile = GetUserProfile(user_index);
  if (!user_profile) {
    REXKRNL_ERROR("XamUserCheckPrivilege: user={} mask={:08X} -> X_ERROR_NO_SUCH_USER (no profile)", (uint32_t)user_index, (uint32_t)mask);
    return X_ERROR_NO_SUCH_USER;
  }

  if (user_profile->signin_state() != X_USER_SIGNIN_STATE::SignedInToLive) {
    REXKRNL_INFO("XamUserCheckPrivilege: user={} mask={:08X} -> NOT_LOGGED_ON", (uint32_t)user_index, (uint32_t)mask);
    return X_ERROR_NOT_LOGGED_ON;
  }

  // Allow all privileges including multiplayer.
  // NOTE: pfResult is TRUE when the user HAS the privilege.
  REXKRNL_INFO("XamUserCheckPrivilege: user={} mask={:08X} -> 1 (granted)", (uint32_t)user_index, (uint32_t)mask);
  *out_value = 1;
  return X_ERROR_SUCCESS;
}

u32 XamUserContentRestrictionGetFlags_entry(u32 user_index, mapped_u32 out_flags) {
  REXKRNL_INFO("XamUserContentRestrictionGetFlags: user={}", (uint32_t)user_index);
  if (!IsUserSignedIn(user_index)) {
    REXKRNL_ERROR("XamUserContentRestrictionGetFlags: user={} -> X_ERROR_NO_SUCH_USER (not signed in)", (uint32_t)user_index);
    return X_ERROR_NO_SUCH_USER;
  }

  // No restrictions?
  *out_flags = 0;
  REXKRNL_INFO("XamUserContentRestrictionGetFlags: user={} -> {:08X}", (uint32_t)user_index, (uint32_t)*out_flags);
  return X_ERROR_SUCCESS;
}

u32 XamUserContentRestrictionGetRating_entry(u32 user_index, u32 unk1, mapped_u32 out_unk2, mapped_u32 out_unk3) {
  if (!IsUserSignedIn(user_index)) {
    REXKRNL_ERROR("XamUserContentRestrictionGetRating: user={} -> X_ERROR_NO_SUCH_USER (not signed in)", (uint32_t)user_index);
    return X_ERROR_NO_SUCH_USER;
  }

  // Some games have special case paths for 3F that differ from the failure
  // path, so my guess is that's 'don't care'.
  *out_unk2 = 0x3F;
  *out_unk3 = 0;
  REXKRNL_INFO("XamUserContentRestrictionGetRating: user={} -> unk2={:08X} unk3={:08X}", (uint32_t)user_index, (uint32_t)*out_unk2, (uint32_t)*out_unk3);
  return X_ERROR_SUCCESS;
}

u32 XamUserContentRestrictionCheckAccess_entry(u32 user_index, u32 unk1, u32 unk2, u32 unk3, u32 unk4, mapped_u32 out_unk5, u32 overlapped_ptr) {
  *out_unk5 = 1;

  if (overlapped_ptr) {
    // TODO(benvanik): does this need the access arg on it?
    REXKRNL_INFO("XamUserContentRestrictionCheckAccess: user={} -> overlapped_ptr={:08X} completed with X_ERROR_SUCCESS", (uint32_t)user_index, (uint32_t)overlapped_ptr);
    REX_KERNEL_STATE()->CompleteOverlappedImmediate(overlapped_ptr, X_ERROR_SUCCESS);
  }

  return X_ERROR_SUCCESS;
}

u32 XamUserIsOnlineEnabled_entry(u32 user_index) {
  REXKRNL_INFO("XamUserIsOnlineEnabled: user={}", (uint32_t)user_index);
  if (user_index >= XUserMaxUserCount) {
    REXKRNL_ERROR("XamUserIsOnlineEnabled: user={} -> 0 (user_index out of range)", (uint32_t)user_index);
    return 0;
  }

  const auto* user_profile = GetUserProfile(user_index);
  if (!user_profile) {
    REXKRNL_ERROR("XamUserIsOnlineEnabled: user={} -> 0 (no profile)", (uint32_t)user_index);
    return 0;
  }

  const uint32_t result = user_profile->IsLiveEnabled() ? 1u : 0u;
  REXKRNL_INFO("XamUserIsOnlineEnabled: user={} -> {}", (uint32_t)user_index, result);
  return result;
}

u32 XamUserGetCachedUserFlags_entry(u32 user_index) {
  const auto* user_profile = GetUserProfile(user_index);
  if (!user_profile) {
    REXKRNL_ERROR("XamUserGetCachedUserFlags: user={} -> 0 (no profile)", (uint32_t)user_index);
    return 0;
  }

  const uint32_t flags = user_profile->GetCachedFlags();
  REXKRNL_INFO("XamUserGetCachedUserFlags: user={} -> {:08X}", (uint32_t)user_index, flags);
  return flags;
}

u32 XamUserGetUserFlags_entry(u32 user_index) {
  const auto* user_profile = GetUserProfile(user_index);
  if (!user_profile) {
    REXKRNL_ERROR("XamUserGetUserFlags: user={} -> 0 (no profile)", (uint32_t)user_index);
    return 0;
  }

  const uint32_t flags = user_profile->GetCachedFlags();
  REXKRNL_INFO("XamUserGetUserFlags: user={} -> {:08X}", (uint32_t)user_index, flags);
  return flags;
}

u32 XamUserGetUserFlagsFromXUID_entry(u64 xuid) {
  const auto* user_profile = GetUserProfileAny(xuid);
  if (!user_profile) {
    REXKRNL_ERROR("XamUserGetUserFlagsFromXUID: xuid={:016X} -> 0 (no profile)", (uint64_t)xuid);
    return 0;
  }

  const uint32_t flags = user_profile->GetCachedFlags();
  REXKRNL_INFO("XamUserGetUserFlagsFromXUID: xuid={:016X} -> {:08X}", (uint64_t)xuid, flags);
  return flags;
}

u32 XamUserGetMembershipTierFromXUID_entry(u64 xuid) {
  const auto* user_profile = GetUserProfileAny(xuid);
  if (!user_profile) {
    REXKRNL_ERROR("XamUserGetMembershipTierFromXUID: xuid={:016X} -> X_XAMACCOUNTINFO::AccountSubscriptionTier::kSubscriptionTierNone (no profile)", (uint64_t)xuid);
    return X_XAMACCOUNTINFO::AccountSubscriptionTier::kSubscriptionTierNone;
  }

  const uint32_t tier = user_profile->GetSubscriptionTier();
  REXKRNL_INFO("XamUserGetMembershipTierFromXUID: xuid={:016X} -> {}", (uint64_t)xuid, tier);
  return tier;
}

u32 XamUserGetMembershipTier_entry(u32 user_index) {
  if (user_index >= XUserMaxUserCount) {
    REXKRNL_ERROR("XamUserGetMembershipTier: user={} -> X_XAMACCOUNTINFO::AccountSubscriptionTier::kSubscriptionTierNone (user_index out of range)", (uint32_t)user_index);
    return X_XAMACCOUNTINFO::AccountSubscriptionTier::kSubscriptionTierNone;
  }

  const auto* user_profile = GetUserProfile(user_index);
  if (!user_profile) {
    REXKRNL_ERROR("XamUserGetMembershipTier: user={} -> X_XAMACCOUNTINFO::AccountSubscriptionTier::kSubscriptionTierNone (no profile)", (uint32_t)user_index);
    return X_XAMACCOUNTINFO::AccountSubscriptionTier::kSubscriptionTierNone;
  }

  const uint32_t tier = user_profile->GetSubscriptionTier();
  REXKRNL_INFO("XamUserGetMembershipTier: user={} -> {}", (uint32_t)user_index, tier);
  return tier;
}

u32 XamUserGetSubscriptionType_entry(u32 user_index, mapped_u32 subscription_ptr, mapped_u32 r5, u32 overlapped_ptr) {
  if (user_index >= XUserMaxUserCount) {
    REXKRNL_ERROR("XamUserGetSubscriptionType: user={} -> X_E_INVALIDARG (user_index out of range)", (uint32_t)user_index);
    return X_E_INVALIDARG;
  }

  if (!subscription_ptr || !r5) {
    REXKRNL_ERROR("XamUserGetSubscriptionType: user={} -> X_E_INVALIDARG (null pointer for subscription_ptr or r5)", (uint32_t)user_index);
    return X_E_INVALIDARG;
  }

  const auto* user_profile = GetUserProfile(user_index);
  if (!user_profile) {
    REXKRNL_ERROR("XamUserGetSubscriptionType: user={} -> X_E_NO_SUCH_USER (no profile)", (uint32_t)user_index);
    return X_ERROR_INVALID_PARAMETER;
  }

  *subscription_ptr = user_profile->GetSubscriptionTier();
  *r5 = 0;

  return X_ERROR_SUCCESS;
}

u32 XamUserGetIndexFromXUID_entry(u64 xuid, u32 flags, mapped_u32 index_ptr) {
  if (!index_ptr) {
    REXKRNL_ERROR("XamUserGetIndexFromXUID: X_E_INVALIDARG (null pointer for index_ptr)");
    return X_E_INVALIDARG;
  }

  auto* profile_manager = REX_KERNEL_STATE()->profile_manager();
  uint8_t user_index = profile_manager->GetUserIndexAssignedToProfile(xuid);
  if (user_index == XUserIndexAny) {
    REXKRNL_ERROR("XamUserGetIndexFromXUID: X_E_NO_SUCH_USER (no user index assigned to xuid {:016X})", (uint64_t)xuid);
    user_index = profile_manager->GetUserIndexAssignedToLiveProfile(xuid);
  }

  if (user_index == XUserIndexAny) {
    REXKRNL_ERROR("XamUserGetIndexFromXUID: X_E_NO_SUCH_USER (no user index assigned to live profile xuid {:016X})", (uint64_t)xuid);
    return X_E_NO_SUCH_USER;
  }

  *index_ptr = user_index;
  REXKRNL_INFO("XamUserGetIndexFromXUID: xuid={:016X} -> user_index={}", (uint64_t)xuid, (uint32_t)user_index);
  return X_ERROR_SUCCESS;
}

u32 XamUserGetAgeGroup_entry(u32 user_index, mapped_u32 age_ptr, u32 overlapped_ptr) {
  // X_USER_AGE_GROUP::ADULT
  constexpr uint32_t kAgeGroupAdult = 2;

  if (!age_ptr) {
    REXKRNL_ERROR("XamUserGetAgeGroup: user={} -> X_E_INVALIDARG (null pointer for age_ptr)", (uint32_t)user_index);
    return X_ERROR_INVALID_PARAMETER;
  }

  if (!IsUserSignedIn(user_index)) {
    REXKRNL_ERROR("XamUserGetAgeGroup: user={} -> X_E_NO_SUCH_USER (not signed in)", (uint32_t)user_index);
    return X_ERROR_NO_SUCH_USER;
  }

  *age_ptr = kAgeGroupAdult;

  if (overlapped_ptr) {
    REXKRNL_INFO("XamUserGetAgeGroup: user={} -> overlapped_ptr={:08X} completed with X_ERROR_SUCCESS", (uint32_t)user_index, (uint32_t)overlapped_ptr);
    REX_KERNEL_STATE()->CompleteOverlappedImmediate(overlapped_ptr, X_ERROR_SUCCESS);
    return X_ERROR_IO_PENDING;
  }
  return X_ERROR_SUCCESS;
}

u32 XamUserIsUnsafeProgrammingAllowed_entry(u32 user_index, u32 unk, mapped_u32 result_ptr) {
  if (!result_ptr) {
    REXKRNL_ERROR("XamUserIsUnsafeProgrammingAllowed: user={} -> X_E_INVALIDARG (null pointer for result_ptr)", (uint32_t)user_index);
    return X_ERROR_INVALID_PARAMETER;
  }

  if (user_index != XUserIndexAny && user_index >= XUserMaxUserCount) {
    REXKRNL_ERROR("XamUserIsUnsafeProgrammingAllowed: user={} -> X_E_INVALIDARG (user_index out of range)", (uint32_t)user_index);
    return X_ERROR_INVALID_PARAMETER;
  }

  *result_ptr = 1;
  REXKRNL_INFO("XamUserIsUnsafeProgrammingAllowed: user={} -> result=1 (allowed)", (uint32_t)user_index);
  return X_ERROR_SUCCESS;
}

u32 XamUserAreUsersFriends_entry(u32 user_index, u32 unk1, u32 unk2, mapped_u32 out_value, u32 overlapped_ptr) {
  uint32_t are_friends = 0;
  X_RESULT result;

  if (user_index >= XUserMaxUserCount) {
    REXKRNL_ERROR("XamUserAreUsersFriends: user={} -> X_E_INVALIDARG (user_index out of range)", (uint32_t)user_index);
    result = X_ERROR_INVALID_PARAMETER;
  } else {
    REXKRNL_INFO("XamUserAreUsersFriends: user={} -> checking friendship status", (uint32_t)user_index);
    const auto* user_profile = GetUserProfile(user_index);
    if (user_profile) {
      if (user_profile->signin_state() == X_USER_SIGNIN_STATE::NotSignedIn) {
        result = X_ERROR_NOT_LOGGED_ON;
      } else {
        // No friends!
        are_friends = 0;
        result = X_ERROR_SUCCESS;
      }
    } else {
      result = X_ERROR_NO_SUCH_USER;  // if user is local -> X_ERROR_NOT_LOGGED_ON
    }
  }

  if (out_value) {
    assert_true(!overlapped_ptr);
    *out_value = result == X_ERROR_SUCCESS ? are_friends : 0;
    return result;
  } else if (overlapped_ptr) {
    assert_true(!out_value);
    REX_KERNEL_STATE()->CompleteOverlappedImmediateEx(
        overlapped_ptr, result == X_ERROR_SUCCESS ? X_ERROR_SUCCESS : X_ERROR_FUNCTION_FAILED,
        X_HRESULT_FROM_WIN32(result), result == X_ERROR_SUCCESS ? are_friends : 0);
    return X_ERROR_IO_PENDING;
  } else {
    assert_always();
    return X_ERROR_INVALID_PARAMETER;
  }
}

u32 XamShowSigninUI_entry(u32 unk, u32 unk_mask) {
  REXKRNL_INFO("XamShowSigninUI: unk={:08X} unk_mask={:08X}", (uint32_t)unk, (uint32_t)unk_mask);
  // Mask values vary. Probably matching user types? Local/remote?

  // To fix game modes that display a 4 profile signin UI (even if playing
  // alone):
  // XN_SYS_SIGNINCHANGED
  REX_KERNEL_STATE()->BroadcastNotification(
      0x0000000A,
      static_cast<uint32_t>(
          REX_KERNEL_STATE()->profile_manager()->GetUsedUserSlots().to_ulong()));
  // Games seem to sit and loop until we trigger this notification:
  // XN_SYS_UI (off)
  REX_KERNEL_STATE()->BroadcastNotification(0x00000009, 0);
  return X_ERROR_SUCCESS;
}

// TODO(gibbed): probably a FILETIME/LARGE_INTEGER, unknown currently
struct X_ACHIEVEMENT_UNLOCK_TIME {
  rex::be<uint32_t> unk_0;
  rex::be<uint32_t> unk_4;
};

struct X_ACHIEVEMENT_DETAILS {
  rex::be<uint32_t> id;
  rex::be<uint32_t> label_ptr;
  rex::be<uint32_t> description_ptr;
  rex::be<uint32_t> unachieved_ptr;
  rex::be<uint32_t> image_id;
  rex::be<uint32_t> gamerscore;
  X_ACHIEVEMENT_UNLOCK_TIME unlock_time;
  rex::be<uint32_t> flags;

  static const size_t kStringBufferSize = 464;
};
static_assert_size(X_ACHIEVEMENT_DETAILS, 36);

class XStaticAchievementEnumerator : public XEnumerator {
 public:
  struct AchievementDetails {
    uint32_t id;
    std::u16string label;
    std::u16string description;
    std::u16string unachieved;
    uint32_t image_id;
    uint32_t gamerscore;
    struct {
      uint32_t unk_0;
      uint32_t unk_4;
    } unlock_time;
    uint32_t flags;
  };

  XStaticAchievementEnumerator(KernelState* kernel_state, size_t items_per_enumerate,
                               uint32_t flags)
      : XEnumerator(kernel_state, items_per_enumerate,
                    sizeof(X_ACHIEVEMENT_DETAILS) +
                        (!!(flags & 7) ? X_ACHIEVEMENT_DETAILS::kStringBufferSize : 0)),
        flags_(flags) {}

  void AppendItem(AchievementDetails item) { items_.push_back(std::move(item)); }

  uint32_t WriteItems(uint32_t buffer_ptr, uint8_t* buffer_data, uint32_t* written_count) override {
    size_t count = std::min(items_.size() - current_item_, items_per_enumerate());
    if (!count) {
      return X_ERROR_NO_MORE_FILES;
    }

    size_t size = count * item_size();

    auto details = reinterpret_cast<X_ACHIEVEMENT_DETAILS*>(buffer_data);
    size_t string_offset = items_per_enumerate() * sizeof(X_ACHIEVEMENT_DETAILS);
    auto string_buffer =
        StringBuffer{buffer_ptr + static_cast<uint32_t>(string_offset), &buffer_data[string_offset],
                     count * X_ACHIEVEMENT_DETAILS::kStringBufferSize};
    for (size_t i = 0, o = current_item_; i < count; ++i, ++current_item_) {
      const auto& item = items_[current_item_];
      details[i].id = item.id;
      details[i].label_ptr = !!(flags_ & 1) ? AppendString(string_buffer, item.label) : 0;
      details[i].description_ptr =
          !!(flags_ & 2) ? AppendString(string_buffer, item.description) : 0;
      details[i].unachieved_ptr = !!(flags_ & 4) ? AppendString(string_buffer, item.unachieved) : 0;
      details[i].image_id = item.image_id;
      details[i].gamerscore = item.gamerscore;
      details[i].unlock_time.unk_0 = item.unlock_time.unk_0;
      details[i].unlock_time.unk_4 = item.unlock_time.unk_4;
      details[i].flags = item.flags;
    }

    if (written_count) {
      *written_count = static_cast<uint32_t>(count);
    }

    return X_ERROR_SUCCESS;
  }

 private:
  struct StringBuffer {
    uint32_t ptr;
    uint8_t* data;
    size_t remaining_bytes;
  };

  uint32_t AppendString(StringBuffer& sb, const std::u16string_view string) {
    size_t count = string.length() + 1;
    size_t size = count * sizeof(char16_t);
    if (size > sb.remaining_bytes) {
      assert_always();
      return 0;
    }
    auto ptr = sb.ptr;
    rex::string::copy_and_swap_truncating(reinterpret_cast<char16_t*>(sb.data), string, count);
    sb.ptr += static_cast<uint32_t>(size);
    sb.data += size;
    sb.remaining_bytes -= size;
    return ptr;
  }

 private:
  uint32_t flags_;
  std::vector<AchievementDetails> items_;
  size_t current_item_ = 0;
};

u32 XamUserCreateAchievementEnumerator_entry(u32 title_id, u32 user_index, u32 xuid, u32 flags, u32 offset, u32 count, mapped_u32 buffer_size_ptr, mapped_u32 handle_ptr) {
  if (!count || !buffer_size_ptr || !handle_ptr) {
    REXKRNL_ERROR("XamUserCreateAchievementEnumerator: X_E_INVALIDARG (null pointer for buffer_size_ptr or handle_ptr, or count is zero)");
    return X_ERROR_INVALID_PARAMETER;
  }

  if (user_index >= XUserMaxUserCount) {
    REXKRNL_ERROR("XamUserCreateAchievementEnumerator: X_E_INVALIDARG (user_index out of range)");
    return X_ERROR_INVALID_PARAMETER;
  }

  size_t entry_size = sizeof(X_ACHIEVEMENT_DETAILS);
  if (flags & 7) {
    entry_size += X_ACHIEVEMENT_DETAILS::kStringBufferSize;
  }

  if (buffer_size_ptr) {
    *buffer_size_ptr = static_cast<uint32_t>(entry_size) * count;
  }

  auto e = object_ref<XStaticAchievementEnumerator>(
      new XStaticAchievementEnumerator(REX_KERNEL_STATE(), count, flags));
  auto result = e->Initialize(user_index, 0xFB, 0xB000A, 0xB000B, 0);
  if (XFAILED(result)) {
    REXKRNL_ERROR("XamUserCreateAchievementEnumerator: X_E_OUTOFMEMORY (failed to initialize enumerator)");
    return result;
  }

  // ACHIEVED | ACHIEVED_ONLINE flags the game checks to consider an achievement earned.
  constexpr uint32_t kAchievedFlags = 0x00030000;

  auto fill_unlock = [](XStaticAchievementEnumerator::AchievementDetails& item, uint32_t id,
                        const rex::system::KernelState* ks) {
    uint64_t ft = ks->GetAchievementUnlockTime(id);
    if (ft) {
      item.flags |= kAchievedFlags;
      item.unlock_time.unk_0 = static_cast<uint32_t>(ft & 0xFFFF'FFFF);
      item.unlock_time.unk_4 = static_cast<uint32_t>(ft >> 32);
    }
  };

  const auto* ks = REX_KERNEL_STATE();

  // Prefer the runtime store (populated from TOML or XDBF at boot) so that
  // dev-edited labels/descriptions are visible to the game's own queries.
  const auto store = ks->loaded_achievements();
  if (!store.empty()) {
    for (const auto& info : store) {
      auto item = XStaticAchievementEnumerator::AchievementDetails{
          info.id,
          rex::string::to_utf16(info.label),
          rex::string::to_utf16(info.description),
          rex::string::to_utf16(info.unachieved_description),
          info.image_id,
          info.gamerscore,
          {0, 0},
          info.flags};
      fill_unlock(item, info.id, ks);
      e->AppendItem(item);
    }
  } else {
    const util::XdbfGameData db = ks->title_xdbf();
    if (db.is_valid()) {
      const XLanguage language =
          db.GetExistingLanguage(static_cast<XLanguage>(REXCVAR_GET(user_language)));
      for (const util::XdbfAchievementTableEntry& entry : db.GetAchievements()) {
        auto item = XStaticAchievementEnumerator::AchievementDetails{
            entry.id,
            rex::string::to_utf16(db.GetStringTableEntry(language, entry.label_id)),
            rex::string::to_utf16(db.GetStringTableEntry(language, entry.description_id)),
            rex::string::to_utf16(db.GetStringTableEntry(language, entry.unachieved_id)),
            entry.image_id,
            entry.gamerscore,
            {0, 0},
            entry.flags};
        fill_unlock(item, entry.id, ks);
        e->AppendItem(item);
      }
    }
  }

  *handle_ptr = e->handle();
  return X_ERROR_SUCCESS;
}

u32 XamParseGamerTileKey_entry(mapped_u32 key_ptr, mapped_u32 out1_ptr, mapped_u32 out2_ptr,
                               mapped_u32 out3_ptr) {
  *out1_ptr = 0xC0DE0001;
  *out2_ptr = 0xC0DE0002;
  *out3_ptr = 0xC0DE0003;
  REXKRNL_INFO("XamParseGamerTileKey: key={:08X} -> out1={:08X} out2={:08X} out3={:08X}", (uint32_t)*key_ptr, (uint32_t)*out1_ptr, (uint32_t)*out2_ptr, (uint32_t)*out3_ptr);
  return X_ERROR_SUCCESS;
}

// Ported from netplay XamReadTileToTexture: decodes the user's gamer pic PNG
// into the destination texture (BGRA/ARGB, row stride padded). Falls back to
// a solid black tile when the profile has no picture.
u32 XamReadTileToTexture_entry(u32 tile_type, u32 title_id, u64 tile_id, u32 user_index, mapped_void buffer_ptr, u32 stride, u32 height, u32 overlapped_ptr) {
  if (!buffer_ptr || !stride || !height) {
    REXKRNL_ERROR("XamReadTileToTexture: X_E_INVALIDARG (null pointer for buffer_ptr, or stride/height is zero)");
    return X_ERROR_INVALID_PARAMETER;
  }

  const size_t buffer_size = size_t(stride) * size_t(height);

  std::span<const uint8_t> icon_data{};

  auto* user_profile = GetUserProfile(user_index);
  if (!user_profile) {
    // Some titles pass 0xFF/garbage user indices with a tile key; use the
    // primary profile's picture in that case.
    user_profile = GetUserProfile(0);
  }
  if (user_profile) {
    // Pick small/large tile based on requested height.
    const XTileType icon_type =
        height <= kProfileIconSizeSmall.second ? XTileType::kGamerTileSmall
                                               : XTileType::kGamerTile;
    icon_data = user_profile->GetProfileIcon(icon_type);
    if (icon_data.empty()) {
      icon_data = user_profile->GetProfileIcon(XTileType::kGamerTile);
    }
  }

  std::memset(buffer_ptr, 0, buffer_size);

  bool decoded = false;
  if (!icon_data.empty()) {
    int width = 0, img_height = 0, channels = 0;
    unsigned char* image_data = stbi_load_from_memory(
        icon_data.data(), static_cast<int>(icon_data.size()), &width, &img_height,
        &channels, STBI_rgb_alpha);
    if (image_data) {
      // RGBA -> ARGB
      const size_t pixel_count = size_t(width) * size_t(img_height);
      for (size_t i = 0; i < pixel_count; i++) {
        unsigned char* pixel = &image_data[i * sizeof(uint32_t)];
        std::swap(pixel[0], pixel[3]);
        std::swap(pixel[1], pixel[3]);
        std::swap(pixel[2], pixel[3]);
      }

      const size_t row_size_bytes = size_t(width) * sizeof(uint32_t);
      const size_t copy_row_bytes = std::min(row_size_bytes, size_t(stride));
      const int copy_rows = std::min<int>(img_height, int(height));
      auto* dest = static_cast<uint8_t*>(buffer_ptr);
      for (int y = 0; y < copy_rows; ++y) {
        std::memcpy(dest + size_t(y) * stride, &image_data[y * row_size_bytes],
                    copy_row_bytes);
      }

      stbi_image_free(image_data);
      decoded = true;
    }
  }

  if (!decoded) {
    // Solid black (full alpha) tile.
    auto* dest = static_cast<uint8_t*>(buffer_ptr);
    for (size_t i = 0; i < buffer_size; ++i) {
      dest[i] = (i % 4 == 0) ? 0xFF : 0x00;
    }
  }

  if (overlapped_ptr) {
    REX_KERNEL_STATE()->CompleteOverlappedImmediate(overlapped_ptr, X_ERROR_SUCCESS);
    return X_ERROR_IO_PENDING;
  }
  return X_ERROR_SUCCESS;
}

u32 XamWriteGamerTile_entry(u32 arg1, u32 arg2, u32 arg3, u32 arg4, u32 arg5, u32 overlapped_ptr) {
  REXKRNL_INFO("XamWriteGamerTile: arg1={:08X} arg2={:08X} arg3={:08X} arg4={:08X} arg5={:08X}", (uint32_t)arg1, (uint32_t)arg2, (uint32_t)arg3, (uint32_t)arg4, (uint32_t)arg5);
  if (overlapped_ptr) {
    REX_KERNEL_STATE()->CompleteOverlappedImmediate(overlapped_ptr, X_ERROR_SUCCESS);
    return X_ERROR_IO_PENDING;
  }
  return X_ERROR_SUCCESS;
}

u32 XamSessionCreateHandle_entry(mapped_u32 handle_ptr) {
  REXKRNL_INFO("XamSessionCreateHandle: handle_ptr={:08X}", (uint32_t)handle_ptr);
  *handle_ptr = 0xCAFEDEAD;
  return X_ERROR_SUCCESS;
}

u32 XamSessionRefObjByHandle_entry(u32 handle, mapped_u32 obj_ptr) {
  REXKRNL_INFO("XamSessionRefObjByHandle: handle={:08X} obj_ptr={:08X}", (uint32_t)handle, (uint32_t)obj_ptr);
  assert_true(handle == 0xCAFEDEAD);
  // TODO(PermaNull): Implement this properly,
  // For the time being returning 0xDEADF00D will prevent crashing.
  *obj_ptr = 0xDEADF00D;
  return X_ERROR_SUCCESS;
}

}  // namespace xam
}  // namespace kernel
}  // namespace rex

REX_EXPORT(__imp__XamUserGetXUID, rex::kernel::xam::XamUserGetXUID_entry)
REX_EXPORT(__imp__XamUserGetSigninState, rex::kernel::xam::XamUserGetSigninState_entry)
REX_EXPORT(__imp__XamUserGetSigninInfo, rex::kernel::xam::XamUserGetSigninInfo_entry)
REX_EXPORT(__imp__XamUserGetName, rex::kernel::xam::XamUserGetName_entry)
REX_EXPORT(__imp__XamUserGetGamerTag, rex::kernel::xam::XamUserGetGamerTag_entry)
REX_EXPORT(__imp__XamUserReadProfileSettings, rex::kernel::xam::XamUserReadProfileSettings_entry)
REX_EXPORT(__imp__XamUserReadProfileSettingsEx,
           rex::kernel::xam::XamUserReadProfileSettingsEx_entry)
REX_EXPORT(__imp__XamUserWriteProfileSettings, rex::kernel::xam::XamUserWriteProfileSettings_entry)
REX_EXPORT(__imp__XamUserCheckPrivilege, rex::kernel::xam::XamUserCheckPrivilege_entry)
REX_EXPORT(__imp__XamUserContentRestrictionGetFlags,
           rex::kernel::xam::XamUserContentRestrictionGetFlags_entry)
REX_EXPORT(__imp__XamUserContentRestrictionGetRating,
           rex::kernel::xam::XamUserContentRestrictionGetRating_entry)
REX_EXPORT(__imp__XamUserContentRestrictionCheckAccess,
           rex::kernel::xam::XamUserContentRestrictionCheckAccess_entry)
REX_EXPORT(__imp__XamUserIsOnlineEnabled, rex::kernel::xam::XamUserIsOnlineEnabled_entry)
REX_EXPORT(__imp__XamUserGetMembershipTier, rex::kernel::xam::XamUserGetMembershipTier_entry)
REX_EXPORT(__imp__XamUserAreUsersFriends, rex::kernel::xam::XamUserAreUsersFriends_entry)
REX_EXPORT(__imp__XamShowSigninUI, rex::kernel::xam::XamShowSigninUI_entry)
REX_EXPORT(__imp__XamUserCreateAchievementEnumerator,
           rex::kernel::xam::XamUserCreateAchievementEnumerator_entry)
REX_EXPORT(__imp__XamParseGamerTileKey, rex::kernel::xam::XamParseGamerTileKey_entry)
REX_EXPORT(__imp__XamReadTileToTexture, rex::kernel::xam::XamReadTileToTexture_entry)
REX_EXPORT(__imp__XamWriteGamerTile, rex::kernel::xam::XamWriteGamerTile_entry)
REX_EXPORT(__imp__XamSessionCreateHandle, rex::kernel::xam::XamSessionCreateHandle_entry)
REX_EXPORT(__imp__XamSessionRefObjByHandle, rex::kernel::xam::XamSessionRefObjByHandle_entry)

REX_EXPORT_STUB(__imp__XamUserAddRecentPlayer);
REX_EXPORT_STUB(__imp__XamUserAllowedToPostToSocialNetwork);
REX_EXPORT_STUB(__imp__XamUserCreateAvatarAssetEnumerator);
REX_EXPORT_STUB(__imp__XamUserCreatePlayerEnumerator);
REX_EXPORT_STUB(__imp__XamUserCreateStatsEnumerator);
REX_EXPORT_STUB(__imp__XamUserCreateTitlesPlayedEnumerator);
REX_EXPORT_STUB(__imp__XamUserFlushLogonQueue);
REX_EXPORT_STUB(__imp__XamUserGetAge);
REX_EXPORT(__imp__XamUserGetAgeGroup, rex::kernel::xam::XamUserGetAgeGroup_entry);
REX_EXPORT(__imp__XamUserGetCachedUserFlags, rex::kernel::xam::XamUserGetCachedUserFlags_entry);
REX_EXPORT_STUB(__imp__XamUserGetDeviceId);
REX_EXPORT(__imp__XamUserGetIndexFromXUID, rex::kernel::xam::XamUserGetIndexFromXUID_entry);
REX_EXPORT(__imp__XamUserGetMembershipTierFromXUID, rex::kernel::xam::XamUserGetMembershipTierFromXUID_entry);
REX_EXPORT_STUB(__imp__XamUserGetOnlineCountryFromXUID);
REX_EXPORT_STUB(__imp__XamUserGetOnlineLanguageFromXUID);
REX_EXPORT_STUB(__imp__XamUserGetOnlineXUIDFromOfflineXUID);
REX_EXPORT_STUB(__imp__XamUserGetReportingInfo);
REX_EXPORT_STUB(__imp__XamUserGetRequestedUserIndexMask);
REX_EXPORT(__imp__XamUserGetSubscriptionType, rex::kernel::xam::XamUserGetSubscriptionType_entry);
REX_EXPORT(__imp__XamUserGetUserFlags, rex::kernel::xam::XamUserGetUserFlags_entry);
REX_EXPORT(__imp__XamUserGetUserFlagsFromXUID, rex::kernel::xam::XamUserGetUserFlagsFromXUID_entry);
REX_EXPORT_STUB(__imp__XamUserGetUserIndexMask);
REX_EXPORT_STUB(__imp__XamUserGetUserTenure);
REX_EXPORT_STUB(__imp__XamUserGetUsersMissingAvatars);
REX_EXPORT_STUB(__imp__XamUserGetXUIDForTFA);
REX_EXPORT_STUB(__imp__XamUserInvalidateProfileSetting);
REX_EXPORT_STUB(__imp__XamUserIsGuest);
REX_EXPORT_STUB(__imp__XamUserIsLogonPreviewModeEnabled);
REX_EXPORT_STUB(__imp__XamUserIsParentalControlled);
REX_EXPORT_STUB(__imp__XamUserIsPartial);
REX_EXPORT_STUB(__imp__XamUserIsPartialProfile);
REX_EXPORT(__imp__XamUserIsUnsafeProgrammingAllowed, rex::kernel::xam::XamUserIsUnsafeProgrammingAllowed_entry);
REX_EXPORT_STUB(__imp__XamUserLockLogonPreviewMode);
REX_EXPORT_STUB(__imp__XamUserLogon);
REX_EXPORT_STUB(__imp__XamUserLogonEx);
REX_EXPORT_STUB(__imp__XamUserLookupDevice);
REX_EXPORT_STUB(__imp__XamUserNuiBind);
REX_EXPORT_STUB(__imp__XamUserNuiEnableBiometric);
REX_EXPORT_STUB(__imp__XamUserNuiGetEnrollmentIndex);
REX_EXPORT_STUB(__imp__XamUserNuiGetUserIndex);
REX_EXPORT_STUB(__imp__XamUserNuiGetUserIndexForBind);
REX_EXPORT_STUB(__imp__XamUserNuiGetUserIndexForSignin);
REX_EXPORT_STUB(__imp__XamUserNuiIsBiometricEnabled);
REX_EXPORT_STUB(__imp__XamUserNuiUnbind);
REX_EXPORT_STUB(__imp__XamUserOverrideBindingCallbacks);
REX_EXPORT_STUB(__imp__XamUserOverrideDeviceBindings);
REX_EXPORT_STUB(__imp__XamUserOverrideGlobalState);
REX_EXPORT_STUB(__imp__XamUserOverrideUserInfo);
REX_EXPORT_STUB(__imp__XamUserPrefetchProfileSettings);
REX_EXPORT_STUB(__imp__XamUserProfileSync);
REX_EXPORT_STUB(__imp__XamUserReadUserPreference);
REX_EXPORT_STUB(__imp__XamUserResetSubscriptionType);
REX_EXPORT_STUB(__imp__XamUserUnlockLogonPreviewMode);
REX_EXPORT_STUB(__imp__XamUserUpdateRecentPlayer);
REX_EXPORT_STUB(__imp__XamUserValidateAvatarManifest);
REX_EXPORT_STUB(__imp__XamUserWriteUserPreference);
REX_EXPORT_STUB(__imp__XamVerifyPasscode);
