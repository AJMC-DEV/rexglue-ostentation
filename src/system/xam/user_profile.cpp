/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2020 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 *
 * @modified    Tom Clay, 2026 - Adapted for ReXGlue runtime
 * @modified    2026 - Account-based profile model ported from xenia-canary
 *              netplay (src/xenia/kernel/xam/user_profile.cc).
 */

#include <fstream>
#include <sstream>

#include <fmt/format.h>

#include <rex/cvar.h>
#include <rex/logging.h>
#include <rex/system/kernel_state.h>
#include <rex/system/xam/user_profile.h>

REXCVAR_DECLARE(bool, xlive_web_enabled);

namespace rex {
namespace system {
namespace xam {

UserProfile::UserProfile(uint64_t xuid, const X_XAMACCOUNTINFO* account_info,
                         std::filesystem::path profile_path)
    : xuid_(xuid),
      account_info_(*account_info),
      profile_path_(std::move(profile_path)),
      profile_images_() {
  // 58410A1F checks the user XUID against a mask of 0x00C0000000000000 (3<<54),
  // if non-zero, it prevents the user from playing the game.
  // "You do not have permissions to perform this operation."
  LoadProfileIcon(XTileType::kGamerTile);
  LoadProfileIcon(XTileType::kGamerTileSmall);
  LoadProfileIcon(XTileType::kAvatarGamerTile);
  LoadProfileIcon(XTileType::kAvatarGamerTileSmall);

  AddDefaultSettings();
}

X_USER_SIGNIN_STATE UserProfile::signin_state() const {
  return IsLiveEnabled() && REXCVAR_GET(xlive_web_enabled)
             ? X_USER_SIGNIN_STATE::SignedInToLive
             : X_USER_SIGNIN_STATE::SignedInLocally;
}

std::span<const uint8_t> UserProfile::GetProfileIcon(XTileType icon_type) {
  // Coalesce equivalent tile types, like netplay does.
  if (icon_type == XTileType::kPersonalGamerTile ||
      icon_type == XTileType::kLocalGamerTile ||
      icon_type == XTileType::kGamerTileByImageId ||
      icon_type == XTileType::kGamerTileByKey) {
    icon_type = XTileType::kGamerTile;
  }

  if (icon_type == XTileType::kPersonalGamerTileSmall ||
      icon_type == XTileType::kLocalGamerTileSmall) {
    icon_type = XTileType::kGamerTileSmall;
  }

  if (profile_images_.find(icon_type) == profile_images_.cend()) {
    return {};
  }

  return {profile_images_[icon_type].data(), profile_images_[icon_type].size()};
}

void UserProfile::LoadProfileIcon(XTileType tile_type) {
  if (!kTileFileNames.count(tile_type)) {
    return;
  }

  const std::filesystem::path path =
      profile_path_ / kTileFileNames.at(tile_type);

  std::ifstream file(path, std::ios::binary | std::ios::ate);
  if (!file) {
    return;
  }

  const auto size = file.tellg();
  file.seekg(0, std::ios::beg);

  std::vector<uint8_t> data(static_cast<size_t>(size));
  file.read(reinterpret_cast<char*>(data.data()), size);
  if (!file.good()) {
    return;
  }

  profile_images_.insert_or_assign(tile_type, std::move(data));
}

void UserProfile::WriteProfileIcon(XTileType tile_type,
                                   std::span<const uint8_t> icon_data) {
  if (!kTileFileNames.count(tile_type)) {
    return;
  }

  const std::filesystem::path path =
      profile_path_ / kTileFileNames.at(tile_type);

  std::error_code ec;
  std::filesystem::create_directories(path.parent_path(), ec);

  std::ofstream file(path, std::ios::binary | std::ios::trunc);
  if (!file) {
    return;
  }
  file.write(reinterpret_cast<const char*>(icon_data.data()),
             icon_data.size());

  profile_images_.insert_or_assign(
      tile_type, std::vector<uint8_t>(icon_data.begin(), icon_data.end()));
}

void UserProfile::AddDefaultSettings() {
  // https://cs.rin.ru/forum/viewtopic.php?f=38&t=60668&hilit=gfwl+live&start=195
  // https://github.com/arkem/py360/blob/master/py360/constants.py
  // XPROFILE_GAMER_YAXIS_INVERSION
  AddSetting(std::make_unique<Int32Setting>(0x10040002, 0));
  // XPROFILE_OPTION_CONTROLLER_VIBRATION
  AddSetting(std::make_unique<Int32Setting>(0x10040003, 3));
  // XPROFILE_GAMERCARD_ZONE
  AddSetting(std::make_unique<Int32Setting>(0x10040004, 0));
  // XPROFILE_GAMERCARD_REGION
  AddSetting(std::make_unique<Int32Setting>(0x10040005, 0));
  // XPROFILE_GAMERCARD_CRED
  AddSetting(std::make_unique<Int32Setting>(0x10040006, 0xFA));
  // XPROFILE_GAMERCARD_REP
  AddSetting(std::make_unique<FloatSetting>(0x5004000B, 0.0f));
  // XPROFILE_OPTION_VOICE_MUTED
  AddSetting(std::make_unique<Int32Setting>(0x1004000C, 0));
  // XPROFILE_OPTION_VOICE_THRU_SPEAKERS
  AddSetting(std::make_unique<Int32Setting>(0x1004000D, 0));
  // XPROFILE_OPTION_VOICE_VOLUME
  AddSetting(std::make_unique<Int32Setting>(0x1004000E, 0x64));
  // XPROFILE_GAMERCARD_MOTTO
  AddSetting(std::make_unique<UnicodeSetting>(0x402C0011, u""));
  // XPROFILE_GAMERCARD_TITLES_PLAYED
  AddSetting(std::make_unique<Int32Setting>(0x10040012, 1));
  // XPROFILE_GAMERCARD_ACHIEVEMENTS_EARNED
  AddSetting(std::make_unique<Int32Setting>(0x10040013, 0));
  // XPROFILE_GAMER_DIFFICULTY
  AddSetting(std::make_unique<Int32Setting>(0x10040015, 0));
  // XPROFILE_GAMER_CONTROL_SENSITIVITY
  AddSetting(std::make_unique<Int32Setting>(0x10040018, 0));
  // Preferred color 1
  AddSetting(std::make_unique<Int32Setting>(0x1004001D, 0xFFFF0000u));
  // Preferred color 2
  AddSetting(std::make_unique<Int32Setting>(0x1004001E, 0xFF00FF00u));
  // XPROFILE_GAMER_ACTION_AUTO_AIM
  AddSetting(std::make_unique<Int32Setting>(0x10040022, 1));
  // XPROFILE_GAMER_ACTION_AUTO_CENTER
  AddSetting(std::make_unique<Int32Setting>(0x10040023, 0));
  // XPROFILE_GAMER_ACTION_MOVEMENT_CONTROL
  AddSetting(std::make_unique<Int32Setting>(0x10040024, 0));
  // XPROFILE_GAMER_RACE_TRANSMISSION
  AddSetting(std::make_unique<Int32Setting>(0x10040026, 0));
  // XPROFILE_GAMER_RACE_CAMERA_LOCATION
  AddSetting(std::make_unique<Int32Setting>(0x10040027, 0));
  // XPROFILE_GAMER_RACE_BRAKE_CONTROL
  AddSetting(std::make_unique<Int32Setting>(0x10040028, 0));
  // XPROFILE_GAMER_RACE_ACCELERATOR_CONTROL
  AddSetting(std::make_unique<Int32Setting>(0x10040029, 0));
  // XPROFILE_GAMERCARD_TITLE_CRED_EARNED
  AddSetting(std::make_unique<Int32Setting>(0x10040038, 0));
  // XPROFILE_GAMERCARD_TITLE_ACHIEVEMENTS_EARNED
  AddSetting(std::make_unique<Int32Setting>(0x10040039, 0));

  // If we set this, games will try to get it.
  // XPROFILE_GAMERCARD_PICTURE_KEY
  AddSetting(std::make_unique<UnicodeSetting>(0x4064000F, u"gamercard_picture_key"));

  // XPROFILE_TITLE_SPECIFIC1
  AddSetting(std::make_unique<BinarySetting>(0x63E83FFF));
  // XPROFILE_TITLE_SPECIFIC2
  AddSetting(std::make_unique<BinarySetting>(0x63E83FFE));
  // XPROFILE_TITLE_SPECIFIC3
  AddSetting(std::make_unique<BinarySetting>(0x63E83FFD));
}

void UserProfile::AddSetting(std::unique_ptr<Setting> setting) {
  Setting* previous_setting = setting.get();
  std::swap(settings_[setting->setting_id], previous_setting);

  if (setting->is_set && setting->is_title_specific()) {
    SaveSetting(setting.get());
  }

  if (previous_setting) {
    // replace: swap out the old setting from the owning list
    for (auto vec_it = setting_list_.begin(); vec_it != setting_list_.end(); ++vec_it) {
      if (vec_it->get() == previous_setting) {
        vec_it->swap(setting);
        break;
      }
    }
  } else {
    // new setting: add to the owning list
    setting_list_.push_back(std::move(setting));
  }
}

UserProfile::Setting* UserProfile::GetSetting(uint32_t setting_id) {
  const auto& it = settings_.find(setting_id);
  if (it == settings_.end()) {
    return nullptr;
  }
  UserProfile::Setting* setting = it->second;
  if (setting->is_title_specific()) {
    // If what we have loaded in memory isn't for the title that is running
    // right now, then load it from disk.
    if (kernel_state_->title_id() != setting->loaded_title_id) {
      LoadSetting(setting);
    }
  }
  return setting;
}

void UserProfile::LoadSetting(UserProfile::Setting* setting) {
  if (setting->is_title_specific()) {
    auto content_dir = kernel_state_->content_manager()->ResolveGameUserContentPath();
    auto setting_id = fmt::format("{:08X}", setting->setting_id);
    auto file_path = content_dir / setting_id;
    auto file = rex::filesystem::OpenFile(file_path, "rb");
    if (file) {
      fseek(file, 0, SEEK_END);
      uint32_t input_file_size = static_cast<uint32_t>(ftell(file));
      fseek(file, 0, SEEK_SET);

      std::vector<uint8_t> serialized_data(input_file_size);
      fread(serialized_data.data(), 1, serialized_data.size(), file);
      fclose(file);
      setting->Deserialize(serialized_data);
      setting->loaded_title_id = kernel_state_->title_id();
    }
  } else {
    // Unsupported for now.  Other settings aren't per-game and need to be
    // stored some other way.
    REXSYS_WARN("Attempting to load unsupported profile setting from disk");
  }
}

void UserProfile::SaveSetting(UserProfile::Setting* setting) {
  if (setting->is_title_specific()) {
    auto serialized_setting = setting->Serialize();
    auto content_dir = kernel_state_->content_manager()->ResolveGameUserContentPath();
    std::filesystem::create_directories(content_dir);
    auto setting_id = fmt::format("{:08X}", setting->setting_id);
    auto file_path = content_dir / setting_id;
    auto file = rex::filesystem::OpenFile(file_path, "wb");
    fwrite(serialized_setting.data(), 1, serialized_setting.size(), file);
    fclose(file);
  } else {
    // Unsupported for now.  Other settings aren't per-game and need to be
    // stored some other way.
    REXSYS_WARN("Attempting to save unsupported profile setting to disk");
  }
}

}  // namespace xam
}  // namespace system
}  // namespace rex
