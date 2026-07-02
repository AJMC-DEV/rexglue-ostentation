/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2024 Xenia Canary. All rights reserved.                          *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 *
 * @brief       Profile/account manager ported from xenia-canary netplay
 *              (src/xenia/kernel/xam/profile_manager.h).
 *              Profiles live on disk in the same layout & Account-file format
 *              as xenia, so profiles can be copied between the two.
 * @modified    2026 - Adapted for ReXGlue runtime
 */

#pragma once

#include <bitset>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include <rex/system/xam/account_info.h>
#include <rex/system/xam/user_profile.h>

namespace rex::system {
class KernelState;
}

namespace rex {
namespace system {
namespace xam {

// Dashboard title id, used as the directory name that holds profile packages.
constexpr uint32_t kProfileDashboardID = 0xFFFE07D1;

constexpr std::string_view kDefaultMountFormat = "User_{:016X}";

class ProfileManager {
 public:
  static bool DecryptAccountFile(const uint8_t* data, X_XAMACCOUNTINFO* output,
                                 bool devkit = false);

  static void EncryptAccountFile(const X_XAMACCOUNTINFO* input, uint8_t* output,
                                 bool devkit = false);

  ProfileManager(KernelState* kernel_state);
  ~ProfileManager() = default;

  // Scans the content root for profiles and signs in the default/first one.
  // Creates a fresh live-enabled profile when none exist.
  void Initialize();

  bool CreateProfile(const std::string gamertag, bool autologin,
                     bool default_xuid = false, uint32_t reserved_flags = 0,
                     uint64_t* out_xuid = nullptr);
  bool CreateProfile(const X_XAMACCOUNTINFO* account_info, uint64_t xuid);

  bool DeleteProfile(const uint64_t xuid);

  bool ModifyAccount(const uint64_t xuid, X_XAMACCOUNTINFO& account,
                     std::function<bool(X_XAMACCOUNTINFO& account)> action);
  bool ConvertToXboxLiveEnabledProfile(const uint64_t xuid);
  bool ConvertToOfflineProfile(const uint64_t xuid);

  bool MountProfile(const uint64_t xuid, std::string mount_path = "");
  bool DismountProfile(const uint64_t xuid);

  void Login(const uint64_t xuid, const uint8_t user_index = XUserIndexAny,
             bool notify = true);
  void Logout(const uint8_t user_index, bool notify = true);

  bool LoadAccount(const uint64_t xuid);
  void ReloadProfiles();
  void ReloadProfile(const uint64_t xuid);

  UserProfile* GetProfile(const uint64_t xuid) const;
  UserProfile* GetProfileLive(const uint64_t xuid_online) const;
  UserProfile* GetProfile(const uint8_t user_index) const;
  uint8_t GetUserIndexAssignedToProfile(const uint64_t xuid) const;
  uint8_t GetUserIndexAssignedToLiveProfile(const uint64_t xuid_online) const;

  std::bitset<XUserMaxUserCount> GetUsedUserSlots() const;

  const std::map<uint64_t, X_XAMACCOUNTINFO>* GetAccounts() {
    return &accounts_;
  }
  const X_XAMACCOUNTINFO* GetAccount(const uint64_t xuid);

  uint32_t GetAccountCount() const {
    return static_cast<uint32_t>(accounts_.size());
  }
  bool IsAnyProfileSignedIn() const { return !logged_profiles_.empty(); }
  uint32_t SignedInProfilesCount() const {
    return static_cast<uint32_t>(logged_profiles_.size());
  }

  std::filesystem::path GetProfileContentPath(
      const uint64_t xuid, const uint32_t title_id = -1) const;

  bool UpdateAccount(const uint64_t xuid, const X_XAMACCOUNTINFO* account);

  // Renames the profile's gamertag (persists to the Account file). Re-logs the
  // profile if it was signed in.
  bool SetGamertag(const uint64_t xuid, const std::string& gamertag);

  static bool IsGamertagValid(const std::string gamertag);

  uint64_t GenerateXuid() const {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    // Offline XUIDs are 0xE000.... with 48 bits of uniqueness.
    return (0xE000ULL << 48) | (gen() & 0x0000FFFFFFFFFFFFULL);
  }

  uint64_t GenerateXuidOnline() const {
    std::random_device rd;
    std::mt19937 gen(rd());
    return (0x9ULL << 48) + (gen() % (1u << 31));
  }

 private:
  bool CreateAccount(const uint64_t xuid, const std::string gamertag,
                     uint32_t reserved_flags);
  bool CreateAccount(const uint64_t xuid, const X_XAMACCOUNTINFO* account);
  void SetDefaultXboxLiveEnabledAccountSettings(
      X_XAMACCOUNTINFO& account) const;

  std::filesystem::path GetProfilePath(const uint64_t xuid) const;
  std::filesystem::path GetProfilePath(const std::string xuid) const;
  std::filesystem::path GetAccountFilePath(const uint64_t xuid) const;

  std::filesystem::path content_root() const;

  std::vector<uint64_t> FindProfiles() const;

  uint8_t FindFirstFreeProfileSlot() const;

  std::map<uint64_t, X_XAMACCOUNTINFO> accounts_;
  std::map<uint8_t, std::unique_ptr<UserProfile>> logged_profiles_;

  KernelState* kernel_state_;
};

}  // namespace xam
}  // namespace system
}  // namespace rex
