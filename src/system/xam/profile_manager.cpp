/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2024 Xenia Canary. All rights reserved.                          *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 *
 * @brief       Profile/account manager ported from xenia-canary netplay
 *              (src/xenia/kernel/xam/profile_manager.cc).
 * @modified    2026 - Adapted for ReXGlue runtime
 */

#include <rex/system/xam/profile_manager.h>

#include <fstream>
#include <regex>

#include <fmt/format.h>

#include <rex/cvar.h>
#include <rex/filesystem/devices/host_path_device.h>
#include <rex/logging.h>
#include <rex/system/kernel_state.h>

#include "crypto/TinySHA1.hpp"

REXCVAR_DECLARE(bool, xlive_web_enabled);
REXCVAR_DECLARE(std::string, user_xuid);
REXCVAR_DECLARE(std::string, user_gamertag);
REXCVAR_DECLARE(uint32_t, user_language);
REXCVAR_DECLARE(uint32_t, user_country);

namespace rex {
namespace system {
namespace xam {

// XN_SYS_SIGNINCHANGED
constexpr uint32_t kNotificationSystemSignInChanged = 0x0000000A;

// ---------------------------------------------------------------------------
// Account file crypto (XeCrypt HMAC-SHA1 + RC4), self-contained host-side
// versions of the routines in kernel/xboxkrnl/xboxkrnl_crypt.cpp.
// ---------------------------------------------------------------------------
namespace {

// Retail XeKey 0x19 - account file signing/encryption key.
const uint8_t kXeKey19Retail[16] = {0xE1, 0xBC, 0x15, 0x9C, 0x73, 0xB1,
                                    0xEA, 0xE9, 0xAB, 0x31, 0x70, 0xF3,
                                    0xAD, 0x47, 0xEB, 0xF3};
// Devkit XeKey 0x19.
const uint8_t kXeKey19Devkit[16] = {0xDA, 0xB6, 0x9A, 0xD9, 0x8E, 0x28,
                                    0x76, 0x4F, 0x97, 0x7E, 0xE2, 0x48,
                                    0x7E, 0x4F, 0x3F, 0x68};

const uint8_t* GetXeKey19(bool devkit) {
  return devkit ? kXeKey19Devkit : kXeKey19Retail;
}

void HmacSha(const uint8_t* key, uint32_t key_size, const uint8_t* inp_1,
             uint32_t inp_1_size, uint8_t* out, uint32_t out_size) {
  uint8_t kpad_i[0x40];
  uint8_t kpad_o[0x40];
  uint8_t tmp_key[0x40];
  std::memset(kpad_i, 0x36, 0x40);
  std::memset(kpad_o, 0x5C, 0x40);

  // If key is longer than the block size, use its hash instead.
  if (key_size > 0x40) {
    sha1::SHA1 sha_key;
    sha_key.processBytes(key, key_size);
    sha_key.finalize(tmp_key);
    key_size = 0x14;
  } else {
    std::memcpy(tmp_key, key, key_size);
  }

  for (uint32_t i = 0; i < key_size; i++) {
    kpad_i[i] = tmp_key[i] ^ 0x36;
    kpad_o[i] = tmp_key[i] ^ 0x5C;
  }

  sha1::SHA1 sha;
  sha.processBytes(kpad_i, 0x40);
  if (inp_1_size) {
    sha.processBytes(inp_1, inp_1_size);
  }

  uint8_t digest[0x14];
  sha.finalize(digest);
  sha.reset();

  sha.processBytes(kpad_o, 0x40);
  sha.processBytes(digest, 0x14);
  sha.finalize(digest);

  std::memcpy(out, digest, std::min(out_size, 0x14u));
}

void RC4(const uint8_t* key, uint32_t key_size, const uint8_t* data,
         uint32_t data_size, uint8_t* out) {
  uint8_t s[256];
  for (uint32_t i = 0; i < 256; ++i) {
    s[i] = static_cast<uint8_t>(i);
  }

  uint32_t j = 0;
  for (uint32_t i = 0; i < 256; ++i) {
    j = (j + s[i] + key[i % key_size]) & 0xFF;
    std::swap(s[i], s[j]);
  }

  uint32_t i = 0;
  j = 0;
  for (uint32_t n = 0; n < data_size; ++n) {
    i = (i + 1) & 0xFF;
    j = (j + s[i]) & 0xFF;
    std::swap(s[i], s[j]);
    out[n] = data[n] ^ s[(s[i] + s[j]) & 0xFF];
  }
}

bool ReadHostFile(const std::filesystem::path& path,
                  std::vector<uint8_t>& out_data) {
  std::ifstream file(path, std::ios::binary | std::ios::ate);
  if (!file) {
    return false;
  }
  const auto size = file.tellg();
  file.seekg(0, std::ios::beg);
  out_data.resize(static_cast<size_t>(size));
  file.read(reinterpret_cast<char*>(out_data.data()), size);
  return file.good();
}

bool WriteHostFile(const std::filesystem::path& path, const uint8_t* data,
                   size_t size) {
  std::error_code ec;
  std::filesystem::create_directories(path.parent_path(), ec);
  std::ofstream file(path, std::ios::binary | std::ios::trunc);
  if (!file) {
    return false;
  }
  file.write(reinterpret_cast<const char*>(data), size);
  return file.good();
}

}  // namespace

bool ProfileManager::DecryptAccountFile(const uint8_t* data,
                                        X_XAMACCOUNTINFO* output, bool devkit) {
  const uint8_t* key = GetXeKey19(devkit);

  // Generate RC4 key from data hash
  uint8_t rc4_key[0x14];
  HmacSha(key, 0x10, data, 0x10, rc4_key, 0x14);

  uint8_t dec_data[sizeof(X_XAMACCOUNTINFO) + 8];

  // Decrypt data
  RC4(rc4_key, 0x10, data + 0x10, sizeof(dec_data), dec_data);

  // Verify decrypted data against hash
  uint8_t data_hash[0x14];
  HmacSha(key, 0x10, dec_data, sizeof(dec_data), data_hash, 0x14);

  if (std::memcmp(data, data_hash, 0x10) == 0) {
    // Copy account data to output
    std::memcpy(output, dec_data + 8, sizeof(X_XAMACCOUNTINFO));
    return true;
  }

  return false;
}

void ProfileManager::EncryptAccountFile(const X_XAMACCOUNTINFO* input,
                                        uint8_t* output, bool devkit) {
  const uint8_t* key = GetXeKey19(devkit);

  X_XAMACCOUNTINFO* output_acct =
      reinterpret_cast<X_XAMACCOUNTINFO*>(output + 0x18);
  std::memcpy(output_acct, input, sizeof(X_XAMACCOUNTINFO));

  // Set confounder, should be random but meh
  std::memset(output + 0x10, 0xFD, 8);

  // Encrypted data = xam account info + 8 byte confounder
  uint32_t enc_data_size = sizeof(X_XAMACCOUNTINFO) + 8;

  // Set data hash
  uint8_t data_hash[0x14];
  HmacSha(key, 0x10, output + 0x10, enc_data_size, data_hash, 0x14);

  std::memcpy(output, data_hash, 0x10);

  // Generate RC4 key from data hash
  uint8_t rc4_key[0x14];
  HmacSha(key, 0x10, data_hash, 0x10, rc4_key, 0x14);

  // Encrypt data
  RC4(rc4_key, 0x10, output + 0x10, enc_data_size, output + 0x10);
}

ProfileManager::ProfileManager(KernelState* kernel_state)
    : kernel_state_(kernel_state) {
  logged_profiles_.clear();
  accounts_.clear();
}

std::filesystem::path ProfileManager::content_root() const {
  return kernel_state_->content_manager()->root_path();
}

void ProfileManager::Initialize() {
  for (const auto account_xuid : FindProfiles()) {
    LoadAccount(account_xuid);
  }

  // Pick the profile to auto-login:
  //  1. cvar user_xuid when it matches an existing profile,
  //  2. cvar user_gamertag when it matches an existing profile,
  //  3. first profile found,
  //  4. no profiles at all -> create a fresh one.
  uint64_t login_xuid = 0;

  const std::string& xuid_str = REXCVAR_GET(user_xuid);
  if (!xuid_str.empty()) {
    try {
      const uint64_t wanted = std::stoull(xuid_str, nullptr, 16);
      if (accounts_.count(wanted)) {
        login_xuid = wanted;
      }
    } catch (...) {
    }
  }

  const std::string& gamertag = REXCVAR_GET(user_gamertag);
  if (!login_xuid && !gamertag.empty()) {
    for (const auto& [xuid, account] : accounts_) {
      if (account.GetGamertagString() == gamertag) {
        login_xuid = xuid;
        break;
      }
    }
  }

  if (!login_xuid && !accounts_.empty()) {
    login_xuid = accounts_.begin()->first;
  }

  if (!login_xuid) {
    const std::string new_gamertag = gamertag.empty() ? "Player" : gamertag;
    const uint32_t reserved_flags =
        X_XAMACCOUNTINFO::AccountReservedFlags::kLiveEnabled;
    // default_xuid keeps the legacy fixed XUID (0xB13EBABEBABEBABE) so save
    // content created by older builds stays reachable.
    if (!CreateProfile(new_gamertag, true, /*default_xuid=*/true,
                       reserved_flags, &login_xuid)) {
      REXSYS_ERROR("ProfileManager: Failed to create default profile '{}'",
                   new_gamertag);
      return;
    }
    REXSYS_INFO("ProfileManager: Created default profile '{}' (XUID {:016X})",
                new_gamertag, login_xuid);
    return;  // CreateProfile already logged in.
  }

  Login(login_xuid, 0, false);
}

void ProfileManager::ReloadProfile(const uint64_t xuid) {
  if (accounts_.count(xuid)) {
    accounts_.erase(xuid);
  }

  LoadAccount(xuid);
}

void ProfileManager::ReloadProfiles() {
  for (const auto account_xuid : FindProfiles()) {
    LoadAccount(account_xuid);
  }
}

UserProfile* ProfileManager::GetProfile(const uint64_t xuid) const {
  const uint8_t user_index = GetUserIndexAssignedToProfile(xuid);

  if (user_index >= XUserMaxUserCount) {
    return nullptr;
  }

  return GetProfile(user_index);
}

UserProfile* ProfileManager::GetProfileLive(const uint64_t xuid_online) const {
  const uint8_t user_index = GetUserIndexAssignedToLiveProfile(xuid_online);

  if (user_index >= XUserMaxUserCount) {
    return nullptr;
  }

  return GetProfile(user_index);
}

UserProfile* ProfileManager::GetProfile(uint8_t user_index) const {
  if (user_index == XUserIndexNone) {
    return nullptr;
  }

  if (user_index == XUserIndexLatest || user_index == XUserIndexAny) {
    for (uint8_t i = 0; i < XUserMaxUserCount; i++) {
      if (!logged_profiles_.count(i)) {
        continue;
      }
      return logged_profiles_.at(i).get();
    }
    return nullptr;
  }

  if (!logged_profiles_.count(user_index)) {
    return nullptr;
  }

  return logged_profiles_.at(user_index).get();
}

std::filesystem::path ProfileManager::GetAccountFilePath(
    const uint64_t xuid) const {
  return GetProfilePath(xuid) / "Account";
}

bool ProfileManager::LoadAccount(const uint64_t xuid) {
  const std::string xuid_as_string = fmt::format("{:016X}", xuid);

  REXSYS_INFO("ProfileManager: Loading Account: {}", xuid_as_string);

  std::vector<uint8_t> file_data;
  if (!ReadHostFile(GetAccountFilePath(xuid), file_data)) {
    REXSYS_WARN("ProfileManager: Failed to open Account file for XUID {}",
                xuid_as_string);
    return false;
  }

  if (file_data.size() < sizeof(X_XAMACCOUNTINFO) + 0x18) {
    REXSYS_WARN("ProfileManager: Account file for XUID {} is truncated",
                xuid_as_string);
    return false;
  }

  X_XAMACCOUNTINFO tmp_acct;
  if (!DecryptAccountFile(file_data.data(), &tmp_acct)) {
    if (!DecryptAccountFile(file_data.data(), &tmp_acct, true)) {
      REXSYS_WARN("Failed to decrypt account data file for XUID: {}",
                  xuid_as_string);
      return false;
    }
  }

  accounts_.insert_or_assign(xuid, tmp_acct);
  return true;
}

bool ProfileManager::MountProfile(const uint64_t xuid, std::string mount_path) {
  std::filesystem::path profile_path = GetProfilePath(xuid);
  if (mount_path.empty()) {
    mount_path = fmt::format(kDefaultMountFormat, xuid);
  }
  mount_path += ':';

  auto device = std::make_unique<rex::filesystem::HostPathDevice>(
      mount_path, profile_path, false);
  if (!device->Initialize()) {
    REXSYS_ERROR(
        "MountProfile: Unable to mount {} profile; file not found or "
        "corrupted.",
        rex::path_to_utf8(profile_path));
    return false;
  }
  return kernel_state_->file_system()->RegisterDevice(std::move(device));
}

bool ProfileManager::DismountProfile(const uint64_t xuid) {
  return kernel_state_->file_system()->UnregisterDevice(
      fmt::format(kDefaultMountFormat, xuid) + ':');
}

void ProfileManager::Login(const uint64_t xuid, const uint8_t user_index,
                           bool notify) {
  if (logged_profiles_.size() >= XUserMaxUserCount &&
      user_index >= XUserMaxUserCount) {
    REXSYS_ERROR(
        "Cannot login account with XUID: {:016X} due to lack of free slots "
        "(Max 4 accounts at once)",
        xuid);
    return;
  }

  if (user_index < XUserMaxUserCount) {
    const auto& profile = logged_profiles_.find(user_index);
    if (profile != logged_profiles_.cend()) {
      if (profile->second && profile->second->xuid() == xuid) {
        // Do nothing! User is already signed in to that slot.
        return;
      }
    }
  }

  // Find if xuid is already logged in. We might want to logout.
  auto it = std::find_if(
      logged_profiles_.begin(), logged_profiles_.end(),
      [xuid](const auto& entry) { return entry.second->xuid() == xuid; });
  if (it != logged_profiles_.end()) {
    Logout(it->first);
  }

  if (!accounts_.count(xuid)) {
    return;
  }

  auto& account = accounts_[xuid];
  const uint8_t assigned_user_slot =
      user_index < XUserMaxUserCount ? user_index : FindFirstFreeProfileSlot();

  REXSYS_INFO("Loaded {} (XUID: {:016X}) to slot {}",
              account.GetGamertagString(), xuid, assigned_user_slot);

  MountProfile(xuid);

  auto profile =
      std::make_unique<UserProfile>(xuid, &account, GetProfilePath(xuid));
  profile->set_kernel_state(kernel_state_);
  logged_profiles_[assigned_user_slot] = std::move(profile);

  if (notify) {
    kernel_state_->BroadcastNotification(
        kNotificationSystemSignInChanged,
        static_cast<uint32_t>(GetUsedUserSlots().to_ulong()));
  }
}

void ProfileManager::Logout(const uint8_t user_index, bool notify) {
  auto profile = logged_profiles_.find(user_index);
  if (profile == logged_profiles_.cend()) {
    return;
  }

  DismountProfile(profile->second->xuid());
  logged_profiles_.erase(profile);
  if (notify) {
    kernel_state_->BroadcastNotification(
        kNotificationSystemSignInChanged,
        static_cast<uint32_t>(GetUsedUserSlots().to_ulong()));
  }
}

std::vector<uint64_t> ProfileManager::FindProfiles() const {
  // Info: Profile directory name is also its offline xuid
  std::vector<uint64_t> profiles_xuids;

  const std::filesystem::path root = content_root();
  if (root.empty() || !std::filesystem::exists(root)) {
    return profiles_xuids;
  }

  const std::regex xuid_pattern("[0-9A-F]{16}");

  std::error_code ec;
  for (const auto& entry : std::filesystem::directory_iterator(root, ec)) {
    if (!entry.is_directory()) {
      continue;
    }

    const std::string dir_name = rex::path_to_utf8(entry.path().filename());
    if (!std::regex_match(dir_name, xuid_pattern)) {
      continue;
    }

    if (dir_name == fmt::format("{:016X}", 0)) {
      continue;
    }

    const uint64_t xuid = std::stoull(dir_name, nullptr, 16);

    if (!std::filesystem::exists(GetAccountFilePath(xuid))) {
      REXSYS_WARN("Profile {} doesn't have an Account file!", dir_name);
      continue;
    }

    REXSYS_INFO("ProfileManager: Adding profile {} to profile list", dir_name);
    profiles_xuids.push_back(xuid);
  }

  REXSYS_INFO("ProfileManager: Found {} Profiles", profiles_xuids.size());
  return profiles_xuids;
}

uint8_t ProfileManager::FindFirstFreeProfileSlot() const {
  if (!IsAnyProfileSignedIn()) {
    return 0;
  }

  std::bitset<XUserMaxUserCount> used_slots = {};
  for (const auto& [index, entry] : logged_profiles_) {
    used_slots.set(index);
  }

  for (uint8_t i = 0; i < used_slots.size(); ++i) {
    if (!used_slots[i]) {
      return i;
    }
  }
  return XUserIndexAny;
}

std::bitset<XUserMaxUserCount> ProfileManager::GetUsedUserSlots() const {
  std::bitset<XUserMaxUserCount> used_slots = {};
  for (const auto& [index, entry] : logged_profiles_) {
    if (!entry) {
      continue;
    }

    used_slots.set(index);
  }

  return used_slots;
}

uint8_t ProfileManager::GetUserIndexAssignedToProfile(
    const uint64_t xuid) const {
  for (const auto& [index, entry] : logged_profiles_) {
    if (!entry) {
      continue;
    }

    if (entry->xuid() != xuid) {
      continue;
    }

    return index;
  }
  return XUserIndexAny;
}

uint8_t ProfileManager::GetUserIndexAssignedToLiveProfile(
    const uint64_t xuid_online) const {
  for (const auto& [index, entry] : logged_profiles_) {
    if (!entry) {
      continue;
    }

    if (entry->GetOnlineXUID() != xuid_online) {
      continue;
    }

    return index;
  }
  return XUserIndexAny;
}

std::filesystem::path ProfileManager::GetProfileContentPath(
    const uint64_t xuid, const uint32_t title_id) const {
  std::filesystem::path profile_content_path =
      content_root() / fmt::format("{:016X}", xuid);
  if (title_id != uint32_t(-1) && title_id != 0) {
    profile_content_path =
        profile_content_path / fmt::format("{:08X}", title_id);
  }
  return profile_content_path;
}

std::filesystem::path ProfileManager::GetProfilePath(
    const uint64_t xuid) const {
  return GetProfilePath(fmt::format("{:016X}", xuid));
}

std::filesystem::path ProfileManager::GetProfilePath(
    const std::string xuid) const {
  return content_root() / xuid / fmt::format("{:08X}", kProfileDashboardID) /
         fmt::format("{:08X}", static_cast<uint32_t>(XContentType::kProfile)) /
         xuid;
}

bool ProfileManager::CreateProfile(const std::string gamertag, bool autologin,
                                   bool default_xuid, uint32_t reserved_flags,
                                   uint64_t* out_xuid) {
  const auto xuid = !default_xuid ? GenerateXuid() : 0xB13EBABEBABEBABE;

  std::error_code ec;
  if (!std::filesystem::create_directories(GetProfilePath(xuid), ec)) {
    REXSYS_ERROR("ProfileManager: Failed to create profile directory: {}",
                 ec.message());
    return false;
  }

  const bool is_account_created = CreateAccount(xuid, gamertag, reserved_flags);
  if (is_account_created && autologin) {
    Login(xuid);
  }

  if (out_xuid) {
    *out_xuid = xuid;
  }

  return is_account_created;
}

bool ProfileManager::CreateProfile(const X_XAMACCOUNTINFO* account_info,
                                   uint64_t xuid) {
  if (!xuid) {
    xuid = GenerateXuid();
  }

  std::error_code ec;
  if (!std::filesystem::create_directories(GetProfilePath(xuid), ec)) {
    return false;
  }

  return CreateAccount(xuid, account_info);
}

const X_XAMACCOUNTINFO* ProfileManager::GetAccount(const uint64_t xuid) {
  if (!accounts_.count(xuid)) {
    return nullptr;
  }

  return &accounts_[xuid];
}

bool ProfileManager::CreateAccount(const uint64_t xuid,
                                   const std::string gamertag,
                                   uint32_t reserved_flags) {
  X_XAMACCOUNTINFO account = {};
  account.SetGamertag(gamertag);

  const bool live_enabled =
      reserved_flags & X_XAMACCOUNTINFO::AccountReservedFlags::kLiveEnabled;

  account.reserved_flags = reserved_flags;

  if (live_enabled) {
    SetDefaultXboxLiveEnabledAccountSettings(account);
    account.xuid_online = GenerateXuidOnline();
  }

  return CreateAccount(xuid, &account);
}

bool ProfileManager::CreateAccount(const uint64_t xuid,
                                   const X_XAMACCOUNTINFO* account) {
  const bool result = UpdateAccount(xuid, account);
  if (result) {
    accounts_.insert_or_assign(xuid, *account);
  }
  return result;
}

void ProfileManager::SetDefaultXboxLiveEnabledAccountSettings(
    X_XAMACCOUNTINFO& account) const {
  account.ToggleLiveFlag(true);

  account.SetCountry(
      static_cast<XOnlineCountry>(REXCVAR_GET(user_country) & 0xFF));
  account.SetLanguage(REXCVAR_GET(user_language));

  account.SetSubscriptionTier(
      X_XAMACCOUNTINFO::AccountSubscriptionTier::kSubscriptionTierGold);

  account.SetXboxLiveServiceProvider(X_XAMACCOUNTINFO::ProductionNet);
}

bool ProfileManager::UpdateAccount(const uint64_t xuid,
                                   const X_XAMACCOUNTINFO* account) {
  std::vector<uint8_t> encrypted_data;
  encrypted_data.resize(sizeof(X_XAMACCOUNTINFO) + 0x18);
  EncryptAccountFile(account, encrypted_data.data());

  if (!WriteHostFile(GetAccountFilePath(xuid), encrypted_data.data(),
                     encrypted_data.size())) {
    REXSYS_ERROR("ProfileManager: Failed to write Account file for {:016X}",
                 xuid);
    return false;
  }

  // Refresh the in-memory account data
  accounts_.insert_or_assign(xuid, *account);
  return true;
}

bool ProfileManager::DeleteProfile(const uint64_t xuid) {
  const uint8_t user_index = GetUserIndexAssignedToProfile(xuid);

  if (user_index < XUserMaxUserCount) {
    Logout(user_index);
  }

  if (accounts_.count(xuid)) {
    accounts_.erase(xuid);
  }

  std::error_code ec;
  std::filesystem::remove_all(GetProfileContentPath(xuid), ec);
  if (ec) {
    REXSYS_ERROR("Cannot remove profile: {}", ec.message());
    return false;
  }
  return true;
}

bool ProfileManager::ModifyAccount(
    const uint64_t xuid, X_XAMACCOUNTINFO& account,
    std::function<bool(X_XAMACCOUNTINFO& account)> action) {
  const uint8_t user_index = GetUserIndexAssignedToProfile(xuid);

  if (user_index < XUserMaxUserCount) {
    Logout(user_index);
  }

  if (!accounts_.count(xuid)) {
    return false;
  }

  if (!action(account)) {
    return false;
  }

  if (!UpdateAccount(xuid, &account)) {
    return false;
  }

  if (user_index < XUserMaxUserCount) {
    Login(xuid, user_index);
  }

  return true;
}

bool ProfileManager::ConvertToXboxLiveEnabledProfile(const uint64_t xuid) {
  X_XAMACCOUNTINFO& account = accounts_[xuid];

  auto run = [this](X_XAMACCOUNTINFO& account_info) {
    SetDefaultXboxLiveEnabledAccountSettings(account_info);

    // Set default settings and online XUID once
    if (!account_info.xuid_online) {
      account_info.xuid_online = GenerateXuidOnline();
    }

    return true;
  };

  return ModifyAccount(xuid, account, run);
}

bool ProfileManager::ConvertToOfflineProfile(const uint64_t xuid) {
  X_XAMACCOUNTINFO& account = accounts_[xuid];

  auto run = [](X_XAMACCOUNTINFO& account_info) {
    account_info.ToggleLiveFlag(false);
    account_info.SetSubscriptionTier(
        X_XAMACCOUNTINFO::AccountSubscriptionTier::kSubscriptionTierNone);
    account_info.SetXboxLiveServiceProvider(X_XAMACCOUNTINFO::LiveDisabled);

    return true;
  };

  return ModifyAccount(xuid, account, run);
}

bool ProfileManager::SetGamertag(const uint64_t xuid,
                                 const std::string& gamertag) {
  if (!accounts_.count(xuid)) {
    return false;
  }
  X_XAMACCOUNTINFO& account = accounts_[xuid];
  return ModifyAccount(xuid, account, [&gamertag](X_XAMACCOUNTINFO& a) {
    a.SetGamertag(gamertag);
    return true;
  });
}

bool ProfileManager::IsGamertagValid(const std::string gamertag) {
  std::regex pattern(R"(^[A-Za-z][A-Za-z0-9]*( [A-Za-z0-9]+)*$)");

  if (gamertag.length() < 1 || gamertag.length() > 15) {
    return false;
  }

  return std::regex_match(gamertag, pattern);
}

}  // namespace xam
}  // namespace system
}  // namespace rex
