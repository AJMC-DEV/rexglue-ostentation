/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2022 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 *
 * @modified    Tom Clay, 2026 - Adapted for ReXGlue runtime
 * @modified    2026 - Account-based profile model ported from xenia-canary
 *              netplay (src/xenia/kernel/xam/user_profile.h).
 */

#pragma once

#include <filesystem>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include <fmt/format.h>

#include <rex/memory.h>
#include <rex/stream.h>
#include <rex/system/xam/account_info.h>
#include <rex/system/xtypes.h>

namespace rex::system {
class KernelState;
}

namespace rex {
namespace system {
namespace xam {

struct X_USER_PROFILE_SETTING_DATA {
  // UserProfile::Setting::Type. Appears to be 8-in-32 field, and the upper 24
  // are not always zeroed by the game.
  uint8_t type;
  uint8_t unk_1[3];
  rex::be<uint32_t> unk_4;
  // TODO(sabretooth): not sure if this is a union, but it seems likely.
  // Haven't run into cases other than "binary data" yet.
  union {
    rex::be<int32_t> s32;
    rex::be<int64_t> s64;
    rex::be<uint32_t> u32;
    rex::be<double> f64;
    struct {
      rex::be<uint32_t> size;
      rex::be<uint32_t> ptr;
    } unicode;
    rex::be<float> f32;
    struct {
      rex::be<uint32_t> size;
      rex::be<uint32_t> ptr;
    } binary;
    rex::be<uint64_t> filetime;
  };
};
static_assert_size(X_USER_PROFILE_SETTING_DATA, 16);

struct X_USER_PROFILE_SETTING {
  rex::be<uint32_t> from;
  rex::be<uint32_t> unk04;
  union {
    rex::be<uint32_t> user_index;
    rex::be<uint64_t> xuid;
  };
  rex::be<uint32_t> setting_id;
  rex::be<uint32_t> unk14;
  union {
    uint8_t data_bytes[sizeof(X_USER_PROFILE_SETTING_DATA)];
    X_USER_PROFILE_SETTING_DATA data;
  };
};
static_assert_size(X_USER_PROFILE_SETTING, 40);

// Profile icon (gamer pic) tile types, from netplay.
enum class XTileType {
  kAchievement,
  kGameIcon,
  kGamerTile,
  kGamerTileSmall,
  kLocalGamerTile,
  kLocalGamerTileSmall,
  kBkgnd,
  kAwardedGamerTile,
  kAwardedGamerTileSmall,
  kGamerTileByImageId,
  kPersonalGamerTile,
  kPersonalGamerTileSmall,
  kGamerTileByKey,
  kAvatarGamerTile,
  kAvatarGamerTileSmall,
  kAvatarFullBody
};

// TODO: find filenames of other tile types that are stored in profile
inline const std::map<XTileType, std::string> kTileFileNames = {
    {XTileType::kGamerTile, "tile_64.png"},
    {XTileType::kGamerTileSmall, "tile_32.png"},
    {XTileType::kLocalGamerTile, "tile_64.png"},
    {XTileType::kLocalGamerTileSmall, "tile_32.png"},
    {XTileType::kPersonalGamerTile, "pp_64.png"},
    {XTileType::kPersonalGamerTileSmall, "pp_32.png"},
    {XTileType::kAvatarGamerTile, "avtr_64.png"},
    {XTileType::kAvatarGamerTileSmall, "avtr_32.png"},
};

static constexpr std::pair<uint16_t, uint16_t> kProfileIconSize = {64, 64};
static constexpr std::pair<uint16_t, uint16_t> kProfileIconSizeSmall = {32,
                                                                        32};

class UserProfile {
 public:
  class SettingByteStream : public stream::ByteStream {
   public:
    SettingByteStream(uint32_t ptr, uint8_t* data, size_t data_length, size_t offset = 0)
        : stream::ByteStream(data, data_length, offset), ptr_(ptr) {}

    uint32_t ptr() const { return static_cast<uint32_t>(ptr_ + offset()); }

   private:
    uint32_t ptr_;
  };
  struct Setting {
    enum class Type {
      CONTENT = 0,
      INT32 = 1,
      INT64 = 2,
      DOUBLE = 3,
      WSTRING = 4,
      FLOAT = 5,
      BINARY = 6,
      DATETIME = 7,
      UNSET = 0xFF,
    };
    union Key {
      uint32_t value;
      struct {
        uint32_t id : 14;
        uint32_t unk : 2;
        uint32_t size : 12;
        uint32_t type : 4;
      };
    };
    uint32_t setting_id;
    Type type;
    size_t size;
    bool is_set;
    uint32_t loaded_title_id;
    Setting(uint32_t setting_id, Type type, size_t size, bool is_set)
        : setting_id(setting_id), type(type), size(size), is_set(is_set), loaded_title_id(0) {}
    virtual void Append(X_USER_PROFILE_SETTING_DATA* data, SettingByteStream* stream) {
      (void)stream;
      data->type = static_cast<uint8_t>(type);
    }
    virtual std::vector<uint8_t> Serialize() const { return std::vector<uint8_t>(); }
    virtual void Deserialize(std::vector<uint8_t>) {}
    bool is_title_specific() const { return (setting_id & 0x3F00) == 0x3F00; }
  };
  struct Int32Setting : public Setting {
    Int32Setting(uint32_t setting_id, int32_t value)
        : Setting(setting_id, Type::INT32, 4, true), value(value) {}
    int32_t value;
    void Append(X_USER_PROFILE_SETTING_DATA* data, SettingByteStream* stream) override {
      Setting::Append(data, stream);
      data->s32 = value;
    }
  };
  struct Int64Setting : public Setting {
    Int64Setting(uint32_t setting_id, int64_t value)
        : Setting(setting_id, Type::INT64, 8, true), value(value) {}
    int64_t value;
    void Append(X_USER_PROFILE_SETTING_DATA* data, SettingByteStream* stream) override {
      Setting::Append(data, stream);
      data->s64 = value;
    }
  };
  struct DoubleSetting : public Setting {
    DoubleSetting(uint32_t setting_id, double value)
        : Setting(setting_id, Type::DOUBLE, 8, true), value(value) {}
    double value;
    void Append(X_USER_PROFILE_SETTING_DATA* data, SettingByteStream* stream) override {
      Setting::Append(data, stream);
      data->f64 = value;
    }
  };
  struct UnicodeSetting : public Setting {
    UnicodeSetting(uint32_t setting_id, const std::u16string& value)
        : Setting(setting_id, Type::WSTRING, 8, true), value(value) {}
    std::u16string value;
    void Append(X_USER_PROFILE_SETTING_DATA* data, SettingByteStream* stream) override {
      Setting::Append(data, stream);
      if (value.empty()) {
        data->unicode.size = 0;
        data->unicode.ptr = 0;
      } else {
        size_t count = value.size() + 1;
        size_t size = 2 * count;
        assert_true(size <= std::numeric_limits<uint32_t>::max());
        data->unicode.size = static_cast<uint32_t>(size);
        data->unicode.ptr = stream->ptr();
        auto buffer = reinterpret_cast<uint16_t*>(&stream->data()[stream->offset()]);
        stream->Advance(size);
        memory::copy_and_swap(buffer, (uint16_t*)value.data(), count);
      }
    }
  };
  struct FloatSetting : public Setting {
    FloatSetting(uint32_t setting_id, float value)
        : Setting(setting_id, Type::FLOAT, 4, true), value(value) {}
    float value;
    void Append(X_USER_PROFILE_SETTING_DATA* data, SettingByteStream* stream) override {
      Setting::Append(data, stream);
      data->f32 = value;
    }
  };
  struct BinarySetting : public Setting {
    BinarySetting(uint32_t setting_id) : Setting(setting_id, Type::BINARY, 8, false), value() {}
    BinarySetting(uint32_t setting_id, const std::vector<uint8_t>& value)
        : Setting(setting_id, Type::BINARY, 8, true), value(value) {}
    std::vector<uint8_t> value;
    void Append(X_USER_PROFILE_SETTING_DATA* data, SettingByteStream* stream) override {
      Setting::Append(data, stream);
      if (value.empty()) {
        data->binary.size = 0;
        data->binary.ptr = 0;
      } else {
        size_t size = value.size();
        assert_true(size <= std::numeric_limits<uint32_t>::max());
        data->binary.size = static_cast<uint32_t>(size);
        data->binary.ptr = stream->ptr();
        stream->Write(value.data(), size);
      }
    }
    std::vector<uint8_t> Serialize() const override {
      return std::vector<uint8_t>(value.data(), value.data() + value.size());
    }
    void Deserialize(std::vector<uint8_t> data) override {
      value = data;
      is_set = true;
    }
  };
  struct DateTimeSetting : public Setting {
    DateTimeSetting(uint32_t setting_id, int64_t value)
        : Setting(setting_id, Type::DATETIME, 8, true), value(value) {}
    int64_t value;
    void Append(X_USER_PROFILE_SETTING_DATA* data, SettingByteStream* stream) override {
      Setting::Append(data, stream);
      data->filetime = value;
    }
  };

  UserProfile(uint64_t xuid, const X_XAMACCOUNTINFO* account_info,
              std::filesystem::path profile_path);

  uint64_t xuid() const { return xuid_; }

  // Online (LIVE) XUID: 0x0009.... Zero when profile is not live-enabled.
  uint64_t GetOnlineXUID() const {
    return IsLiveEnabled() ? static_cast<uint64_t>(account_info_.xuid_online)
                           : 0;
  }
  // XUID reported to titles for the signed-in user: online XUID when signed
  // in to LIVE, offline XUID otherwise.
  uint64_t GetLogonXUID() const {
    return IsLiveEnabled() &&
                   signin_state() == X_USER_SIGNIN_STATE::SignedInToLive
               ? static_cast<uint64_t>(account_info_.xuid_online)
               : xuid();
  }

  std::string name() const { return account_info_.GetGamertagString(); }

  X_USER_SIGNIN_STATE signin_state() const;

  uint32_t GetReservedFlags() const { return account_info_.GetReservedFlags(); }
  uint32_t GetCachedFlags() const { return account_info_.GetCachedFlags(); }
  uint32_t GetCountry() const {
    return static_cast<uint32_t>(account_info_.GetCountry());
  }
  uint32_t GetSubscriptionTier() const {
    return account_info_.GetSubscriptionTier();
  }
  uint32_t GetLanguage() const { return account_info_.GetLanguage(); }

  bool IsParentalControlled() const {
    return account_info_.IsParentalControlled();
  }
  bool IsLiveEnabled() const { return account_info_.IsLiveEnabled(); }

  const X_XAMACCOUNTINFO* account_info() const { return &account_info_; }

  void GetPasscode(uint16_t* passcode) const {
    std::memcpy(passcode, account_info_.passcode,
                sizeof(account_info_.passcode));
  }

  // Profile icon (gamer pic) PNG bytes; empty when profile has no custom pic.
  std::span<const uint8_t> GetProfileIcon(XTileType icon_type);
  void WriteProfileIcon(XTileType tile_type,
                        std::span<const uint8_t> icon_data);

  void set_kernel_state(KernelState* ks) { kernel_state_ = ks; }

  void AddSetting(std::unique_ptr<Setting> setting);
  Setting* GetSetting(uint32_t setting_id);

 private:
  uint64_t xuid_;
  X_XAMACCOUNTINFO account_info_;
  std::filesystem::path profile_path_;

  std::map<XTileType, std::vector<uint8_t>> profile_images_;

  std::vector<std::unique_ptr<Setting>> setting_list_;
  std::unordered_map<uint32_t, Setting*> settings_;
  KernelState* kernel_state_ = nullptr;

  void AddDefaultSettings();
  void LoadProfileIcon(XTileType tile_type);
  void LoadSetting(UserProfile::Setting*);
  void SaveSetting(UserProfile::Setting*);
};

}  // namespace xam
}  // namespace system
}  // namespace rex

// fmt formatter for UserProfile::Setting::Type
template <>
struct fmt::formatter<rex::system::xam::UserProfile::Setting::Type> : fmt::formatter<int> {
  template <typename FormatContext>
  auto format(rex::system::xam::UserProfile::Setting::Type t, FormatContext& ctx) const {
    return fmt::formatter<int>::format(static_cast<int>(t), ctx);
  }
};
