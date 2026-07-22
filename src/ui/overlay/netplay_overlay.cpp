/**
 * @file        ui/overlay/netplay_overlay.cpp
 *
 * @brief       Netplay/Xbox LIVE overlay. See netplay_overlay.h.
 *
 * @modified    2026 - ReXGlue netplay UI
 */
#include <rex/ui/overlay/netplay_overlay.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#include <fmt/format.h>
#include <imgui.h>

#include <rex/cvar.h>
#include <rex/logging.h>
#include <rex/string.h>
#include <rex/system/kernel_state.h>
#include <rex/system/xam/profile_manager.h>
#include <rex/system/xam/user_profile.h>
#include <rex/system/xlive_web_client.h>

REXCVAR_DECLARE(bool, xlive_web_enabled);
REXCVAR_DECLARE(std::string, friends_xuids);

namespace rex::ui {

namespace {

// Friends storage lives in the system layer (friends_xuids cvar) so the
// XLiveBase friends enumerator reads the same list this tab edits.
using rex::system::kMaxFriends;
using rex::system::ParseFriendsXuids;
using rex::system::SaveFriendsXuids;

// "Copy" button that puts a bare 16-hex-digit XUID on the clipboard in the
// same format the friend input expects, so an XUID can be moved between two
// instances (or handed to another player) without retyping it.
void CopyXuidButton(const char* id, uint64_t xuid, std::string* status) {
  ImGui::PushID(id);
  if (ImGui::SmallButton("Copy")) {
    const std::string text = fmt::format("{:016X}", xuid);
    ImGui::SetClipboardText(text.c_str());
    if (status) *status = fmt::format("Copied {}", text);
  }
  ImGui::PopID();
}

}  // namespace

using rex::system::XLiveWebClient;
using rex::system::xam::ProfileManager;
using rex::system::xam::UserProfile;
using rex::system::xam::X_USER_SIGNIN_STATE;
using rex::system::xam::XTileType;

NetplayOverlayDialog::NetplayOverlayDialog(ImGuiDrawer* imgui_drawer)
    : ImGuiDialog(imgui_drawer) {
  REXLOG_INFO("NetplayOverlayDialog constructed (drawer={})",
              static_cast<const void*>(imgui_drawer));
}

NetplayOverlayDialog::~NetplayOverlayDialog() {}

static UserProfile* PrimaryProfile() {
  auto* ks = rex::system::kernel_state();
  if (!ks || !ks->profile_manager()) {
    return nullptr;
  }
  return ks->profile_manager()->GetProfile(uint8_t(0));
}

void NetplayOverlayDialog::RefreshFromProfile() {
  auto* profile = PrimaryProfile();
  if (!profile) {
    return;
  }
  rex::string::copy_truncating(gamertag_buf_, profile->name(),
                               sizeof(gamertag_buf_));
  loaded_from_profile_ = true;
}

void NetplayOverlayDialog::OnDraw(ImGuiIO& io) {
  static bool logged_once = false;
  if (!logged_once) {
    REXLOG_INFO("NetplayOverlayDialog::OnDraw first call");
    logged_once = true;
  }
  if (!loaded_from_profile_) {
    RefreshFromProfile();
  }

  ImGui::SetNextWindowPos(ImVec2(60, 60), ImGuiCond_FirstUseEver);
  ImGui::SetNextWindowSize(ImVec2(460, 420), ImGuiCond_FirstUseEver);
  if (ImGui::Begin("Netplay / Xbox LIVE##netplay_overlay", nullptr,
                   ImGuiWindowFlags_NoCollapse)) {
    if (ImGui::BeginTabBar("##netplay_tabs")) {
      if (ImGui::BeginTabItem("Status")) {
        DrawStatusTab();
        ImGui::EndTabItem();
      }
      if (ImGui::BeginTabItem("Profile")) {
        DrawProfileTab();
        ImGui::EndTabItem();
      }
      if (ImGui::BeginTabItem("Friends")) {
        DrawFriendsTab();
        ImGui::EndTabItem();
      }
      ImGui::EndTabBar();
    }
  }
  ImGui::End();
}

void NetplayOverlayDialog::DrawStatusTab() {
  const bool web_enabled = REXCVAR_GET(xlive_web_enabled);

  auto& wc = XLiveWebClient::Get();

  ImGui::TextUnformatted("Xbox LIVE web service");
  ImGui::Separator();

  auto status_line = [](const char* label, bool ok, const char* ok_text,
                        const char* bad_text) {
    ImGui::TextUnformatted(label);
    ImGui::SameLine(200);
    ImGui::TextColored(ok ? ImVec4(0.4f, 1.0f, 0.4f, 1.0f)
                          : ImVec4(1.0f, 0.5f, 0.5f, 1.0f),
                       "%s", ok ? ok_text : bad_text);
  };

  status_line("Netplay enabled:", web_enabled, "yes", "no (xlive_web_enabled=0)");
  status_line("Handshake (/whoami):", wc.is_ready(), "ready", "not ready");
  status_line("Registered (/players):", wc.is_registered(), "registered",
              "not registered");

  ImGui::Spacing();
  ImGui::Text("Public address: %s",
              wc.public_address().empty() ? "(unknown)"
                                          : wc.public_address().c_str());
  if (!wc.registered_xuid().empty()) {
    ImGui::Text("Online XUID:    %s", wc.registered_xuid().c_str());
    ImGui::Text("Machine MAC:    %s", wc.registered_mac().c_str());
  }

  ImGui::Spacing();
  ImGui::Separator();
  if (ImGui::Button("Connect / retry handshake")) {
    // EnsureReady() is idempotent once ready; force a fresh attempt otherwise.
    wc.EnsureReady();
    last_status_ = wc.is_ready() ? "Handshake OK" : "Handshake failed (see log)";
  }
  if (!last_status_.empty()) {
    ImGui::SameLine();
    ImGui::TextUnformatted(last_status_.c_str());
  }

  if (!web_enabled) {
    ImGui::Spacing();
    ImGui::TextWrapped(
        "Netplay is disabled. Set xlive_web_enabled = true in your config (or "
        "the settings overlay) and relaunch to connect to Xbox LIVE.");
  }
}

void NetplayOverlayDialog::DrawProfileTab() {
  auto* ks = rex::system::kernel_state();
  auto* pm = ks ? ks->profile_manager() : nullptr;
  auto* profile = PrimaryProfile();

  if (!pm) {
    ImGui::TextUnformatted("Profile manager unavailable.");
    return;
  }

  if (!profile) {
    ImGui::TextUnformatted("No profile signed in.");
    ImGui::Spacing();
    ImGui::InputText("Gamertag##new", gamertag_buf_, sizeof(gamertag_buf_));
    if (ImGui::Button("Create LIVE profile")) {
      const uint32_t reserved =
          rex::system::xam::X_XAMACCOUNTINFO::kLiveEnabled;
      uint64_t new_xuid = 0;
      std::string tag = gamertag_buf_[0] ? gamertag_buf_ : "Player";
      if (pm->CreateProfile(tag, /*autologin=*/true, /*default_xuid=*/true,
                            reserved, &new_xuid)) {
        last_status_ = fmt::format("Created profile {:016X}", new_xuid);
        loaded_from_profile_ = false;
      } else {
        last_status_ = "Failed to create profile";
      }
    }
    if (!last_status_.empty()) {
      ImGui::TextUnformatted(last_status_.c_str());
    }
    return;
  }

  ImGui::Text("XUID (offline): %016llX",
              static_cast<unsigned long long>(profile->xuid()));
  ImGui::SameLine();
  CopyXuidButton("offlinexuid", profile->xuid(), &last_status_);

  ImGui::Text("XUID (online):  %016llX",
              static_cast<unsigned long long>(profile->GetOnlineXUID()));
  ImGui::SameLine();
  CopyXuidButton("onlinexuid", profile->GetOnlineXUID(), &last_status_);
  ImGui::SameLine();
  if (ImGui::SmallButton("Regenerate##onlinexuid")) {
    if (pm->RegenerateOnlineXUID(profile->xuid())) {
      last_status_ = "New online XUID assigned - restart to re-register";
      loaded_from_profile_ = false;
    } else {
      last_status_ = "Failed to regenerate online XUID";
    }
  }
  if (ImGui::IsItemHovered()) {
    ImGui::SetTooltip(
        "Assign a new random online XUID.\n\n"
        "Use this when a profile folder was copied to make a second local\n"
        "instance: both instances then share one netplay identity, so the\n"
        "backend hides each host's session from the other and their startup\n"
        "cleanup deletes each other's sessions.\n\n"
        "Changes the identity the backend knows you by - leaderboard and\n"
        "presence history tied to the old XUID stays with the old XUID.");
  }
  ImGui::Text("LIVE enabled:   %s", profile->IsLiveEnabled() ? "yes" : "no");
  ImGui::Text("Signed in to:   %s",
              profile->signin_state() == X_USER_SIGNIN_STATE::SignedInToLive
                  ? "Xbox LIVE"
                  : "local");

  ImGui::Spacing();
  ImGui::Separator();
  ImGui::TextUnformatted("Gamertag");
  ImGui::InputText("##gamertag", gamertag_buf_, sizeof(gamertag_buf_));
  ImGui::SameLine();
  if (ImGui::Button("Rename")) {
    std::string tag = gamertag_buf_;
    if (ProfileManager::IsGamertagValid(tag)) {
      if (pm->SetGamertag(profile->xuid(), tag)) {
        last_status_ = "Gamertag updated";
        loaded_from_profile_ = false;
      } else {
        last_status_ = "Rename failed";
      }
    } else {
      last_status_ = "Invalid gamertag (1-15 chars, letters/digits)";
    }
  }

  ImGui::Spacing();
  ImGui::TextUnformatted("Gamer picture (64x64 PNG path)");
  ImGui::InputText("##gamerpic", gamerpic_path_buf_, sizeof(gamerpic_path_buf_));
  ImGui::SameLine();
  if (ImGui::Button("Load")) {
    std::ifstream f(gamerpic_path_buf_, std::ios::binary | std::ios::ate);
    if (f) {
      const auto size = f.tellg();
      f.seekg(0, std::ios::beg);
      std::vector<uint8_t> data(static_cast<size_t>(size));
      f.read(reinterpret_cast<char*>(data.data()), size);
      if (f.good()) {
        // Refresh the profile pointer after the copy; write both tile sizes.
        if (auto* p = PrimaryProfile()) {
          p->WriteProfileIcon(XTileType::kGamerTile, data);
          p->WriteProfileIcon(XTileType::kGamerTileSmall, data);
          last_status_ = "Gamer picture updated";
        }
      } else {
        last_status_ = "Failed to read PNG";
      }
    } else {
      last_status_ = "Could not open PNG file";
    }
  }

  if (!last_status_.empty()) {
    ImGui::Spacing();
    ImGui::TextUnformatted(last_status_.c_str());
  }
}

void NetplayOverlayDialog::DrawFriendsTab() {
  // The dialog is recreated each time the overlay opens, so the list has to be
  // rehydrated from the config rather than kept in the member across opens.
  if (!friends_loaded_) {
    friends_ = ParseFriendsXuids();
    friends_loaded_ = true;
  }

  ImGui::TextWrapped(
      "Friends are stored in the config file (friends_xuids) and persist "
      "across restarts. The web service exposes no friends API, so this list "
      "is local to this machine and is not synced with other players. The "
      "title's own friends list stays empty until the friends enumerator is "
      "implemented.");
  ImGui::Spacing();

  ImGui::InputText("##friendxuid", friend_xuid_buf_, sizeof(friend_xuid_buf_),
                   ImGuiInputTextFlags_CharsHexadecimal);
  ImGui::SameLine();
  if (ImGui::Button("Paste")) {
    const char* clip = ImGui::GetClipboardText();
    if (clip && *clip) {
      // Keep only hex digits: tolerates a pasted "0x" prefix, surrounding
      // whitespace, or a copied line that includes a label.
      std::string filtered;
      for (const char* p = clip; *p && filtered.size() < 16; ++p) {
        if (std::isxdigit(static_cast<unsigned char>(*p))) filtered += *p;
      }
      if (filtered.empty()) {
        last_status_ = "Clipboard has no hex digits";
      } else {
        std::snprintf(friend_xuid_buf_, sizeof(friend_xuid_buf_), "%s",
                      filtered.c_str());
        last_status_ = fmt::format("Pasted {}", filtered);
      }
    } else {
      last_status_ = "Clipboard is empty";
    }
  }
  ImGui::SameLine();
  ImGui::TextUnformatted("XUID (hex)");

  if (ImGui::Button("Add friend")) {
    try {
      uint64_t xuid = std::stoull(friend_xuid_buf_, nullptr, 16);
      auto* profile = PrimaryProfile();
      if (!xuid) {
        last_status_ = "Enter a non-zero XUID";
      } else if (friends_.size() >= kMaxFriends) {
        last_status_ = fmt::format("Friends list is full ({})", kMaxFriends);
      } else if (profile && xuid == profile->GetOnlineXUID()) {
        last_status_ = "That is your own XUID";
      } else if (std::find(friends_.begin(), friends_.end(), xuid) !=
                 friends_.end()) {
        last_status_ = "Already in the list";
      } else {
        friends_.push_back(xuid);
        SaveFriendsXuids(friends_);
        friend_xuid_buf_[0] = '\0';
        last_status_ = fmt::format("Added {:016X}", xuid);
      }
    } catch (...) {
      last_status_ = "Could not parse that XUID";
    }
  }

  ImGui::Spacing();
  ImGui::Separator();
  if (friends_.empty()) {
    ImGui::TextUnformatted("No friends added.");
  } else {
    for (size_t i = 0; i < friends_.size(); ++i) {
      ImGui::Text("%016llX", static_cast<unsigned long long>(friends_[i]));
      ImGui::SameLine();
      ImGui::PushID(static_cast<int>(i));
      CopyXuidButton("copyfriend", friends_[i], &last_status_);
      ImGui::SameLine();
      if (ImGui::SmallButton("Remove")) {
        friends_.erase(friends_.begin() + i);
        SaveFriendsXuids(friends_);
        ImGui::PopID();
        break;
      }
      ImGui::PopID();
    }
  }

  if (!last_status_.empty()) {
    ImGui::Spacing();
    ImGui::TextUnformatted(last_status_.c_str());
  }
}

}  // namespace rex::ui
