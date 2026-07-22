/**
 * @file        rex/ui/overlay/netplay_overlay.h
 *
 * @brief       ImGui overlay for netplay/Xbox LIVE: connection status, profile
 *              editing (gamertag / gamer picture) and a friends list.
 *
 * @modified    2026 - ReXGlue netplay UI
 */
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <rex/ui/imgui_dialog.h>

namespace rex::ui {

class NetplayOverlayDialog : public ImGuiDialog {
 public:
  explicit NetplayOverlayDialog(ImGuiDrawer* imgui_drawer);
  ~NetplayOverlayDialog();

 protected:
  void OnDraw(ImGuiIO& io) override;

 private:
  void DrawStatusTab();
  void DrawProfileTab();
  void DrawFriendsTab();

  void RefreshFromProfile();

  // Editable profile fields (buffers for ImGui inputs).
  char gamertag_buf_[16] = {};
  char gamerpic_path_buf_[512] = {};
  bool loaded_from_profile_ = false;

  // Friends list (add-by-XUID). Persisted in the config file via the
  // friends_xuids cvar; there is no friends backend in the web client, so the
  // list is local to this machine. Loaded lazily because the dialog is
  // recreated every time the overlay opens.
  char friend_xuid_buf_[32] = {};
  std::vector<uint64_t> friends_;
  bool friends_loaded_ = false;

  std::string last_status_;
  double last_refresh_time_ = 0.0;
};

}  // namespace rex::ui
