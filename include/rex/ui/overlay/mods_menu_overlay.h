/**
 * @file        rex/ui/overlay/mods_menu_overlay.h
 *
 * @brief       Read-only ImGui overlay listing enabled mods (name,
 *              description, version, author, icon), sourced from
 *              mods_data_root/<mod>/mod.toml + icon.png. Enabling/disabling
 *              mods and mod load order are managed by an external launcher
 *              via the enabled_mods cvar — this overlay is purely
 *              informational and never touches that cvar.
 */
#pragma once

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include <rex/ui/imgui_dialog.h>

namespace rex::ui {

class ImmediateDrawer;
class ImmediateTexture;

class ModsMenuDialog : public ImGuiDialog {
 public:
  ModsMenuDialog(ImGuiDrawer* imgui_drawer, ImmediateDrawer* immediate_drawer);
  ~ModsMenuDialog() override;

 protected:
  void OnDraw(ImGuiIO& io) override;

 private:
  struct ModEntry {
    std::string name;
    std::string description;
    std::string version;
    std::string author;
    std::filesystem::path folder;
    std::unique_ptr<ImmediateTexture> icon;
  };

  // Rebuilds mods_ from mods_data_root/<enabled mod>/mod.toml + icon.png.
  // A mod folder with a missing or invalid mod.toml is skipped entirely.
  void Rescan();

  ImmediateDrawer* immediate_drawer_ = nullptr;
  std::vector<ModEntry> mods_;
  bool scanned_ = false;
};

}  // namespace rex::ui
