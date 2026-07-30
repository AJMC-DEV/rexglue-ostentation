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
    std::string folder_name;
    std::filesystem::path folder;
    std::unique_ptr<ImmediateTexture> icon;
    bool enabled = false;
  };

  void Rescan();

  void ApplyOrder();

  ImmediateDrawer* immediate_drawer_ = nullptr;
  std::vector<ModEntry> mods_;
  bool scanned_ = false;
  bool order_dirty_ = false;
};

}
