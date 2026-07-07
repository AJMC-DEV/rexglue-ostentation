/**
 * @file        ui/overlay/mods_menu_overlay.cpp
 * @brief       Mods menu overlay. See mods_menu_overlay.h.
 */
#include <rex/ui/overlay/mods_menu_overlay.h>

#include <fstream>
#include <system_error>
#include <vector>

#include <imgui.h>
#include <toml++/toml.hpp>

#include <rex/filesystem.h>
#include <rex/logging.h>
#include <rex/mods.h>
#include <rex/ui/image_decode.h>
#include <rex/ui/immediate_drawer.h>

namespace rex::ui {

namespace {
constexpr float kIconSize = 48.0f;

std::unique_ptr<ImmediateTexture> LoadIcon(ImmediateDrawer* immediate_drawer,
                                           const std::filesystem::path& icon_path) {
  if (!immediate_drawer) return nullptr;
  std::error_code ec;
  if (!std::filesystem::is_regular_file(icon_path, ec)) return nullptr;

  std::ifstream file(icon_path, std::ios::binary | std::ios::ate);
  if (!file) return nullptr;
  const std::streamsize length = file.tellg();
  if (length <= 0) return nullptr;
  file.seekg(0);

  std::vector<uint8_t> bytes(static_cast<size_t>(length));
  if (!file.read(reinterpret_cast<char*>(bytes.data()), length)) return nullptr;

  int width = 0;
  int height = 0;
  std::vector<uint8_t> rgba = DecodeImageRGBA(bytes.data(), bytes.size(), width, height);
  if (rgba.empty() || width <= 0 || height <= 0) return nullptr;

  return immediate_drawer->CreateTexture(static_cast<uint32_t>(width),
                                         static_cast<uint32_t>(height),
                                         ImmediateTextureFilter::kLinear, false, rgba.data());
}
}  // namespace

ModsMenuDialog::ModsMenuDialog(ImGuiDrawer* imgui_drawer, ImmediateDrawer* immediate_drawer)
    : ImGuiDialog(imgui_drawer), immediate_drawer_(immediate_drawer) {}

ModsMenuDialog::~ModsMenuDialog() = default;

void ModsMenuDialog::Rescan() {
  mods_.clear();
  scanned_ = true;

  std::filesystem::path mods_data_root = REXCVAR_GET(mods_data_root);
  if (mods_data_root.empty()) {
    mods_data_root = rex::filesystem::GetExecutableFolder() / "mods";
  }

  for (const auto& mod_dir : rex::GetEnabledModDirs(mods_data_root)) {
    const auto toml_path = mod_dir / "mod.toml";
    std::error_code ec;
    if (!std::filesystem::is_regular_file(toml_path, ec)) {
      REXLOG_WARN("Mods menu: skipping '{}' (no mod.toml)", mod_dir.filename().string());
      continue;
    }

    toml::table table;
    try {
      table = toml::parse_file(toml_path.string());
    } catch (const toml::parse_error& err) {
      REXLOG_WARN("Mods menu: skipping '{}' (failed to parse mod.toml: {})",
                  mod_dir.filename().string(), err.what());
      continue;
    }

    auto name = table["name"].value<std::string>();
    auto description = table["description"].value<std::string>();
    auto version = table["version"].value<std::string>();
    auto author = table["author"].value<std::string>();
    if (!name || !description || !version || !author) {
      REXLOG_WARN("Mods menu: skipping '{}' (mod.toml missing a required field)",
                  mod_dir.filename().string());
      continue;
    }

    ModEntry entry;
    entry.name        = std::move(*name);
    entry.description = std::move(*description);
    entry.version     = std::move(*version);
    entry.author      = std::move(*author);
    entry.folder      = mod_dir;
    entry.icon        = LoadIcon(immediate_drawer_, mod_dir / "icon.png");
    mods_.push_back(std::move(entry));
  }
}

void ModsMenuDialog::OnDraw(ImGuiIO& io) {
  if (!scanned_) {
    Rescan();
  }

  ImGui::SetNextWindowPos(ImVec2(io.DisplaySize.x * 0.5f, 40.0f), ImGuiCond_FirstUseEver,
                          ImVec2(0.5f, 0.0f));
  ImGui::SetNextWindowSize(ImVec2(560.0f, 480.0f), ImGuiCond_FirstUseEver);

  if (ImGui::Begin("Mods##mods_menu_overlay", nullptr, ImGuiWindowFlags_NoCollapse)) {
    ImGui::TextDisabled("Mods are enabled and ordered Externally");
    ImGui::SameLine(ImGui::GetWindowWidth() - 86.0f);
    if (ImGui::SmallButton("Refresh")) {
      Rescan();
    }
    ImGui::Separator();
    ImGui::Spacing();

    if (mods_.empty()) {
      ImGui::TextUnformatted("No enabled mods found.");
    } else {
      ImGui::BeginChild("##modslist", ImVec2(0.0f, 0.0f), false);
      for (size_t i = 0; i < mods_.size(); ++i) {
        const auto& mod = mods_[i];
        ImGui::PushID(static_cast<int>(i));

        if (mod.icon) {
          ImGui::Image(reinterpret_cast<ImTextureID>(mod.icon.get()),
                       ImVec2(kIconSize, kIconSize));
        } else {
          ImGui::Dummy(ImVec2(kIconSize, kIconSize));
        }
        ImGui::SameLine();

        ImGui::BeginGroup();
        ImGui::Text("%s", mod.name.c_str());
        ImGui::SameLine();
        ImGui::TextDisabled("v%s by %s", mod.version.c_str(), mod.author.c_str());
        ImGui::TextWrapped("%s", mod.description.c_str());
        ImGui::EndGroup();

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::PopID();
      }
      ImGui::EndChild();
    }
  }
  ImGui::End();
}

}  // namespace rex::ui
