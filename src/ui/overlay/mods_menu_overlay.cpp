/**
 * @file        ui/overlay/mods_menu_overlay.cpp
 * @brief       Mods menu overlay. See mods_menu_overlay.h.
 */
#include <rex/ui/overlay/mods_menu_overlay.h>

#include <algorithm>
#include <fstream>
#include <system_error>
#include <utility>
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

std::unique_ptr<ImmediateTexture> LoadIcon(ImmediateDrawer* drawer,
                                           const std::filesystem::path& icon_path) {
  if (!drawer) return nullptr;
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

  return drawer->CreateTexture(static_cast<uint32_t>(width), static_cast<uint32_t>(height),
                               ImmediateTextureFilter::kLinear, false, rgba.data());
}

}  // namespace

ModsMenuDialog::ModsMenuDialog(ImGuiDrawer* imgui_drawer, ImmediateDrawer* immediate_drawer)
    : ImGuiDialog(imgui_drawer), immediate_drawer_(immediate_drawer) {}

ModsMenuDialog::~ModsMenuDialog() = default;

void ModsMenuDialog::Rescan() {
  mods_.clear();
  scanned_ = true;

  const auto mods_root = rex::GetModsRoot();
  // The <exe>/mods fallback is always searched, mirroring GetEnabledModDirs.
  std::vector<std::filesystem::path> roots{mods_root};
  const auto exe_mods = rex::filesystem::GetExecutableFolder() / "mods";
  std::error_code ec;
  if (std::filesystem::weakly_canonical(exe_mods, ec) !=
      std::filesystem::weakly_canonical(mods_root, ec)) {
    roots.push_back(exe_mods);
  }

  // Every folder present on disk, first root winning a name collision.
  std::vector<std::filesystem::path> folders;
  for (const auto& root : roots) {
    ec.clear();
    if (!std::filesystem::is_directory(root, ec)) continue;
    for (const auto& entry : std::filesystem::directory_iterator(root, ec)) {
      if (!entry.is_directory()) continue;
      const std::string name = entry.path().filename().string();
      // Dot-folders are tooling state, not mods.
      if (!name.empty() && name[0] == '.') continue;
      bool seen = false;
      for (const auto& existing : folders) {
        if (rex::ModNamesEqual(existing.filename().string(), name)) {
          seen = true;
          break;
        }
      }
      if (!seen) folders.push_back(entry.path());
    }
  }

  const auto enabled = rex::ParseModList(REXCVAR_GET(enabled_mods));

  auto build = [&](const std::filesystem::path& dir, bool is_enabled) {
    ModEntry mod;
    mod.folder = dir;
    mod.folder_name = dir.filename().string();
    mod.name = mod.folder_name;
    mod.enabled = is_enabled;

    // mod.toml is optional: shader/texture-only mods carry no metadata.
    const auto toml_path = dir / "mod.toml";
    ec.clear();
    if (std::filesystem::is_regular_file(toml_path, ec)) {
      try {
        const toml::table table = toml::parse_file(toml_path.string());
        if (auto v = table["name"].value<std::string>(); v && !v->empty()) mod.name = *v;
        mod.description = table["description"].value_or<std::string>("");
        mod.version = table["version"].value_or<std::string>("");
        mod.author = table["author"].value_or<std::string>("");
      } catch (const toml::parse_error& err) {
        REXLOG_WARN("Mods menu: '{}' has an unreadable mod.toml: {}", mod.folder_name, err.what());
      }
    }
    mod.icon = LoadIcon(immediate_drawer_, dir / "icon.png");
    mods_.push_back(std::move(mod));
  };

  // Enabled mods first, in their configured priority order.
  for (const auto& name : enabled) {
    for (const auto& dir : folders) {
      if (rex::ModNamesEqual(dir.filename().string(), name)) {
        build(dir, true);
        break;
      }
    }
  }
  // Then everything else, alphabetically.
  std::vector<std::filesystem::path> rest;
  for (const auto& dir : folders) {
    bool listed = false;
    for (const auto& mod : mods_) {
      if (rex::ModNamesEqual(mod.folder_name, dir.filename().string())) {
        listed = true;
        break;
      }
    }
    if (!listed) rest.push_back(dir);
  }
  std::sort(rest.begin(), rest.end(), [](const auto& a, const auto& b) {
    return a.filename().string() < b.filename().string();
  });
  for (const auto& dir : rest) build(dir, false);
}

void ModsMenuDialog::ApplyOrder() {
  std::vector<std::string> names;
  for (const auto& mod : mods_) {
    if (mod.enabled) names.push_back(mod.folder_name);
  }
  REXCVAR_SET(enabled_mods, rex::FormatModList(names));
  const auto& config = rex::cvar::GetConfigPath();
  if (config.empty()) {
    REXLOG_WARN("Mods menu: no config path known; mod changes are session-only");
  } else {
    rex::cvar::SaveConfig(config);
  }
  order_dirty_ = true;
}

void ModsMenuDialog::OnDraw(ImGuiIO& io) {
  if (!scanned_) Rescan();

  ImGui::SetNextWindowPos(ImVec2(io.DisplaySize.x * 0.5f, 40.0f), ImGuiCond_FirstUseEver,
                          ImVec2(0.5f, 0.0f));
  ImGui::SetNextWindowSize(ImVec2(620.0f, 520.0f), ImGuiCond_FirstUseEver);

  if (ImGui::Begin("Mods##mods_menu_overlay", nullptr, ImGuiWindowFlags_NoCollapse)) {
    if (ImGui::Button("Rescan")) Rescan();
    ImGui::SameLine();
    ImGui::TextDisabled("Drag the grip to reorder \xE2\x80\x94 higher wins conflicts");

    if (order_dirty_) {
      ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.8f, 0.35f, 1.0f));
      ImGui::TextUnformatted("Restart the game to apply mod changes.");
      ImGui::PopStyleColor();
    }
    ImGui::Separator();

    if (mods_.empty()) {
      ImGui::TextUnformatted("No mod folders found.");
      ImGui::TextDisabled("%s", rex::GetModsRoot().string().c_str());
    } else {
      ImGui::BeginChild("##modslist", ImVec2(0.0f, 0.0f), false);
      int move_from = -1;
      int move_to = -1;

      for (size_t i = 0; i < mods_.size(); ++i) {
        auto& mod = mods_[i];
        ImGui::PushID(static_cast<int>(i));

        const float row_top = ImGui::GetCursorPosY();
        bool enabled = mod.enabled;
        if (ImGui::Checkbox("##enabled", &enabled)) {
          mod.enabled = enabled;
          ApplyOrder();
        }
        ImGui::SameLine();

        if (mod.icon) {
          ImGui::Image(reinterpret_cast<ImTextureID>(mod.icon.get()), ImVec2(kIconSize, kIconSize));
        } else {
          ImGui::Dummy(ImVec2(kIconSize, kIconSize));
        }
        ImGui::SameLine();

        ImGui::BeginGroup();
        if (!mod.enabled) {
          ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyle().Colors[ImGuiCol_TextDisabled]);
        }
        ImGui::TextUnformatted(mod.name.c_str());
        if (!mod.enabled) ImGui::PopStyleColor();
        if (!mod.version.empty() || !mod.author.empty()) {
          ImGui::SameLine();
          ImGui::TextDisabled("v%s%s%s", mod.version.empty() ? "?" : mod.version.c_str(),
                              mod.author.empty() ? "" : " by ", mod.author.c_str());
        }
        if (!mod.description.empty()) ImGui::TextWrapped("%s", mod.description.c_str());
        ImGui::EndGroup();

        // Grip on the right edge. The classic ImGui reorder idiom: while the grip
        // is held, a drag that leaves the item swaps it with its neighbour.
        const float grip_width = 26.0f;
        ImGui::SameLine(ImGui::GetContentRegionMax().x - grip_width);
        ImGui::SetCursorPosY(row_top);
        ImGui::Button("\xE2\x89\xA1", ImVec2(grip_width, ImGui::GetFrameHeight()));
        if (ImGui::IsItemHovered()) ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeNS);
        if (ImGui::IsItemActive() && !ImGui::IsItemHovered()) {
          const float delta = ImGui::GetMouseDragDelta(ImGuiMouseButton_Left).y;
          const int next = static_cast<int>(i) + (delta < 0.0f ? -1 : 1);
          if (next >= 0 && next < static_cast<int>(mods_.size())) {
            move_from = static_cast<int>(i);
            move_to = next;
            ImGui::ResetMouseDragDelta();
          }
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::PopID();
      }

      if (move_from >= 0 && move_to >= 0) {
        std::swap(mods_[static_cast<size_t>(move_from)], mods_[static_cast<size_t>(move_to)]);
        ApplyOrder();
      }
      ImGui::EndChild();
    }
  }
  ImGui::End();
}

}  // namespace rex::ui
