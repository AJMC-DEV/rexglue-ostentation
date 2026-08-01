/**
 * @file        ui/overlay/mods_menu_overlay.cpp
 * @brief       Mods menu overlay. See mods_menu_overlay.h.
 */
#include <rex/ui/overlay/mods_menu_overlay.h>

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <system_error>
#include <utility>
#include <vector>

#include <imgui.h>
#include <toml++/toml.hpp>

#include <rex/filesystem.h>
#include <rex/logging.h>
#include <rex/mods.h>
#include <rex/system.h>
#include <rex/ui/image_decode.h>
#include <rex/ui/immediate_drawer.h>

namespace rex::ui {

namespace {

constexpr float kIconSize = 40.0f;
constexpr float kRowPad = 6.0f;
constexpr float kButtonZone = 108.0f;

std::unique_ptr<ImmediateTexture> LoadIcon(ImmediateDrawer* drawer, const std::filesystem::path& icon_path) {
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

  return drawer->CreateTexture(static_cast<uint32_t>(width), static_cast<uint32_t>(height), ImmediateTextureFilter::kLinear, false, rgba.data());
}

std::string ClipToWidth(const std::string& text, float max_width) {
  static constexpr const char* kEllipsis = "...";
  if (text.empty() || max_width <= 0.0f) return text;
  if (ImGui::CalcTextSize(text.c_str()).x <= max_width) return text;
  const float ellipsis_w = ImGui::CalcTextSize(kEllipsis).x;
  size_t len = text.size();
  while (len > 0) {
    --len;
    while (len > 0 && (static_cast<unsigned char>(text[len]) & 0xC0) == 0x80) --len;
    if (ImGui::CalcTextSize(text.c_str(), text.c_str() + len).x + ellipsis_w <= max_width) break;
  }
  return text.substr(0, len) + kEllipsis;
}

float RowHeight() {
  return std::max(kIconSize, ImGui::GetTextLineHeightWithSpacing() * 2.0f) + kRowPad * 2.0f;
}

}

ModsMenuDialog::ModsMenuDialog(ImGuiDrawer* imgui_drawer, ImmediateDrawer* immediate_drawer) : ImGuiDialog(imgui_drawer), immediate_drawer_(immediate_drawer) {}

ModsMenuDialog::~ModsMenuDialog() = default;

void ModsMenuDialog::Rescan() {
  mods_.clear();
  scanned_ = true;

  const auto mods_root = rex::GetModsRoot();
  std::vector<std::filesystem::path> roots{mods_root};
  const auto exe_mods = rex::filesystem::GetExecutableFolder() / "mods";
  std::error_code ec;
  if (std::filesystem::weakly_canonical(exe_mods, ec) !=
      std::filesystem::weakly_canonical(mods_root, ec)) {
    roots.push_back(exe_mods);
  }

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
        REXLOG_WARN("'{}' has an unreadable mod.toml: {}", mod.folder_name, err.what());
      }
    }
    mod.icon = LoadIcon(immediate_drawer_, dir / "icon.png");
    mods_.push_back(std::move(mod));
  };

  for (const auto& name : enabled) {
    for (const auto& dir : folders) {
      if (rex::ModNamesEqual(dir.filename().string(), name)) {
        build(dir, true);
        break;
      }
    }
  }
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
    REXLOG_WARN("No config path known, mod changes are session only");
  } else {
    rex::cvar::SaveConfig(config);
  }
  order_dirty_ = true;
}

size_t ModsMenuDialog::EnabledCount() const {
  size_t count = 0;
  for (const auto& mod : mods_) {
    if (!mod.enabled) break;
    ++count;
  }
  return count;
}

bool ModsMenuDialog::DrawRow(const ModEntry& mod, bool enabled_column, size_t index,
                             PendingAction& pending) {
  const ImGuiStyle& style = ImGui::GetStyle();
  const float row_h = RowHeight();
  const ImVec2 origin = ImGui::GetCursorPos();
  const ImVec2 screen = ImGui::GetCursorScreenPos();
  const float avail = ImGui::GetContentRegionAvail().x;
  const ImVec2 row_max(screen.x + avail, screen.y + row_h);
  const bool hovered = ImGui::IsWindowHovered(ImGuiHoveredFlags_AllowWhenBlockedByActiveItem) && ImGui::IsMouseHoveringRect(screen, row_max);
  if (hovered) {
    ImGui::GetWindowDrawList()->AddRectFilled(screen, row_max, IM_COL32(255, 255, 255, 20), 3.0f);
  }

  ImGui::SetCursorPos(ImVec2(origin.x + kRowPad, origin.y + (row_h - kIconSize) * 0.5f));
  if (mod.icon) {
    ImGui::Image(reinterpret_cast<ImTextureID>(mod.icon.get()), ImVec2(kIconSize, kIconSize));
  } else {
    const ImVec2 box = ImGui::GetCursorScreenPos();
    ImGui::GetWindowDrawList()->AddRectFilled(box, ImVec2(box.x + kIconSize, box.y + kIconSize), IM_COL32(38, 42, 50, 255), 3.0f);
    ImGui::Dummy(ImVec2(kIconSize, kIconSize));
  }

  const float text_x = origin.x + kRowPad + kIconSize + kRowPad;
  const float text_w = std::max(40.0f, avail - (text_x - origin.x) - kButtonZone);
  ImGui::SetCursorPos(ImVec2(text_x, origin.y + kRowPad));
  ImGui::TextUnformatted(ClipToWidth(mod.name, text_w).c_str());

  std::string meta;
  if (!mod.version.empty()) meta = "v" + mod.version;
  if (!mod.author.empty()) meta += (meta.empty() ? "" : " ") + std::string("by ") + mod.author;
  if (!mod.description.empty()) meta += (meta.empty() ? "" : " \xC2\xB7 ") + mod.description;
  if (meta.empty()) meta = mod.folder_name;
  ImGui::SetCursorPos(ImVec2(text_x, origin.y + kRowPad + ImGui::GetTextLineHeightWithSpacing()));
  ImGui::TextDisabled("%s", ClipToWidth(meta, text_w).c_str());

  bool swap_column = false;
  if (hovered) {
    const float button_w = ImGui::GetFrameHeight();
    const int buttons = enabled_column ? 3 : 1;
    const float cluster_w = buttons * button_w + (buttons - 1) * style.ItemSpacing.x;
    ImGui::SetCursorPos(ImVec2(origin.x + avail - cluster_w - kRowPad, origin.y + (row_h - button_w) * 0.5f));

    if (enabled_column) {
      if (ImGui::ArrowButton("##disable", ImGuiDir_Left)) swap_column = true;
      ImGui::SameLine();
      ImGui::BeginDisabled(index == 0);
      if (ImGui::ArrowButton("##up", ImGuiDir_Up)) {
        pending.kind = PendingAction::Kind::kMoveUp;
        pending.index = index;
      }
      ImGui::EndDisabled();
      ImGui::SameLine();
      ImGui::BeginDisabled(index + 1 >= EnabledCount());
      if (ImGui::ArrowButton("##down", ImGuiDir_Down)) {
        pending.kind = PendingAction::Kind::kMoveDown;
        pending.index = index;
      }
      ImGui::EndDisabled();
    } else if (ImGui::ArrowButton("##enable", ImGuiDir_Right)) {
      swap_column = true;
    }
  }

  ImGui::SetCursorPos(origin);
  ImGui::Dummy(ImVec2(avail, row_h));
  return swap_column;
}

void ModsMenuDialog::DrawColumn(const char* id, bool enabled_column, float width, float height,
                                PendingAction& pending) {
  ImGui::BeginChild(id, ImVec2(width, height), ImGuiChildFlags_Borders);

  size_t shown = 0;
  for (size_t i = 0; i < mods_.size(); ++i) {
    if (mods_[i].enabled != enabled_column) continue;
    ++shown;
    ImGui::PushID(static_cast<int>(i));
    if (DrawRow(mods_[i], enabled_column, i, pending)) {
      pending.kind =
          enabled_column ? PendingAction::Kind::kDisable : PendingAction::Kind::kEnable;
      pending.index = i;
    }
    ImGui::PopID();
  }

  if (shown == 0) {
    ImGui::Spacing();
    ImGui::TextDisabled(enabled_column ? "  No mods enabled." : "  Nothing available.");
  }

  ImGui::EndChild();
}

void ModsMenuDialog::OnDraw(ImGuiIO& io) {
  if (!scanned_) Rescan();

  const ImGuiStyle& style = ImGui::GetStyle();
  ImGui::SetNextWindowPos(ImVec2(io.DisplaySize.x * 0.5f, io.DisplaySize.y * 0.5f),
                          ImGuiCond_FirstUseEver, ImVec2(0.5f, 0.5f));
  ImGui::SetNextWindowSize(ImVec2(940.0f, 560.0f), ImGuiCond_FirstUseEver);
  ImGui::SetNextWindowSizeConstraints(ImVec2(640.0f, 360.0f), ImVec2(FLT_MAX, FLT_MAX));

  if (ImGui::Begin("Mods##mods_menu_overlay", nullptr, ImGuiWindowFlags_NoCollapse)) {
    if (order_dirty_) {
      ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.8f, 0.35f, 1.0f));
      ImGui::TextUnformatted("Restart the game to apply mod changes.");
      ImGui::SameLine();
      ImGui::PopStyleColor();
      if (ImGui::Button("Restart Now")) {
        if (rex::RelaunchProcess()) {
          REXLOG_INFO("Relaunching to apply mod changes.");
          rex::FlushLogging();
          std::_Exit(0);
        }
        REXLOG_ERROR("Could not relaunch, restart manually to apply mod changes.");
      }
    } else {
      ImGui::NewLine();
    }
    ImGui::Separator();

    // Reserve the footer, then split the remainder into two equal columns.
    const float footer_h = ImGui::GetFrameHeightWithSpacing() + style.ItemSpacing.y;
    const float body_h = ImGui::GetContentRegionAvail().y - footer_h;
    const float column_w = (ImGui::GetContentRegionAvail().x - style.ItemSpacing.x) * 0.5f;

    PendingAction pending;

    const float list_h = body_h - ImGui::GetTextLineHeightWithSpacing();

    ImGui::BeginGroup();
    ImGui::TextUnformatted("Available");
    DrawColumn("##available", false, column_w, list_h, pending);
    ImGui::EndGroup();

    ImGui::SameLine();

    ImGui::BeginGroup();
    ImGui::TextUnformatted("Enabled");
    DrawColumn("##enabled", true, column_w, list_h, pending);
    ImGui::EndGroup();

    // --- footer -----------------------------------------------------------
    if (ImGui::Button("Open Mods Folder")) {
      const auto root = rex::GetModsRoot();
      std::error_code ec;
      // Nothing opens if the folder was never created, so make it on demand.
      std::filesystem::create_directories(root, ec);
      rex::LaunchFileExplorer(root);
    }
    ImGui::SameLine();
    ImGui::BeginDisabled(true);
    ImGui::Button("Browse Mods");
    ImGui::EndDisabled();

    const char* kOptionsLabel = "Mod Options";
    const float options_w =
        ImGui::CalcTextSize(kOptionsLabel).x + style.FramePadding.x * 2.0f;
    ImGui::SameLine();
    ImGui::SetCursorPosX(ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x - options_w);
    ImGui::BeginDisabled(true);
    ImGui::Button(kOptionsLabel);
    ImGui::EndDisabled();

    // --- apply the frame's single mutation --------------------------------
    const size_t enabled_count = EnabledCount();
    switch (pending.kind) {
      case PendingAction::Kind::kEnable:
        // Newly enabled mods join the end of the load order (lowest priority).
        mods_[pending.index].enabled = true;
        std::rotate(mods_.begin() + static_cast<ptrdiff_t>(enabled_count),
                    mods_.begin() + static_cast<ptrdiff_t>(pending.index),
                    mods_.begin() + static_cast<ptrdiff_t>(pending.index) + 1);
        ApplyOrder();
        break;
      case PendingAction::Kind::kDisable:
        // Drops out of the prefix and lands at the head of the disabled block.
        mods_[pending.index].enabled = false;
        std::rotate(mods_.begin() + static_cast<ptrdiff_t>(pending.index),
                    mods_.begin() + static_cast<ptrdiff_t>(pending.index) + 1,
                    mods_.begin() + static_cast<ptrdiff_t>(enabled_count));
        ApplyOrder();
        break;
      case PendingAction::Kind::kMoveUp:
        if (pending.index > 0) {
          std::swap(mods_[pending.index], mods_[pending.index - 1]);
          ApplyOrder();
        }
        break;
      case PendingAction::Kind::kMoveDown:
        if (pending.index + 1 < enabled_count) {
          std::swap(mods_[pending.index], mods_[pending.index + 1]);
          ApplyOrder();
        }
        break;
      case PendingAction::Kind::kNone:
        break;
    }
  }
  ImGui::End();
}

}  // namespace rex::ui
