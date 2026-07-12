/**
 * @file        core/mods.cpp
 * @brief       Shared mod-folder configuration. See rex/mods.h.
 */
#include <rex/mods.h>

#include <cctype>
#include <string>
#include <string_view>
#include <system_error>

#include <rex/filesystem.h>

REXCVAR_DEFINE_STRING(mods_data_root, "", "MODS",
                      "Path to mods data directory. <exe>/mods is always "
                      "searched as a fallback in addition to this path.");
REXCVAR_DEFINE_STRING(enabled_mods, "", "MODS",
                      "Comma-separated, ordered list of mod folder names to load "
                      "from mods_data_root (e.g. \"betterwater, bettersky\"). Mod "
                      "folders listed neither here nor in default_mods are "
                      "ignored. Earlier entries take precedence over later ones "
                      "for conflicting files.");
REXCVAR_DEFINE_STRING(default_mods, "", "MODS",
                      "Comma-separated, ordered list of mod folder names that are "
                      "always loaded even when absent from enabled_mods (for mods "
                      "bundled with the game). Loaded after all enabled_mods "
                      "entries, so user-enabled mods win conflicts.");

namespace rex {

namespace {

// Case-insensitive comparison for mod folder names, matching the
// case-insensitive filesystems the folders live on.
bool NamesEqual(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) return false;
  for (size_t i = 0; i < a.size(); ++i) {
    if (std::tolower(static_cast<unsigned char>(a[i])) !=
        std::tolower(static_cast<unsigned char>(b[i]))) {
      return false;
    }
  }
  return true;
}

// Appends the trimmed, comma-separated entries of `list` to `names`,
// skipping entries already present.
void AppendNames(const std::string& list, std::vector<std::string>& names) {
  size_t start = 0;
  while (start <= list.size()) {
    const size_t comma = list.find(',', start);
    const size_t end   = (comma == std::string::npos) ? list.size() : comma;

    std::string_view name(list.data() + start, end - start);
    const size_t b = name.find_first_not_of(" \t");
    const size_t e = name.find_last_not_of(" \t");
    if (b != std::string_view::npos) {
      name = name.substr(b, e - b + 1);
      bool duplicate = false;
      for (const auto& existing : names) {
        if (NamesEqual(existing, name)) {
          duplicate = true;
          break;
        }
      }
      if (!duplicate) {
        names.emplace_back(name);
      }
    }

    if (comma == std::string::npos) break;
    start = comma + 1;
  }
}

}  // namespace

std::vector<std::filesystem::path> GetEnabledModDirs(const std::filesystem::path& mods_root) {
  // enabled_mods first (user order = priority), then any default_mods not
  // already listed — bundled defaults never outrank user-enabled mods.
  std::vector<std::string> names;
  AppendNames(REXCVAR_GET(enabled_mods), names);
  AppendNames(REXCVAR_GET(default_mods), names);

  // Each name resolves against the caller's root first, then against the
  // always-present <exe>/mods so bundled mods survive a redirected
  // mods_data_root.
  std::vector<std::filesystem::path> roots;
  roots.push_back(mods_root);
  const auto exe_mods = rex::filesystem::GetExecutableFolder() / "mods";
  std::error_code ec;
  if (std::filesystem::weakly_canonical(exe_mods, ec) !=
      std::filesystem::weakly_canonical(mods_root, ec)) {
    roots.push_back(exe_mods);
  }

  std::vector<std::filesystem::path> dirs;
  for (const auto& name : names) {
    for (const auto& root : roots) {
      auto dir = root / name;
      ec.clear();
      if (std::filesystem::is_directory(dir, ec)) {
        dirs.push_back(std::move(dir));
        break;
      }
    }
  }

  return dirs;
}

}  // namespace rex
