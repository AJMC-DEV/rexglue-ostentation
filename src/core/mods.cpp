/**
 * @file        core/mods.cpp
 * @brief       Shared mod-folder configuration. See rex/mods.h.
 */
#include <rex/mods.h>

#include <string>
#include <string_view>
#include <system_error>

REXCVAR_DEFINE_STRING(mods_data_root, "", "MODS", "Path to mods data directory");
REXCVAR_DEFINE_STRING(enabled_mods, "", "MODS",
                      "Comma-separated, ordered list of mod folder names to load "
                      "from mods_data_root (e.g. \"betterwater, bettersky\"). Mod "
                      "folders not listed here are ignored. Earlier entries take "
                      "precedence over later ones for conflicting files.");

namespace rex {

std::vector<std::filesystem::path> GetEnabledModDirs(const std::filesystem::path& mods_root) {
  std::vector<std::filesystem::path> dirs;

  const std::string enabled = REXCVAR_GET(enabled_mods);
  std::error_code ec;

  size_t start = 0;
  while (start <= enabled.size()) {
    const size_t comma = enabled.find(',', start);
    const size_t end   = (comma == std::string::npos) ? enabled.size() : comma;

    std::string_view name(enabled.data() + start, end - start);
    const size_t b = name.find_first_not_of(" \t");
    const size_t e = name.find_last_not_of(" \t");
    if (b != std::string_view::npos) {
      name = name.substr(b, e - b + 1);
      auto dir = mods_root / name;
      if (std::filesystem::is_directory(dir, ec)) {
        dirs.push_back(std::move(dir));
      }
    }

    if (comma == std::string::npos) break;
    start = comma + 1;
  }

  return dirs;
}

}  // namespace rex
