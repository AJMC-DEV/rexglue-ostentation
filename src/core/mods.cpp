#include <rex/mods.h>

#include <atomic>
#include <cctype>
#include <string>
#include <string_view>
#include <system_error>

#include <rex/filesystem.h>
#include <rex/graphics/mod_shader_params.h>

namespace rex {
namespace gpu {
static std::atomic<float> g_mod_params[kModShaderParamCount] = {};
void SetModShaderParam(uint32_t index, float value) {
  if (index < kModShaderParamCount) g_mod_params[index].store(value, std::memory_order_relaxed);
}
float GetModShaderParam(uint32_t index) {
  return index < kModShaderParamCount ? g_mod_params[index].load(std::memory_order_relaxed) : 0.0f;
}
}
}

REXCVAR_DEFINE_STRING(mods_data_root, "", "MODS",
                      "Path to mods data directory. <exe>/mods is always searched as a fallback.");
REXCVAR_DEFINE_STRING(enabled_mods, "", "MODS", "Comma-separated, ordered list of mod folder names to load ");
REXCVAR_DEFINE_STRING(default_mods, "", "MODS", "Comma-separated, ordered list of mod folder names that are always loaded even when absent from enabled_mods");

namespace rex {

namespace {

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
        if (ModNamesEqual(existing, name)) {
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

}

bool ModNamesEqual(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) return false;
  for (size_t i = 0; i < a.size(); ++i) {
    if (std::tolower(static_cast<unsigned char>(a[i])) !=
        std::tolower(static_cast<unsigned char>(b[i]))) {
      return false;
    }
  }
  return true;
}

std::vector<std::string> ParseModList(const std::string& list) {
  std::vector<std::string> names;
  AppendNames(list, names);
  return names;
}

std::string FormatModList(const std::vector<std::string>& names) {
  std::string out;
  for (const auto& name : names) {
    if (name.empty()) continue;
    if (!out.empty()) out += ", ";
    out += name;
  }
  return out;
}

std::filesystem::path GetModsRoot() {
  std::filesystem::path root = REXCVAR_GET(mods_data_root);
  if (root.empty()) root = rex::filesystem::GetExecutableFolder() / "mods";
  return root;
}

std::vector<std::filesystem::path> GetEnabledModDirs(const std::filesystem::path& mods_root) {
  std::vector<std::string> names;
  AppendNames(REXCVAR_GET(enabled_mods), names);
  AppendNames(REXCVAR_GET(default_mods), names);

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

}
