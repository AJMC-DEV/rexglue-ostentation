#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include <rex/cvar.h>

REXCVAR_DECLARE(std::string, mods_data_root);
REXCVAR_DECLARE(std::string, enabled_mods);
REXCVAR_DECLARE(std::string, default_mods);

namespace rex {

std::vector<std::string> ParseModList(const std::string& list);

std::string FormatModList(const std::vector<std::string>& names);

bool ModNamesEqual(std::string_view a, std::string_view b);

std::filesystem::path GetModsRoot();

std::vector<std::filesystem::path> GetEnabledModDirs(const std::filesystem::path& mods_root);

}
