/**
 * @file        rex/mods.h
 *
 * @brief       Shared mod-folder configuration. Lives in rexcore (not the
 *              graphics module) because mods are not GPU-specific — a mod
 *              folder may carry shaders/, textures/, or purely metadata
 *              (mod.toml, icon.png) for display in the in-game mods menu.
 */
#pragma once

#include <filesystem>
#include <vector>

#include <rex/cvar.h>

// Path to the mods data directory (parent of per-mod folders). Empty means
// "use the caller's default" (e.g. <root>/mods).
REXCVAR_DECLARE(std::string, mods_data_root);

// Comma-separated, ordered list of mod folder names to load from
// mods_data_root (e.g. "betterwater, bettersky"). A mod folder that exists
// under mods_data_root but is not listed here is skipped entirely. Order
// defines priority: a mod earlier in the list wins over a later one when
// both provide a replacement for the same file.
REXCVAR_DECLARE(std::string, enabled_mods);

namespace rex {

// Returns the enabled mod root directories under mods_root
// (mods_root/<name>/), in the order given by the enabled_mods cvar.
// Callers look for subfolders inside each (e.g. "shaders", "textures") or
// metadata files (mod.toml, icon.png) directly inside the mod root.
std::vector<std::filesystem::path> GetEnabledModDirs(const std::filesystem::path& mods_root);

}  // namespace rex
