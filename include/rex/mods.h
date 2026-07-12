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
// "use the caller's default" (e.g. <root>/mods). The <exe>/mods folder is
// always searched as a fallback root even when this points elsewhere, so
// mods bundled next to the executable keep working when an external
// launcher redirects the root.
REXCVAR_DECLARE(std::string, mods_data_root);

// Comma-separated, ordered list of mod folder names to load from
// mods_data_root (e.g. "betterwater, bettersky"). A mod folder that exists
// under mods_data_root but is listed in neither this cvar nor default_mods
// is skipped entirely. Order defines priority: a mod earlier in the list
// wins over a later one when both provide a replacement for the same file.
REXCVAR_DECLARE(std::string, enabled_mods);

// Comma-separated, ordered list of mod folder names that are always loaded,
// whether or not they appear in enabled_mods. Intended for mods bundled
// with the game. They load after (at lower priority than) every
// enabled_mods entry, so user-enabled mods override bundled defaults; a
// name in both lists keeps its enabled_mods position.
REXCVAR_DECLARE(std::string, default_mods);

namespace rex {

// Returns the active mod root directories (mods_root/<name>/), in priority
// order: every enabled_mods entry first, then default_mods entries not
// already listed. Each name resolves against mods_root first, then against
// the always-searched <exe>/mods fallback root. Callers look for subfolders
// inside each (e.g. "shaders", "textures") or metadata files (mod.toml,
// icon.png) directly inside the mod root.
std::vector<std::filesystem::path> GetEnabledModDirs(const std::filesystem::path& mods_root);

}  // namespace rex
