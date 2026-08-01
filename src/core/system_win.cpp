/**
 * @file        core/system_win.cpp
 * @brief       Windows implementations of rex/system.h platform helpers.
 *
 * @copyright   Copyright (c) 2026 Tom Clay
 * @license     BSD 3-Clause License
 */

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
// ShellExecuteW, for the browser/explorer launchers.
#include <shellapi.h>

#include <filesystem>
#include <system_error>

#include <rex/string.h>
#include <rex/system.h>

namespace rex {

void ShowSimpleMessageBox(SimpleMessageBoxType type, std::string_view message) {
  UINT flags = MB_OK | MB_TOPMOST | MB_SETFOREGROUND;
  const wchar_t* title = L"ReXGlue";
  switch (type) {
    case SimpleMessageBoxType::Help:
      flags |= MB_ICONINFORMATION;
      break;
    case SimpleMessageBoxType::Warning:
      flags |= MB_ICONWARNING;
      break;
    case SimpleMessageBoxType::Error:
      flags |= MB_ICONERROR;
      break;
  }
  auto wide = rex::string::to_utf16(message);
  ::MessageBoxW(nullptr, reinterpret_cast<const wchar_t*>(wide.c_str()), title, flags);
}

void LaunchWebBrowser(const std::string_view url) {
  auto wide = rex::string::to_utf16(url);
  ::ShellExecuteW(nullptr, L"open", reinterpret_cast<const wchar_t*>(wide.c_str()), nullptr, nullptr,
                  SW_SHOWNORMAL);
}

bool RelaunchProcess() {
  // GetCommandLineW already includes argv[0], so this reproduces the launch
  // verbatim. CreateProcessW may write to the buffer, hence the mutable copy.
  const wchar_t* command_line = ::GetCommandLineW();
  if (!command_line || !*command_line) return false;
  std::wstring copy(command_line);

  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION process{};
  // A null working directory inherits ours, which relative config paths rely on.
  if (!::CreateProcessW(nullptr, copy.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr,
                        &startup, &process)) {
    return false;
  }
  ::CloseHandle(process.hThread);
  ::CloseHandle(process.hProcess);
  return true;
}

void LaunchFileExplorer(const std::filesystem::path& path) {
  // Callers routinely pass relative paths (mods_data_root defaults to "./mods/"),
  // which ShellExecute resolves against the process CWD unreliably and often just
  // fails on. Normalise to a clean absolute path first.
  std::error_code ec;
  std::filesystem::path target = std::filesystem::weakly_canonical(path, ec);
  if (ec || target.empty()) {
    ec.clear();
    target = std::filesystem::absolute(path, ec);
  }
  if (ec || target.empty()) target = path;

  // "open" on a directory hands it to Explorer; native_type is already wchar_t
  // on Windows so no conversion is needed.
  ::ShellExecuteW(nullptr, L"open", target.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}

}  // namespace rex
