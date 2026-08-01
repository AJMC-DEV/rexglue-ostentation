/**
 * @file        core/system_posix.cpp
 * @brief       POSIX implementations of rex/system.h platform helpers.
 *
 * @copyright   Copyright (c) 2026 Tom Clay
 * @license     BSD 3-Clause License
 */

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <system_error>
#include <vector>

#include <sys/wait.h>
#include <unistd.h>

#include <rex/system.h>

namespace rex {

namespace {

// fork+exec rather than std::system, so a path containing spaces, quotes or
// shell metacharacters is passed through verbatim instead of being reparsed.
void OpenWithXdg(const std::string& target) {
  const pid_t pid = ::fork();
  if (pid == 0) {
    ::execlp("xdg-open", "xdg-open", target.c_str(), nullptr);
    ::_exit(127);  // exec failed; never return into the parent's runtime
  }
  if (pid > 0) {
    // xdg-open returns immediately after handing off, so reaping here is cheap
    // and avoids leaving a zombie behind.
    int status = 0;
    ::waitpid(pid, &status, 0);
  }
}

}  // namespace

// TODO(tomc): add linux support for showing a native message box
void ShowSimpleMessageBox(SimpleMessageBoxType type, std::string_view message) {
  const char* level = "INFO";
  switch (type) {
    case SimpleMessageBoxType::Help:
      level = "INFO";
      break;
    case SimpleMessageBoxType::Warning:
      level = "WARNING";
      break;
    case SimpleMessageBoxType::Error:
      level = "ERROR";
      break;
  }
  std::fprintf(stderr, "[%s] %.*s\n", level, static_cast<int>(message.size()), message.data());
  std::fflush(stderr);
}

void LaunchWebBrowser(const std::string_view url) {
  OpenWithXdg(std::string(url));
}

void LaunchFileExplorer(const std::filesystem::path& path) {
  // Normalise for the same reason as the Windows path: callers pass things like
  // "./mods/", and an absolute target is what a file manager wants.
  std::error_code ec;
  std::filesystem::path target = std::filesystem::weakly_canonical(path, ec);
  if (ec || target.empty()) target = path;
  OpenWithXdg(target.string());
}

bool RelaunchProcess() {
  // /proc/self/cmdline holds the original argv as NUL-separated strings, which
  // is the only place to recover them from arbitrary code.
  std::ifstream cmdline("/proc/self/cmdline", std::ios::binary);
  if (!cmdline) return false;
  std::string raw((std::istreambuf_iterator<char>(cmdline)), std::istreambuf_iterator<char>());
  if (raw.empty()) return false;

  std::vector<std::string> args;
  for (size_t start = 0; start < raw.size();) {
    const size_t end = raw.find('\0', start);
    const size_t stop = (end == std::string::npos) ? raw.size() : end;
    if (stop > start) args.emplace_back(raw, start, stop - start);
    if (end == std::string::npos) break;
    start = end + 1;
  }
  if (args.empty()) return false;

  std::vector<char*> argv;
  argv.reserve(args.size() + 1);
  for (auto& arg : args) argv.push_back(arg.data());
  argv.push_back(nullptr);

  const pid_t pid = ::fork();
  if (pid == 0) {
    // /proc/self/exe resolves the real binary even if argv[0] was mangled.
    ::execv("/proc/self/exe", argv.data());
    ::_exit(127);  // exec failed; never return into the parent's runtime
  }
  // Deliberately not reaped: the caller exits immediately, so the child is
  // reparented to init rather than left as our zombie.
  return pid > 0;
}

}  // namespace rex
