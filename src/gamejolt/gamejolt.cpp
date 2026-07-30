#include <rex/gamejolt.h>

#include <rex/crypto/md5.h>
#include <rex/cvar.h>
#include <rex/filesystem.h>
#include <rex/logging.h>
#include <rex/platform.h>
#include <rex/system/achievement_manager.h>
#include <rex/system/kernel_state.h>

#include "thirdparty/crypto/TinySHA1.hpp"

#include <toml++/toml.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <fstream>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

REXCVAR_DEFINE_BOOL(gamejolt_enabled, true, "Thirdparty",
                    "Enable the Game Jolt API client (trophies, play sessions)");
REXCVAR_DEFINE_STRING(gamejolt_username, "", "Thirdparty", "Game Jolt username");
REXCVAR_DEFINE_STRING(gamejolt_user_token, "", "Thirdparty",
                      "Game Jolt user token (from the Game Jolt profile page, not the password)");
REXCVAR_DEFINE_BOOL(gamejolt_trophies, true, "Thirdparty",
                    "Award Game Jolt trophies when achievements unlock");
REXCVAR_DEFINE_BOOL(gamejolt_trophy_pull, true, "Thirdparty",
                    "Unlock local achievements for trophies already achieved on Game Jolt");
REXCVAR_DEFINE_BOOL(gamejolt_trophy_match_by_name, true, "Thirdparty",
                    "Map achievements to trophies by matching the achievement label against the "
                    "trophy title when no explicit mapping exists");
REXCVAR_DEFINE_BOOL(gamejolt_sessions, true, "Thirdparty",
                    "Keep a Game Jolt play session open while the game runs");
REXCVAR_DEFINE_INT32(gamejolt_timeout_ms, 8000, "Thirdparty", "Game Jolt request timeout")
    .range(500, 60000);
REXCVAR_DEFINE_STRING(gamejolt_signature, "md5", "Thirdparty",
                      "Hash used to sign Game Jolt requests")
    .allowed({"md5", "sha1"});
REXCVAR_DEFINE_BOOL(gamejolt_log_requests, false, "Thirdparty",
                    "Log every Game Jolt request and response");

// Windows is currently the only platform with an HTTPS backend available here
// (WinHTTP). Everything else compiles to a no-op client.
#if REX_PLATFORM_WIN32
#define REX_GAMEJOLT_HAVE_HTTP 1
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <winhttp.h>
#else
#define REX_GAMEJOLT_HAVE_HTTP 0
#endif

namespace rex::gamejolt {

namespace {

constexpr const char* kApiBase = "https://api.gamejolt.com/api/game/v1_2";

// Game Jolt drops a session after 120s without a ping; stay well inside that.
constexpr auto kSessionPingInterval = std::chrono::seconds(30);
// Retry cadence for requests that failed in transport (offline, DNS, timeout).
constexpr auto kRetryInterval = std::chrono::seconds(30);
constexpr auto kAuthRetryInterval = std::chrono::seconds(60);
// How often to notice that the title registered more achievements.
constexpr auto kCatalogPollInterval = std::chrono::seconds(5);

using Params = std::vector<std::pair<std::string, std::string>>;

struct TrophyInfo {
  uint32_t id = 0;
  std::string title;
  bool achieved = false;
};

enum class CommandKind {
  kAuth,
  kSignOut,
  kAward,
  kRemove,
  kSync,
};

struct Command {
  CommandKind kind = CommandKind::kSync;
  uint32_t trophy_id = 0;
};

// --- shared state ----------------------------------------------------------
// g_mutex guards every non-atomic global below. The worker thread copies what
// it needs into locals and releases the lock before issuing requests.

std::mutex g_mutex;
std::condition_variable g_cv;
std::deque<Command> g_queue;
std::atomic<bool> g_running{false};
std::thread g_thread;

std::string g_game_id;
std::string g_private_key;
std::string g_username;
std::string g_user_token;
std::string g_last_error;
std::atomic<SignInState> g_state{SignInState::kSignedOut};
std::atomic<bool> g_session_active{true};

// achievement id -> trophy id, from MapTrophy() / LoadTrophyMap().
std::unordered_map<uint32_t, uint32_t> g_trophy_map;
// Trophy catalog fetched on sign-in; drives name matching and reconciliation.
std::vector<TrophyInfo> g_trophies;
// Achievements we have already complained about, so the log stays readable.
std::unordered_set<uint32_t> g_unmapped_warned;

// --- worker-thread-only state ----------------------------------------------

bool g_attached = false;
system::AchievementListenerHandle g_listener = 0;
bool g_session_open = false;
std::vector<Command> g_retry;
// Set when a sync could not reach the network, so the retry timer picks it up
// instead of the command loop spinning on it every tick.
bool g_sync_pending = false;
// Guards the pull direction: unlocking a local achievement fires the bridge
// callback, which would otherwise re-award the trophy we just read as achieved.
std::atomic<bool> g_pulling{false};
// The catalog is empty until the title loads its XDBF achievements, and hooks
// may register more later. Re-sync whenever it grows, otherwise a sync that ran
// before the title was up would be the only one we ever attempt.
size_t g_catalog_size = 0;

void Enqueue(Command cmd) {
  {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_queue.push_back(cmd);
  }
  g_cv.notify_one();
}

void SetError(std::string message) {
  std::lock_guard<std::mutex> lock(g_mutex);
  g_last_error = std::move(message);
}

// ---------------------------------------------------------------------------
// URL building and request signing
// ---------------------------------------------------------------------------

std::string UrlEncode(std::string_view in) {
  static constexpr char kHex[] = "0123456789ABCDEF";
  std::string out;
  out.reserve(in.size());
  for (unsigned char c : in) {
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' ||
        c == '_' || c == '.' || c == '~') {
      out += static_cast<char>(c);
    } else {
      out += '%';
      out += kHex[c >> 4];
      out += kHex[c & 0x0F];
    }
  }
  return out;
}

std::string Sha1Hex(const std::string& data) {
  sha1::SHA1 sha;
  sha.processBytes(data.data(), data.size());
  sha1::SHA1::digest32_t digest;
  sha.finalize(digest);
  char buf[41] = {};
  for (int i = 0; i < 5; ++i) {
    std::snprintf(buf + i * 8, 9, "%08x", digest[i]);
  }
  return std::string(buf, 40);
}

// Game Jolt authenticates a request by hashing the full URL concatenated with
// the game's private key; the digest travels back as the `signature` parameter.
std::string SignUrl(const std::string& url, const std::string& private_key) {
  const std::string payload = url + private_key;
  if (REXCVAR_GET(gamejolt_signature) == "sha1") {
    return Sha1Hex(payload);
  }
  return crypto::md5(payload);
}

std::string BuildSignedUrl(std::string_view endpoint, const Params& params,
                           const std::string& game_id, const std::string& private_key) {
  std::string url = kApiBase;
  url += endpoint;
  url += "?game_id=";
  url += UrlEncode(game_id);
  url += "&format=json";
  for (const auto& [key, value] : params) {
    url += '&';
    url += key;
    url += '=';
    url += UrlEncode(value);
  }
  // The signature covers the URL as built so far, and is then appended to it.
  const std::string signature = SignUrl(url, private_key);
  url += "&signature=";
  url += signature;
  return url;
}

// ---------------------------------------------------------------------------
// Minimal JSON readers
//
// Game Jolt responses are shallow — a success flag, a message, and at most one
// array of flat objects — so a full parser would be more machinery than the
// payloads justify.
// ---------------------------------------------------------------------------

// Returns the raw value that follows "key": — string contents with the quotes
// stripped, or the literal text for numbers/booleans/null. Empty if absent.
std::string JsonValue(std::string_view json, std::string_view key) {
  std::string needle = "\"";
  needle += key;
  needle += "\"";
  size_t pos = json.find(needle);
  if (pos == std::string_view::npos) {
    return {};
  }
  pos += needle.size();
  while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) {
    ++pos;
  }
  if (pos >= json.size() || json[pos] != ':') {
    return {};
  }
  ++pos;
  while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) {
    ++pos;
  }
  if (pos >= json.size()) {
    return {};
  }

  std::string out;
  if (json[pos] == '"') {
    ++pos;
    while (pos < json.size() && json[pos] != '"') {
      if (json[pos] == '\\' && pos + 1 < json.size()) {
        ++pos;
        switch (json[pos]) {
          case 'n': out += '\n'; break;
          case 'r': out += '\r'; break;
          case 't': out += '\t'; break;
          default: out += json[pos]; break;
        }
      } else {
        out += json[pos];
      }
      ++pos;
    }
  } else {
    while (pos < json.size() && json[pos] != ',' && json[pos] != '}' && json[pos] != ']' &&
           json[pos] != ' ' && json[pos] != '\n' && json[pos] != '\r') {
      out += json[pos];
      ++pos;
    }
  }
  return out;
}

// Splits the array at "key" into its top-level `{...}` elements.
std::vector<std::string> JsonObjectArray(std::string_view json, std::string_view key) {
  std::vector<std::string> out;
  std::string needle = "\"";
  needle += key;
  needle += "\"";
  size_t pos = json.find(needle);
  if (pos == std::string_view::npos) {
    return out;
  }
  pos = json.find('[', pos + needle.size());
  if (pos == std::string_view::npos) {
    return out;
  }
  ++pos;

  int depth = 0;
  size_t start = 0;
  bool in_string = false;
  for (; pos < json.size(); ++pos) {
    const char c = json[pos];
    if (in_string) {
      if (c == '\\') {
        ++pos;
      } else if (c == '"') {
        in_string = false;
      }
      continue;
    }
    if (c == '"') {
      in_string = true;
    } else if (c == '{') {
      if (depth == 0) {
        start = pos;
      }
      ++depth;
    } else if (c == '}') {
      if (--depth == 0) {
        out.emplace_back(json.substr(start, pos - start + 1));
      }
    } else if (c == ']' && depth == 0) {
      break;
    }
  }
  return out;
}

uint32_t ParseU32(const std::string& text) {
  uint32_t value = 0;
  for (char c : text) {
    if (c < '0' || c > '9') {
      return 0;
    }
    value = value * 10 + static_cast<uint32_t>(c - '0');
  }
  return value;
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

struct Response {
  bool transport = false;  // the request itself completed
  bool ok = false;         // ... and the API reported success
  std::string body;
  std::string message;  // Game Jolt's error text, when it supplied one
};

#if REX_GAMEJOLT_HAVE_HTTP

// api.gamejolt.com is the only host we talk to, so one session handle is reused
// for the lifetime of the worker thread.
class HttpSession {
 public:
  HttpSession() {
    session_ = ::WinHttpOpen(L"ReXGlue/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                             WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  }
  ~HttpSession() {
    if (session_) {
      ::WinHttpCloseHandle(session_);
    }
  }

  bool Get(const std::string& url, std::string& out, int timeout_ms) {
    if (!session_) {
      return false;
    }
    // Split "https://host/path?query" — the scheme and host are fixed by
    // kApiBase, so only the path needs extracting.
    constexpr std::string_view kScheme = "https://";
    if (url.compare(0, kScheme.size(), kScheme) != 0) {
      return false;
    }
    const size_t host_start = kScheme.size();
    const size_t path_start = url.find('/', host_start);
    if (path_start == std::string::npos) {
      return false;
    }
    const std::string host = url.substr(host_start, path_start - host_start);
    const std::string path = url.substr(path_start);

    const std::wstring whost(host.begin(), host.end());
    const std::wstring wpath(path.begin(), path.end());

    HINTERNET conn = ::WinHttpConnect(session_, whost.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!conn) {
      return false;
    }
    HINTERNET request =
        ::WinHttpOpenRequest(conn, L"GET", wpath.c_str(), nullptr, WINHTTP_NO_REFERER,
                             WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!request) {
      ::WinHttpCloseHandle(conn);
      return false;
    }
    ::WinHttpSetTimeouts(request, timeout_ms, timeout_ms, timeout_ms, timeout_ms);

    bool ok = ::WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                   WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
              ::WinHttpReceiveResponse(request, nullptr);
    if (ok) {
      DWORD avail = 0;
      while (::WinHttpQueryDataAvailable(request, &avail) && avail > 0) {
        std::string chunk(avail, '\0');
        DWORD read = 0;
        if (!::WinHttpReadData(request, chunk.data(), avail, &read)) {
          break;
        }
        out.append(chunk.data(), read);
      }
    }

    ::WinHttpCloseHandle(request);
    ::WinHttpCloseHandle(conn);
    return ok;
  }

 private:
  HINTERNET session_ = nullptr;
};

HttpSession& Http() {
  static HttpSession session;
  return session;
}

#endif  // REX_GAMEJOLT_HAVE_HTTP

Response Request(std::string_view endpoint, const Params& params) {
  Response response;

  std::string game_id;
  std::string private_key;
  {
    std::lock_guard<std::mutex> lock(g_mutex);
    game_id = g_game_id;
    private_key = g_private_key;
  }
  if (game_id.empty()) {
    response.message = "no game id configured";
    return response;
  }

  const std::string url = BuildSignedUrl(endpoint, params, game_id, private_key);
  const bool log = REXCVAR_GET(gamejolt_log_requests);
  if (log) {
    REXLOG_INFO("GameJolt: GET {}", url);
  }

#if REX_GAMEJOLT_HAVE_HTTP
  response.transport = Http().Get(url, response.body, REXCVAR_GET(gamejolt_timeout_ms));
#else
  response.message = "no HTTPS backend on this platform";
  return response;
#endif

  if (log) {
    REXLOG_INFO("GameJolt: -> transport={} body={}", response.transport, response.body);
  }
  if (!response.transport) {
    response.message = "request failed (offline?)";
    return response;
  }

  response.ok = JsonValue(response.body, "success") == "true";
  if (!response.ok) {
    response.message = JsonValue(response.body, "message");
    if (response.message.empty()) {
      response.message = "request rejected by Game Jolt";
    }
  }
  return response;
}

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

// The Game Jolt desktop client writes `.gj-credentials` next to the executable
// when it launches a game: a version line ("1.0" / "0.1") followed by the
// username and the user token.
bool ReadCredentialsFile(const std::filesystem::path& path, std::string& username,
                         std::string& token) {
  std::ifstream file(path);
  if (!file) {
    return false;
  }
  std::vector<std::string> lines;
  std::string line;
  while (lines.size() < 4 && std::getline(file, line)) {
    while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) {
      line.pop_back();
    }
    lines.push_back(line);
  }
  // Tolerate both the versioned layout and a bare username/token pair.
  size_t index = 0;
  if (!lines.empty() && !lines[0].empty() && lines[0].find('.') != std::string::npos &&
      lines[0][0] >= '0' && lines[0][0] <= '9') {
    index = 1;
  }
  if (lines.size() < index + 2) {
    return false;
  }
  username = lines[index];
  token = lines[index + 1];
  return !username.empty() && !token.empty();
}

bool ResolveCredentials(std::string& username, std::string& token) {
  username = REXCVAR_GET(gamejolt_username);
  token = REXCVAR_GET(gamejolt_user_token);
  if (!username.empty() && !token.empty()) {
    return true;
  }

  const std::filesystem::path candidates[] = {
      filesystem::GetExecutableFolder() / ".gj-credentials",
      std::filesystem::current_path() / ".gj-credentials",
  };
  for (const auto& candidate : candidates) {
    std::error_code ec;
    if (!std::filesystem::exists(candidate, ec)) {
      continue;
    }
    if (ReadCredentialsFile(candidate, username, token)) {
      REXLOG_INFO("GameJolt: using credentials from {}", candidate.string());
      return true;
    }
  }
  return false;
}

void PersistCredentials(const std::string& username, const std::string& token) {
  REXCVAR_SET(gamejolt_username, username);
  REXCVAR_SET(gamejolt_user_token, token);
  const auto& config = cvar::GetConfigPath();
  if (config.empty()) {
    REXLOG_WARN("GameJolt: no config path known, sign-in is session-only");
    return;
  }
  cvar::SaveConfig(config);
}

// ---------------------------------------------------------------------------
// Trophy <-> achievement mapping
// ---------------------------------------------------------------------------

// Comparison key for name matching: lowercase, ASCII alphanumerics only, so
// punctuation and spacing differences between the XDBF label and the trophy
// title do not defeat the match. Non-ASCII bytes are dropped, so titles that
// agree on their accents still match ("Piñata!" vs "piñata") but ones that
// differ do not ("Piñata" vs "Pinata") — spell the trophy title the way the
// achievement does, or add an explicit [[trophies]] mapping.
std::string NormalizeTitle(std::string_view title) {
  std::string out;
  out.reserve(title.size());
  for (unsigned char c : title) {
    if (c >= 'A' && c <= 'Z') {
      out += static_cast<char>(c - 'A' + 'a');
    } else if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
      out += static_cast<char>(c);
    }
  }
  return out;
}

system::AchievementManager* Achievements() {
  auto* kernel = system::kernel_state();
  return kernel ? &kernel->achievements() : nullptr;
}

// Returns the Game Jolt trophy ID for an achievement, or 0 when unmapped. The
// label comes from the caller (both the unlock event and ListAchievements()
// carry it) so this never has to reach back into the manager.
uint32_t ResolveTrophy(uint32_t achievement_id, std::string_view label) {
  std::lock_guard<std::mutex> lock(g_mutex);
  auto it = g_trophy_map.find(achievement_id);
  if (it != g_trophy_map.end()) {
    return it->second;
  }
  if (!REXCVAR_GET(gamejolt_trophy_match_by_name)) {
    return 0;
  }
  const std::string wanted = NormalizeTitle(label);
  if (wanted.empty()) {
    return 0;
  }
  for (const auto& trophy : g_trophies) {
    if (NormalizeTitle(trophy.title) == wanted) {
      return trophy.id;
    }
  }
  return 0;
}

void WarnUnmapped(uint32_t achievement_id) {
  {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_unmapped_warned.insert(achievement_id).second) {
      return;
    }
  }
  REXLOG_WARN(
      "GameJolt: achievement {} has no matching trophy — add a [[trophies]] entry or rename the "
      "trophy to match the achievement label",
      achievement_id);
}

// ---------------------------------------------------------------------------
// API calls (worker thread only)
// ---------------------------------------------------------------------------

Params UserParams() {
  std::lock_guard<std::mutex> lock(g_mutex);
  return {{"username", g_username}, {"user_token", g_user_token}};
}

bool FetchTrophies(std::vector<TrophyInfo>& out, Response& response) {
  response = Request("/trophies/", UserParams());
  if (!response.ok) {
    return false;
  }
  for (const auto& object : JsonObjectArray(response.body, "trophies")) {
    TrophyInfo trophy;
    trophy.id = ParseU32(JsonValue(object, "id"));
    trophy.title = JsonValue(object, "title");
    // `achieved` is JSON false when locked, or a "3 hours ago" style string.
    const std::string achieved = JsonValue(object, "achieved");
    trophy.achieved = !achieved.empty() && achieved != "false";
    if (trophy.id) {
      out.push_back(std::move(trophy));
    }
  }
  return true;
}

// Reconciles both directions: local unlocks are pushed up as trophies, and
// trophies already achieved on Game Jolt unlock the local achievement so
// progress follows the player between machines.
void Reconcile() {
  if (g_state.load() != SignInState::kSignedIn || !REXCVAR_GET(gamejolt_trophies)) {
    return;
  }

  std::vector<TrophyInfo> trophies;
  Response response;
  if (!FetchTrophies(trophies, response)) {
    REXLOG_WARN("GameJolt: could not fetch trophies: {}", response.message);
    // A rejection will not fix itself, but a transport failure might.
    g_sync_pending = !response.transport;
    return;
  }
  g_sync_pending = false;
  {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_trophies = trophies;
  }

  auto* manager = Achievements();
  if (!manager) {
    return;
  }

  const bool pull = REXCVAR_GET(gamejolt_trophy_pull);
  size_t pushed = 0;
  size_t pulled = 0;
  for (const auto& achievement : manager->ListAchievements()) {
    const uint32_t trophy_id = ResolveTrophy(achievement.id, achievement.label);
    if (!trophy_id) {
      continue;
    }
    auto trophy = std::find_if(trophies.begin(), trophies.end(),
                               [&](const TrophyInfo& t) { return t.id == trophy_id; });
    if (trophy == trophies.end()) {
      continue;
    }

    const bool unlocked_locally = manager->IsUnlocked(achievement.id);
    if (unlocked_locally && !trophy->achieved) {
      Enqueue({CommandKind::kAward, trophy_id});
      ++pushed;
    } else if (!unlocked_locally && trophy->achieved && pull) {
      // Suppress the toast: these were earned in an earlier session, so
      // replaying the notifications on startup would be noise.
      g_pulling = true;
      manager->UnlockAchievement(achievement.id, system::AchievementNotification::kSuppress);
      g_pulling = false;
      ++pulled;
    }
  }
  if (pushed || pulled) {
    REXLOG_INFO("GameJolt: trophy sync — {} to award, {} restored locally", pushed, pulled);
  }
}

void OpenSession() {
  if (g_session_open || !REXCVAR_GET(gamejolt_sessions) ||
      g_state.load() != SignInState::kSignedIn) {
    return;
  }
  const Response response = Request("/sessions/open/", UserParams());
  if (response.ok) {
    g_session_open = true;
  } else {
    REXLOG_WARN("GameJolt: could not open play session: {}", response.message);
  }
}

void PingSession() {
  if (!REXCVAR_GET(gamejolt_sessions) || g_state.load() != SignInState::kSignedIn) {
    return;
  }
  if (!g_session_open) {
    OpenSession();
    return;
  }
  Params params = UserParams();
  params.emplace_back("status", g_session_active.load() ? "active" : "idle");
  const Response response = Request("/sessions/ping/", params);
  if (!response.ok) {
    // A dropped session must be reopened; pinging a closed one keeps failing.
    g_session_open = false;
  }
}

void CloseSession() {
  if (!g_session_open) {
    return;
  }
  Request("/sessions/close/", UserParams());
  g_session_open = false;
}

void Authenticate() {
  std::string username;
  std::string token;
  if (!ResolveCredentials(username, token)) {
    g_state = SignInState::kSignedOut;
    SetError("no Game Jolt credentials — set gamejolt_username and gamejolt_user_token");
    return;
  }

  {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_username = username;
    g_user_token = token;
  }
  g_state = SignInState::kPending;

  const Response response = Request("/users/auth/", {{"username", username}, {"user_token", token}});
  if (!response.ok) {
    g_state = response.transport ? SignInState::kFailed : SignInState::kSignedOut;
    SetError(response.message);
    REXLOG_WARN("GameJolt: sign-in failed for '{}': {}", username, response.message);
    return;
  }

  g_state = SignInState::kSignedIn;
  SetError({});
  REXLOG_INFO("GameJolt: signed in as '{}'", username);
  OpenSession();
  Reconcile();
}

void SendTrophy(const Command& cmd) {
  if (g_state.load() != SignInState::kSignedIn) {
    // Nothing to do: the reconciliation pass on the next successful sign-in
    // replays anything the local unlock state says is still owed.
    return;
  }
  const char* endpoint =
      cmd.kind == CommandKind::kAward ? "/trophies/add-achieved/" : "/trophies/remove-achieved/";
  Params params = UserParams();
  params.emplace_back("trophy_id", std::to_string(cmd.trophy_id));

  const Response response = Request(endpoint, params);
  if (response.ok) {
    if (cmd.kind == CommandKind::kAward) {
      REXLOG_INFO("GameJolt: awarded trophy {}", cmd.trophy_id);
    }
    std::lock_guard<std::mutex> lock(g_mutex);
    for (auto& trophy : g_trophies) {
      if (trophy.id == cmd.trophy_id) {
        trophy.achieved = cmd.kind == CommandKind::kAward;
      }
    }
    return;
  }

  if (!response.transport) {
    g_retry.push_back(cmd);
    REXLOG_WARN("GameJolt: trophy {} deferred: {}", cmd.trophy_id, response.message);
  } else {
    // "already achieved" lands here too, which is fine — the end state matches.
    REXLOG_WARN("GameJolt: trophy {} rejected: {}", cmd.trophy_id, response.message);
  }
}

// ---------------------------------------------------------------------------
// Achievement bridge
// ---------------------------------------------------------------------------

void TryAttachAchievements() {
  if (g_attached) {
    return;
  }
  auto* manager = Achievements();
  if (!manager) {
    return;  // the kernel is not up yet; the worker retries
  }
  g_listener = manager->RegisterUnlockCallback([](const system::AchievementEvent& event) {
    if (!REXCVAR_GET(gamejolt_trophies) || g_pulling.load()) {
      return;
    }
    const uint32_t trophy_id = ResolveTrophy(event.achievement.id, event.achievement.label);
    if (!trophy_id) {
      WarnUnmapped(event.achievement.id);
      return;
    }
    Enqueue({CommandKind::kAward, trophy_id});
  });
  g_attached = true;
  REXLOG_INFO("GameJolt: achievement bridge attached");
}

// Enqueues a sync when the achievement catalog grows. The kernel comes up
// before the title loads its XDBF achievements, so the sign-in reconciliation
// usually runs against an empty catalog; without this the pull direction would
// never get a chance to restore trophies earned on another machine.
void PollCatalog() {
  auto* manager = Achievements();
  if (!manager) {
    return;
  }
  const size_t size = manager->ListAchievements().size();
  if (size <= g_catalog_size) {
    return;
  }
  g_catalog_size = size;
  Enqueue({CommandKind::kSync, 0});
}

void DetachAchievements() {
  if (!g_attached) {
    return;
  }
  if (auto* manager = Achievements()) {
    manager->UnregisterCallback(g_listener);
  }
  g_listener = 0;
  g_attached = false;
}

// ---------------------------------------------------------------------------
// Worker thread
// ---------------------------------------------------------------------------

void WorkerThread() {
  using clock = std::chrono::steady_clock;
  auto next_ping = clock::now();
  auto next_retry = clock::now() + kRetryInterval;
  auto next_auth_retry = clock::time_point::max();
  auto next_catalog_poll = clock::now();

  while (g_running.load()) {
    std::deque<Command> batch;
    {
      std::unique_lock<std::mutex> lock(g_mutex);
      g_cv.wait_for(lock, std::chrono::milliseconds(250),
                    [] { return !g_queue.empty() || !g_running.load(); });
      batch.swap(g_queue);
    }
    if (!g_running.load()) {
      break;
    }

    const bool enabled = REXCVAR_GET(gamejolt_enabled);

    for (const auto& cmd : batch) {
      if (!enabled) {
        break;
      }
      switch (cmd.kind) {
        case CommandKind::kAuth:
          Authenticate();
          next_auth_retry = g_state.load() == SignInState::kSignedIn
                                ? clock::time_point::max()
                                : clock::now() + kAuthRetryInterval;
          break;
        case CommandKind::kSignOut:
          CloseSession();
          g_state = SignInState::kSignedOut;
          next_auth_retry = clock::time_point::max();
          break;
        case CommandKind::kAward:
        case CommandKind::kRemove:
          SendTrophy(cmd);
          break;
        case CommandKind::kSync:
          Reconcile();
          break;
      }
    }

    if (!enabled) {
      CloseSession();
      continue;
    }

    TryAttachAchievements();

    const auto now = clock::now();

    if (now >= next_catalog_poll) {
      next_catalog_poll = now + kCatalogPollInterval;
      PollCatalog();
    }

    // Only a transport failure sets next_auth_retry; a rejected token is not
    // retried until SignIn() supplies new credentials.
    if (now >= next_auth_retry && g_state.load() != SignInState::kSignedIn) {
      next_auth_retry = clock::time_point::max();
      Enqueue({CommandKind::kAuth, 0});
    }

    if (now >= next_ping) {
      next_ping = now + kSessionPingInterval;
      PingSession();
    }

    if (now >= next_retry) {
      next_retry = now + kRetryInterval;
      if (g_state.load() == SignInState::kSignedIn) {
        if (!g_retry.empty()) {
          std::vector<Command> pending;
          pending.swap(g_retry);
          for (const auto& cmd : pending) {
            SendTrophy(cmd);
          }
        }
        if (g_sync_pending) {
          Reconcile();
        }
      }
    }
  }

  CloseSession();
  DetachAchievements();
}

// Game Jolt expires a session roughly 120s after the last ping, so an abrupt
// exit is recoverable — but joining the worker here keeps it out of CRT
// teardown, and closes the session immediately in the normal case.
struct AtExitInstaller {
  AtExitInstaller() {
    std::atexit([] { Stop(); });
  }
} g_atexit_installer;

}  // namespace

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

void Start(const char* game_id, const char* private_key) {
  if (!game_id || *game_id == '\0' || !private_key || *private_key == '\0') {
    REXLOG_WARN("GameJolt: Start() needs both a game id and a private key — skipping");
    return;
  }
#if !REX_GAMEJOLT_HAVE_HTTP
  (void)game_id;
  (void)private_key;
  REXLOG_WARN("GameJolt: no HTTPS backend on this platform — client disabled");
  return;
#else
  if (!REXCVAR_GET(gamejolt_enabled)) {
    REXLOG_INFO("GameJolt: disabled by gamejolt_enabled");
    return;
  }
  {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_game_id = game_id;
    g_private_key = private_key;
  }
  if (g_running.exchange(true)) {
    Enqueue({CommandKind::kAuth, 0});  // credentials may have changed
    return;
  }
  g_thread = std::thread(WorkerThread);
  Enqueue({CommandKind::kAuth, 0});
#endif
}

void Stop() {
  if (!g_running.exchange(false)) {
    return;
  }
  g_cv.notify_all();
  if (g_thread.joinable()) {
    g_thread.join();
  }
  g_state = SignInState::kSignedOut;
}

bool IsStarted() {
  return g_running.load();
}

void SignIn(const std::string& username, const std::string& user_token) {
  if (username.empty() || user_token.empty()) {
    SetError("username and user token are both required");
    return;
  }
  PersistCredentials(username, user_token);
  {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_username = username;
    g_user_token = user_token;
  }
  g_state = SignInState::kPending;
  Enqueue({CommandKind::kAuth, 0});
}

void SignOut() {
  Enqueue({CommandKind::kSignOut, 0});
}

SignInState GetSignInState() {
  return g_state.load();
}

std::string GetUsername() {
  std::lock_guard<std::mutex> lock(g_mutex);
  return g_username;
}

std::string GetLastError() {
  std::lock_guard<std::mutex> lock(g_mutex);
  return g_last_error;
}

void MapTrophy(uint32_t achievement_id, uint32_t trophy_id) {
  std::lock_guard<std::mutex> lock(g_mutex);
  g_trophy_map[achievement_id] = trophy_id;
  g_unmapped_warned.erase(achievement_id);
}

bool LoadTrophyMap(const std::filesystem::path& path) {
  try {
    auto table = toml::parse_file(path.string());
    const auto* entries = table["trophies"].as_array();
    if (!entries) {
      REXLOG_WARN("GameJolt: no [[trophies]] entries in {}", path.string());
      return false;
    }
    size_t loaded = 0;
    for (const auto& node : *entries) {
      const auto* entry = node.as_table();
      if (!entry) {
        continue;
      }
      const auto achievement_id =
          static_cast<uint32_t>((*entry)["achievement_id"].value_or<int64_t>(0));
      const auto trophy_id = static_cast<uint32_t>((*entry)["trophy_id"].value_or<int64_t>(0));
      if (!achievement_id || !trophy_id) {
        REXLOG_WARN("GameJolt: skipping [[trophies]] entry with a missing id in {}", path.string());
        continue;
      }
      MapTrophy(achievement_id, trophy_id);
      ++loaded;
    }
    REXLOG_INFO("GameJolt: loaded {} trophy mappings from {}", loaded, path.string());
    return loaded > 0;
  } catch (const toml::parse_error& error) {
    REXLOG_WARN("GameJolt: failed to parse {}: {}", path.string(), error.what());
    return false;
  }
}

void AwardTrophy(uint32_t trophy_id) {
  if (trophy_id) {
    Enqueue({CommandKind::kAward, trophy_id});
  }
}

void RemoveTrophy(uint32_t trophy_id) {
  if (trophy_id) {
    Enqueue({CommandKind::kRemove, trophy_id});
  }
}

void SyncTrophies() {
  Enqueue({CommandKind::kSync, 0});
}

void SetSessionActive(bool active) {
  g_session_active = active;
}

}  // namespace rex::gamejolt
