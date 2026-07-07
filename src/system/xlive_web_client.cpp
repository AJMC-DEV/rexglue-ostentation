/**
 * @file        system/xlive_web_client.cpp
 * @brief       HTTP REST client for the XLive web netplay API.
 *              Uses WinHTTP on Windows.
 *
 * @modified    2026 - ReXGlue NX1-style netplay port
 */

#include <rex/system/xlive_web_client.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <regex>
#include <sstream>

#include <rex/cvar.h>
#include <rex/logging.h>
#include <rex/platform.h>
#include <rex/system/kernel_state.h>

// Declared in xlive_flags.cpp
REXCVAR_DECLARE(bool,        xlive_web_enabled);
REXCVAR_DECLARE(std::string, xlive_web_api_address);
REXCVAR_DECLARE(int32_t,     xlive_web_timeout_ms);
REXCVAR_DECLARE(bool,        xlive_web_log_requests);
REXCVAR_DECLARE(bool,        xlive_web_probe_on_startup);
REXCVAR_DECLARE(bool,        xlive_web_delete_stale_on_startup);
REXCVAR_DECLARE(std::string, user_gamertag);
REXCVAR_DECLARE(std::string, user_xuid);
REXCVAR_DECLARE(int32_t,     systemlink_port_offset);

#if REX_PLATFORM_WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

namespace rex::system {

#define XLIVE_LOG(...) REXSYS_INFO("[XLive] " __VA_ARGS__)
#define XLIVE_ERR(...) REXSYS_WARN("[XLive] " __VA_ARGS__)

// ---------------------------------------------------------------------------
// Tiny JSON helpers
// ---------------------------------------------------------------------------

namespace json {

static std::string Unquote(const std::string& s) {
  if (s.size() >= 2 && s.front() == '"' && s.back() == '"')
    return s.substr(1, s.size() - 2);
  return s;
}

std::string GetString(const std::string& json, const std::string& key) {
  // Match "key" : "value"  or  "key":"value"
  std::string pattern = "\"" + key + "\"\\s*:\\s*\"([^\"]*)\"";
  try {
    std::regex re(pattern);
    std::smatch m;
    if (std::regex_search(json, m, re)) return m[1].str();
  } catch (...) {}
  return {};
}

uint64_t GetUInt64(const std::string& json, const std::string& key) {
  std::string pattern = "\"" + key + "\"\\s*:\\s*([0-9]+)";
  try {
    std::regex re(pattern);
    std::smatch m;
    if (std::regex_search(json, m, re))
      return std::stoull(m[1].str());
  } catch (...) {}
  // Also try hex string variant "key":"0xABCD..."
  std::string sv = GetString(json, key);
  if (!sv.empty()) {
    try { return std::stoull(sv, nullptr, 16); } catch (...) {}
  }
  return 0;
}

uint32_t GetUInt32(const std::string& json, const std::string& key) {
  return static_cast<uint32_t>(GetUInt64(json, key));
}

std::vector<std::string> GetArray(const std::string& j, const std::string& key) {
  std::vector<std::string> result;
  // Find "key":[ ... ]
  std::string search = "\"" + key + "\"";
  auto pos = j.find(search);
  if (pos == std::string::npos) return result;
  pos = j.find('[', pos + search.size());
  if (pos == std::string::npos) return result;

  int depth = 0;
  size_t obj_start = std::string::npos;
  for (size_t i = pos; i < j.size(); ++i) {
    if (j[i] == '{') {
      if (depth == 0) obj_start = i;
      ++depth;
    } else if (j[i] == '}') {
      --depth;
      if (depth == 0 && obj_start != std::string::npos) {
        result.push_back(j.substr(obj_start, i - obj_start + 1));
        obj_start = std::string::npos;
      }
    } else if (j[i] == ']' && depth == 0) {
      break;
    }
  }
  return result;
}

// Extract an array of quoted strings: "key":["a","b",...]. Handles the simple
// escapes (\" and \\) that base64 never actually produces but which keep this
// honest.
std::vector<std::string> GetStringArray(const std::string& j, const std::string& key) {
  std::vector<std::string> result;
  std::string search = "\"" + key + "\"";
  auto pos = j.find(search);
  if (pos == std::string::npos) return result;
  pos = j.find('[', pos + search.size());
  if (pos == std::string::npos) return result;

  for (size_t i = pos + 1; i < j.size(); ++i) {
    if (j[i] == ']') break;
    if (j[i] == '"') {
      std::string s;
      for (++i; i < j.size() && j[i] != '"'; ++i) {
        if (j[i] == '\\' && i + 1 < j.size()) ++i;
        s += j[i];
      }
      result.push_back(std::move(s));
    }
  }
  return result;
}

}  // namespace json

// ---------------------------------------------------------------------------
// Base64 decode (standard alphabet, ignores padding/whitespace)
// ---------------------------------------------------------------------------

static bool Base64Decode(const std::string& in, std::vector<uint8_t>& out) {
  auto val = [](char c) -> int {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
  };
  out.clear();
  int buffer = 0, bits = 0;
  for (char c : in) {
    if (c == '=' ) break;
    int v = val(c);
    if (v < 0) continue;  // skip whitespace/newlines
    buffer = (buffer << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<uint8_t>((buffer >> bits) & 0xFF));
    }
  }
  return true;
}

static std::string Base64Encode(const std::vector<uint8_t>& in) {
  static const char* tbl =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve((in.size() + 2) / 3 * 4);
  size_t i = 0;
  for (; i + 3 <= in.size(); i += 3) {
    uint32_t n = (in[i] << 16) | (in[i + 1] << 8) | in[i + 2];
    out += tbl[(n >> 18) & 0x3F];
    out += tbl[(n >> 12) & 0x3F];
    out += tbl[(n >> 6) & 0x3F];
    out += tbl[n & 0x3F];
  }
  if (i < in.size()) {
    uint32_t n = in[i] << 16;
    bool two = (i + 1 < in.size());
    if (two) n |= in[i + 1] << 8;
    out += tbl[(n >> 18) & 0x3F];
    out += tbl[(n >> 12) & 0x3F];
    out += two ? tbl[(n >> 6) & 0x3F] : '=';
    out += '=';
  }
  return out;
}

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

static std::string ToHex(const uint8_t* data, size_t len) {
  std::string out;
  out.reserve(len * 2);
  static const char hex[] = "0123456789abcdef";
  for (size_t i = 0; i < len; ++i) {
    out += hex[(data[i] >> 4) & 0xF];
    out += hex[data[i] & 0xF];
  }
  return out;
}

static bool FromHex(const std::string& hex, uint8_t* out, size_t max_len) {
  size_t len = std::min(hex.size() / 2, max_len);
  for (size_t i = 0; i < len; ++i) {
    unsigned int byte = 0;
    if (sscanf(hex.c_str() + i * 2, "%02x", &byte) != 1) return false;
    out[i] = static_cast<uint8_t>(byte);
  }
  return true;
}

static std::string MacFromXuid(uint64_t xuid) {
  uint8_t mac[6];
  for (int i = 0; i < 6; ++i)
    mac[i] = static_cast<uint8_t>(xuid >> (i * 8));
  return ToHex(mac, 6);
}

// ---------------------------------------------------------------------------
// URL decomposition
// ---------------------------------------------------------------------------

struct ParsedUrl {
  bool   https   = true;
  std::wstring host;
  uint16_t port  = 443;
  std::wstring path;
};

static ParsedUrl ParseUrl(const std::string& url) {
  ParsedUrl r;
  std::string s = url;
  if (s.rfind("http://", 0) == 0) {
    r.https = false;
    r.port  = 80;
    s = s.substr(7);
  } else if (s.rfind("https://", 0) == 0) {
    s = s.substr(8);
  }
  // Strip trailing slash from the base
  auto slash_pos = s.find('/');
  std::string host_part = (slash_pos == std::string::npos) ? s : s.substr(0, slash_pos);
  std::string path_part = (slash_pos == std::string::npos) ? "/" : s.substr(slash_pos);

  // Port in host_part?
  auto colon = host_part.rfind(':');
  if (colon != std::string::npos) {
    try { r.port = static_cast<uint16_t>(std::stoi(host_part.substr(colon + 1))); } catch (...) {}
    host_part = host_part.substr(0, colon);
  }

  r.host = std::wstring(host_part.begin(), host_part.end());
  r.path = std::wstring(path_part.begin(), path_part.end());
  return r;
}

// ---------------------------------------------------------------------------
// WinHTTP implementation (Windows only)
// ---------------------------------------------------------------------------

#if REX_PLATFORM_WIN32

class WinHttpSession {
 public:
  WinHttpSession() {
    hSession_ = WinHttpOpen(L"ReXGlue/1.0",
                            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                            WINHTTP_NO_PROXY_NAME,
                            WINHTTP_NO_PROXY_BYPASS, 0);
  }
  ~WinHttpSession() {
    if (hSession_) WinHttpCloseHandle(hSession_);
  }

  bool Request(const std::string& full_url,
               const std::wstring& method,
               const std::string& request_body,
               std::string& out_response,
               int timeout_ms) {
    ParsedUrl pu = ParseUrl(full_url);

    HINTERNET hConn = WinHttpConnect(hSession_, pu.host.c_str(), pu.port, 0);
    if (!hConn) return false;

    DWORD flags = pu.https ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hReq = WinHttpOpenRequest(hConn, method.c_str(), pu.path.c_str(),
                                        nullptr, WINHTTP_NO_REFERER,
                                        WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hReq) { WinHttpCloseHandle(hConn); return false; }

    // Set timeout
    WinHttpSetTimeouts(hReq, timeout_ms, timeout_ms, timeout_ms, timeout_ms);

    // Headers
    const wchar_t* headers = L"Content-Type: application/json\r\nAccept: application/json\r\n";
    DWORD hdrLen = static_cast<DWORD>(wcslen(headers));

    LPCVOID body_ptr = request_body.empty() ? nullptr : static_cast<LPCVOID>(request_body.c_str());
    DWORD   body_len = static_cast<DWORD>(request_body.size());

    BOOL ok = WinHttpSendRequest(hReq, headers, hdrLen,
                                 const_cast<LPVOID>(body_ptr), body_len, body_len, 0);
    if (!ok) { WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); return false; }

    ok = WinHttpReceiveResponse(hReq, nullptr);
    if (!ok) { WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); return false; }

    // Read response
    DWORD avail = 0;
    while (WinHttpQueryDataAvailable(hReq, &avail) && avail > 0) {
      std::string chunk(avail, '\0');
      DWORD read = 0;
      if (WinHttpReadData(hReq, chunk.data(), avail, &read))
        out_response.append(chunk.data(), read);
    }

    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConn);
    return true;
  }

 private:
  HINTERNET hSession_ = nullptr;
};

static WinHttpSession& GetWinHttp() {
  static WinHttpSession s;
  return s;
}

#endif  // REX_PLATFORM_WIN32

// ---------------------------------------------------------------------------
// XLiveWebClient
// ---------------------------------------------------------------------------

static XLiveWebClient g_web_client;
XLiveWebClient& XLiveWebClient::Get() { return g_web_client; }

std::string XLiveWebClient::BaseUrl() const {
  std::string base = REXCVAR_GET(xlive_web_api_address);
  if (!base.empty() && base.back() == '/') base.pop_back();
  return base;
}

std::string XLiveWebClient::SessionsPath(uint32_t title_id) const {
  char buf[64];
  snprintf(buf, sizeof(buf), "/title/%08X/sessions", title_id);
  return buf;
}

std::string XLiveWebClient::SessionPath(uint32_t title_id,
                                        const std::string& id) const {
  char buf[128];
  snprintf(buf, sizeof(buf), "/title/%08X/sessions/%s", title_id, id.c_str());
  return buf;
}

uint32_t XLiveWebClient::public_address_net() const {
#if REX_PLATFORM_WIN32
  return inet_addr(public_address_.c_str());
#else
  uint32_t addr = 0;
  inet_pton(AF_INET, public_address_.c_str(), &addr);
  return addr;
#endif
}

bool XLiveWebClient::HttpGet(const std::string& path, std::string& out) {
#if REX_PLATFORM_WIN32
  std::string url = BaseUrl() + path;
  if (REXCVAR_GET(xlive_web_log_requests)) XLIVE_LOG("GET {}", url);
  bool ok = GetWinHttp().Request(url, L"GET", {}, out, REXCVAR_GET(xlive_web_timeout_ms));
  if (REXCVAR_GET(xlive_web_log_requests)) XLIVE_LOG("GET {} -> {}", url, out);
  return ok;
#else
  (void)path; (void)out;
  return false;
#endif
}

bool XLiveWebClient::HttpPost(const std::string& path, const std::string& body,
                              std::string& out) {
#if REX_PLATFORM_WIN32
  std::string url = BaseUrl() + path;
  if (REXCVAR_GET(xlive_web_log_requests)) XLIVE_LOG("POST {} body={}", url, body);
  bool ok = GetWinHttp().Request(url, L"POST", body, out, REXCVAR_GET(xlive_web_timeout_ms));
  if (REXCVAR_GET(xlive_web_log_requests)) XLIVE_LOG("POST {} -> {}", url, out);
  return ok;
#else
  (void)path; (void)body; (void)out;
  return false;
#endif
}

bool XLiveWebClient::HttpDelete(const std::string& path, std::string& out) {
#if REX_PLATFORM_WIN32
  std::string url = BaseUrl() + path;
  if (REXCVAR_GET(xlive_web_log_requests)) XLIVE_LOG("DELETE {}", url);
  bool ok = GetWinHttp().Request(url, L"DELETE", {}, out, REXCVAR_GET(xlive_web_timeout_ms));
  if (REXCVAR_GET(xlive_web_log_requests)) XLIVE_LOG("DELETE {} -> {}", url, out);
  return ok;
#else
  (void)path; (void)out;
  return false;
#endif
}

bool XLiveWebClient::EnsureReady() {
  std::lock_guard<std::mutex> lk(mtx_);
  if (ready_)         return true;
  if (startup_tried_) return false;
  startup_tried_ = true;

  if (!REXCVAR_GET(xlive_web_enabled)) {
    XLIVE_LOG("XLive web disabled (xlive_web_enabled = false)");
    return false;
  }

  // 1. Whoami
  std::string body;
  if (!HttpGet("/whoami", body)) {
    XLIVE_ERR("GET /whoami failed");
    return false;
  }
  public_address_ = json::GetString(body, "address");
  if (public_address_.empty()) public_address_ = body;  // raw IP fallback
  // Strip quotes / whitespace
  while (!public_address_.empty() &&
         (public_address_.front() == '"' || public_address_.front() == ' '))
    public_address_ = public_address_.substr(1);
  while (!public_address_.empty() &&
         (public_address_.back() == '"' || public_address_.back() == ' ' ||
          public_address_.back() == '\n' || public_address_.back() == '\r'))
    public_address_.pop_back();

  XLIVE_LOG("XLive web /whoami -> {}", public_address_);

  if (!REXCVAR_GET(xlive_web_probe_on_startup)) {
    ready_ = true;
    return true;
  }

  // 2. Resolve identity from the signed-in profile (falling back to cvars).
  // The netplay backend keys players on the ONLINE (0x0009...) XUID; the MAC
  // stays derived from the offline XUID so it matches the XNADDR we hand to
  // the game in XNetGetTitleXnAddr.
  uint64_t offline_xuid = 0;
  uint64_t online_xuid = 0;
  std::string gamertag = REXCVAR_GET(user_gamertag);

  if (auto* ks = kernel_state()) {
    if (auto* profile = ks->user_profile()) {
      offline_xuid = profile->xuid();
      online_xuid = profile->GetOnlineXUID();
      gamertag = profile->name();
    }
  }

  if (!offline_xuid) {
    std::string xuid_str = REXCVAR_GET(user_xuid);
    if (xuid_str.empty()) {
      offline_xuid = 0xB13EBABEBABEBABE;  // default
    } else {
      try { offline_xuid = std::stoull(xuid_str, nullptr, 16); } catch (...) {}
    }
  }
  if (!online_xuid) {
    // Synthesize an online XUID like older builds did.
    online_xuid = 0x0009000000000000ULL | (offline_xuid & 0x0000FFFFFFFFFFFFULL);
  }
  if (gamertag.empty()) gamertag = "Player";

  registered_xuid_ = fmt::format("{:016X}", online_xuid);
  registered_mac_  = MacFromXuid(offline_xuid);

  // 3. Register player
  if (!RegisterPlayer(online_xuid, gamertag, registered_mac_)) {
    XLIVE_ERR("Failed to register player with web service");
    // Non-fatal – continue
  }

  // 4. Optionally delete stale sessions
  if (REXCVAR_GET(xlive_web_delete_stale_on_startup)) {
    std::string dummy;
    HttpDelete("/DeleteSessions/" + registered_mac_, dummy);
  }

  ready_ = true;
  return true;
}

bool XLiveWebClient::RegisterPlayer(uint64_t xuid, const std::string& gamertag,
                                    const std::string& machine_id) {
  // machineId on the netplay backend is 0xFA00000000000000 | mac, formatted
  // as 16 lowercase hex chars (see netplay GetMachineId/PlayerObjectJSON).
  uint64_t mac_u64 = 0;
  try { mac_u64 = std::stoull(machine_id, nullptr, 16); } catch (...) {}
  const std::string netplay_machine_id =
      fmt::format("{:016x}", 0xFA00000000000000ULL | mac_u64);

  std::string payload = fmt::format(
      R"({{"xuid":"{}","gamertag":"{}","machineId":"{}","hostAddress":"{}","macAddress":"{}","settings":{{}}}})",
      fmt::format("{:016X}", xuid), gamertag, netplay_machine_id,
      public_address_, machine_id);

  std::string resp;
  bool ok = HttpPost("/players", payload, resp);
  // The backend returns 201 with the player object on success; a 500 or an
  // error body means we are NOT registered even if the HTTP call "worked".
  if (ok && resp.find("Internal server error") != std::string::npos) {
    XLIVE_ERR("XLive web /players registration failed: {}", resp);
    ok = false;
  }
  if (ok) {
    registered_ok_ = true;
    XLIVE_LOG("XLive web /players registered {} ({})", gamertag,
              fmt::format("{:016X}", xuid));
  }
  return ok;
}

bool XLiveWebClient::CreateSession(uint32_t title_id, const WebSession& info,
                                   std::string& out_session_id) {
  std::string session_id_hex = info.xnkid_hex;
  if (session_id_hex.size() != 16) session_id_hex = std::string(16, '0');
  // HOST(1) | PRESENCE(2) | PEER_NETWORK(32) = 35 = 0x23
  // PRESENCE makes isAdvertised=true on the server so search returns it.

  const auto* user_profile = REX_KERNEL_STATE()->profile_manager()->GetProfile(static_cast<uint8_t>(0));
  if (!user_profile) {
    REXKRNL_ERROR("XamUserGetSigninInfo: X_E_NO_SUCH_USER (user_index {} not signed in)", (uint32_t)0);
    return X_E_NO_SUCH_USER;
  }
  
  const int kSessionFlags = 35;
  std::string payload = fmt::format(
      R"({{"xuid":"{}","sessionId":"{}","xnkid":"{}","xnkey":"{}","flags":{},"publicSlotsCount":{},"privateSlotsCount":{},"hostAddress":"{}","macAddress":"{}","port":{},"mediaId":"{}","version":"{}"}})",
      user_profile->GetOnlineXUID() ? fmt::format("{:016X}", user_profile->GetOnlineXUID()) : registered_xuid_,
      session_id_hex,
      info.xnkid_hex,
      info.xnkey_hex,
      kSessionFlags,
      info.slots_public ? info.slots_public : 4,
      info.slots_private,
      info.host_address.empty() ? public_address_ : info.host_address,
      info.mac_address.empty() ? registered_mac_ : info.mac_address,
      info.port,
      info.media_id,
      info.version);

  std::string resp;
  bool ok = HttpPost(SessionsPath(title_id), payload, resp);

  // HttpPost only tells us the request completed; the backend still rejects
  // with a JSON error body (e.g. 403 "Player not found") if the session's host
  // xuid isn't a registered player. Treat that as a real failure so callers
  // don't cache an empty/invalid session id.
  if (ok && (resp.find("\"error\"") != std::string::npos ||
             resp.find("statusCode") != std::string::npos)) {
    XLIVE_ERR("CreateSession rejected by backend: {}", resp);
    ok = false;
  }

  if (ok) {
    out_session_id = json::GetString(resp, "id");
    if (out_session_id.empty()) out_session_id = json::GetString(resp, "sessionId");
    XLIVE_LOG("CreateSession -> id={}", out_session_id);
  } else {
    XLIVE_ERR("CreateSession failed: payload={} resp={}", payload, resp);
  }
  return ok;
}

bool XLiveWebClient::SearchSessions(uint32_t title_id,
                                    std::vector<WebSession>& out) {
  // Server requires searchIndex, resultsCount, numUsers, searcher_xuid
  std::string payload = fmt::format(
      R"({{"searchIndex":0,"resultsCount":20,"numUsers":1,"searcher_xuid":"{}"}})",
      registered_xuid_.empty() ? "0000000000000000" : registered_xuid_);

  std::string resp;
  bool ok = HttpPost(SessionsPath(title_id) + "/search", payload, resp);
  if (!ok) return false;

  auto arr = json::GetArray(resp, "sessions");
  if (arr.empty()) arr = json::GetArray(resp, "results");
  // Flat array fallback: the top-level JSON is itself an array
  if (arr.empty()) arr = json::GetArray("{\"s\":" + resp + "}", "s");

  for (auto& obj : arr) {
    WebSession ws;
    if (ParseWebSession(obj, ws)) out.push_back(std::move(ws));
  }
  return true;
}

bool XLiveWebClient::FetchSession(uint32_t title_id, const std::string& id,
                                  WebSession& out) {
  std::string resp;
  bool ok = HttpGet(SessionPath(title_id, id), resp);
  if (!ok) return false;
  return ParseWebSession(resp, out);
}

bool XLiveWebClient::GetSessionProperties(uint32_t title_id,
                                          const std::string& session_id,
                                          std::vector<std::vector<uint8_t>>& out) {
  std::string resp;
  if (!HttpGet(SessionPath(title_id, session_id) + "/properties", resp)) {
    return false;
  }
  // Body: {"properties":["<base64>", ...]} — each blob is a serialized
  // xam::Property ([id LE u32][X_USER_DATA 16][ext bytes]).
  auto b64s = json::GetStringArray(resp, "properties");
  for (auto& b64 : b64s) {
    std::vector<uint8_t> bytes;
    if (Base64Decode(b64, bytes) && bytes.size() >= 4 + 16) {
      out.push_back(std::move(bytes));
    }
  }
  XLIVE_LOG("GetSessionProperties {} -> {} properties", session_id, out.size());
  return true;
}

bool XLiveWebClient::SetSessionProperties(
    uint32_t title_id, const std::string& session_id,
    const std::vector<std::vector<uint8_t>>& blobs) {
  std::string arr;
  for (size_t i = 0; i < blobs.size(); ++i) {
    if (i) arr += ",";
    arr += "\"" + Base64Encode(blobs[i]) + "\"";
  }
  std::string payload = "{\"properties\":[" + arr + "]}";
  std::string resp;
  bool ok = HttpPost(SessionPath(title_id, session_id) + "/properties", payload, resp);
  XLIVE_LOG("SetSessionProperties {} -> {} properties (ok={})", session_id,
            blobs.size(), ok);
  return ok;
}

bool XLiveWebClient::JoinSession(uint32_t title_id, const std::string& id,
                                 uint64_t xuid) {
  std::string payload = fmt::format(R"({{"xuid":"{}","gamertag":"{}"}})",
                                    fmt::format("{:016X}", xuid),
                                    REXCVAR_GET(user_gamertag));
  std::string resp;
  return HttpPost(SessionPath(title_id, id) + "/join", payload, resp);
}

bool XLiveWebClient::PrejoinSession(uint32_t title_id, const std::string& id,
                                    uint64_t xuid) {
  std::string payload = fmt::format(R"({{"xuid":"{}","gamertag":"{}"}})",
                                    fmt::format("{:016X}", xuid),
                                    REXCVAR_GET(user_gamertag));
  std::string resp;
  return HttpPost(SessionPath(title_id, id) + "/prejoin", payload, resp);
}

bool XLiveWebClient::LeaveSession(uint32_t title_id, const std::string& id,
                                  uint64_t xuid) {
  std::string payload = fmt::format(R"({{"xuid":"{}"}})",
                                    fmt::format("{:016X}", xuid));
  std::string resp;
  return HttpPost(SessionPath(title_id, id) + "/leave", payload, resp);
}

bool XLiveWebClient::DeleteSession(uint32_t title_id, const std::string& id) {
  std::string resp;
  return HttpDelete(SessionPath(title_id, id), resp);
}

bool XLiveWebClient::DeleteStaleSessions(bool by_mac, const std::string& mac) {
  std::string resp;
  if (by_mac && !mac.empty())
    return HttpDelete("/DeleteSessions/" + mac, resp);
  return HttpDelete("/DeleteSessions", resp);
}

bool XLiveWebClient::UploadQos(uint32_t title_id, const std::string& id,
                               const std::vector<uint8_t>& data) {
  std::string hex = ToHex(data.data(), data.size());
  std::string payload = fmt::format(R"({{"data":"{}"}})", hex);
  std::string resp;
  return HttpPost(SessionPath(title_id, id) + "/qos", payload, resp);
}

bool XLiveWebClient::DownloadQos(uint32_t title_id, const std::string& id,
                                 std::vector<uint8_t>& out) {
  std::string resp;
  if (!HttpGet(SessionPath(title_id, id) + "/qos", resp)) return false;
  std::string hex = json::GetString(resp, "data");
  if (hex.empty()) return false;
  out.resize(hex.size() / 2);
  return FromHex(hex, out.data(), out.size());
}

bool XLiveWebClient::FindPlayerByIp(const std::string& ip, WebSession& out) {
  std::string payload = fmt::format(R"({{"address":"{}"}})", ip);
  std::string resp;
  if (!HttpPost("/players/find", payload, resp)) return false;
  return ParseWebSession(resp, out);
}

bool XLiveWebClient::EnsureHostSession(uint32_t title_id, uint16_t port) {
  {
    std::lock_guard<std::mutex> lk(mtx_);
    if (auto_host_tried_) return !auto_host_session_id_.empty();
    if (!ready_) return false;
    auto_host_tried_ = true;  // prevent concurrent re-entry
  }
  // Create a stub session so the broadcast bridge on other instances can
  // discover this machine's port via the web API.  The XNKID/XNKEY are
  // all-zeros because the real session key is conveyed in the UDP packets
  // themselves — the web entry is only used for address/port discovery.
  WebSession stub{};
  stub.host_address = public_address_;
  stub.port         = port;
  stub.slots_public = 4;
  stub.xnkid_hex    = std::string(16, '0');
  stub.xnkey_hex    = std::string(32, '0');

  std::string id;
  bool ok = CreateSession(title_id, stub, id);
  {
    std::lock_guard<std::mutex> lk(mtx_);
    auto_host_session_id_ = id;
  }
  if (ok) XLIVE_LOG("EnsureHostSession: auto-registered stub session id={} port={}", id, port);
  else    XLIVE_ERR("EnsureHostSession: failed to register stub session");
  return ok;
}

bool XLiveWebClient::ParseWebSession(const std::string& obj, WebSession& out) {
  REXKRNL_INFO("ParseWebSession: obj={}", obj);

  out.session_id   = json::GetString(obj, "id");
  if (out.session_id.empty()) out.session_id = json::GetString(obj, "sessionId");
  out.host_address = json::GetString(obj, "hostAddress");
  if (out.host_address.empty()) out.host_address = json::GetString(obj, "address");
  out.port         = static_cast<uint16_t>(json::GetUInt32(obj, "port"));
  out.mac_address  = json::GetString(obj, "macAddress");
  out.xnkid_hex    = json::GetString(obj, "xnkid");
  if (out.xnkid_hex.empty()) out.xnkid_hex = json::GetString(obj, "xnkid_hex");
  if (out.xnkid_hex.empty()) {
    std::string session_id = out.session_id;
    if (session_id.size() == 16) {
      out.xnkid_hex = session_id;
      std::transform(out.xnkid_hex.begin(), out.xnkid_hex.end(), out.xnkid_hex.begin(), ::tolower);
    }
  }
  out.xnkey_hex    = json::GetString(obj, "xnkey");
  if (out.xnkey_hex.empty()) out.xnkey_hex = json::GetString(obj, "xnkey_hex");
  if (out.xnkey_hex.empty()) {
    out.xnkey_hex = std::string(32, '0');
  }
  out.slots_public = json::GetUInt32(obj, "publicSlotsCount");
  if (!out.slots_public) out.slots_public = json::GetUInt32(obj, "slotsPublic");
  if (!out.slots_public) out.slots_public = json::GetUInt32(obj, "slots_public");
  out.slots_private= json::GetUInt32(obj, "privateSlotsCount");
  if (!out.slots_private) out.slots_private = json::GetUInt32(obj, "slotsPrivate");
  out.open_public    = json::GetUInt32(obj, "openPublicSlotsCount");
  out.open_private   = json::GetUInt32(obj, "openPrivateSlotsCount");
  out.filled_public  = json::GetUInt32(obj, "filledPublicSlotsCount");
  out.filled_private = json::GetUInt32(obj, "filledPrivateSlotsCount");
  out.nonce        = json::GetUInt64(obj, "nonce");
  out.port_offset  = json::GetUInt32(obj, "portOffset");

  std::string xuid_str = json::GetString(obj, "xuid");
  if (!xuid_str.empty())
    try { out.host_xuid = std::stoull(xuid_str, nullptr, 16); } catch (...) {}

  REXKRNL_INFO("ParseWebSession: session_id={} host_address={} port={} mac_address={} xnkid_hex={} xnkey_hex={} slots_public={} slots_private={} nonce={:016X} port_offset={}", out.session_id, out.host_address, out.port, out.mac_address, out.xnkid_hex, out.xnkey_hex, out.slots_public, out.slots_private, out.nonce, out.port_offset);
  return !out.host_address.empty();
}

}  // namespace rex::system
