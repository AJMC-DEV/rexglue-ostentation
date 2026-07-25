/**
 * @file        system/upnp.cpp
 * @brief       Automatic NAT traversal via UPnP IGD port forwarding.
 *
 *   Self-contained UPnP Internet Gateway Device client:
 *     1. SSDP discovery (UDP multicast to 239.255.255.250:1900) to find the
 *        router and the LOCATION of its device description.
 *     2. Fetch + parse the device description XML for the WANIPConnection /
 *        WANPPPConnection service control URL.
 *     3. SOAP AddPortMapping / DeletePortMapping (HTTP POST via WinHTTP).
 *
 *   No third-party dependency (miniupnpc etc.) — the netplay stack is already
 *   Windows/WinHTTP/Winsock based, so this matches it.
 *
 * @modified    2026 - ReXGlue netplay
 */

#include <rex/system/upnp.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <fmt/format.h>

#include <rex/cvar.h>
#include <rex/logging.h>
#include <rex/platform.h>
#include <rex/system/xlive_web_client.h>

// Declared in xlive_flags.cpp
REXCVAR_DECLARE(bool, upnp_enabled);
REXCVAR_DECLARE(int32_t, upnp_lease_seconds);

#if REX_PLATFORM_WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#endif

namespace rex::system {

#define UPNP_LOG(...) REXSYS_INFO("[UPnP] " __VA_ARGS__)
#define UPNP_WARN(...) REXSYS_WARN("[UPnP] " __VA_ARGS__)

#if REX_PLATFORM_WIN32

namespace {

constexpr char kSsdpMulticastAddr[] = "239.255.255.250";
constexpr uint16_t kSsdpPort = 1900;
constexpr char kMappingDescription[] = "ReXGlue Netplay";

// ---------------------------------------------------------------------------
// Small string / URL helpers
// ---------------------------------------------------------------------------

std::string ToLower(std::string s) {
  for (char& c : s) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
  return s;
}

// Case-insensitive extraction of a single HTTP header value (SSDP responses are
// HTTP/1.1 formatted). Returns the trimmed value or "" if absent.
std::string GetHttpHeader(const std::string& response, const std::string& name) {
  const std::string haystack = ToLower(response);
  const std::string needle = ToLower(name) + ":";
  size_t pos = haystack.find(needle);
  if (pos == std::string::npos) return {};
  pos += needle.size();
  size_t end = response.find_first_of("\r\n", pos);
  std::string value = response.substr(pos, end - pos);
  // Trim surrounding whitespace.
  size_t b = value.find_first_not_of(" \t");
  size_t e = value.find_last_not_of(" \t\r\n");
  if (b == std::string::npos) return {};
  return value.substr(b, e - b + 1);
}

// Extract the text between <tag> and </tag>, searching from `from`. Namespace
// prefixes are ignored by matching only the local tag name.
std::string GetXmlTag(const std::string& xml, const std::string& tag,
                      size_t from = 0) {
  const std::string open = "<" + tag + ">";
  const std::string close = "</" + tag + ">";
  size_t start = xml.find(open, from);
  if (start == std::string::npos) return {};
  start += open.size();
  size_t end = xml.find(close, start);
  if (end == std::string::npos) return {};
  return xml.substr(start, end - start);
}

struct ParsedUrl {
  std::string host;
  uint16_t port = 80;
  std::string path = "/";
  bool https = false;
};

ParsedUrl ParseUrl(const std::string& url) {
  ParsedUrl r;
  std::string rest = url;
  if (rest.compare(0, 8, "https://") == 0) {
    r.https = true;
    r.port = 443;
    rest = rest.substr(8);
  } else if (rest.compare(0, 7, "http://") == 0) {
    rest = rest.substr(7);
  }
  size_t slash = rest.find('/');
  std::string authority = rest.substr(0, slash);
  r.path = (slash == std::string::npos) ? "/" : rest.substr(slash);
  size_t colon = authority.find(':');
  if (colon == std::string::npos) {
    r.host = authority;
  } else {
    r.host = authority.substr(0, colon);
    r.port = static_cast<uint16_t>(std::atoi(authority.c_str() + colon + 1));
  }
  return r;
}

// The scheme://host:port origin of a URL, without the path.
std::string UrlOrigin(const std::string& url) {
  ParsedUrl p = ParseUrl(url);
  const char* scheme = p.https ? "https://" : "http://";
  return fmt::format("{}{}:{}", scheme, p.host, p.port);
}

// Resolve a (possibly relative) control URL against the device description's
// LOCATION origin and optional <URLBase>.
std::string ResolveControlUrl(const std::string& location,
                              const std::string& url_base,
                              const std::string& control_url) {
  if (control_url.compare(0, 7, "http://") == 0 ||
      control_url.compare(0, 8, "https://") == 0) {
    return control_url;
  }
  const std::string origin =
      !url_base.empty() ? UrlOrigin(url_base) : UrlOrigin(location);
  if (!control_url.empty() && control_url.front() == '/') {
    return origin + control_url;
  }
  return origin + "/" + control_url;
}

// ---------------------------------------------------------------------------
// WinHTTP request (arbitrary method/headers/body -> status + body)
// ---------------------------------------------------------------------------

bool HttpRequest(const std::string& url, const std::wstring& method,
                 const std::wstring& headers, const std::string& body,
                 int timeout_ms, DWORD& out_status, std::string& out_body) {
  out_status = 0;
  out_body.clear();
  ParsedUrl pu = ParseUrl(url);

  HINTERNET hSession = WinHttpOpen(L"ReXGlue-UPnP/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY,
                                   WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  if (!hSession) return false;

  const std::wstring whost(pu.host.begin(), pu.host.end());
  const std::wstring wpath(pu.path.begin(), pu.path.end());

  HINTERNET hConn = WinHttpConnect(hSession, whost.c_str(), pu.port, 0);
  if (!hConn) {
    WinHttpCloseHandle(hSession);
    return false;
  }

  DWORD flags = pu.https ? WINHTTP_FLAG_SECURE : 0;
  HINTERNET hReq = WinHttpOpenRequest(hConn, method.c_str(), wpath.c_str(), nullptr,
                                      WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                      flags);
  if (!hReq) {
    WinHttpCloseHandle(hConn);
    WinHttpCloseHandle(hSession);
    return false;
  }

  WinHttpSetTimeouts(hReq, timeout_ms, timeout_ms, timeout_ms, timeout_ms);

  const wchar_t* hdr = headers.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers.c_str();
  DWORD hdr_len = headers.empty() ? 0 : static_cast<DWORD>(headers.size());

  LPCVOID body_ptr = body.empty() ? nullptr : static_cast<LPCVOID>(body.data());
  DWORD body_len = static_cast<DWORD>(body.size());

  bool ok = WinHttpSendRequest(hReq, hdr, hdr_len, const_cast<LPVOID>(body_ptr),
                               body_len, body_len, 0) != FALSE;
  if (ok) ok = WinHttpReceiveResponse(hReq, nullptr) != FALSE;

  if (ok) {
    DWORD status = 0;
    DWORD status_size = sizeof(status);
    WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size,
                        WINHTTP_NO_HEADER_INDEX);
    out_status = status;

    DWORD avail = 0;
    while (WinHttpQueryDataAvailable(hReq, &avail) && avail > 0) {
      std::string chunk(avail, '\0');
      DWORD read = 0;
      if (WinHttpReadData(hReq, chunk.data(), avail, &read)) {
        out_body.append(chunk.data(), read);
      } else {
        break;
      }
    }
  }

  WinHttpCloseHandle(hReq);
  WinHttpCloseHandle(hConn);
  WinHttpCloseHandle(hSession);
  return ok;
}

// ---------------------------------------------------------------------------
// UPnP manager implementation
// ---------------------------------------------------------------------------

struct DesiredMapping {
  uint16_t port = 0;
  bool udp = true;
  // steady_clock time at which the router-side lease should be renewed. Zero
  // means "not mapped yet, add ASAP".
  std::chrono::steady_clock::time_point next_renew{};
};

class Impl {
 public:
  static Impl& Get() {
    static Impl instance;
    return instance;
  }

  void RequestMapping(uint16_t port, bool udp) {
    if (port == 0) return;
    if (!REXCVAR_GET(upnp_enabled)) return;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      for (const auto& m : desired_) {
        if (m.port == port && m.udp == udp) return;  // already tracked
      }
      desired_.push_back(DesiredMapping{port, udp, {}});
      UPNP_LOG("Queued {} port {} for forwarding", udp ? "UDP" : "TCP", port);
      EnsureWorkerLocked();
    }
    cv_.notify_all();
  }

  bool is_available() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return discovered_;
  }

  void Shutdown() {
    std::thread worker;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (!worker_running_) return;
      stop_ = true;
      worker = std::move(worker_);
      worker_running_ = false;
    }
    cv_.notify_all();
    if (worker.joinable()) worker.join();
  }

 private:
  Impl() = default;
  ~Impl() { Shutdown(); }

  void EnsureWorkerLocked() {
    if (worker_running_) return;
    stop_ = false;
    worker_running_ = true;
    worker_ = std::thread([this] { WorkerMain(); });
    // Delete our mappings even if the host forgets to call Shutdown().
    static std::once_flag atexit_once;
    std::call_once(atexit_once,
                   [] { std::atexit([] { Impl::Get().Shutdown(); }); });
  }

  // ------------------------------------------------------------------
  // Worker
  // ------------------------------------------------------------------
  void WorkerMain() {
    using namespace std::chrono;
    auto next_discovery_attempt = steady_clock::now();

    for (;;) {
      std::unique_lock<std::mutex> lock(mutex_);
      if (stop_) break;

      if (!discovered_) {
        if (steady_clock::now() >= next_discovery_attempt) {
          lock.unlock();
          const bool ok = Discover();
          lock.lock();
          if (stop_) break;
          if (!ok) {
            // Routers that don't answer SSDP won't start answering soon; back
            // off so we're not spamming multicast every loop.
            next_discovery_attempt = steady_clock::now() + seconds(30);
          }
        }
        if (!discovered_) {
          cv_.wait_until(lock, next_discovery_attempt,
                         [this] { return stop_.load(); });
          continue;
        }
      }

      // Apply / renew mappings that are due.
      const auto now = steady_clock::now();
      std::vector<DesiredMapping> due;
      for (auto& m : desired_) {
        if (m.next_renew.time_since_epoch().count() == 0 || now >= m.next_renew) {
          due.push_back(m);
        }
      }

      const int lease = LeaseSeconds();
      const std::string internal_ip = internal_ip_;
      const std::string control_url = control_url_;
      const std::string service_type = service_type_;
      lock.unlock();

      for (const auto& m : due) {
        const bool ok = AddPortMapping(control_url, service_type, internal_ip,
                                       m.port, m.udp, lease);
        std::lock_guard<std::mutex> relock(mutex_);
        for (auto& d : desired_) {
          if (d.port == m.port && d.udp == m.udp) {
            // Renew at half the lease; retry sooner if the add failed so a
            // transient router hiccup self-heals.
            d.next_renew =
                steady_clock::now() +
                (ok ? seconds(lease > 0 ? lease / 2 : 1800) : seconds(60));
          }
        }
      }

      lock.lock();
      if (stop_) break;
      // Wake for the soonest renewal, but at least every 5 minutes so newly
      // queued ports get picked up promptly.
      auto wake = now + minutes(5);
      for (const auto& m : desired_) {
        if (m.next_renew.time_since_epoch().count() != 0 && m.next_renew < wake) {
          wake = m.next_renew;
        }
      }
      cv_.wait_until(lock, wake, [this] { return stop_.load(); });
    }

    // Teardown: remove every mapping we created.
    DeleteAllMappings();
  }

  int LeaseSeconds() const {
    int lease = REXCVAR_GET(upnp_lease_seconds);
    if (lease < 0) lease = 0;
    return lease;
  }

  // ------------------------------------------------------------------
  // Discovery
  // ------------------------------------------------------------------
  bool Discover() {
    std::vector<std::string> locations = SsdpSearch();
    if (locations.empty()) {
      UPNP_WARN("No router answered SSDP discovery. Enable UPnP on the router, "
                "or (if a VPN/Hyper-V/WSL adapter is active) it may be "
                "intercepting multicast. Manual port forwarding of the netplay "
                "UDP port remains an alternative.");
      return false;
    }

    for (const std::string& location : locations) {
      DWORD status = 0;
      std::string xml;
      if (!HttpRequest(location, L"GET", L"", "", 3000, status, xml) ||
          status != 200 || xml.empty()) {
        continue;
      }

      const std::string url_base = GetXmlTag(xml, "URLBase");

      // Prefer WANIPConnection (Ethernet/cable), fall back to WANPPPConnection
      // (DSL). Match on the local service name so :1 / :2 both work.
      for (const char* wanted : {"WANIPConnection", "WANPPPConnection"}) {
        size_t svc = xml.find(wanted);
        if (svc == std::string::npos) continue;

        // Recover the full serviceType value enclosing this match.
        size_t type_open = xml.rfind("<serviceType>", svc);
        size_t type_close = xml.find("</serviceType>", svc);
        if (type_open == std::string::npos || type_close == std::string::npos) {
          continue;
        }
        type_open += std::strlen("<serviceType>");
        std::string service_type = xml.substr(type_open, type_close - type_open);

        std::string control = GetXmlTag(xml, "controlURL", svc);
        if (control.empty()) continue;

        const std::string full = ResolveControlUrl(location, url_base, control);
        const std::string internal_ip = DetectInternalIp(ParseUrl(location).host);
        if (internal_ip.empty()) {
          UPNP_WARN("Found IGD but could not determine our LAN address");
          continue;
        }

        {
          std::lock_guard<std::mutex> lock(mutex_);
          control_url_ = full;
          service_type_ = service_type;
          internal_ip_ = internal_ip;
          discovered_ = true;
        }
        UPNP_LOG("IGD found: service='{}' control='{}' internalClient={}",
                 service_type, full, internal_ip);
        return true;
      }
    }

    UPNP_WARN("IGD responded but exposes no WAN connection service");
    return false;
  }

  // Send M-SEARCH and collect unique LOCATION URLs from the replies.
  // Every "up", non-loopback IPv4 unicast address on this machine, in network
  // byte order. The router only answers a probe that actually egresses the LAN
  // adapter it sits on; letting Windows pick a default multicast interface
  // silently loses the probe to a Hyper-V/WSL/VMware/VPN virtual adapter, which
  // is the usual reason discovery "finds no router". So we probe from each.
  std::vector<uint32_t> EnumerateLocalIpv4() {
    std::vector<uint32_t> ips;
    ULONG size = 15000;
    std::vector<uint8_t> buffer(size);
    const ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                        GAA_FLAG_SKIP_DNS_SERVER;
    ULONG ret = GetAdaptersAddresses(
        AF_INET, flags, nullptr,
        reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &size);
    if (ret == ERROR_BUFFER_OVERFLOW) {
      buffer.resize(size);
      ret = GetAdaptersAddresses(
          AF_INET, flags, nullptr,
          reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &size);
    }
    if (ret != NO_ERROR) return ips;

    for (auto* a = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()); a;
         a = a->Next) {
      if (a->OperStatus != IfOperStatusUp) continue;
      if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
      for (auto* ua = a->FirstUnicastAddress; ua; ua = ua->Next) {
        auto* sa = reinterpret_cast<sockaddr_in*>(ua->Address.lpSockaddr);
        if (sa && sa->sin_family == AF_INET) {
          const uint32_t ip = sa->sin_addr.s_addr;
          if (ip != 0 && ip != htonl(INADDR_LOOPBACK)) ips.push_back(ip);
        }
      }
    }
    return ips;
  }

  // Send M-SEARCH out one specific interface and collect LOCATION URLs from the
  // (unicast) replies. if_addr == INADDR_ANY uses the OS default interface.
  void QuerySsdpInterface(uint32_t if_addr, std::vector<std::string>& locations) {
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return;

    // Bind to the interface so replies return here and multicast egresses it.
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = if_addr;  // ANY when 0
    bind(s, reinterpret_cast<sockaddr*>(&local), sizeof(local));

    if (if_addr != INADDR_ANY) {
      // Pin multicast egress to this interface (in_addr, network byte order).
      setsockopt(s, IPPROTO_IP, IP_MULTICAST_IF,
                 reinterpret_cast<const char*>(&if_addr), sizeof(if_addr));
    }
    const DWORD ttl = 2;
    setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, reinterpret_cast<const char*>(&ttl),
               sizeof(ttl));
    const DWORD recv_timeout = 1200;  // ms
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&recv_timeout),
               sizeof(recv_timeout));

    sockaddr_in dest{};
    dest.sin_family = AF_INET;
    dest.sin_port = htons(kSsdpPort);
    inet_pton(AF_INET, kSsdpMulticastAddr, &dest.sin_addr);

    // Probe both the IGD device type and the WAN connection services directly;
    // some routers only answer the specific service search.
    const char* search_targets[] = {
        "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
        "urn:schemas-upnp-org:service:WANIPConnection:1",
        "urn:schemas-upnp-org:service:WANPPPConnection:1",
        "ssdp:all",
    };
    for (const char* st : search_targets) {
      const std::string msearch = fmt::format(
          "M-SEARCH * HTTP/1.1\r\n"
          "HOST: {}:{}\r\n"
          "MAN: \"ssdp:discover\"\r\n"
          "MX: 2\r\n"
          "ST: {}\r\n"
          "\r\n",
          kSsdpMulticastAddr, kSsdpPort, st);
      // SSDP is UDP; send each target twice since the first is often dropped.
      for (int i = 0; i < 2; ++i) {
        sendto(s, msearch.data(), static_cast<int>(msearch.size()), 0,
               reinterpret_cast<sockaddr*>(&dest), sizeof(dest));
      }
    }

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    char buf[2048];
    while (std::chrono::steady_clock::now() < deadline) {
      sockaddr_in from{};
      int from_len = sizeof(from);
      int n = recvfrom(s, buf, sizeof(buf) - 1, 0, reinterpret_cast<sockaddr*>(&from),
                       &from_len);
      if (n <= 0) continue;  // timeout tick; keep draining until deadline
      buf[n] = '\0';
      std::string response(buf, n);
      std::string location = GetHttpHeader(response, "LOCATION");
      if (!location.empty() &&
          std::find(locations.begin(), locations.end(), location) == locations.end()) {
        locations.push_back(location);
      }
    }

    closesocket(s);
  }

  std::vector<std::string> SsdpSearch() {
    std::vector<std::string> locations;

    std::vector<uint32_t> interfaces = EnumerateLocalIpv4();
    // Always include the OS default interface as a fallback in case enumeration
    // came up empty or missed the right adapter.
    interfaces.push_back(INADDR_ANY);

    UPNP_LOG("SSDP discovery across {} interface(s)", interfaces.size());
    for (uint32_t if_addr : interfaces) {
      QuerySsdpInterface(if_addr, locations);
    }

    UPNP_LOG("SSDP discovery collected {} device location(s)", locations.size());
    return locations;
  }

  // The source IP the OS would use to reach the router is exactly the
  // NewInternalClient the mapping must point at.
  std::string DetectInternalIp(const std::string& igd_host) {
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s != INVALID_SOCKET) {
      sockaddr_in probe{};
      probe.sin_family = AF_INET;
      probe.sin_port = htons(kSsdpPort);
      if (inet_pton(AF_INET, igd_host.c_str(), &probe.sin_addr) == 1 &&
          connect(s, reinterpret_cast<sockaddr*>(&probe), sizeof(probe)) == 0) {
        sockaddr_in local{};
        int len = sizeof(local);
        if (getsockname(s, reinterpret_cast<sockaddr*>(&local), &len) == 0) {
          char ip[INET_ADDRSTRLEN] = {};
          if (inet_ntop(AF_INET, &local.sin_addr, ip, sizeof(ip)) && ip[0]) {
            closesocket(s);
            return ip;
          }
        }
      }
      closesocket(s);
    }
    // Fall back to the netplay layer's own LAN detection (honours lan_ip cvar).
    return XLiveWebClient::Get().lan_address();
  }

  // ------------------------------------------------------------------
  // SOAP
  // ------------------------------------------------------------------
  bool AddPortMapping(const std::string& control_url, const std::string& service_type,
                      const std::string& internal_ip, uint16_t port, bool udp,
                      int lease) {
    if (control_url.empty()) return false;
    const char* proto = udp ? "UDP" : "TCP";

    DWORD status = 0;
    std::string resp;
    bool ok = SoapAddPortMapping(control_url, service_type, internal_ip, port, udp,
                                 lease, status, resp);

    // 725 OnlyPermanentLeasesSupported: some routers reject a finite lease.
    // Retry as a permanent (0) mapping.
    if ((!ok || status != 200) && lease != 0 &&
        resp.find("OnlyPermanentLeasesSupported") != std::string::npos) {
      ok = SoapAddPortMapping(control_url, service_type, internal_ip, port, udp, 0,
                              status, resp);
    }

    if (ok && status == 200) {
      UPNP_LOG("Mapped {} {} -> {}:{} (lease {}s)", proto, port, internal_ip, port,
               lease);
      return true;
    }

    // 718 ConflictInMappingEntry: a forward for this external port already
    // exists. That's harmless only if it points at THIS machine — otherwise the
    // router is delivering the port to some other/stale internal client and a
    // hosted session here is unreachable, so we must reclaim it. Look up where
    // the existing rule actually points before deciding.
    if (resp.find("ConflictInMappingEntry") != std::string::npos) {
      std::string existing_client;
      const bool got = SoapGetSpecificPortMapping(control_url, service_type, port,
                                                  udp, existing_client);
      if (got && existing_client == internal_ip) {
        UPNP_LOG("{} port {} is already forwarded to this machine ({}) — good",
                 proto, port, internal_ip);
        return true;
      }

      // Couldn't read the existing rule — typically a static/manual forward the
      // router hides from UPnP. Do NOT delete it: on a router that permitted the
      // delete we'd wipe a forward that may already be correct and end up worse
      // off. Just tell the user how to verify it. This is the common case for a
      // player who already set up manual forwarding.
      if (!got) {
        UPNP_WARN("{} port {} already has a forward the router won't expose to "
                  "UPnP (usually a manual/static rule). Leaving it untouched. If "
                  "hosting is unreachable, confirm the router forwards {} {} to "
                  "THIS PC ({}), or delete that manual rule and let UPnP manage it.",
                  proto, port, proto, port, internal_ip);
        return true;
      }

      // Positively points at a different client (stale DHCP lease, another
      // device). Reclaim it: delete and re-add pointed at us.
      UPNP_WARN("{} port {} is forwarded to {} (not us, {}); reclaiming it", proto,
                port, existing_client, internal_ip);
      DeletePortMapping(control_url, service_type, port, udp);

      DWORD retry_status = 0;
      std::string retry_resp;
      bool retried = SoapAddPortMapping(control_url, service_type, internal_ip, port,
                                        udp, lease, retry_status, retry_resp);
      if ((!retried || retry_status != 200) && lease != 0 &&
          retry_resp.find("OnlyPermanentLeasesSupported") != std::string::npos) {
        retried = SoapAddPortMapping(control_url, service_type, internal_ip, port,
                                     udp, 0, retry_status, retry_resp);
      }
      if (retried && retry_status == 200) {
        UPNP_LOG("Reclaimed {} port {} -> {}:{}", proto, port, internal_ip, port);
        return true;
      }
      UPNP_WARN("Could not reclaim {} port {} (status={}); the existing forward to "
                "{} is static. Point it at this PC ({}) in the router, or remove "
                "it so UPnP can. Hosting on this port is unreachable until then.",
                proto, port, retry_status, existing_client, internal_ip);
      return false;
    }

    UPNP_WARN("AddPortMapping {} {} failed (status={})", proto, port, status);
    return false;
  }

  // Read the existing forward for {external port, proto}. Fills out_internal_client
  // with the LAN IP the router currently delivers this port to. Returns false if
  // there is no such mapping or the query failed.
  bool SoapGetSpecificPortMapping(const std::string& control_url,
                                  const std::string& service_type, uint16_t port,
                                  bool udp, std::string& out_internal_client) {
    out_internal_client.clear();
    const std::string body = fmt::format(
        "<?xml version=\"1.0\"?>\r\n"
        "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
        "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
        "<s:Body>"
        "<u:GetSpecificPortMappingEntry xmlns:u=\"{svc}\">"
        "<NewRemoteHost></NewRemoteHost>"
        "<NewExternalPort>{port}</NewExternalPort>"
        "<NewProtocol>{proto}</NewProtocol>"
        "</u:GetSpecificPortMappingEntry>"
        "</s:Body></s:Envelope>",
        fmt::arg("svc", service_type), fmt::arg("port", port),
        fmt::arg("proto", udp ? "UDP" : "TCP"));

    const std::wstring headers =
        SoapHeaders(service_type, L"GetSpecificPortMappingEntry");
    DWORD status = 0;
    std::string resp;
    if (!HttpRequest(control_url, L"POST", headers, body, 3000, status, resp) ||
        status != 200) {
      return false;
    }
    out_internal_client = GetXmlTag(resp, "NewInternalClient");
    return !out_internal_client.empty();
  }

  bool SoapAddPortMapping(const std::string& control_url,
                          const std::string& service_type,
                          const std::string& internal_ip, uint16_t port, bool udp,
                          int lease, DWORD& out_status, std::string& out_body) {
    const std::string body = fmt::format(
        "<?xml version=\"1.0\"?>\r\n"
        "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
        "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
        "<s:Body>"
        "<u:AddPortMapping xmlns:u=\"{svc}\">"
        "<NewRemoteHost></NewRemoteHost>"
        "<NewExternalPort>{port}</NewExternalPort>"
        "<NewProtocol>{proto}</NewProtocol>"
        "<NewInternalPort>{port}</NewInternalPort>"
        "<NewInternalClient>{ip}</NewInternalClient>"
        "<NewEnabled>1</NewEnabled>"
        "<NewPortMappingDescription>{desc}</NewPortMappingDescription>"
        "<NewLeaseDuration>{lease}</NewLeaseDuration>"
        "</u:AddPortMapping>"
        "</s:Body></s:Envelope>",
        fmt::arg("svc", service_type), fmt::arg("port", port),
        fmt::arg("proto", udp ? "UDP" : "TCP"), fmt::arg("ip", internal_ip),
        fmt::arg("desc", kMappingDescription), fmt::arg("lease", lease));

    const std::wstring headers = SoapHeaders(service_type, L"AddPortMapping");
    return HttpRequest(control_url, L"POST", headers, body, 4000, out_status,
                       out_body);
  }

  bool DeletePortMapping(const std::string& control_url,
                         const std::string& service_type, uint16_t port, bool udp) {
    const std::string body = fmt::format(
        "<?xml version=\"1.0\"?>\r\n"
        "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
        "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
        "<s:Body>"
        "<u:DeletePortMapping xmlns:u=\"{svc}\">"
        "<NewRemoteHost></NewRemoteHost>"
        "<NewExternalPort>{port}</NewExternalPort>"
        "<NewProtocol>{proto}</NewProtocol>"
        "</u:DeletePortMapping>"
        "</s:Body></s:Envelope>",
        fmt::arg("svc", service_type), fmt::arg("port", port),
        fmt::arg("proto", udp ? "UDP" : "TCP"));

    const std::wstring headers = SoapHeaders(service_type, L"DeletePortMapping");
    DWORD status = 0;
    std::string resp;
    const bool ok =
        HttpRequest(control_url, L"POST", headers, body, 3000, status, resp);
    return ok && status == 200;
  }

  std::wstring SoapHeaders(const std::string& service_type,
                           const std::wstring& action) {
    // SOAPAction: "<serviceType>#<action>"
    std::wstring wsvc(service_type.begin(), service_type.end());
    return L"Content-Type: text/xml; charset=\"utf-8\"\r\n"
           L"SOAPAction: \"" +
           wsvc + L"#" + action + L"\"\r\n";
  }

  void DeleteAllMappings() {
    std::vector<DesiredMapping> mappings;
    std::string control_url, service_type;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (!discovered_) return;
      mappings = desired_;
      control_url = control_url_;
      service_type = service_type_;
    }
    for (const auto& m : mappings) {
      if (DeletePortMapping(control_url, service_type, m.port, m.udp)) {
        UPNP_LOG("Removed {} port {} forward", m.udp ? "UDP" : "TCP", m.port);
      }
    }
  }

  mutable std::mutex mutex_;
  std::condition_variable cv_;
  std::thread worker_;
  std::atomic<bool> stop_{false};
  bool worker_running_ = false;

  bool discovered_ = false;
  std::string control_url_;
  std::string service_type_;
  std::string internal_ip_;

  std::vector<DesiredMapping> desired_;
};

}  // namespace

UpnpManager& UpnpManager::Get() {
  static UpnpManager instance;
  return instance;
}

void UpnpManager::RequestMapping(uint16_t port, bool udp) {
  Impl::Get().RequestMapping(port, udp);
}

bool UpnpManager::is_available() const { return Impl::Get().is_available(); }

void UpnpManager::Shutdown() { Impl::Get().Shutdown(); }

#else  // !REX_PLATFORM_WIN32

// UPnP is only implemented for the Windows netplay build for now. Non-Windows
// targets get a no-op manager so callers don't need platform guards.
UpnpManager& UpnpManager::Get() {
  static UpnpManager instance;
  return instance;
}
void UpnpManager::RequestMapping(uint16_t, bool) {}
bool UpnpManager::is_available() const { return false; }
void UpnpManager::Shutdown() {}

#endif  // REX_PLATFORM_WIN32

}  // namespace rex::system
