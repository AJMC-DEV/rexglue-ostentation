/**
 * @file        system/upnp.cpp
 * @brief       Automatic NAT traversal via UPnP IGD port forwarding.
 *
 *   Ported from Xenia Canary's xe::kernel::UPnP, which is built on miniupnpc
 *   (thirdparty/miniupnp). miniupnpc handles SSDP discovery, device
 *   description parsing and the SOAP AddPortMapping/DeletePortMapping calls,
 *   including the long tail of router quirks a hand-rolled client trips over.
 *
 *   Two behaviours are kept from ReXGlue's previous hand-rolled client because
 *   miniupnpc has no equivalent:
 *     - Discovery probes every local IPv4 adapter, not just the OS-default
 *       multicast interface. A Hyper-V/WSL/VMware/VPN adapter otherwise
 *       swallows the M-SEARCH, which is the usual reason "no router found".
 *     - ConflictInMappingEntry (718) is resolved by reading the existing rule
 *       and reclaiming it only when it points at some other machine.
 *
 * @modified    2026 - ReXGlue netplay
 */

#include <rex/system/upnp.h>

#include <rex/platform.h>

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
#elif REX_PLATFORM_LINUX
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include <miniupnpc.h>
#include <miniwget.h>
#include <upnpcommands.h>
#include <upnperrors.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <vector>

#include <fmt/format.h>

#include <rex/cvar.h>
#include <rex/logging.h>

// Declared in xlive_flags.cpp
REXCVAR_DECLARE(bool, upnp_enabled);
REXCVAR_DECLARE(int32_t, upnp_lease_seconds);
REXCVAR_DECLARE(std::string, upnp_root);

namespace rex::system {

#define UPNP_LOG(...) REXSYS_INFO("[UPnP] " __VA_ARGS__)
#define UPNP_WARN(...) REXSYS_WARN("[UPnP] " __VA_ARGS__)
#define UPNP_ERROR(...) REXSYS_ERROR("[UPnP] " __VA_ARGS__)

namespace {

constexpr char kMappingDescription[] = "ReXGlue Netplay";

// How long to wait for SSDP replies on each interface probed.
constexpr int kDiscoveryDelayMs = 2000;

// Renewal interval used when the router only supports permanent (infinite)
// leases, so a router reboot still gets our mappings back reasonably soon.
constexpr std::chrono::seconds kPermanentLeaseRefreshInterval{45 * 60};

// Write upnp_root back to the config file so the next run skips SSDP discovery
// entirely. Cvars are only written on an explicit SaveConfig, and nothing else
// in a netplay session triggers one.
void PersistUPnPRoot() {
  const auto& path = rex::cvar::GetConfigPath();
  if (path.empty()) {
    // Headless/tool runs never loaded a config; the cache is session-only.
    return;
  }
  rex::cvar::SaveConfig(path);
}

// Every "up", non-loopback IPv4 unicast address on this machine, as dotted
// strings suitable for miniupnpc's `multicastif` parameter.
std::vector<std::string> EnumerateLocalIpv4Strings() {
  std::vector<std::string> ips;

#if REX_PLATFORM_WIN32
  ULONG size = 15000;
  std::vector<uint8_t> buffer(size);
  const ULONG flags =
      GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
  ULONG ret = GetAdaptersAddresses(
      AF_INET, flags, nullptr,
      reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &size);
  if (ret == ERROR_BUFFER_OVERFLOW) {
    buffer.resize(size);
    ret = GetAdaptersAddresses(
        AF_INET, flags, nullptr,
        reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &size);
  }
  if (ret != NO_ERROR) {
    return ips;
  }

  for (auto* a = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()); a;
       a = a->Next) {
    if (a->OperStatus != IfOperStatusUp) continue;
    if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
    for (auto* ua = a->FirstUnicastAddress; ua; ua = ua->Next) {
      auto* sa = reinterpret_cast<sockaddr_in*>(ua->Address.lpSockaddr);
      if (!sa || sa->sin_family != AF_INET) continue;
      if (!sa->sin_addr.s_addr || sa->sin_addr.s_addr == htonl(INADDR_LOOPBACK)) {
        continue;
      }
      char ip[INET_ADDRSTRLEN] = {};
      if (inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip)) && ip[0]) {
        ips.emplace_back(ip);
      }
    }
  }
#elif REX_PLATFORM_LINUX
  ifaddrs* addrs = nullptr;
  if (getifaddrs(&addrs) != 0) {
    return ips;
  }
  for (ifaddrs* it = addrs; it; it = it->ifa_next) {
    if (!it->ifa_addr || it->ifa_addr->sa_family != AF_INET) continue;
    if (!(it->ifa_flags & IFF_UP) || (it->ifa_flags & IFF_LOOPBACK)) continue;
    auto* sa = reinterpret_cast<sockaddr_in*>(it->ifa_addr);
    char ip[INET_ADDRSTRLEN] = {};
    if (inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip)) && ip[0]) {
      ips.emplace_back(ip);
    }
  }
  freeifaddrs(addrs);
#endif

  // Deduplicate; multi-homed adapters can repeat an address.
  std::sort(ips.begin(), ips.end());
  ips.erase(std::unique(ips.begin(), ips.end()), ips.end());
  return ips;
}

}  // namespace

// miniupnpc state, kept out of the public header.
struct UPnP::IgdState {
  IGDdatas data = {};
  UPNPUrls urls = {};
  // Our LAN address on the route to the IGD, filled by miniupnpc.
  char lan_addr[128] = {};
  // FreeUPNPUrls must only run on a struct a successful lookup populated.
  bool urls_valid = false;
};

UPnP& UPnP::Get() {
  static UPnP instance;
  return instance;
}

UPnP::UPnP() : igd_(std::make_unique<IgdState>()) {}

UPnP::~UPnP() { Shutdown(); }

std::chrono::seconds UPnP::LeaseDuration() const {
  int32_t lease = REXCVAR_GET(upnp_lease_seconds);
  if (lease < 0) {
    lease = 0;
  }
  return std::chrono::seconds(lease);
}

std::chrono::seconds UPnP::RefreshInterval() const {
  const auto lease = LeaseDuration();
  if (lease.count() == 0) {
    return kPermanentLeaseRefreshInterval;
  }
  // Renew at half the lease so one missed cycle doesn't drop the mapping,
  // with a floor so a tiny configured lease can't spin the refresher.
  return std::max(std::chrono::seconds(60), lease / 2);
}

void UPnP::Initialize() {
  if (active_ || !REXCVAR_GET(upnp_enabled)) {
    return;
  }

  bool expected = false;
  if (!initialized_.compare_exchange_strong(expected, true)) {
    return;
  }

  get_valid_IGD_ = std::async(std::launch::async, &UPnP::GetValidIGD, this);
}

void UPnP::Start() {
  if (active_ || !REXCVAR_GET(upnp_enabled)) {
    return;
  }

  if (!get_valid_IGD_.valid()) {
    Initialize();
    if (!get_valid_IGD_.valid()) {
      return;
    }
  }

  const std::optional<std::string> igd_desc = get_valid_IGD_.get();

  if (igd_desc.has_value()) {
    // Cache the root description URL so the next run skips discovery. Some
    // routers answer HTTP 401 to actions issued against a freshly rediscovered
    // device, so reusing the known-good URL is also more reliable.
    if (REXCVAR_GET(upnp_root) != igd_desc.value()) {
      REXCVAR_SET(upnp_root, igd_desc.value());
      PersistUPnPRoot();
    }

    active_ = true;
    StartPeriodicPortsRefresher();

    // Anything requested while discovery was still running is waiting here.
    OpenTrackedPorts();
  } else if (!REXCVAR_GET(upnp_root).empty()) {
    // The cached router didn't answer and rediscovery found nothing either.
    // Drop the stale URL so the next run does a clean search.
    REXCVAR_SET(upnp_root, std::string());
    PersistUPnPRoot();
  }
}

void UPnP::StartAsync() {
  if (active_ || !REXCVAR_GET(upnp_enabled)) {
    return;
  }
  // A Start() already in flight owns get_valid_IGD_; don't launch a second.
  if (start_async_.valid() &&
      start_async_.wait_for(std::chrono::seconds(0)) != std::future_status::ready) {
    return;
  }
  start_async_ = std::async(std::launch::async, &UPnP::Start, this);
}

void UPnP::Shutdown() {
  StopPeriodicPortsRefresher();

  if (start_async_.valid()) {
    start_async_.wait();
  }

  // Drain in-flight adds first, or one could land after CloseOpenPorts() and
  // leave a mapping behind.
  {
    std::lock_guard actions_lock(actions_mutex_);
    for (auto& action : pending_actions_) {
      if (action.valid()) {
        action.wait();
      }
    }
    pending_actions_.clear();
  }

  CloseOpenPorts();

  active_ = false;

  std::lock_guard igd_lock(igd_mutex_);
  if (igd_->urls_valid) {
    FreeUPNPUrls(&igd_->urls);
    igd_->urls_valid = false;
  }
}

std::optional<std::string> UPnP::GetValidIGD() {
  // Check the saved UPnP device is still valid. This ensures we do not receive
  // HTTP_UNAUTHORIZED when performing UPnP actions.
  const std::string saved_root = REXCVAR_GET(upnp_root);
  if (!saved_root.empty()) {
    UPNP_LOG("Trying saved IGD root {}", saved_root);
    if (LoadIGD(saved_root)) {
      return saved_root;
    }
    UPNP_LOG("Saved IGD root is stale; rediscovering");
  }

  return DiscoverValidIGD();
}

std::optional<std::string> UPnP::DiscoverValidIGD() {
  std::lock_guard igd_lock(igd_mutex_);

  CleanupIGD();

  // Probe the OS-default multicast interface first, then each local adapter.
  // Letting Windows pick the interface loses the M-SEARCH to a Hyper-V/WSL/
  // VPN virtual adapter on a lot of machines.
  std::vector<std::string> interfaces = EnumerateLocalIpv4Strings();
  interfaces.insert(interfaces.begin(), std::string());

  UPNP_LOG("Starting UPnP search across {} interface(s)", interfaces.size());

  for (const std::string& if_addr : interfaces) {
    int error = 0;
    UPNPDev* device_list =
        upnpDiscover(kDiscoveryDelayMs, if_addr.empty() ? nullptr : if_addr.c_str(),
                     nullptr, 0, 0, 2, &error);

    if (!device_list) {
      if (error) {
        UPNP_LOG("No devices via {}: error code {}",
                 if_addr.empty() ? "default interface" : if_addr, error);
      }
      continue;
    }

    const int status =
        UPNP_GetValidIGD(device_list, &igd_->urls, &igd_->data, igd_->lan_addr,
                         sizeof(igd_->lan_addr), nullptr, 0);

    std::optional<std::string> igd_desc_url;

    switch (status) {
      case UPNP_NO_IGD: {
        UPNP_WARN("No IGD found via {}.",
                  if_addr.empty() ? "default interface" : if_addr);
      } break;
      case UPNP_CONNECTED_IGD: {
        igd_->urls_valid = true;
        igd_desc_url = igd_->urls.rootdescURL;
        UPNP_LOG("Found valid and connected IGD at {}", igd_->urls.rootdescURL);
      } break;
      case UPNP_PRIVATEIP_IGD: {
        igd_->urls_valid = true;
        igd_desc_url = igd_->urls.rootdescURL;
        UPNP_LOG(
            "Found valid and connected IGD but with a reserved address at {}",
            igd_->urls.rootdescURL);
      } break;
      case UPNP_DISCONNECTED_IGD: {
        UPNP_WARN("Found valid IGD, but it reported as NOT connected.");
      } break;
      case UPNP_UNKNOWN_DEVICE: {
        UPNP_WARN("UPnP device has been found but was not recognized as an IGD.");
      } break;
      default: {
        UPNP_WARN("No valid IGD found (status: {}).", status);
      } break;
    }

    freeUPNPDevlist(device_list);

    if (igd_desc_url.has_value()) {
      UPNP_LOG("Local address on the route to the IGD: {}", igd_->lan_addr);
      return igd_desc_url;
    }

    // UPNP_GetValidIGD can partially fill urls even when it reports no IGD.
    CleanupIGD();
  }

  UPNP_WARN(
      "No UPnP router answered. Enable UPnP on the router (or forward the "
      "netplay ports manually) if hosting is unreachable from the internet.");
  return std::nullopt;
}

bool UPnP::LoadIGD(std::string igd_root) {
  std::lock_guard igd_lock(igd_mutex_);

  CleanupIGD();

  const bool ok = UPNP_GetIGDFromUrl(igd_root.c_str(), &igd_->urls, &igd_->data,
                                     igd_->lan_addr, sizeof(igd_->lan_addr)) != 0;
  igd_->urls_valid = ok;
  return ok;
}

void UPnP::CleanupIGD() {
  // Caller holds igd_mutex_.
  if (igd_->urls_valid) {
    FreeUPNPUrls(&igd_->urls);
    igd_->urls_valid = false;
  }
  igd_->urls = {};
  igd_->data = {};
  std::fill_n(igd_->lan_addr, sizeof(igd_->lan_addr), '\0');
}

std::future<int32_t> UPnP::AddPortAsync(std::string addr, uint16_t internal_port,
                                        std::string protocol) {
  return std::async(std::launch::async, &UPnP::AddPort, this, addr, internal_port,
                    protocol);
}

// Games can bind to ports or close sockets from any thread, therefore all
// member variables must be accessed and written to safely using a mutex.
int32_t UPnP::AddPort(std::string addr, uint16_t internal_port,
                      std::string protocol) {
  if (!active_) {
    return UPNPCOMMAND_UNKNOWN_ERROR;
  }

  std::lock_guard igd_lock(igd_mutex_);
  std::lock_guard bindings_lock(mutex_bindings_);

  if (!igd_->urls_valid || !igd_->urls.controlURL) {
    return UPNPCOMMAND_UNKNOWN_ERROR;
  }

  internal_port = GetMappedBindPort(internal_port);

  // If the port is already open then skip opening it again.
  if (port_bindings_.contains(protocol)) {
    if (port_bindings_.at(protocol).contains(internal_port)) {
      return UPNPCOMMAND_SUCCESS;
    }
  }

  TrackPort(internal_port, protocol);

  if (addr.empty()) {
    addr = igd_->lan_addr;
  }

  const uint16_t external_port = internal_port;
  const std::string internal_port_str = fmt::format("{}", internal_port);
  const std::string external_port_str = fmt::format("{}", external_port);
  const std::string lease_time_str = fmt::format("{}", LeaseDuration().count());

  int result = UPNP_AddPortMapping(
      igd_->urls.controlURL, igd_->data.first.servicetype,
      external_port_str.c_str(), internal_port_str.c_str(), addr.c_str(),
      kMappingDescription, protocol.c_str(), nullptr, lease_time_str.c_str());

  if (result == static_cast<int>(UPnPErrorCodes::OnlyPermanentLeasesSupported)) {
    result = UPNP_AddPortMapping(
        igd_->urls.controlURL, igd_->data.first.servicetype,
        external_port_str.c_str(), internal_port_str.c_str(), addr.c_str(),
        kMappingDescription, protocol.c_str(), nullptr, "0");

    leases_supported_ = false;
  }

  // ConflictInMappingEntry: a forward for this external port already exists.
  // That's harmless only if it points at THIS machine — otherwise the router is
  // delivering the port to some other/stale internal client and a session
  // hosted here is unreachable, so we must reclaim it. Read where the existing
  // rule actually points before deciding.
  if (result == static_cast<int>(UPnPErrorCodes::ConflictInMappingEntry)) {
    char existing_client[64] = {};
    char existing_port[8] = {};
    char existing_desc[128] = {};
    char existing_enabled[8] = {};
    char existing_lease[16] = {};

    const int query = UPNP_GetSpecificPortMappingEntry(
        igd_->urls.controlURL, igd_->data.first.servicetype,
        external_port_str.c_str(), protocol.c_str(), nullptr, existing_client,
        existing_port, existing_desc, existing_enabled, existing_lease);

    if (query == UPNPCOMMAND_SUCCESS && addr == existing_client) {
      UPNP_LOG("{} port {} is already forwarded to this machine ({}) — good",
               protocol, external_port, addr);
      port_bindings_[protocol][internal_port] = external_port;
      port_binding_results_[protocol][external_port] = UPNPCOMMAND_SUCCESS;
      return UPNPCOMMAND_SUCCESS;
    }

    if (query != UPNPCOMMAND_SUCCESS) {
      // Typically a static/manual forward the router hides from UPnP. Do NOT
      // delete it: on a router that permitted the delete we'd wipe a forward
      // that may already be correct and end up worse off.
      UPNP_WARN(
          "{} port {} already has a forward the router won't expose to UPnP "
          "(usually a manual/static rule). Leaving it untouched. If hosting is "
          "unreachable, confirm the router forwards {} {} to THIS PC ({}), or "
          "delete that manual rule and let UPnP manage it.",
          protocol, external_port, protocol, external_port, addr);
      port_binding_results_[protocol][external_port] = result;
      return result;
    }

    // Positively points at a different client (stale DHCP lease, another
    // device). Reclaim it: delete, then re-add pointed at us.
    UPNP_WARN("{} port {} is forwarded to {} (not us, {}); reclaiming it",
              protocol, external_port, existing_client, addr);

    UPNP_DeletePortMapping(igd_->urls.controlURL, igd_->data.first.servicetype,
                           external_port_str.c_str(), protocol.c_str(), nullptr);

    result = UPNP_AddPortMapping(
        igd_->urls.controlURL, igd_->data.first.servicetype,
        external_port_str.c_str(), internal_port_str.c_str(), addr.c_str(),
        kMappingDescription, protocol.c_str(), nullptr,
        leases_supported_ ? lease_time_str.c_str() : "0");
  }

  if (result != UPNPCOMMAND_SUCCESS) {
    if (result == static_cast<int>(UPnPErrorCodes::HttpUnauthorized)) {
      UPNP_ERROR("UPnP Unauthorized!");
    }

    UPNP_ERROR("Failed to bind port! {}:{}({}) to IGD:{}", addr, internal_port,
               protocol, external_port);
    UPNP_ERROR("UPnP error code {} ({})", result,
               GetUPnPErrorCodeToDesc(result));

    port_binding_results_[protocol][external_port] = result;
    return result;
  }

  port_bindings_[protocol][internal_port] = external_port;

  UPNP_LOG("Successfully opened {}:{}({}) to IGD:{} (lease {}s)", addr,
           internal_port, protocol, external_port,
           leases_supported_ ? LeaseDuration().count() : 0);

  port_binding_results_[protocol][external_port] = result;

  return result;
}

std::future<int32_t> UPnP::RemovePortAsync(uint16_t port, std::string protocol) {
  return std::async(std::launch::async, &UPnP::RemovePort, this, port, protocol);
}

int32_t UPnP::RemovePort(uint16_t port, std::string protocol) {
  if (!active_) {
    return UPNPCOMMAND_UNKNOWN_ERROR;
  }

  std::lock_guard igd_lock(igd_mutex_);
  std::lock_guard bindings_lock(mutex_bindings_);

  if (!igd_->urls_valid || !igd_->urls.controlURL) {
    return UPNPCOMMAND_UNKNOWN_ERROR;
  }

  if (!port_bindings_.contains(protocol)) {
    return UPNPCOMMAND_UNKNOWN_ERROR;
  }

  const auto& port_mapping = port_bindings_.at(protocol);

  if (!port_mapping.contains(port)) {
    return UPNPCOMMAND_UNKNOWN_ERROR;
  }

  const std::string external_port_str = fmt::format("{}", port);

  const int result = UPNP_DeletePortMapping(
      igd_->urls.controlURL, igd_->data.first.servicetype,
      external_port_str.c_str(), protocol.c_str(), nullptr);

  if (result != UPNPCOMMAND_SUCCESS) {
    UPNP_WARN("Failed to delete port mapping IGD:{}({}): {} ({})",
              external_port_str, protocol, result,
              GetUPnPErrorCodeToDesc(result));
  } else {
    UPNP_LOG("Removed {} port {} forward", protocol, port);
  }

  port_binding_results_.at(protocol).erase(port);
  port_bindings_.at(protocol).erase(port);

  if (port_binding_results_.at(protocol).empty()) {
    port_binding_results_.erase(protocol);
  }

  if (port_bindings_.at(protocol).empty()) {
    port_bindings_.erase(protocol);
  }

  return result;
}

void UPnP::QueueAction(std::future<int32_t> action) {
  std::lock_guard actions_lock(actions_mutex_);
  pending_actions_.erase(
      std::remove_if(pending_actions_.begin(), pending_actions_.end(),
                     [](const std::future<int32_t>& f) {
                       return !f.valid() ||
                              f.wait_for(std::chrono::seconds(0)) ==
                                  std::future_status::ready;
                     }),
      pending_actions_.end());
  pending_actions_.push_back(std::move(action));
}

void UPnP::RequestMapping(uint16_t port, bool udp) {
  if (!port || !REXCVAR_GET(upnp_enabled)) {
    return;
  }

  const std::string protocol = udp ? "UDP" : "TCP";

  if (!active_) {
    // Discovery hasn't finished (or hasn't started). Remember the port; Start()
    // opens everything tracked once an IGD is known.
    TrackPort(GetMappedBindPort(port), protocol);
    StartAsync();
    return;
  }

  // AddPort performs blocking SOAP round-trips and the caller is usually a
  // title thread inside bind().
  QueueAction(AddPortAsync(GetLocalIP(), port, protocol));
}

void UPnP::ReleaseMapping(uint16_t port, bool udp) {
  if (!port || !active_) {
    return;
  }
  QueueAction(RemovePortAsync(GetMappedBindPort(port), udp ? "UDP" : "TCP"));
}

std::string UPnP::GetLocalIP() {
  std::lock_guard igd_lock(igd_mutex_);
  return igd_->lan_addr;
}

std::string UPnP::GetLocalIP_wget() {
  char lan_addr[64] = {};
  int response_size = 0;
  int status = 0;

  const std::string root = REXCVAR_GET(upnp_root);
  if (root.empty()) {
    return {};
  }

  void* data = miniwget_getaddr(root.c_str(), &response_size, lan_addr,
                                sizeof(lan_addr), 0, &status);
  free(data);

  if (status != 200) {
    UPNP_LOG("Local IP lookup returned HTTP status {}", status);
  }

  return lan_addr;
}

void UPnP::TrackPort(uint16_t port, std::string protocol) {
  std::lock_guard tracked_lock(mutex_tracked_ports_);
  tracked_ports_[protocol].insert(port);
}

void UPnP::OpenTrackedPorts() {
  if (!active_) {
    return;
  }

  const std::string local_ip = GetLocalIP();

  for (const auto& [protocol, internal_ports] : GetTrackedPorts()) {
    for (const auto& internal_port : internal_ports) {
      AddPort(local_ip, internal_port, protocol);
    }
  }
}

void UPnP::OpenPorts(
    std::map<std::string, std::map<uint16_t, uint16_t>> open_ports) {
  if (!active_) {
    return;
  }

  const std::string local_ip = GetLocalIP();

  for (const auto& [protocol, ports] : open_ports) {
    for (const auto& [internal_port, external_port] : ports) {
      AddPort(local_ip, internal_port, protocol);
    }
  }
}

void UPnP::CloseOpenPorts() {
  if (!active_) {
    return;
  }

  const auto opened_ports = GetOpenedPorts();

  for (const auto& [protocol, prot_bindings] : opened_ports) {
    for (const auto& [internal_port, external_port] : prot_bindings) {
      RemovePort(external_port, protocol);
    }
  }
}

void UPnP::RefreshPorts() {
  const auto opened_ports = GetOpenedPorts();

  // First remove all the ports, otherwise we receive a conflict-in-mapping
  // -entry error when re-adding them.
  CloseOpenPorts();

  // Open all tracked ports back, effectively resetting the lease time.
  OpenPorts(opened_ports);
}

void UPnP::StartPeriodicPortsRefresher() {
  std::lock_guard lock(refresher_mutex_);
  if (refresher_thread_.joinable()) {
    return;
  }

  refresher_stop_ = false;
  refresher_thread_ = std::thread([this]() {
    for (;;) {
      const auto interval = RefreshInterval();
      {
        std::unique_lock lock(refresher_mutex_);
        refresher_cv_.wait_for(lock, interval, [this] { return refresher_stop_; });
        if (refresher_stop_) {
          return;
        }
      }

      // We don't know whether the router supports variable lease times until
      // the first port is opened; permanent mappings need no renewal, but we
      // still re-add periodically so a router reboot doesn't strand us.
      RefreshPorts();
    }
  });
}

void UPnP::StopPeriodicPortsRefresher() {
  std::thread thread;
  {
    std::lock_guard lock(refresher_mutex_);
    if (!refresher_thread_.joinable()) {
      return;
    }
    refresher_stop_ = true;
    thread = std::move(refresher_thread_);
  }
  refresher_cv_.notify_all();
  thread.join();
}

uint16_t UPnP::GetMappedConnectPort(uint16_t external_port) {
  std::lock_guard mapped_lock(mapped_mutex_);

  if (mapped_connect_ports_.contains(external_port)) {
    return mapped_connect_ports_[external_port];
  }

  // A wildcard entry maps every guest port to one host port.
  if (mapped_connect_ports_.contains(0)) {
    return mapped_connect_ports_.at(0);
  }

  return external_port;
}

uint16_t UPnP::GetMappedBindPort(uint16_t external_port) {
  std::lock_guard mapped_lock(mapped_mutex_);

  if (mapped_bind_ports_.contains(external_port)) {
    return mapped_bind_ports_[external_port];
  }

  if (mapped_bind_ports_.contains(0)) {
    return mapped_bind_ports_.at(0);
  }

  return external_port;
}

const std::map<std::string, std::map<uint16_t, uint16_t>>
UPnP::GetOpenedPorts() {
  std::lock_guard bindings_lock(mutex_bindings_);
  return port_bindings_;
}

const std::map<std::string, std::map<uint16_t, int32_t>>
UPnP::GetPortBindingResults() {
  std::lock_guard bindings_lock(mutex_bindings_);
  return port_binding_results_;
}

const std::map<std::string, std::set<uint16_t>> UPnP::GetTrackedPorts() {
  std::lock_guard tracked_lock(mutex_tracked_ports_);
  return tracked_ports_;
}

std::string_view UPnP::GetMiniUPnPcErrorCodeToDesc(int32_t error) noexcept {
  switch (error) {
    case UPNPCOMMAND_SUCCESS:
      return "Success";
    case UPNPCOMMAND_INVALID_ARGS:
      return "Invalid Args";
    case UPNPCOMMAND_HTTP_ERROR:
      return "HTTP Error";
    case UPNPCOMMAND_INVALID_RESPONSE:
      return "Invalid Response";
    case UPNPCOMMAND_MEM_ALLOC_ERROR:
      return "Memory Allocation";
    case UPNPCOMMAND_UNKNOWN_ERROR:
    default:
      return "Unknown Error Code";
  }
}

std::string_view UPnP::GetUPnPErrorCodeToDesc(int32_t error) noexcept {
  return GetUPnPErrorCodeToDesc(static_cast<UPnPErrorCodes>(error));
}

std::string_view UPnP::GetUPnPErrorCodeToDesc(UPnPErrorCodes error) noexcept {
  switch (error) {
    case UPnPErrorCodes::Success:
      return "Success";

    case UPnPErrorCodes::HttpUnauthorized:
      return "HTTP Unauthorized";

    case UPnPErrorCodes::ActionNotAuthorized:
      return "Action Not Authorized";

    case UPnPErrorCodes::InactiveConnectionStateRequired:
      return "Inactive Connection State Required";
    case UPnPErrorCodes::ConnectionSetupFailed:
      return "Connection Setup Failed";
    case UPnPErrorCodes::ConnectionSetupInProgress:
      return "Connection Setup In Progress";
    case UPnPErrorCodes::ConnectionNotConfigured:
      return "Connection Not Configured";
    case UPnPErrorCodes::DisconnectInProgress:
      return "Disconnect In Progress";
    case UPnPErrorCodes::InvalidLayer2Address:
      return "Invalid Layer2 Address";
    case UPnPErrorCodes::InternetAccessDisabled:
      return "Internet Access Disabled";
    case UPnPErrorCodes::InvalidConnectionType:
      return "Invalid Connection Type";
    case UPnPErrorCodes::ConnectionAlreadyTerminated:
      return "Connection Already Terminated";
    case UPnPErrorCodes::SpecifiedArrayIndexInvalid:
      return "Specified Array Index Invalid";
    case UPnPErrorCodes::NoSuchEntryInArray:
      return "No Such Entry In Array";
    case UPnPErrorCodes::WildcardNotPermittedInSourceIP:
      return "Wildcard Not Permitted In Source IP";
    case UPnPErrorCodes::WildcardNotPermittedInExternalPort:
      return "Wildcard Not Permitted In External Port";
    case UPnPErrorCodes::ConflictInMappingEntry:
      return "Conflict In Mapping Entry";
    case UPnPErrorCodes::SamePortValuesRequired:
      return "Same Port Values Required";
    case UPnPErrorCodes::OnlyPermanentLeasesSupported:
      return "Only Permanent Lease Supported";
    case UPnPErrorCodes::RemoteHostOnlySupportsRawTcp:
      return "Remote Host Only Supports Raw TCP";
    case UPnPErrorCodes::ExternalPortOnlySupportsWildcard:
      return "External Port Only Supports Wildcard";
    case UPnPErrorCodes::NoPortMappingsAvailable:
      return "No Port Mappings Available";
    case UPnPErrorCodes::ConflictWithOtherMechanisms:
      return "Conflict With Other Mechanisms";
    case UPnPErrorCodes::PortMappingNotFound:
      return "Port Mapping Not Found";
    case UPnPErrorCodes::InconsistentParameters:
      return "Inconsistent Parameters";
  }

  const auto error_code = static_cast<int32_t>(error);

  if (error_code < 0) {
    return GetMiniUPnPcErrorCodeToDesc(error_code);
  }

  if (error_code >= 600 && error_code <= 699) {
    return "Unknown Common Action Error";
  }

  if (error_code >= 700 && error_code <= 799) {
    return "Unknown Action Specific Error";
  }

  return "Unknown Error Code";
}

}  // namespace rex::system
