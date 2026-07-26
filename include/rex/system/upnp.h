#pragma once
/**
 * @file        system/upnp.h
 * @brief       Automatic NAT traversal via UPnP IGD port forwarding.
 *
 *   ~60% of players can't or won't set up manual port forwarding, which is the
 *   single most common reason a hosted System Link/XLink session is
 *   unreachable from the internet. This asks the home router (an
 *   InternetGatewayDevice) to forward the netplay ports to this machine
 *   automatically, replicating what a manual port-forward rule does.
 *
 *   Backed by miniupnpc (thirdparty/miniupnp). Discovery and every SOAP action
 *   are blocking, so the guest-facing paths use the *Async variants and never
 *   stall a title thread. Mappings are created with a finite lease and
 *   periodically renewed; they are deleted on clean shutdown, and if the
 *   process crashes the lease guarantees the router reclaims them on its own.
 *
 *   The discovered IGD's root description URL is cached in the upnp_root cvar
 *   so subsequent runs skip SSDP discovery entirely — this also avoids the
 *   HTTP 401 some routers return when re-discovering an already-known device.
 *
 * @modified    2026 - ReXGlue netplay
 */

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace rex::system {

class UPnP {
 public:
  // https://openconnectivity.org/developer/specifications/upnp-resources/upnp/internet-gateway-device-igd-v-2-0/
  // http://upnp.org/specs/gw/UPnP-gw-WANIPConnection-v2-Service.pdf
  enum class UPnPErrorCodes : int32_t {
    // General
    Success = 0,

    // Client-side Issues (400-499)
    HttpUnauthorized = 401,

    // Common Action Errors (600-699)
    ActionNotAuthorized = 606,

    // Action-specific errors for standard actions (700-799)
    InactiveConnectionStateRequired = 703,
    ConnectionSetupFailed = 704,
    ConnectionSetupInProgress = 705,
    ConnectionNotConfigured = 706,
    DisconnectInProgress = 707,
    InvalidLayer2Address = 708,
    InternetAccessDisabled = 709,
    InvalidConnectionType = 710,
    ConnectionAlreadyTerminated = 711,
    SpecifiedArrayIndexInvalid = 713,
    NoSuchEntryInArray = 714,
    WildcardNotPermittedInSourceIP = 715,
    WildcardNotPermittedInExternalPort = 716,
    ConflictInMappingEntry = 718,
    SamePortValuesRequired = 724,
    OnlyPermanentLeasesSupported = 725,
    RemoteHostOnlySupportsRawTcp = 726,
    ExternalPortOnlySupportsWildcard = 727,
    NoPortMappingsAvailable = 728,
    ConflictWithOtherMechanisms = 729,
    PortMappingNotFound = 730,
    InconsistentParameters = 733
  };

  // Process-wide instance. The guest can bind sockets from any thread, so every
  // public member is safe to call concurrently.
  static UPnP& Get();

  UPnP();
  ~UPnP();

  bool IsActive() const { return active_; }

  bool IsVariableLeaseSupported() const { return leases_supported_; }

  // Kick off IGD discovery on a background thread. Returns immediately. Safe to
  // call repeatedly; only the first call does work.
  void Initialize();

  // Wait for the discovery started by Initialize() (starting it first if it
  // hasn't been), publish the result to the upnp_root cvar and, on success,
  // arm the periodic lease refresher. Blocking — call it off the guest threads.
  void Start();

  // Non-blocking Start(): runs Start() on a worker if discovery hasn't
  // completed yet. Used by socket paths that must not stall.
  void StartAsync();

  // Shut down the refresher and remove every mapping we created. Idempotent.
  void Shutdown();

  std::optional<std::string> GetValidIGD();

  std::optional<std::string> DiscoverValidIGD();

  bool LoadIGD(std::string igd_root);

  std::future<int32_t> AddPortAsync(std::string addr, uint16_t internal_port,
                                    std::string protocol);

  int32_t AddPort(std::string addr, uint16_t internal_port,
                  std::string protocol);

  std::future<int32_t> RemovePortAsync(uint16_t port, std::string protocol);

  int32_t RemovePort(uint16_t internal_port, std::string protocol);

  // Convenience wrapper used by XSocket::Bind: ensures UPnP is started, then
  // asynchronously forwards `port`. Non-blocking, idempotent, and a no-op when
  // the upnp_enabled cvar is false. Ports requested before an IGD is known are
  // tracked and opened once discovery succeeds.
  void RequestMapping(uint16_t port, bool udp = true);

  // Counterpart of RequestMapping used by XSocket::Close: asynchronously drops
  // the forward. Non-blocking; the lease would expire on its own anyway.
  void ReleaseMapping(uint16_t port, bool udp = true);

  // The LAN address of this host as seen on the route to the IGD. This is
  // exactly the NewInternalClient a mapping must point at.
  std::string GetLocalIP();

  static std::string GetLocalIP_wget();

  void TrackPort(uint16_t port, std::string protocol);

  void OpenTrackedPorts();

  void OpenPorts(
      std::map<std::string, std::map<uint16_t, uint16_t>> open_ports);

  void CloseOpenPorts();

  void RefreshPorts();

  uint16_t GetMappedConnectPort(uint16_t external_port);

  uint16_t GetMappedBindPort(uint16_t external_port);

  const std::map<std::string, std::map<uint16_t, uint16_t>> GetOpenedPorts();

  const std::map<std::string, std::map<uint16_t, int32_t>>
  GetPortBindingResults();

  const std::map<std::string, std::set<uint16_t>> GetTrackedPorts();

  static std::string_view GetMiniUPnPcErrorCodeToDesc(int32_t error) noexcept;

  static std::string_view GetUPnPErrorCodeToDesc(int32_t error) noexcept;

  static std::string_view GetUPnPErrorCodeToDesc(UPnPErrorCodes error) noexcept;

  void AddMappedConnectPort(uint16_t port, uint16_t mapped_port) {
    std::lock_guard mapped_lock(mapped_mutex_);
    mapped_connect_ports_.insert({port, mapped_port});
  }

  void AddMappedBindPort(uint16_t port, uint16_t mapped_port) {
    std::lock_guard mapped_lock(mapped_mutex_);
    mapped_bind_ports_.insert({port, mapped_port});
  }

  UPnP(const UPnP&) = delete;
  UPnP& operator=(const UPnP&) = delete;

 private:
  // miniupnpc's IGDdatas/UPNPUrls are held behind a pimpl so this installed SDK
  // header doesn't drag miniupnpc into every consumer's include path.
  struct IgdState;

  void CleanupIGD();
  void StartPeriodicPortsRefresher();
  void StopPeriodicPortsRefresher();

  // Requested lease duration, from the upnp_lease_seconds cvar.
  std::chrono::seconds LeaseDuration() const;
  // How often to renew, derived from the lease.
  std::chrono::seconds RefreshInterval() const;

  // Park a fire-and-forget async action. A std::async future blocks in its own
  // destructor, so dropping one on the floor would turn every "async" add or
  // remove back into a synchronous SOAP round-trip on a title thread. Completed
  // actions are reaped on each call.
  void QueueAction(std::future<int32_t> action);

  std::mutex actions_mutex_;
  std::vector<std::future<int32_t>> pending_actions_;

  std::future<std::optional<std::string>> get_valid_IGD_;
  std::future<void> start_async_;

  std::atomic<bool> active_ = false;
  std::atomic<bool> leases_supported_ = true;
  std::atomic<bool> initialized_ = false;

  std::mutex igd_mutex_;
  std::unique_ptr<IgdState> igd_;

  // The lease refresher runs on its own thread rather than the shared timer
  // queue: every renew performs blocking SOAP round-trips, which would stall
  // unrelated timers.
  std::mutex refresher_mutex_;
  std::condition_variable refresher_cv_;
  std::thread refresher_thread_;
  bool refresher_stop_ = false;

  std::mutex mutex_tracked_ports_;
  std::map<std::string, std::set<uint16_t>> tracked_ports_;

  std::mutex mutex_bindings_;
  std::map<std::string, std::map<uint16_t, uint16_t>> port_bindings_;
  std::map<std::string, std::map<uint16_t, int32_t>> port_binding_results_;

  std::mutex mapped_mutex_;
  std::map<uint16_t, uint16_t> mapped_connect_ports_;
  std::map<uint16_t, uint16_t> mapped_bind_ports_;
};

}  // namespace rex::system
