/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2013 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 *
 * @modified    Tom Clay, 2026 - Adapted for ReXGlue runtime
 */

#include <cerrno>
#include <chrono>
#include <cstring>
#include <mutex>
#include <thread>
#include <unordered_map>

#include <rex/cvar.h>
#include <rex/kernel/xam/module.h>
#include <rex/logging.h>
#include <rex/platform.h>
#include <rex/system/kernel_state.h>
#include <rex/system/upnp.h>
#include <rex/system/xlive_web_client.h>
#include <rex/system/xsession.h>
#include <rex/system/xsocket.h>
// #include <rex/system/xnet.h>

#include <rex/net/socket.h>

REXCVAR_DECLARE(bool,    xlive_web_enabled);
REXCVAR_DECLARE(bool,    xlive_web_bridge_systemlink_broadcast);
REXCVAR_DECLARE(bool,    xlive_web_bridge_synthesize_lan_info);
REXCVAR_DECLARE(bool,    xlive_web_bridge_loopback_same_public_ip);
REXCVAR_DECLARE(int32_t, systemlink_base_port);
REXCVAR_DECLARE(int32_t, systemlink_port_offset);
REXCVAR_DECLARE(bool,    systemlink_lan_discovery);
REXCVAR_DECLARE(bool,    netplay_firewall_prompt);

// Standard socket types used by Xbox API emulation
#if REX_PLATFORM_WIN32
#include <WinSock2.h>

#include <WS2tcpip.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#endif

namespace rex::system {

namespace {
constexpr size_t kMaxIncomingPackets = 64;

// Tag carried by LAN hole-punch datagrams; the receiving runtime swallows
// these before the title sees them.
constexpr uint8_t kLanPunchTag[4] = {'R', 'X', 'P', 'H'};

std::mutex g_bound_udp_mutex;
std::unordered_map<uint16_t, XSocket*>& BoundUdpSockets() {
  static std::unordered_map<uint16_t, XSocket*> sockets;
  return sockets;
}

std::mutex g_punch_history_mutex;
std::unordered_map<uint32_t, std::chrono::steady_clock::time_point>& PunchHistory() {
  static std::unordered_map<uint32_t, std::chrono::steady_clock::time_point> history;
  return history;
}

int GetNativeSocketError() {
#if REX_PLATFORM_WIN32
  return WSAGetLastError();
#else
  return errno;
#endif
}

// Windows shows its native "Allow this app through the firewall" prompt the
// first time a program listens for inbound connections with no existing rule.
// The title's UDP binds don't reliably trigger it, but a TCP listen() does —
// and the allow-rule Windows creates when the user clicks "Allow access" is
// per-application, so it also covers our inbound netplay UDP. We open a
// short-lived throwaway TCP listener once to coax that prompt. We never add a
// firewall rule ourselves and never request elevation; the user drives the
// standard Windows dialog. If they previously clicked "Cancel", Windows keeps a
// block rule and won't prompt again — that must be undone manually.
void TriggerFirewallPromptOnce(uint16_t port) {
#if REX_PLATFORM_WIN32
  if (!REXCVAR_GET(netplay_firewall_prompt)) {
    return;
  }
  static std::once_flag once;
  std::call_once(once, [port] {
    std::thread([port] {
      const auto listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
      if (listener == INVALID_SOCKET) {
        return;
      }
      sockaddr_in addr{};
      addr.sin_family = AF_INET;
      addr.sin_addr.s_addr = htonl(INADDR_ANY);
      addr.sin_port = htons(port);
      // TCP and UDP port spaces are separate, so this never collides with the
      // title's UDP bind on the same number. If some TCP already holds it, fall
      // back to an ephemeral port — any listen() on this exe provokes the
      // per-application prompt just the same.
      if (bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        addr.sin_port = 0;
        bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
      }
      if (listen(listener, 1) == 0) {
        REXKRNL_INFO("XSocket: opened transient TCP listener (port {}) to trigger "
                     "the Windows Firewall allow prompt", port);
        // Stay listening long enough for the firewall service to register it
        // and for the user to answer the dialog, then tear it down.
        std::this_thread::sleep_for(std::chrono::seconds(20));
      }
      rex::net::socket_close(static_cast<uint64_t>(listener));
    }).detach();
  });
#else
  (void)port;
#endif
}

bool IsLanPunchDatagram(const uint8_t* buf, uint32_t buf_len, int received) {
  return received == static_cast<int>(sizeof(kLanPunchTag)) &&
         buf_len >= sizeof(kLanPunchTag) &&
         std::memcmp(buf, kLanPunchTag, sizeof(kLanPunchTag)) == 0;
}

// A peer probe heard on the announce port proves the peer is reachable; the
// session-port socket then punches that peer so its inbound filter state
// opens before the title attempts the join exchange.
void MaybeLanJoinPunch(uint16_t local_port, const sockaddr_in& src) {
  if (!REXCVAR_GET(systemlink_lan_discovery) ||
      !REXCVAR_GET(xlive_web_bridge_systemlink_broadcast)) {
    return;
  }
  const uint16_t base_port = static_cast<uint16_t>(REXCVAR_GET(systemlink_base_port));
  const uint16_t announce_port =
      static_cast<uint16_t>(base_port + REXCVAR_GET(systemlink_port_offset));
  const uint16_t session_port = static_cast<uint16_t>(base_port - 1);
  if (base_port == 0 || session_port == 0 || local_port != announce_port) {
    return;
  }
  const uint32_t peer_net = src.sin_addr.s_addr;
  if (peer_net == htonl(INADDR_LOOPBACK) ||
      peer_net == XLiveWebClient::Get().lan_address_net()) {
    return;
  }
  {
    const auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(g_punch_history_mutex);
    auto& last = PunchHistory()[peer_net];
    if (last.time_since_epoch().count() != 0 && now - last < std::chrono::seconds(5)) {
      return;
    }
    last = now;
  }
  XSocket::PunchFromBoundUdpSocket(session_port, peer_net, session_port);
}
}  // namespace

bool XSocket::EnsureLanProbeSocket(uint32_t bind_address_net) {
  std::lock_guard<std::mutex> lock(lan_probe_mutex_);
  if (lan_probe_handle_ != ~0ull)
    return true;
  if (lan_probe_failed_)
    return false;

  const auto probe = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
#if REX_PLATFORM_WIN32
  const bool invalid_probe = probe == INVALID_SOCKET;
#else
  const bool invalid_probe = probe < 0;
#endif
  if (invalid_probe) {
    lan_probe_failed_ = true;
    REXKRNL_WARN("XSocket LAN probe socket creation failed err={}", GetNativeSocketError());
    return false;
  }

  const int broadcast = 1;
  if (setsockopt(probe, SOL_SOCKET, SO_BROADCAST, reinterpret_cast<const char*>(&broadcast),
                 sizeof(broadcast)) != 0) {
    const int error = GetNativeSocketError();
    rex::net::socket_close(static_cast<uint64_t>(probe));
    lan_probe_failed_ = true;
    REXKRNL_WARN("XSocket LAN probe SO_BROADCAST failed err={}", error);
    return false;
  }

  sockaddr_in local{};
  local.sin_family = AF_INET;
  // Pin the probe to the physical LAN adapter. A zero address preserves the
  // previous INADDR_ANY fallback.
  local.sin_addr.s_addr = bind_address_net;
  if (bind(probe, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) {
    const int error = GetNativeSocketError();
    rex::net::socket_close(static_cast<uint64_t>(probe));
    lan_probe_failed_ = true;
    REXKRNL_WARN("XSocket LAN probe bind failed err={}", error);
    return false;
  }

#if REX_PLATFORM_WIN32
  u_long nonblocking = 1;
  const int nonblocking_result = ioctlsocket(probe, FIONBIO, &nonblocking);
#else
  const int current_flags = fcntl(probe, F_GETFL, 0);
  const int nonblocking_result =
      current_flags < 0 ? -1 : fcntl(probe, F_SETFL, current_flags | O_NONBLOCK);
#endif
  if (nonblocking_result != 0) {
    const int error = GetNativeSocketError();
    rex::net::socket_close(static_cast<uint64_t>(probe));
    lan_probe_failed_ = true;
    REXKRNL_WARN("XSocket LAN probe nonblocking setup failed err={}", error);
    return false;
  }

  char bound_ip[INET_ADDRSTRLEN] = {};
  inet_ntop(AF_INET, &local.sin_addr, bound_ip, sizeof(bound_ip));
  lan_probe_handle_ = static_cast<uint64_t>(probe);
  REXKRNL_INFO("XSocket LAN probe socket bound to {}", bound_ip);
  return true;
}

size_t XSocket::GetNativeReadHandles(uint64_t* handles, size_t capacity) const {
  size_t count = 0;
  if (native_handle_ != ~0ull && count < capacity) {
    handles[count++] = native_handle_;
  }

  std::lock_guard<std::mutex> lock(lan_probe_mutex_);
  if (lan_probe_handle_ != ~0ull && count < capacity) {
    handles[count++] = lan_probe_handle_;
  }
  return count;
}

bool XSocket::IsNativeReadHandle(uint64_t handle) const {
  if (handle == native_handle_)
    return native_handle_ != ~0ull;
  std::lock_guard<std::mutex> lock(lan_probe_mutex_);
  return handle == lan_probe_handle_ && lan_probe_handle_ != ~0ull;
}

bool XSocket::PunchFromBoundUdpSocket(uint16_t local_port, uint32_t peer_ip_net,
                                      uint16_t peer_port) {
  std::lock_guard<std::mutex> lock(g_bound_udp_mutex);
  auto& sockets = BoundUdpSockets();
  const auto it = sockets.find(local_port);
  if (it == sockets.end()) {
    return false;
  }
  sockaddr_in peer{};
  peer.sin_family = AF_INET;
  peer.sin_port = htons(peer_port);
  peer.sin_addr.s_addr = peer_ip_net;
  const int sent =
      sendto(it->second->native_handle_, reinterpret_cast<const char*>(kLanPunchTag),
             sizeof(kLanPunchTag), 0, reinterpret_cast<sockaddr*>(&peer), sizeof(peer));
  char peer_ip[INET_ADDRSTRLEN] = {};
  inet_ntop(AF_INET, &peer.sin_addr, peer_ip, sizeof(peer_ip));
  if (sent != static_cast<int>(sizeof(kLanPunchTag))) {
    REXKRNL_WARN("XSocket LAN punch from port {} to {}:{} failed err={}", local_port, peer_ip,
                 peer_port, GetNativeSocketError());
    return false;
  }
  REXKRNL_INFO("XSocket LAN punch sent from port {} to {}:{}", local_port, peer_ip, peer_port);
  return true;
}

XSocket::XSocket(KernelState* kernel_state) : XObject(kernel_state, kObjectType) {}

XSocket::XSocket(KernelState* kernel_state, uint64_t native_handle)
    : XObject(kernel_state, kObjectType), native_handle_(native_handle) {}

XSocket::~XSocket() {
  Close();
}

X_STATUS XSocket::Initialize(AddressFamily af, Type type, Protocol proto) {
  af_ = af;
  type_ = type;
  proto_ = proto;

  if (proto == Protocol::IPPROTO_VDP) {
    // VDP is a layer on top of UDP.
    proto = Protocol::IPPROTO_UDP;
  }

  native_handle_ = socket(af, type, proto);
  if (native_handle_ == -1) {
    return X_STATUS_UNSUCCESSFUL;
  }

  return X_STATUS_SUCCESS;
}

X_STATUS XSocket::Close() {
  bool close_failed = false;
  {
    std::lock_guard<std::mutex> lock(g_bound_udp_mutex);
    auto& sockets = BoundUdpSockets();
    const auto it = sockets.find(bound_port_);
    if (it != sockets.end() && it->second == this) {
      sockets.erase(it);
    }
  }
  {
    std::lock_guard<std::mutex> lock(lan_probe_mutex_);
    if (lan_probe_handle_ != ~0ull) {
      close_failed = rex::net::socket_close(lan_probe_handle_) != 0;
      lan_probe_handle_ = ~0ull;
    }
  }
  {
    std::lock_guard<std::mutex> lock(incoming_packet_mutex_);
    while (!incoming_packets_.empty()) {
      delete[] incoming_packets_.front();
      incoming_packets_.pop();
    }
  }
  if (native_handle_ != ~0ull) {
    close_failed = rex::net::socket_close(native_handle_) != 0 || close_failed;
    native_handle_ = ~0ull;
  }

  return close_failed ? X_STATUS_UNSUCCESSFUL : X_STATUS_SUCCESS;
}

X_STATUS XSocket::SetOption(uint32_t level, uint32_t optname, void* optval_ptr, uint32_t optlen) {
  if (level == 0xFFFF && (optname == 0x5801 || optname == 0x5802)) {
    // Disable socket encryption
    secure_ = false;
    return X_STATUS_SUCCESS;
  }

  int ret = setsockopt(native_handle_, level, optname, (char*)optval_ptr, optlen);
  if (ret < 0) {
    // TODO: WSAGetLastError()
    return X_STATUS_UNSUCCESSFUL;
  }

  // SO_BROADCAST
  if (level == 0xFFFF && optname == 0x0020) {
    broadcast_socket_ = true;
  }

  return X_STATUS_SUCCESS;
}

X_STATUS XSocket::IOControl(uint32_t cmd, uint8_t* arg_ptr) {
  int ret = rex::net::socket_ioctl(native_handle_, cmd, arg_ptr);
  if (ret < 0) {
    // TODO: Get last error
    return X_STATUS_UNSUCCESSFUL;
  }

  return X_STATUS_SUCCESS;
}

X_STATUS XSocket::Connect(N_XSOCKADDR* name, int name_len) {
  int ret = connect(native_handle_, (sockaddr*)name, name_len);
  if (ret < 0) {
    return X_STATUS_UNSUCCESSFUL;
  }

  return X_STATUS_SUCCESS;
}

X_STATUS XSocket::Bind(N_XSOCKADDR_IN* name, int name_len) {
  uint16_t req_port = 0;
  if (name) {
    const uint32_t req_addr_host = static_cast<uint32_t>(name->sin_addr);
    req_port = static_cast<uint16_t>(name->sin_port);
    if (req_addr_host != 0) {
      // Titles may bind to the specific address advertised by
      // XNetGetTitleXnAddr. A specifically-bound UDP socket never receives
      // broadcast datagrams on Windows, which kills System Link discovery,
      // so normalize to ANY - the port is what matters.
      uint32_t nbo = htonl(req_addr_host);
      char req_ip[INET_ADDRSTRLEN] = {};
      inet_ntop(AF_INET, &nbo, req_ip, sizeof(req_ip));
      REXKRNL_INFO("XSocket::Bind rewriting requested address {}:{} to ANY", req_ip,
                   req_port);
      name->sin_addr = 0u;
    } else {
      REXKRNL_INFO("XSocket::Bind ANY:{}", req_port);
    }

    // Apply systemlink_port_offset to the actual bind, not just to what we
    // advertise. XNetGetTitleXnAddr already reports base+offset and the
    // announce/punch paths already assume the local socket sits there, but
    // without this the title bound its real ports and two local instances
    // fought over them — the second one's bind just failed. Peers undo this
    // in SendTo by shifting their destination by our advertised offset.
    // Port 0 means "pick an ephemeral port"; never shift that.
    const int32_t sl_offset = REXCVAR_GET(systemlink_port_offset);
    if (sl_offset && req_port) {
      const uint16_t shifted = static_cast<uint16_t>(req_port + sl_offset);
      REXKRNL_INFO("XSocket::Bind applying systemlink_port_offset {}: {} -> {}",
                   sl_offset, req_port, shifted);
      name->sin_port = shifted;
      req_port = shifted;
    }
  }
  int ret = bind(native_handle_, (sockaddr*)name, name_len);
  if (ret < 0) {
    // Silent failure here is why a port collision looked like "the join just
    // never happens": the title carries on with an unbound socket.
    REXKRNL_ERROR("XSocket::Bind FAILED for port {} (err={}) — port already in "
                  "use? Another emulator instance on this machine binds the "
                  "same System Link ports unless systemlink_port_offset differs.",
                  req_port, GetNativeSocketError());
    return X_STATUS_UNSUCCESSFUL;
  }

  bound_ = true;
  bound_port_ = name->sin_port;
  if (type_ == SOCK_DGRAM && bound_port_ != 0) {
    std::lock_guard<std::mutex> lock(g_bound_udp_mutex);
    BoundUdpSockets()[bound_port_] = this;
  }

  // Ask the router to forward this UDP port to us so peers on the internet can
  // reach a hosted session without the player setting up manual port
  // forwarding. Only meaningful for web netplay, and req_port here is the
  // host-order port number the title actually listens on (post offset shift).
  // The manager is non-blocking, idempotent, and no-ops when upnp_enabled is
  // false, so this is safe to call on every bind.
  if (type_ == SOCK_DGRAM && req_port != 0 && REXCVAR_GET(xlive_web_enabled)) {
    UpnpManager::Get().RequestMapping(req_port, /*udp=*/true);
    // Coax Windows' native firewall allow-prompt so inbound netplay traffic
    // isn't silently dropped (fires at most once per process).
    TriggerFirewallPromptOnce(req_port);
  }

  return X_STATUS_SUCCESS;
}

X_STATUS XSocket::Listen(int backlog) {
  int ret = listen(native_handle_, backlog);
  if (ret < 0) {
    return X_STATUS_UNSUCCESSFUL;
  }

  return X_STATUS_SUCCESS;
}

object_ref<XSocket> XSocket::Accept(N_XSOCKADDR* name, int* name_len) {
  sockaddr n_sockaddr;
  socklen_t n_name_len = sizeof(sockaddr);
  uintptr_t ret = accept(native_handle_, &n_sockaddr, &n_name_len);
  if (ret == -1) {
    std::memset(name, 0, *name_len);
    *name_len = 0;
    return nullptr;
  }

  std::memcpy(name, &n_sockaddr, n_name_len);
  *name_len = n_name_len;

  // Create a kernel object to represent the new socket, and copy parameters
  // over.
  auto socket = object_ref<XSocket>(new XSocket(kernel_state_, ret));
  socket->af_ = af_;
  socket->type_ = type_;
  socket->proto_ = proto_;

  return socket;
}

int XSocket::Shutdown(int how) {
  return shutdown(native_handle_, how);
}

int XSocket::Recv(uint8_t* buf, uint32_t buf_len, uint32_t flags) {
  return recv(native_handle_, reinterpret_cast<char*>(buf), buf_len, flags);
}

int XSocket::RecvFrom(uint8_t* buf, uint32_t buf_len, uint32_t flags, N_XSOCKADDR_IN* from,
                      uint32_t* from_len) {
  // A probe reply belongs only to the XSocket that owns this helper. Drain
  // one datagram per guest receive so readiness and delivery stay paired.
  {
    std::lock_guard<std::mutex> lock(lan_probe_mutex_);
    if (lan_probe_handle_ != ~0ull) {
      uint8_t reply[2048];
      sockaddr_in src{};
      socklen_t src_len = sizeof(src);
      const int n = recvfrom(lan_probe_handle_, reinterpret_cast<char*>(reply), sizeof(reply), 0,
                             reinterpret_cast<sockaddr*>(&src), &src_len);
      if (n > 0) {
        QueuePacket(ntohl(src.sin_addr.s_addr), ntohs(src.sin_port), reply, static_cast<size_t>(n));
        char src_ip_str[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, &src.sin_addr, src_ip_str, sizeof(src_ip_str));
        REXKRNL_DEBUG("XSocket::RecvFrom injected {} probe reply bytes from {}:{}", n, src_ip_str,
                      ntohs(src.sin_port));
      }
    }
  }
  {
    std::lock_guard<std::mutex> lock(incoming_packet_mutex_);
    if (!incoming_packets_.empty()) {
      packet* pkt = reinterpret_cast<packet*>(incoming_packets_.front());
      int data_len = pkt->data_len;
      std::memcpy(buf, pkt->data, std::min(static_cast<uint32_t>(pkt->data_len), buf_len));

      if (from) {
        from->sin_family  = 2;  // AF_INET
        from->sin_addr    = pkt->src_ip;
        from->sin_port    = pkt->src_port;
        std::memset(from->x_sin_zero, 0, sizeof(from->x_sin_zero));
      }
      if (from_len) {
        *from_len = sizeof(N_XSOCKADDR_IN);
      }

      incoming_packets_.pop();
      delete[] reinterpret_cast<uint8_t*>(pkt);
      return data_len;
    }
  }

  sockaddr_in nfrom;
  socklen_t nfromlen = sizeof(sockaddr_in);
  int ret;
  for (;;) {
    nfromlen = sizeof(sockaddr_in);
    ret = recvfrom(native_handle_, reinterpret_cast<char*>(buf), buf_len, flags,
                   (sockaddr*)&nfrom, &nfromlen);
    if (ret > 0 && IsLanPunchDatagram(buf, buf_len, ret)) {
      char src_ip_str[INET_ADDRSTRLEN] = {};
      inet_ntop(AF_INET, &nfrom.sin_addr, src_ip_str, sizeof(src_ip_str));
      REXKRNL_DEBUG("XSocket::RecvFrom swallowed LAN punch from {}:{}", src_ip_str,
                    ntohs(nfrom.sin_port));
      continue;
    }
    break;
  }
  if (ret > 0) {
    char src_ip_str[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &nfrom.sin_addr, src_ip_str, sizeof(src_ip_str));
    // Local port this arrived on — compare against the local port SendTo uses.
    // A mismatch means our reply leaves via a different NAT mapping than the
    // one the peer's NAT already has a hole punched for, so it gets silently
    // dropped even though sendto() itself reports success.
    sockaddr_in local{};
    socklen_t local_len = sizeof(local);
    uint16_t local_port = 0;
    if (getsockname(native_handle_, (sockaddr*)&local, &local_len) == 0) {
      local_port = ntohs(local.sin_port);
    }
    REXKRNL_DEBUG("XSocket::RecvFrom got {} bytes from {}:{} (our local port={})", ret,
                  src_ip_str, ntohs(nfrom.sin_port), local_port);
    if (netplay_rx_info_logged_ < kNetplayInfoLogCap) {
      ++netplay_rx_info_logged_;
      REXKRNL_INFO("XSocket netplay RX: {} bytes from {}:{} arrived on our local "
                   "port {}",
                   ret, src_ip_str, ntohs(nfrom.sin_port), local_port);
    }
    MaybeLanJoinPunch(local_port, nfrom);
  }
  if (from) {
    from->sin_family = nfrom.sin_family;
    from->sin_addr = ntohl(nfrom.sin_addr.s_addr);  // BE <- BE
    // Host-order value through the big-endian guest field, matching the
    // injected helper path: a raw network-order write reads back
    // byte-swapped, so the title replies to port 59395 instead of 1000.
    from->sin_port = ntohs(nfrom.sin_port);
    std::memset(from->x_sin_zero, 0, sizeof(from->x_sin_zero));
  }

  if (from_len) {
    *from_len = nfromlen;
  }

  return ret;
}

int XSocket::Send(const uint8_t* buf, uint32_t buf_len, uint32_t flags) {
  return send(native_handle_, reinterpret_cast<const char*>(buf), buf_len, flags);
}

int XSocket::SendTo(uint8_t* buf, uint32_t buf_len, uint32_t flags, N_XSOCKADDR_IN* to,
                    uint32_t to_len) {
  sockaddr_in nto{};
  uint32_t dest_addr = 0;

  if (to) {
    dest_addr = to->sin_addr;  // host byte order (be<> read of guest NBO bytes)
    uint16_t dest_port_nbo = htons(static_cast<uint16_t>(to->sin_port));
    if (REXCVAR_GET(xlive_web_enabled) && (dest_addr & 0xFF000000u) == 0xAB000000u) {
      XNetAddrEntry entry;
      if (XNetAddrCache::Get().Lookup(dest_addr, entry)) {
        // Cache stores addresses as NBO patterns; normalize to host order so
        // both the token and raw-address paths agree below.
        bool lan_peer = false;
        dest_addr = ntohl(entry.xn_addr.inaOnline);
        if (!dest_addr && entry.xn_addr.ina) {
          dest_addr = ntohl(entry.xn_addr.ina);  // pure-LAN entry (no web)
          lan_peer = true;
        }

        // Same public IP but a different machine on our LAN: use its LAN
        // address; the same-public-IP loopback remap below won't match it.
        //
        // ina must differ from inaOnline to carry any LAN information. A web
        // session has only one address field, and the search-result writer
        // fills both ina and inaOnline from it, so ina == inaOnline means
        // "public IP, LAN unknown". Treating that as a LAN peer skipped the
        // port-offset shift below and sent every packet to our own port.
        auto& wc = XLiveWebClient::Get();
        if (wc.is_ready() && entry.xn_addr.inaOnline == wc.public_address_net() &&
            entry.xn_addr.ina && entry.xn_addr.ina != entry.xn_addr.inaOnline &&
            entry.xn_addr.ina != htonl(INADDR_LOOPBACK) &&
            entry.xn_addr.ina != wc.lan_address_net()) {
          dest_addr = ntohl(entry.xn_addr.ina);
          lan_peer = true;
        }

        // The advertised port is only a real destination for a peer that binds
        // an OFFSET copy of the title's System Link ports (another rexglue
        // instance running with systemlink_port_offset). Xenia advertises a
        // hardcoded 36000 (XLiveAPI::GetPlayerPort) that it never binds — it
        // binds the title's real ports (verified: xenia listens on 1000/1001)
        // and its own SendTo uses the guest's destination port verbatim.
        // Replacing our port with the advertised one there fires every packet
        // at a closed port, so the join silently times out.
        //
        // Shift the guest's port by the peer's offset instead of replacing it,
        // so multi-port System Link titles keep their per-socket distinction.
        if (entry.xn_addr.wPortOnline && !lan_peer) {
          const uint16_t adv  = ntohs(entry.xn_addr.wPortOnline);
          const uint16_t base =
              static_cast<uint16_t>(REXCVAR_GET(systemlink_base_port));
          const int32_t peer_offset =
              static_cast<int32_t>(adv) - static_cast<int32_t>(base);
          // Offset 0 means the peer binds the title's ports natively, and an
          // implausibly large delta means the advertised value isn't a port
          // the peer listens on at all (xenia's 36000). Both keep our port.
          constexpr int32_t kMaxPeerPortOffset = 4096;
          if (peer_offset > 0 && peer_offset <= kMaxPeerPortOffset) {
            dest_port_nbo = htons(
                static_cast<uint16_t>(ntohs(dest_port_nbo) + peer_offset));
          }
        }
      }
    }

    nto.sin_addr.s_addr = htonl(dest_addr);
    // Hardcode AF_INET: the guest-side family value isn't guaranteed to be a
    // valid host AF, and only IPv4 is supported here anyway.
    nto.sin_family = AF_INET;
    nto.sin_port   = dest_port_nbo;

    // Two instances behind one public IP can't reach each other through it
    // (home NATs don't hairpin), so route unicast aimed at our own public IP
    // via loopback — the same remap the broadcast bridge applies.
    if (REXCVAR_GET(xlive_web_enabled) &&
        REXCVAR_GET(xlive_web_bridge_loopback_same_public_ip)) {
      auto& wc = XLiveWebClient::Get();
      if (wc.is_ready() && nto.sin_addr.s_addr == wc.public_address_net()) {
        REXKRNL_DEBUG("XSocket::SendTo remapping same-public-IP unicast {}:{} to loopback",
                      wc.public_address(), static_cast<uint16_t>(to->sin_port));
        nto.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      }
    }
  }

  if (to && REXCVAR_GET(xlive_web_enabled) && REXCVAR_GET(xlive_web_bridge_systemlink_broadcast)) {
    uint16_t dest_port = static_cast<uint16_t>(to->sin_port);
    uint16_t base_port = static_cast<uint16_t>(REXCVAR_GET(systemlink_base_port));
    uint16_t sl_port   = static_cast<uint16_t>(base_port + REXCVAR_GET(systemlink_port_offset));

    bool is_broadcast = (dest_addr == 0xFFFFFFFFu) ||
                        ((dest_addr & 0xFFu) == 0xFFu);
    bool is_sl_port = (dest_port == base_port) || (dest_port == base_port - 1) ||
                      (dest_port == base_port + 12);

    REXKRNL_DEBUG("XSocket::SendTo broadcast check: dest_addr={:08X} dest_port={} base_port={} sl_port={} is_broadcast={} is_sl_port={}",
                  dest_addr, dest_port, base_port, sl_port, is_broadcast, is_sl_port);

    if (is_broadcast && is_sl_port) {
      REXKRNL_DEBUG("XSocket::SendTo intercepting SL broadcast to port {}, querying web sessions (title={:08X})...",
                    dest_port, kernel_state_->title_id());
      auto& wc = XLiveWebClient::Get();
      wc.EnsureReady();

      wc.EnsureHostSession(kernel_state_->title_id(), sl_port);

      std::vector<WebSession> sessions;
      bool search_ok = wc.SearchSessions(kernel_state_->title_id(), sessions);
      REXKRNL_DEBUG("XSocket::SendTo SearchSessions ok={} count={}", search_ok, sessions.size());
      if (search_ok) {
        const std::string& my_ip = wc.public_address();
        bool loopback_enabled = REXCVAR_GET(xlive_web_bridge_loopback_same_public_ip);
        REXKRNL_DEBUG("XSocket::SendTo my_ip={} sl_port={} loopback_same_public_ip={}", my_ip, sl_port, loopback_enabled);
        for (const auto& ws : sessions) {
          if (ws.host_address.empty()) {
            REXKRNL_WARN("XSocket::SendTo skipping session with empty host_address (xuid={:016X})", ws.host_xuid);
            continue;
          }
          uint16_t peer_port = ws.port ? ws.port : sl_port;
          bool is_self = (ws.host_address == my_ip) && (peer_port == sl_port);
          if (is_self) {
            REXKRNL_DEBUG("XSocket::SendTo skipping self (addr={} port={})", ws.host_address, peer_port);
            continue;
          }
          bool same_public_ip = ws.host_address == my_ip;
          if (!loopback_enabled && same_public_ip) {
            REXKRNL_DEBUG("XSocket::SendTo skipping same-IP session (loopback disabled): xuid={:016X} addr={} port={}",
                          ws.host_xuid, ws.host_address, ws.port);
            continue;
          }
          uint32_t peer_ip =
              (same_public_ip && loopback_enabled)
                  ? htonl(INADDR_LOOPBACK)
                  : inet_addr(ws.host_address.c_str());

          char peer_ip_str[INET_ADDRSTRLEN] = {};
          inet_ntop(AF_INET, &peer_ip, peer_ip_str, sizeof(peer_ip_str));
          REXKRNL_DEBUG("XSocket::SendTo forwarding {} bytes to {}:{} (web_addr={} port={} same_ip={} loopback={})",
                        buf_len, peer_ip_str, peer_port,
                        ws.host_address, ws.port, same_public_ip, loopback_enabled);

          sockaddr_in peer{};
          peer.sin_family      = AF_INET;
          peer.sin_port        = htons(peer_port);
          peer.sin_addr.s_addr = peer_ip;
          int sent = sendto(native_handle_, reinterpret_cast<char*>(buf), buf_len, flags,
                            reinterpret_cast<sockaddr*>(&peer), sizeof(peer));
          if (sent < 0) {
            REXKRNL_WARN("XSocket::SendTo sendto to {}:{} failed (WSAError={})",
                         peer_ip_str, peer_port, WSAGetLastError());
          }
        }
      }

      if (REXCVAR_GET(systemlink_lan_discovery)) {
        // Peers behind our own NAT are skipped or loopback-remapped by the web
        // fan-out above; a genuine broadcast is the only way same-subnet
        // machines can hear this probe (their replies come back unicast from
        // their real LAN address on the normal recv path).
        int bc_on = 1;
        const int bc_opt_rc = setsockopt(native_handle_, SOL_SOCKET, SO_BROADCAST,
                                         reinterpret_cast<const char*>(&bc_on), sizeof(bc_on));
        sockaddr_in bcast{};
        bcast.sin_family = AF_INET;
        bcast.sin_port = htons(dest_port);
        bcast.sin_addr.s_addr = htonl(INADDR_BROADCAST);
        const int bc_sent = sendto(native_handle_, reinterpret_cast<char*>(buf), buf_len, flags,
                                   reinterpret_cast<sockaddr*>(&bcast), sizeof(bcast));
        if (bc_sent < 0) {
          const int bc_err = WSAGetLastError();
          int bc_state = 0;
          socklen_t bc_state_len = sizeof(bc_state);
          getsockopt(native_handle_, SOL_SOCKET, SO_BROADCAST, reinterpret_cast<char*>(&bc_state),
                     &bc_state_len);
          int so_type = 0;
          socklen_t so_type_len = sizeof(so_type);
          getsockopt(native_handle_, SOL_SOCKET, SO_TYPE, reinterpret_cast<char*>(&so_type),
                     &so_type_len);
          REXKRNL_WARN(
              "XSocket::SendTo LAN broadcast FAILED err={} opt_rc={} so_broadcast={} "
              "so_type={} guest_flags={} handle={}",
              bc_err, bc_opt_rc, bc_state, so_type, flags, native_handle_);
          // Fall back to this logical socket's helper. Replies are surfaced
          // through this same XSocket in select and RecvFrom.
          if (EnsureLanProbeSocket(XLiveWebClient::Get().lan_address_net())) {
            std::lock_guard<std::mutex> lock(lan_probe_mutex_);
            const int alt_sent = sendto(lan_probe_handle_, reinterpret_cast<char*>(buf), buf_len, 0,
                                        reinterpret_cast<sockaddr*>(&bcast), sizeof(bcast));
            if (alt_sent < 0) {
              REXKRNL_WARN("XSocket::SendTo LAN probe socket broadcast ALSO failed err={}",
                           WSAGetLastError());
            } else {
              REXKRNL_DEBUG("XSocket::SendTo LAN probe socket sent {} bytes to port {}", alt_sent,
                            dest_port);
            }
          }
        } else {
          REXKRNL_DEBUG("XSocket::SendTo LAN broadcast passthrough port {} -> {} bytes", dest_port,
                        bc_sent);
        }
      }
      return static_cast<int>(buf_len);
    }
  }

  if (to) {
    // Genuine broadcasts (e.g. real UDP SL probes when the web bridge is
    // disabled or didn't intercept this send) need SO_BROADCAST set on the
    // socket or sendto() fails outright.
    uint32_t nto_addr_host = ntohl(nto.sin_addr.s_addr);
    bool direct_is_broadcast =
        (nto_addr_host == 0xFFFFFFFFu) || ((nto_addr_host & 0xFFu) == 0xFFu);
    if (direct_is_broadcast) {
      int bc_on = 1;
      setsockopt(native_handle_, SOL_SOCKET, SO_BROADCAST,
                reinterpret_cast<const char*>(&bc_on), sizeof(bc_on));
    }
  }

  int direct_result = sendto(native_handle_, reinterpret_cast<char*>(buf), buf_len, flags,
                            to ? (sockaddr*)&nto : nullptr, to ? sizeof(nto) : to_len);
  // Capture the error immediately: inet_ntop/getsockname below can clear it,
  // which previously made every failure log as WSAError=0.
  int direct_wsa_err = (direct_result < 0) ? WSAGetLastError() : 0;
  if (to) {
    char dest_ip_str[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &nto.sin_addr, dest_ip_str, sizeof(dest_ip_str));
    sockaddr_in local{};
    socklen_t local_len = sizeof(local);
    uint16_t local_port = 0;
    if (getsockname(native_handle_, (sockaddr*)&local, &local_len) == 0) {
      local_port = ntohs(local.sin_port);
    }
    if (direct_result < 0) {
      REXKRNL_WARN("XSocket::SendTo direct unicast to {}:{} FAILED buf_len={} WSAError={} "
                   "(our local port={})",
                   dest_ip_str, ntohs(nto.sin_port), buf_len, direct_wsa_err, local_port);
    } else {
      REXKRNL_DEBUG("XSocket::SendTo direct unicast to {}:{} ok, sent {} bytes "
                    "(our local port={})",
                    dest_ip_str, ntohs(nto.sin_port), direct_result, local_port);
      if (netplay_tx_info_logged_ < kNetplayInfoLogCap) {
        ++netplay_tx_info_logged_;
        REXKRNL_INFO("XSocket netplay TX: {} bytes to {}:{} from our local port {}",
                     direct_result, dest_ip_str, ntohs(nto.sin_port), local_port);
      }
    }
  }
  return direct_result;
}

bool XSocket::QueuePacket(uint32_t src_ip, uint16_t src_port, const uint8_t* buf, size_t len) {
  packet* pkt = reinterpret_cast<packet*>(new uint8_t[sizeof(packet) + len]);
  pkt->src_ip = src_ip;
  pkt->src_port = src_port;

  pkt->data_len = (uint16_t)len;
  std::memcpy(pkt->data, buf, len);

  std::lock_guard<std::mutex> lock(incoming_packet_mutex_);
  if (incoming_packets_.size() >= kMaxIncomingPackets) {
    delete[] incoming_packets_.front();
    incoming_packets_.pop();
  }
  incoming_packets_.push((uint8_t*)pkt);
  return true;
}

}  // namespace rex::system
