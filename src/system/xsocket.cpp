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

#include <cstring>

#include <rex/cvar.h>
#include <rex/kernel/xam/module.h>
#include <rex/logging.h>
#include <rex/platform.h>
#include <rex/system/kernel_state.h>
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

// Standard socket types used by Xbox API emulation
#if REX_PLATFORM_WIN32
#include <WinSock2.h>

#include <WS2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#endif

namespace rex::system {

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
  int ret = rex::net::socket_close(native_handle_);
  if (ret != 0) {
    return X_STATUS_UNSUCCESSFUL;
  }

  return X_STATUS_SUCCESS;
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
  int ret = bind(native_handle_, (sockaddr*)name, name_len);
  if (ret < 0) {
    return X_STATUS_UNSUCCESSFUL;
  }

  bound_ = true;
  bound_port_ = name->sin_port;

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
  int ret = recvfrom(native_handle_, reinterpret_cast<char*>(buf), buf_len, flags,
                     (sockaddr*)&nfrom, &nfromlen);
  if (ret > 0) {
    char src_ip_str[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &nfrom.sin_addr, src_ip_str, sizeof(src_ip_str));
    REXKRNL_DEBUG("XSocket::RecvFrom got {} bytes from {}:{}", ret, src_ip_str, ntohs(nfrom.sin_port));
  }
  if (from) {
    from->sin_family = nfrom.sin_family;
    from->sin_addr = ntohl(nfrom.sin_addr.s_addr);  // BE <- BE
    from->sin_port = nfrom.sin_port;
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
    dest_addr = to->sin_addr;  // host byte order (as stored in the field)
    if (REXCVAR_GET(xlive_web_enabled) && (dest_addr & 0xFF000000u) == 0xAB000000u) {
      XNetAddrEntry entry;
      if (XNetAddrCache::Get().Lookup(dest_addr, entry)) {
        dest_addr = entry.xn_addr.inaOnline;
      }
    }

    nto.sin_addr.s_addr = dest_addr;
    nto.sin_family = to->sin_family;
    nto.sin_port   = to->sin_port;
  }

  if (to && REXCVAR_GET(xlive_web_enabled) && REXCVAR_GET(xlive_web_bridge_systemlink_broadcast)) {
    uint16_t dest_port = static_cast<uint16_t>(to->sin_port);
    uint16_t base_port = static_cast<uint16_t>(REXCVAR_GET(systemlink_base_port));
    uint16_t sl_port   = static_cast<uint16_t>(base_port + REXCVAR_GET(systemlink_port_offset));

    bool is_broadcast = (dest_addr == 0xFFFFFFFFu) ||
                        ((dest_addr & 0xFFu) == 0xFFu);
    bool is_sl_port = (dest_port == base_port) || (dest_port == base_port - 1) ||
                      (dest_port == base_port + 12);

    REXKRNL_INFO("XSocket::SendTo broadcast check: dest_addr={:08X} dest_port={} base_port={} sl_port={} is_broadcast={} is_sl_port={}",
                 dest_addr, dest_port, base_port, sl_port, is_broadcast, is_sl_port);

    if (is_broadcast && is_sl_port) {
      REXKRNL_INFO("XSocket::SendTo intercepting SL broadcast to port {}, querying web sessions (title={:08X})...",
                   dest_port, kernel_state_->title_id());
      auto& wc = XLiveWebClient::Get();
      wc.EnsureReady();

      wc.EnsureHostSession(kernel_state_->title_id(), sl_port);

      std::vector<WebSession> sessions;
      bool search_ok = wc.SearchSessions(kernel_state_->title_id(), sessions);
      REXKRNL_INFO("XSocket::SendTo SearchSessions ok={} count={}", search_ok, sessions.size());
      if (search_ok) {
        const std::string& my_ip = wc.public_address();
        bool loopback_enabled = REXCVAR_GET(xlive_web_bridge_loopback_same_public_ip);
        REXKRNL_INFO("XSocket::SendTo my_ip={} sl_port={} loopback_same_public_ip={}", my_ip, sl_port, loopback_enabled);
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
            REXKRNL_INFO("XSocket::SendTo skipping same-IP session (loopback disabled): xuid={:016X} addr={} port={}",
                         ws.host_xuid, ws.host_address, ws.port);
            continue;
          }
          uint32_t peer_ip =
              (same_public_ip && loopback_enabled)
                  ? htonl(INADDR_LOOPBACK)
                  : inet_addr(ws.host_address.c_str());

          char peer_ip_str[INET_ADDRSTRLEN] = {};
          inet_ntop(AF_INET, &peer_ip, peer_ip_str, sizeof(peer_ip_str));
          REXKRNL_INFO("XSocket::SendTo forwarding {} bytes to {}:{} (web_addr={} port={} same_ip={} loopback={})",
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
      return static_cast<int>(buf_len);
    }
  }

  return sendto(native_handle_, reinterpret_cast<char*>(buf), buf_len, flags,
                to ? (sockaddr*)&nto : nullptr, to_len);
}

bool XSocket::QueuePacket(uint32_t src_ip, uint16_t src_port, const uint8_t* buf, size_t len) {
  packet* pkt = reinterpret_cast<packet*>(new uint8_t[sizeof(packet) + len]);
  pkt->src_ip = src_ip;
  pkt->src_port = src_port;

  pkt->data_len = (uint16_t)len;
  std::memcpy(pkt->data, buf, len);

  std::lock_guard<std::mutex> lock(incoming_packet_mutex_);
  incoming_packets_.push((uint8_t*)pkt);

  // TODO: Limit on number of incoming packets?
  return true;
}

}  // namespace rex::system