/**
 * @file        system/lan_interfaces.cpp
 * @brief       IPv4 interface discovery for device-to-device System Link
 *
 * @copyright   Copyright (c) 2026 Tom Clay <tomc@tctechstuff.com>
 *              All rights reserved.
 *
 * @license     BSD 3-Clause License
 *              See LICENSE file in the project root for full license text.
 */

#include <rex/system/lan_interfaces.h>

#include <algorithm>
#include <vector>

#include <rex/platform.h>

#if REX_PLATFORM_WIN32
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iphlpapi.h>
#else
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#endif

namespace rex::system {

namespace {

uint32_t PrefixToNetmask(uint8_t prefix_length) {
  if (prefix_length == 0)
    return 0;
  if (prefix_length >= 32)
    return htonl(0xFFFFFFFFu);
  return htonl(0xFFFFFFFFu << (32u - prefix_length));
}

bool ContainsAddress(const std::vector<IPv4BroadcastTarget>& targets, uint32_t address_net) {
  return std::any_of(targets.begin(), targets.end(),
                     [address_net](const IPv4BroadcastTarget& target) {
                       return target.address_net == address_net;
                     });
}

}  // namespace

std::vector<IPv4InterfaceAddress> EnumerateLocalIPv4Interfaces() {
  std::vector<IPv4InterfaceAddress> result;

#if REX_PLATFORM_WIN32
  ULONG buffer_size = 16 * 1024;
  std::vector<uint8_t> buffer(buffer_size);
  auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
  ULONG status = GetAdaptersAddresses(
      AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, nullptr,
      adapters, &buffer_size);
  if (status == ERROR_BUFFER_OVERFLOW) {
    buffer.resize(buffer_size);
    adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
    status = GetAdaptersAddresses(
        AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
        nullptr, adapters, &buffer_size);
  }
  if (status != NO_ERROR)
    return result;

  for (auto* adapter = adapters; adapter; adapter = adapter->Next) {
    const bool is_up = adapter->OperStatus == IfOperStatusUp;
    const bool is_loopback = adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK;
    for (auto* unicast = adapter->FirstUnicastAddress; unicast; unicast = unicast->Next) {
      if (!unicast->Address.lpSockaddr || unicast->Address.lpSockaddr->sa_family != AF_INET) {
        continue;
      }
      const auto* address = reinterpret_cast<const sockaddr_in*>(unicast->Address.lpSockaddr);
      result.push_back({address->sin_addr.s_addr, PrefixToNetmask(unicast->OnLinkPrefixLength),
                        is_up, is_loopback});
    }
  }
#else
  ifaddrs* interfaces = nullptr;
  if (getifaddrs(&interfaces) != 0)
    return result;
  for (auto* interface = interfaces; interface; interface = interface->ifa_next) {
    if (!interface->ifa_addr || interface->ifa_addr->sa_family != AF_INET) {
      continue;
    }
    const auto* address = reinterpret_cast<const sockaddr_in*>(interface->ifa_addr);
    const auto* netmask = reinterpret_cast<const sockaddr_in*>(interface->ifa_netmask);
    result.push_back({address->sin_addr.s_addr, netmask ? netmask->sin_addr.s_addr : 0,
                      (interface->ifa_flags & IFF_UP) != 0,
                      (interface->ifa_flags & IFF_LOOPBACK) != 0});
  }
  freeifaddrs(interfaces);
#endif

  return result;
}

std::vector<IPv4BroadcastTarget> BuildSystemLinkBroadcastTargets(
    const std::vector<IPv4InterfaceAddress>& interfaces, uint32_t override_address_net) {
  std::vector<IPv4BroadcastTarget> targets;
  for (const auto& interface : interfaces) {
    if (!interface.is_up || interface.is_loopback || interface.address_net == 0) {
      continue;
    }
    if (override_address_net != 0 && interface.address_net != override_address_net) {
      continue;
    }
    if (ContainsAddress(targets, interface.address_net))
      continue;

    const uint32_t address_host = ntohl(interface.address_net);
    const uint32_t mask_host = ntohl(interface.netmask_net);
    uint32_t broadcast_net = htonl(address_host | ~mask_host);
    if (broadcast_net == interface.address_net) {
      broadcast_net = htonl(INADDR_BROADCAST);
    }
    targets.push_back({interface.address_net, broadcast_net});
  }

  if (override_address_net != 0 && !ContainsAddress(targets, override_address_net)) {
    targets.push_back({override_address_net, htonl(INADDR_BROADCAST)});
  }
  return targets;
}

bool IsLocalIPv4Address(uint32_t address_net) {
  const auto interfaces = EnumerateLocalIPv4Interfaces();
  return std::any_of(interfaces.begin(), interfaces.end(),
                     [address_net](const IPv4InterfaceAddress& interface) {
                       return interface.address_net == address_net;
                     });
}

}  // namespace rex::system
