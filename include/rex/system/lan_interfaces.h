#pragma once
/**
 * @file        system/lan_interfaces.h
 * @brief       IPv4 interface discovery for device-to-device System Link
 *
 * @copyright   Copyright (c) 2026 Tom Clay <tomc@tctechstuff.com>
 *              All rights reserved.
 *
 * @license     BSD 3-Clause License
 *              See LICENSE file in the project root for full license text.
 */

#include <cstdint>
#include <vector>

namespace rex::system {

struct IPv4InterfaceAddress {
  uint32_t address_net = 0;
  uint32_t netmask_net = 0;
  bool is_up = false;
  bool is_loopback = false;
};

struct IPv4BroadcastTarget {
  uint32_t address_net = 0;
  uint32_t broadcast_net = 0;
};

/// Return local IPv4 interface addresses.
std::vector<IPv4InterfaceAddress> EnumerateLocalIPv4Interfaces();

/// Select broadcast targets for an optional IPv4 override.
std::vector<IPv4BroadcastTarget> BuildSystemLinkBroadcastTargets(
    const std::vector<IPv4InterfaceAddress>& interfaces, uint32_t override_address_net);

bool IsLocalIPv4Address(uint32_t address_net);

}  // namespace rex::system
