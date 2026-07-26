/**
 * @file        tests/unit/system/lan_interfaces_test.cpp
 * @brief       Unit tests for adapter-independent System Link discovery
 *
 * @copyright   Copyright (c) 2026 Tom Clay <tomc@tctechstuff.com>
 *              All rights reserved.
 *
 * @license     BSD 3-Clause License
 *              See LICENSE file in the project root for full license text.
 */

#include <catch2/catch_test_macros.hpp>

#include <rex/platform.h>
#include <rex/system/lan_interfaces.h>

#if REX_PLATFORM_WIN32
#include <WinSock2.h>
#include <WS2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include <vector>

namespace {

uint32_t Address(const char* text) {
  uint32_t address = 0;
  REQUIRE(inet_pton(AF_INET, text, &address) == 1);
  return address;
}

}  // namespace

TEST_CASE("System Link discovery selects every usable IPv4 adapter",
          "[runtime][network][lan][interfaces]") {
  const std::vector<rex::system::IPv4InterfaceAddress> interfaces = {
      {Address("192.168.50.7"), Address("255.255.255.0"), true, false},
      {Address("100.92.13.4"), Address("255.255.255.0"), true, false},
      {Address("10.30.0.9"), Address("255.255.0.0"), false, false},
      {Address("127.0.0.1"), Address("255.0.0.0"), true, true},
  };

  const auto targets = rex::system::BuildSystemLinkBroadcastTargets(interfaces, 0);

  REQUIRE(targets.size() == 2);
  CHECK(targets[0].address_net == Address("192.168.50.7"));
  CHECK(targets[0].broadcast_net == Address("192.168.50.255"));
  CHECK(targets[1].address_net == Address("100.92.13.4"));
  CHECK(targets[1].broadcast_net == Address("100.92.13.255"));
}

TEST_CASE("System Link LAN address override selects one adapter",
          "[runtime][network][lan][interfaces]") {
  const auto override_address = Address("100.92.13.4");
  const std::vector<rex::system::IPv4InterfaceAddress> interfaces = {
      {Address("192.168.50.7"), Address("255.255.255.0"), true, false},
      {override_address, Address("255.255.255.0"), true, false},
  };

  const auto targets = rex::system::BuildSystemLinkBroadcastTargets(interfaces, override_address);

  REQUIRE(targets.size() == 1);
  CHECK(targets[0].address_net == override_address);
  CHECK(targets[0].broadcast_net == Address("100.92.13.255"));
}

TEST_CASE("System Link preserves an explicit unmatched VPN address",
          "[runtime][network][lan][interfaces]") {
  const auto override_address = Address("172.29.44.8");
  const std::vector<rex::system::IPv4InterfaceAddress> interfaces = {
      {Address("192.168.50.7"), Address("255.255.255.0"), true, false},
  };

  const auto targets = rex::system::BuildSystemLinkBroadcastTargets(interfaces, override_address);

  REQUIRE(targets.size() == 1);
  CHECK(targets[0].address_net == override_address);
  CHECK(targets[0].broadcast_net == htonl(INADDR_BROADCAST));
}
