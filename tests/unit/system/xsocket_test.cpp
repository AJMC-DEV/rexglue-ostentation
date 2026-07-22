/**
 * @file        tests/unit/system/xsocket_test.cpp
 * @brief       Unit tests for logical Xbox socket native-read readiness
 *
 * @copyright   Copyright (c) 2026 Tom Clay <tomc@tctechstuff.com>
 *              All rights reserved.
 *
 * @license     BSD 3-Clause License
 *              See LICENSE file in the project root for full license text.
 */

#include <catch2/catch_test_macros.hpp>

#include <rex/net/socket.h>
#include <rex/platform.h>
#include <rex/system/xsocket.h>

#if REX_PLATFORM_WIN32
#include <WinSock2.h>
#include <WS2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include <algorithm>
#include <array>
#include <cstring>

namespace {

#if REX_PLATFORM_WIN32
struct WinsockScope {
  WinsockScope() {
    WSADATA data{};
    REQUIRE(WSAStartup(MAKEWORD(2, 2), &data) == 0);
  }

  ~WinsockScope() { WSACleanup(); }
};
#endif

uint64_t CreateUdpSender(sockaddr_in* address) {
  const auto sender = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
#if REX_PLATFORM_WIN32
  REQUIRE(sender != INVALID_SOCKET);
#else
  REQUIRE(sender >= 0);
#endif

  address->sin_family = AF_INET;
  address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address->sin_port = 0;
  REQUIRE(bind(sender, reinterpret_cast<const sockaddr*>(address), sizeof(*address)) == 0);

  socklen_t address_len = sizeof(*address);
  REQUIRE(getsockname(sender, reinterpret_cast<sockaddr*>(address), &address_len) == 0);
  return static_cast<uint64_t>(sender);
}

}  // namespace

TEST_CASE("XSocket exposes its primary and owned LAN helper read handles",
          "[runtime][network][lan]") {
#if REX_PLATFORM_WIN32
  WinsockScope winsock;
#endif
  rex::system::XSocket socket(nullptr);
  REQUIRE(socket.Initialize(static_cast<rex::system::XSocket::AddressFamily>(AF_INET),
                            static_cast<rex::system::XSocket::Type>(SOCK_DGRAM),
                            static_cast<rex::system::XSocket::Protocol>(IPPROTO_UDP)) ==
          rex::X_STATUS{0});

  std::array<uint64_t, 2> handles{};
  REQUIRE(socket.GetNativeReadHandles(handles.data(), handles.size()) == 1);
  CHECK(handles[0] == socket.native_handle());
  CHECK(socket.IsNativeReadHandle(handles[0]));

  REQUIRE(socket.EnsureLanProbeSocket(htonl(INADDR_LOOPBACK)));
  REQUIRE(socket.GetNativeReadHandles(handles.data(), handles.size()) == 2);
  CHECK(handles[0] == socket.native_handle());
  CHECK(handles[1] != handles[0]);
  CHECK(socket.IsNativeReadHandle(handles[1]));
}

TEST_CASE("XSocket maps LAN helper readiness and receives its datagram",
          "[runtime][network][lan]") {
#if REX_PLATFORM_WIN32
  WinsockScope winsock;
#endif
  rex::system::XSocket socket(nullptr);
  REQUIRE(socket.Initialize(static_cast<rex::system::XSocket::AddressFamily>(AF_INET),
                            static_cast<rex::system::XSocket::Type>(SOCK_DGRAM),
                            static_cast<rex::system::XSocket::Protocol>(IPPROTO_UDP)) ==
          rex::X_STATUS{0});
  REQUIRE(socket.EnsureLanProbeSocket(htonl(INADDR_LOOPBACK)));

  std::array<uint64_t, 2> handles{};
  REQUIRE(socket.GetNativeReadHandles(handles.data(), handles.size()) == 2);

  sockaddr_in helper_address{};
  socklen_t helper_address_len = sizeof(helper_address);
  REQUIRE(getsockname(handles[1], reinterpret_cast<sockaddr*>(&helper_address),
                      &helper_address_len) == 0);

  sockaddr_in sender_address{};
  const uint64_t sender = CreateUdpSender(&sender_address);
  const std::array<uint8_t, 8> payload = {'V', 'P', '-', 'L', 'A', 'N', '!', 0};
  REQUIRE(sendto(sender, reinterpret_cast<const char*>(payload.data()), payload.size(), 0,
                 reinterpret_cast<const sockaddr*>(&helper_address),
                 sizeof(helper_address)) == static_cast<int>(payload.size()));

  fd_set read_set;
  FD_ZERO(&read_set);
  for (uint64_t handle : handles) {
    FD_SET(handle, &read_set);
  }
  timeval timeout{1, 0};
  const auto max_handle = *std::max_element(handles.begin(), handles.end());
  REQUIRE(select(static_cast<int>(max_handle + 1), &read_set, nullptr, nullptr, &timeout) == 1);
  REQUIRE(FD_ISSET(handles[1], &read_set));
  CHECK(socket.IsNativeReadHandle(handles[1]));

  std::array<uint8_t, 32> received{};
  rex::system::N_XSOCKADDR_IN from{};
  uint32_t from_len = sizeof(from);
  REQUIRE(socket.RecvFrom(received.data(), received.size(), 0, &from, &from_len) ==
          static_cast<int>(payload.size()));
  CHECK(std::memcmp(received.data(), payload.data(), payload.size()) == 0);
  CHECK(static_cast<uint32_t>(from.sin_addr) == ntohl(sender_address.sin_addr.s_addr));
  CHECK(static_cast<uint16_t>(from.sin_port) == ntohs(sender_address.sin_port));
  CHECK(from_len == sizeof(from));

  rex::net::socket_close(sender);
}

TEST_CASE("XSocket punches the LAN session port and swallows punch tags",
          "[runtime][network][lan]") {
#if REX_PLATFORM_WIN32
  WinsockScope winsock;
#endif
  constexpr uint16_t kDataPort = 45871;
  rex::system::XSocket data(nullptr);
  REQUIRE(data.Initialize(static_cast<rex::system::XSocket::AddressFamily>(AF_INET),
                          static_cast<rex::system::XSocket::Type>(SOCK_DGRAM),
                          static_cast<rex::system::XSocket::Protocol>(IPPROTO_UDP)) ==
          rex::X_STATUS{0});
  rex::system::N_XSOCKADDR_IN bind_addr{};
  bind_addr.sin_family = AF_INET;
  bind_addr.sin_port = kDataPort;
  bind_addr.sin_addr = 0;
  REQUIRE(data.Bind(&bind_addr, sizeof(sockaddr_in)) == rex::X_STATUS{0});

  sockaddr_in receiver_address{};
  const uint64_t receiver = CreateUdpSender(&receiver_address);

  REQUIRE(rex::system::XSocket::PunchFromBoundUdpSocket(
      kDataPort, receiver_address.sin_addr.s_addr, ntohs(receiver_address.sin_port)));

  fd_set read_set;
  FD_ZERO(&read_set);
  FD_SET(receiver, &read_set);
  timeval timeout{1, 0};
  REQUIRE(select(static_cast<int>(receiver + 1), &read_set, nullptr, nullptr, &timeout) == 1);
  std::array<uint8_t, 16> punch{};
  REQUIRE(recv(receiver, reinterpret_cast<char*>(punch.data()), punch.size(), 0) == 4);
  CHECK(std::memcmp(punch.data(), "RXPH", 4) == 0);

  sockaddr_in data_address{};
  data_address.sin_family = AF_INET;
  data_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  data_address.sin_port = htons(kDataPort);
  const std::array<uint8_t, 4> tag = {'R', 'X', 'P', 'H'};
  const std::array<uint8_t, 5> payload = {'j', 'o', 'i', 'n', '!'};
  REQUIRE(sendto(receiver, reinterpret_cast<const char*>(tag.data()), tag.size(), 0,
                 reinterpret_cast<const sockaddr*>(&data_address),
                 sizeof(data_address)) == static_cast<int>(tag.size()));
  REQUIRE(sendto(receiver, reinterpret_cast<const char*>(payload.data()), payload.size(), 0,
                 reinterpret_cast<const sockaddr*>(&data_address),
                 sizeof(data_address)) == static_cast<int>(payload.size()));

  std::array<uint8_t, 16> received{};
  rex::system::N_XSOCKADDR_IN from{};
  uint32_t from_len = sizeof(from);
  REQUIRE(data.RecvFrom(received.data(), received.size(), 0, &from, &from_len) ==
          static_cast<int>(payload.size()));
  CHECK(std::memcmp(received.data(), payload.data(), payload.size()) == 0);
  // The native receive path must report the source endpoint in the byte
  // order the guest expects, like the injected helper path does; a raw
  // network-order write reads back byte-swapped (1000 becomes 59395).
  CHECK(static_cast<uint32_t>(from.sin_addr) == ntohl(receiver_address.sin_addr.s_addr));
  CHECK(static_cast<uint16_t>(from.sin_port) == ntohs(receiver_address.sin_port));

  REQUIRE(data.Close() == rex::X_STATUS{0});
  CHECK_FALSE(rex::system::XSocket::PunchFromBoundUdpSocket(
      kDataPort, receiver_address.sin_addr.s_addr, ntohs(receiver_address.sin_port)));

  rex::net::socket_close(receiver);
}


TEST_CASE("XSocket LAN helpers isolate readiness and packets by owner", "[runtime][network][lan]") {
#if REX_PLATFORM_WIN32
  WinsockScope winsock;
#endif
  rex::system::XSocket first(nullptr);
  rex::system::XSocket second(nullptr);
  const auto af = static_cast<rex::system::XSocket::AddressFamily>(AF_INET);
  const auto type = static_cast<rex::system::XSocket::Type>(SOCK_DGRAM);
  const auto protocol = static_cast<rex::system::XSocket::Protocol>(IPPROTO_UDP);
  REQUIRE(first.Initialize(af, type, protocol) == rex::X_STATUS{0});
  REQUIRE(second.Initialize(af, type, protocol) == rex::X_STATUS{0});
  REQUIRE(first.EnsureLanProbeSocket(htonl(INADDR_LOOPBACK)));
  REQUIRE(second.EnsureLanProbeSocket(htonl(INADDR_LOOPBACK)));

  std::array<uint64_t, 2> first_handles{};
  std::array<uint64_t, 2> second_handles{};
  REQUIRE(first.GetNativeReadHandles(first_handles.data(), first_handles.size()) == 2);
  REQUIRE(second.GetNativeReadHandles(second_handles.data(), second_handles.size()) == 2);
  REQUIRE(first_handles[1] != second_handles[1]);
  CHECK_FALSE(first.IsNativeReadHandle(second_handles[1]));
  CHECK_FALSE(second.IsNativeReadHandle(first_handles[1]));

  sockaddr_in first_helper{};
  sockaddr_in second_helper{};
  socklen_t address_len = sizeof(sockaddr_in);
  REQUIRE(getsockname(first_handles[1], reinterpret_cast<sockaddr*>(&first_helper), &address_len) ==
          0);
  address_len = sizeof(sockaddr_in);
  REQUIRE(getsockname(second_handles[1], reinterpret_cast<sockaddr*>(&second_helper),
                      &address_len) == 0);

  sockaddr_in sender_address{};
  const uint64_t sender = CreateUdpSender(&sender_address);
  const std::array<uint8_t, 5> first_payload = {'f', 'i', 'r', 's', 't'};
  const std::array<uint8_t, 6> second_payload = {'s', 'e', 'c', 'o', 'n', 'd'};
  REQUIRE(sendto(sender, reinterpret_cast<const char*>(first_payload.data()), first_payload.size(),
                 0, reinterpret_cast<const sockaddr*>(&first_helper),
                 sizeof(first_helper)) == static_cast<int>(first_payload.size()));
  REQUIRE(sendto(sender, reinterpret_cast<const char*>(second_payload.data()),
                 second_payload.size(), 0, reinterpret_cast<const sockaddr*>(&second_helper),
                 sizeof(second_helper)) == static_cast<int>(second_payload.size()));

  std::array<uint8_t, 16> received{};
  rex::system::N_XSOCKADDR_IN from{};
  uint32_t from_len = sizeof(from);
  REQUIRE(first.RecvFrom(received.data(), received.size(), 0, &from, &from_len) ==
          static_cast<int>(first_payload.size()));
  CHECK(std::memcmp(received.data(), first_payload.data(), first_payload.size()) == 0);

  received.fill(0);
  from_len = sizeof(from);
  REQUIRE(second.RecvFrom(received.data(), received.size(), 0, &from, &from_len) ==
          static_cast<int>(second_payload.size()));
  CHECK(std::memcmp(received.data(), second_payload.data(), second_payload.size()) == 0);

  rex::net::socket_close(sender);
}
