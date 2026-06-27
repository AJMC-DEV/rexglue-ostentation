/**
 * @file        ppc/guest_global.h
 * @brief       Macro-based guest memory global variable accessors.
 *
 * Provides transparent read/write access to big-endian guest memory locations
 * with automatic byte swapping. Generated code from TOML [globals] definitions
 * uses these macros.
 *
 * @copyright   Copyright (c) 2026 Tom Clay <tomc@tctechstuff.com>
 *              All rights reserved.
 *
 * @license     BSD 3-Clause License
 *              See LICENSE file in the project root for full license text.
 */

#pragma once

#include <bit>
#include <cstdint>
#include <type_traits>

#include <rex/types.h>

namespace rex {

/// Global base address for guest virtual memory.
/// Must be set by runtime initialization before accessing guest globals.
inline uint8_t* g_guest_membase = nullptr;

namespace detail {

/// Accessor class for transparent big-endian guest memory access.
/// Supports assignment and implicit conversion with automatic byte swapping.
template <typename T, uint32_t GuestAddr>
struct GuestGlobalAccessor {
  static_assert(std::is_trivially_copyable_v<T>, "GuestGlobal type must be trivially copyable");
  static_assert(sizeof(T) == 1 || sizeof(T) == 2 || sizeof(T) == 4 || sizeof(T) == 8,
                "GuestGlobal type must be 1, 2, 4, or 8 bytes");

  [[nodiscard]] T* raw_ptr() const noexcept {
    return reinterpret_cast<T*>(g_guest_membase + GuestAddr);
  }

  [[nodiscard]] operator T() const noexcept {
    if constexpr (std::is_floating_point_v<T>) {
      using uint_t =
          std::conditional_t<sizeof(T) == 4, uint32_t,
                             std::conditional_t<sizeof(T) == 8, uint64_t, void>>;
      uint_t raw = rex::byte_swap(*reinterpret_cast<uint_t*>(g_guest_membase + GuestAddr));
      return std::bit_cast<T>(raw);
    } else {
      return rex::byte_swap(*raw_ptr());
    }
  }

  GuestGlobalAccessor& operator=(T value) noexcept {
    if constexpr (std::is_floating_point_v<T>) {
      using uint_t =
          std::conditional_t<sizeof(T) == 4, uint32_t,
                             std::conditional_t<sizeof(T) == 8, uint64_t, void>>;
      *reinterpret_cast<uint_t*>(g_guest_membase + GuestAddr) =
          rex::byte_swap(std::bit_cast<uint_t>(value));
    } else {
      *raw_ptr() = rex::byte_swap(value);
    }
    return *this;
  }

  GuestGlobalAccessor& operator+=(T value) noexcept { return *this = static_cast<T>(*this) + value; }
  GuestGlobalAccessor& operator-=(T value) noexcept { return *this = static_cast<T>(*this) - value; }
  GuestGlobalAccessor& operator*=(T value) noexcept { return *this = static_cast<T>(*this) * value; }
  GuestGlobalAccessor& operator/=(T value) noexcept { return *this = static_cast<T>(*this) / value; }

  template <typename U = T>
  std::enable_if_t<std::is_integral_v<U>, GuestGlobalAccessor&> operator&=(U value) noexcept {
    return *this = static_cast<T>(*this) & value;
  }
  template <typename U = T>
  std::enable_if_t<std::is_integral_v<U>, GuestGlobalAccessor&> operator|=(U value) noexcept {
    return *this = static_cast<T>(*this) | value;
  }
  template <typename U = T>
  std::enable_if_t<std::is_integral_v<U>, GuestGlobalAccessor&> operator^=(U value) noexcept {
    return *this = static_cast<T>(*this) ^ value;
  }

  GuestGlobalAccessor& operator++() noexcept { return *this = static_cast<T>(*this) + T{1}; }
  T operator++(int) noexcept {
    T old = *this;
    ++(*this);
    return old;
  }
  GuestGlobalAccessor& operator--() noexcept { return *this = static_cast<T>(*this) - T{1}; }
  T operator--(int) noexcept {
    T old = *this;
    --(*this);
    return old;
  }

  T* operator&() noexcept { return raw_ptr(); }
  const T* operator&() const noexcept { return raw_ptr(); }
};

}  // namespace detail

}  // namespace rex

/// Define a guest global variable accessor.
/// Usage: DEFINE_GUEST_GLOBAL(g_TestGlobal, int32_t, 0x82BF4F38);
/// Then use: g_TestGlobal = 1; int x = g_TestGlobal;
#define DEFINE_GUEST_GLOBAL(name, type, address) \
  inline ::rex::detail::GuestGlobalAccessor<type, address> name {}

/// Define a guest global as a raw pointer (no byteswap, for pointer types).
/// The address itself is the guest address, not the value at that address.
#define DEFINE_GUEST_GLOBAL_PTR(name, type, address) \
  inline type* const name = reinterpret_cast<type*>(::rex::g_guest_membase + (address))
