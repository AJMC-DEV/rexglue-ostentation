/**
 * @file        rex/input/raw_input.h
 * @brief       Raw keyboard/mouse input interface for direct game access.
 *
 * @copyright   Copyright (c) 2026 Tom Clay <tomc@tctechstuff.com>
 *              All rights reserved.
 *
 * @license     BSD 3-Clause License
 *              See LICENSE file in the project root for full license text.
 *
 * This interface allows games to bypass the controller emulation layer
 * and access raw mouse/keyboard input directly. Use this when you need
 * to hook game functions and manually map controls.
 *
 * Example usage:
 * @code
 *   auto* raw_input = input_system->GetRawInput();
 *   if (raw_input) {
 *     auto [dx, dy] = raw_input->GetMouseDelta();
 *     auto [mx, my] = raw_input->GetMovementInput();  // WASD
 *     if (raw_input->IsKeyDown(VirtualKey::kSpace)) { jump(); }
 *   }
 * @endcode
 */

#pragma once

#include <cstdint>
#include <utility>

namespace rex::ui {
enum class VirtualKey : uint16_t;
}

namespace rex::input {

/// Raw mouse/keyboard input interface.
/// Provides direct access to input state without controller emulation.
class IRawInput {
 public:
  virtual ~IRawInput() = default;

  /// Get the accumulated mouse delta since the last call.
  /// Returns (dx, dy) in pixels. Resets the delta to (0, 0).
  /// @note Thread-safe. Can be called from any thread.
  virtual std::pair<int32_t, int32_t> GetMouseDelta() = 0;

  /// Get the accumulated mouse delta without resetting.
  /// Returns (dx, dy) in pixels.
  /// @note Thread-safe. Can be called from any thread.
  virtual std::pair<int32_t, int32_t> PeekMouseDelta() const = 0;

  /// Clear the accumulated mouse delta without reading it.
  virtual void ClearMouseDelta() = 0;

  /// Get the current mouse position in window client coordinates.
  /// Returns (x, y) in pixels.
  virtual std::pair<int32_t, int32_t> GetMousePosition() const = 0;

  /// Check if a key is currently pressed.
  /// @param vk The virtual key code to check.
  /// @return true if the key is currently held down.
  virtual bool IsKeyDown(rex::ui::VirtualKey vk) const = 0;

  /// Check if a key is currently released.
  /// @param vk The virtual key code to check.
  /// @return true if the key is not currently held down.
  bool IsKeyUp(rex::ui::VirtualKey vk) const { return !IsKeyDown(vk); }

  /// Check if a mouse button is currently pressed.
  /// @param button 0=left, 1=right, 2=middle, 3=x1, 4=x2
  /// @return true if the button is currently held down.
  virtual bool IsMouseButtonDown(int button) const = 0;

  /// Check if a mouse button is currently released.
  bool IsMouseButtonUp(int button) const { return !IsMouseButtonDown(button); }

  /// Get WASD movement input as a 2D vector.
  /// Returns (x, y) where:
  ///   x: -1.0 (A/left), 0.0 (neither), +1.0 (D/right)
  ///   y: -1.0 (S/back), 0.0 (neither), +1.0 (W/forward)
  /// The result is NOT normalized (diagonal can be ~1.41).
  /// @note Uses W/A/S/D keys by default.
  virtual std::pair<float, float> GetMovementInput() const = 0;

  /// Get WASD movement input as a normalized 2D vector.
  /// Same as GetMovementInput() but normalized so diagonal movement
  /// has the same magnitude as cardinal movement.
  /// Returns (0, 0) if no movement keys are pressed.
  virtual std::pair<float, float> GetMovementInputNormalized() const = 0;

  /// Check if the raw input system has focus and is capturing input.
  virtual bool HasFocus() const = 0;

  /// Check if mouse capture is currently active.
  virtual bool IsMouseCaptured() const = 0;

  /// Request to capture or release the mouse.
  /// When captured, the cursor is hidden and centered each frame.
  /// @param capture true to capture, false to release.
  virtual void SetMouseCapture(bool capture) = 0;
};

}  // namespace rex::input
