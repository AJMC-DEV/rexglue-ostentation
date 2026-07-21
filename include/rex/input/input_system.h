#pragma once
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

#include <atomic>
#include <functional>
#include <memory>
#include <vector>

#include <rex/input/input.h>
#include <rex/input/input_driver.h>
#include <rex/system/interfaces/input.h>

namespace rex::ui {
class Window;
}

namespace rex::input {

class InputSystem : public system::IInputSystem {
 public:
  explicit InputSystem(rex::ui::Window* window);
  ~InputSystem() override;

  rex::ui::Window* window() const { return window_; }

  X_STATUS Setup() override;
  void Shutdown() override;

  void AddDriver(std::unique_ptr<InputDriver> driver);
  void AttachWindow(rex::ui::Window* window);
  void SetActiveCallback(std::function<bool()> callback);

  void SetInputMode(InputMode mode);
  void SetInputModeGame() { SetInputMode(InputMode::kGame); }
  void SetInputModeUIOnly() { SetInputMode(InputMode::kUIOnly); }
  InputMode input_mode() const { return input_mode_; }

  void SetShowMouseCursor(bool show);
  bool show_mouse_cursor() const { return show_mouse_cursor_; }
  bool IsGameInputActive() const;

  X_RESULT GetCapabilities(uint32_t user_index, uint32_t flags, X_INPUT_CAPABILITIES* out_caps);
  X_RESULT GetState(uint32_t user_index, X_INPUT_STATE* out_state);
  X_RESULT SetState(uint32_t user_index, X_INPUT_VIBRATION* vibration);
  X_RESULT GetKeystroke(uint32_t user_index, uint32_t flags, X_INPUT_KEYSTROKE* out_keystroke);

  // Physical pad slot currently driving the guest's first controller.
  uint32_t active_pad_slot() const { return active_pad_slot_.load(std::memory_order_relaxed); }

 private:
  static constexpr uint32_t kMaxPadSlots = 4;

  void RefreshDriverActiveCallbacks();
  void NotifyInputModeChanged();

  // Hands the guest's first controller to whichever pad the player is using.
  void UpdateActivePadSlot();
  uint32_t ResolveDriverSlot(const InputDriver& driver, uint32_t user_index) const;

  rex::ui::Window* window_ = nullptr;
  std::function<bool()> active_callback_;
  InputMode input_mode_ = InputMode::kGame;
  bool show_mouse_cursor_ = false;

  // Read from the guest's polling thread, written by the same poll path.
  std::atomic<uint32_t> active_pad_slot_{0};
  std::atomic<uint64_t> last_pad_scan_ms_{0};

  std::vector<std::unique_ptr<InputDriver>> drivers_;
};

/// Create a default InputSystem with SDL + NOP drivers.
/// In tool mode, only the NOP driver is added.
std::unique_ptr<InputSystem> CreateDefaultInputSystem(bool tool_mode);

}  // namespace rex::input
