/**
 * @file        input/mnk/mnk_input_driver.cpp
 * @brief       Keyboard/mouse input driver implementation.
 *
 * @copyright   Copyright (c) 2026 Tom Clay <tomc@tctechstuff.com>
 *              All rights reserved.
 *
 * @license     BSD 3-Clause License
 *              See LICENSE file in the project root for full license text.
 */
#include <rex/input/mnk/mnk_input_driver.h>

#include <rex/cvar.h>
#include <rex/input/input.h>
#include <rex/logging.h>
#include <rex/ui/keybinds.h>
#include <rex/ui/virtual_key.h>
#include <rex/ui/window.h>

#include <algorithm>
#include <cmath>
#include <cstring>

#if REX_PLATFORM_WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#endif

REXCVAR_DEFINE_BOOL(mnk_mode, false, "Input", "Enable keyboard/mouse controller emulation");
REXCVAR_DEFINE_INT32(mnk_user_index, 0, "Input", "Controller slot (0-3) for MnK").range(0, 3);
REXCVAR_DEFINE_DOUBLE(mnk_sensitivity, 1.0, "Input", "Mouse sensitivity for right stick")
    .range(0.01, 10.0);
REXCVAR_DEFINE_DOUBLE(mnk_lstick_scale, 1.0, "Input", "Keyboard left stick scale")
    .range(0.1, 1.0);
REXCVAR_DEFINE_DOUBLE(mnk_lstick_walk_scale, 0.35, "Input", "Keyboard left stick walk scale")
    .range(0.05, 1.0);
REXCVAR_DEFINE_INT32(mnk_keystroke_repeat_delay_ms, 250, "Input",
                     "Delay before keystroke repeat starts (ms)")
    .range(50, 2000);
REXCVAR_DEFINE_INT32(mnk_keystroke_repeat_rate_ms, 33, "Input",
                     "Keystroke repeat interval after the initial delay (ms)")
    .range(10, 500);
REXCVAR_DEFINE_BOOL(mnk_emit_rstick_keystrokes, false, "Input",
                    "Emit XInput keystrokes for the right stick. Disabled by default since "
                    "the stick is mouse-driven and continuous; threshold-based emission can "
                    "noise the queue during normal aiming. Enable for titles whose menus are "
                    "navigated by right-stick keystrokes.");

REXCVAR_DEFINE_STRING(keybind_a, "Space", "Input/Keybinds/Controller", "A button");
REXCVAR_DEFINE_STRING(keybind_b, "Shift", "Input/Keybinds/Controller", "B button");
REXCVAR_DEFINE_STRING(keybind_x, "R", "Input/Keybinds/Controller", "X button");
REXCVAR_DEFINE_STRING(keybind_y, "E", "Input/Keybinds/Controller", "Y button");
REXCVAR_DEFINE_STRING(keybind_left_trigger, "RMB", "Input/Keybinds/Controller", "Left trigger");
REXCVAR_DEFINE_STRING(keybind_right_trigger, "LMB", "Input/Keybinds/Controller", "Right trigger");
REXCVAR_DEFINE_STRING(keybind_left_shoulder, "Q", "Input/Keybinds/Controller", "Left shoulder");
REXCVAR_DEFINE_STRING(keybind_right_shoulder, "F", "Input/Keybinds/Controller", "Right shoulder");
REXCVAR_DEFINE_STRING(keybind_lstick_up, "W", "Input/Keybinds/Controller", "Left stick up");
REXCVAR_DEFINE_STRING(keybind_lstick_down, "S", "Input/Keybinds/Controller", "Left stick down");
REXCVAR_DEFINE_STRING(keybind_lstick_left, "A", "Input/Keybinds/Controller", "Left stick left");
REXCVAR_DEFINE_STRING(keybind_lstick_right, "D", "Input/Keybinds/Controller", "Left stick right");
REXCVAR_DEFINE_STRING(keybind_lstick_press, "C", "Input/Keybinds/Controller", "Left stick press");
REXCVAR_DEFINE_STRING(keybind_lstick_walk, "Control", "Input/Keybinds/Controller",
                      "Left stick walk modifier");
REXCVAR_DEFINE_STRING(keybind_rstick_press, "MMB", "Input/Keybinds/Controller",
                      "Right stick press");
REXCVAR_DEFINE_STRING(keybind_dpad_up, "Up", "Input/Keybinds/Controller", "D-pad up");
REXCVAR_DEFINE_STRING(keybind_dpad_down, "Down", "Input/Keybinds/Controller", "D-pad down");
REXCVAR_DEFINE_STRING(keybind_dpad_left, "Left", "Input/Keybinds/Controller", "D-pad left");
REXCVAR_DEFINE_STRING(keybind_dpad_right, "Right", "Input/Keybinds/Controller", "D-pad right");
REXCVAR_DEFINE_STRING(keybind_back, "Tab", "Input/Keybinds/Controller", "Back button");
REXCVAR_DEFINE_STRING(keybind_start, "Escape", "Input/Keybinds/Controller", "Start button");
REXCVAR_DEFINE_STRING(keybind_guide, "", "Input/Keybinds/Controller", "Guide button");

namespace rex::input::mnk {

using rex::ui::VirtualKey;

MnkInputDriver::MnkInputDriver(rex::ui::Window* window, size_t window_z_order)
    : InputDriver(window, window_z_order) {}

MnkInputDriver::~MnkInputDriver() {
  if (attached_window_) {
    attached_window_->RemoveInputListener(this);
    attached_window_->RemoveListener(this);
    attached_window_ = nullptr;
  }
}

X_STATUS MnkInputDriver::Setup() {
  REXLOG_INFO("MnK input driver initialized");
  return X_STATUS_SUCCESS;
}

void MnkInputDriver::OnWindowAvailable(rex::ui::Window* window) {
  if (window) {
    attached_window_ = window;
    window->AddInputListener(this, window_z_order());
    window->AddListener(this);
  }
}

void MnkInputDriver::OnInputModeChanged(InputMode mode, bool show_mouse_cursor) {
  {
    std::lock_guard lock(state_mutex_);
    input_mode_ = mode;
    show_mouse_cursor_ = show_mouse_cursor;
    if (mode != InputMode::kGame) {
      ResetInputState();
    }
  }
  UpdateMouseCapture();
}

void MnkInputDriver::OnClosing(rex::ui::UIEvent&) {
  if (attached_window_) {
    if (mouse_captured_) {
      mouse_captured_ = false;
      attached_window_->SetCursorVisibility(rex::ui::Window::CursorVisibility::kVisible);
      attached_window_->ReleaseMouse();
    }
    attached_window_->RemoveInputListener(this);
    attached_window_->RemoveListener(this);
    attached_window_ = nullptr;
  }
}

uint32_t MnkInputDriver::UserIndex() const {
  return static_cast<uint32_t>(REXCVAR_GET(mnk_user_index));
}

bool MnkInputDriver::IsEnabled() const {
  return REXCVAR_GET(mnk_mode);
}

// Cvar values may list multiple keys separated by ',' or '|' so a single
// action can be bound to several physical inputs (e.g. "LMB,A"). Whitespace
// around tokens is trimmed; empty tokens are ignored.
template <typename Fn>
static void ForEachBoundKey(const std::string& cvar_val, Fn&& fn) {
  size_t i = 0;
  while (i < cvar_val.size()) {
    size_t j = cvar_val.find_first_of(",|", i);
    if (j == std::string::npos) j = cvar_val.size();
    size_t a = i, b = j;
    while (a < b && (cvar_val[a] == ' ' || cvar_val[a] == '\t')) ++a;
    while (b > a && (cvar_val[b - 1] == ' ' || cvar_val[b - 1] == '\t')) --b;
    if (b > a) {
      VirtualKey vk = rex::ui::ParseVirtualKey(std::string_view(cvar_val).substr(a, b - a));
      if (vk != VirtualKey::kNone && fn(vk)) return;
    }
    i = (j == cvar_val.size()) ? j : j + 1;
  }
}

static bool IsBindPressed(const bool (&key_down)[256], const std::string& cvar_val) {
  bool pressed = false;
  ForEachBoundKey(cvar_val, [&](VirtualKey vk) {
    uint16_t idx = static_cast<uint16_t>(vk);
    if (idx < 256 && key_down[idx]) {
      pressed = true;
      return true;
    }
    return false;
  });
  return pressed;
}

X_RESULT MnkInputDriver::GetCapabilities(uint32_t user_index, uint32_t flags,
                                         X_INPUT_CAPABILITIES* out_caps) {
  if (!IsEnabled() || user_index != UserIndex()) {
    return X_ERROR_DEVICE_NOT_CONNECTED;
  }
  if (out_caps) {
    std::memset(out_caps, 0, sizeof(*out_caps));
    out_caps->type = 0x01;
    out_caps->sub_type = 0x01;
    out_caps->flags = 0;
    out_caps->gamepad.buttons = 0xFFFF;
    out_caps->gamepad.left_trigger = 0xFF;
    out_caps->gamepad.right_trigger = 0xFF;
    out_caps->gamepad.thumb_lx = static_cast<int16_t>(0x7FFF);
    out_caps->gamepad.thumb_ly = static_cast<int16_t>(0x7FFF);
    out_caps->gamepad.thumb_rx = static_cast<int16_t>(0x7FFF);
    out_caps->gamepad.thumb_ry = static_cast<int16_t>(0x7FFF);
    out_caps->vibration.left_motor_speed = 0xFFFF;
    out_caps->vibration.right_motor_speed = 0xFFFF;
  }
  return X_ERROR_SUCCESS;
}

X_RESULT MnkInputDriver::GetState(uint32_t user_index, X_INPUT_STATE* out_state) {
  if (!IsEnabled() || user_index != UserIndex()) {
    return X_ERROR_DEVICE_NOT_CONNECTED;
  }

  UpdateMouseCapture();

  if (!is_active() || !has_focus_) {
    std::lock_guard lock(state_mutex_);
    ResetInputState();
    if (out_state) {
      std::memset(out_state, 0, sizeof(*out_state));
      out_state->packet_number = packet_number_;
    }
    return X_ERROR_SUCCESS;
  }

  std::lock_guard lock(state_mutex_);

  uint16_t buttons = 0;
  if (IsBindPressed(key_down_, REXCVAR_GET(keybind_a)))
    buttons |= X_INPUT_GAMEPAD_A;
  if (IsBindPressed(key_down_, REXCVAR_GET(keybind_b)))
    buttons |= X_INPUT_GAMEPAD_B;
  if (IsBindPressed(key_down_, REXCVAR_GET(keybind_x)))
    buttons |= X_INPUT_GAMEPAD_X;
  if (IsBindPressed(key_down_, REXCVAR_GET(keybind_y)))
    buttons |= X_INPUT_GAMEPAD_Y;
  if (IsBindPressed(key_down_, REXCVAR_GET(keybind_left_shoulder)))
    buttons |= X_INPUT_GAMEPAD_LEFT_SHOULDER;
  if (IsBindPressed(key_down_, REXCVAR_GET(keybind_right_shoulder)))
    buttons |= X_INPUT_GAMEPAD_RIGHT_SHOULDER;
  if (IsBindPressed(key_down_, REXCVAR_GET(keybind_lstick_press)))
    buttons |= X_INPUT_GAMEPAD_LEFT_THUMB;
  if (IsBindPressed(key_down_, REXCVAR_GET(keybind_rstick_press)))
    buttons |= X_INPUT_GAMEPAD_RIGHT_THUMB;
  if (IsBindPressed(key_down_, REXCVAR_GET(keybind_back)))
    buttons |= X_INPUT_GAMEPAD_BACK;
  if (IsBindPressed(key_down_, REXCVAR_GET(keybind_start)))
    buttons |= X_INPUT_GAMEPAD_START;
  if (IsBindPressed(key_down_, REXCVAR_GET(keybind_guide)))
    buttons |= X_INPUT_GAMEPAD_GUIDE;
  if (IsBindPressed(key_down_, REXCVAR_GET(keybind_dpad_up)))
    buttons |= X_INPUT_GAMEPAD_DPAD_UP;
  if (IsBindPressed(key_down_, REXCVAR_GET(keybind_dpad_down)))
    buttons |= X_INPUT_GAMEPAD_DPAD_DOWN;
  if (IsBindPressed(key_down_, REXCVAR_GET(keybind_dpad_left)))
    buttons |= X_INPUT_GAMEPAD_DPAD_LEFT;
  if (IsBindPressed(key_down_, REXCVAR_GET(keybind_dpad_right)))
    buttons |= X_INPUT_GAMEPAD_DPAD_RIGHT;

  uint8_t lt = IsBindPressed(key_down_, REXCVAR_GET(keybind_left_trigger)) ? 0xFF : 0;
  uint8_t rt = IsBindPressed(key_down_, REXCVAR_GET(keybind_right_trigger)) ? 0xFF : 0;

  int32_t lx = 0;
  int32_t ly = 0;
  if (IsBindPressed(key_down_, REXCVAR_GET(keybind_lstick_left)))
    lx -= INT16_MAX;
  if (IsBindPressed(key_down_, REXCVAR_GET(keybind_lstick_right)))
    lx += INT16_MAX;
  if (IsBindPressed(key_down_, REXCVAR_GET(keybind_lstick_up)))
    ly += INT16_MAX;
  if (IsBindPressed(key_down_, REXCVAR_GET(keybind_lstick_down)))
    ly -= INT16_MAX;

  if (lx || ly) {
    double mag = std::sqrt(static_cast<double>(lx) * lx + static_cast<double>(ly) * ly);
    if (mag > INT16_MAX) {
      double scale = static_cast<double>(INT16_MAX) / mag;
      lx = static_cast<int32_t>(std::round(static_cast<double>(lx) * scale));
      ly = static_cast<int32_t>(std::round(static_cast<double>(ly) * scale));
    }

    double scale = IsBindPressed(key_down_, REXCVAR_GET(keybind_lstick_walk))
                       ? REXCVAR_GET(mnk_lstick_walk_scale)
                       : REXCVAR_GET(mnk_lstick_scale);
    lx = static_cast<int32_t>(std::round(static_cast<double>(lx) * scale));
    ly = static_cast<int32_t>(std::round(static_cast<double>(ly) * scale));
  }

  double sensitivity = REXCVAR_GET(mnk_sensitivity);
  constexpr double kBaseScale = 200.0;
  int32_t rx = static_cast<int32_t>(mouse_dx_ * sensitivity * kBaseScale);
  int32_t ry = static_cast<int32_t>(-mouse_dy_ * sensitivity * kBaseScale);
  mouse_dx_ = 0;
  mouse_dy_ = 0;

  auto clamp16 = [](int32_t v) -> int16_t {
    return static_cast<int16_t>(std::clamp(v, (int32_t)INT16_MIN, (int32_t)INT16_MAX));
  };

  packet_number_++;

  TickRepeats();
  EnqueueRStickIfChanged(clamp16(rx), clamp16(ry));

  if (out_state) {
    out_state->packet_number = packet_number_;
    out_state->gamepad.buttons = buttons;
    out_state->gamepad.left_trigger = lt;
    out_state->gamepad.right_trigger = rt;
    out_state->gamepad.thumb_lx = clamp16(lx);
    out_state->gamepad.thumb_ly = clamp16(ly);
    out_state->gamepad.thumb_rx = clamp16(rx);
    out_state->gamepad.thumb_ry = clamp16(ry);
  }
  return X_ERROR_SUCCESS;
}

X_RESULT MnkInputDriver::SetState(uint32_t user_index, X_INPUT_VIBRATION* vibration) {
  if (!IsEnabled() || user_index != UserIndex()) {
    return X_ERROR_DEVICE_NOT_CONNECTED;
  }
  return X_ERROR_SUCCESS;
}

X_RESULT MnkInputDriver::GetKeystroke(uint32_t user_index, uint32_t flags,
                                      X_INPUT_KEYSTROKE* out_keystroke) {
  if (!IsEnabled() || user_index != UserIndex()) {
    return X_ERROR_DEVICE_NOT_CONNECTED;
  }
  std::lock_guard lock(state_mutex_);
  if (!is_active() || !has_focus_) {
    ResetInputState();
    return X_ERROR_EMPTY;
  }
  TickRepeats();
  if (keystroke_queue_.empty()) {
    return X_ERROR_EMPTY;
  }
  if (out_keystroke) {
    *out_keystroke = keystroke_queue_.front();
  }
  keystroke_queue_.pop();
  return X_ERROR_SUCCESS;
}

void MnkInputDriver::EnqueueKeystroke(uint16_t vk_pad, uint16_t flags) {
  X_INPUT_KEYSTROKE ks = {};
  ks.virtual_key = vk_pad;
  ks.unicode = 0;
  ks.flags = flags;
  ks.user_index = static_cast<uint8_t>(UserIndex());
  ks.hid_code = 0;
  keystroke_queue_.push(ks);
}

void MnkInputDriver::HandleEdge(PadIdx idx, uint16_t vk_pad, bool down) {
  auto& s = pad_states_[idx];
  if (down && !s.held) {
    auto now = std::chrono::steady_clock::now();
    s.held = true;
    s.vk_pad = vk_pad;
    s.pressed_at = now;
    s.last_event_at = now;
    EnqueueKeystroke(vk_pad, X_INPUT_KEYSTROKE_KEYDOWN);
  } else if (!down && s.held) {
    s.held = false;
    EnqueueKeystroke(s.vk_pad, X_INPUT_KEYSTROKE_KEYUP);
  }
}

void MnkInputDriver::HandleStickDirChange(PadIdx idx, uint16_t new_dir) {
  auto& s = pad_states_[idx];
  if (new_dir == s.vk_pad)
    return;
  if (s.held) {
    EnqueueKeystroke(s.vk_pad, X_INPUT_KEYSTROKE_KEYUP);
    s.held = false;
  }
  s.vk_pad = new_dir;
  if (new_dir != static_cast<uint16_t>(VirtualKey::kNone)) {
    auto now = std::chrono::steady_clock::now();
    s.held = true;
    s.pressed_at = now;
    s.last_event_at = now;
    EnqueueKeystroke(new_dir, X_INPUT_KEYSTROKE_KEYDOWN);
  }
}

void MnkInputDriver::EmitButtonChange(VirtualKey key_vk, bool down) {
  auto try_match = [this, key_vk, down](const std::string& cvar_val, PadIdx idx,
                                        VirtualKey vk_pad) {
    bool matched = false;
    ForEachBoundKey(cvar_val, [&](VirtualKey vk) {
      if (vk == key_vk) {
        matched = true;
        return true;
      }
      return false;
    });
    if (matched) {
      HandleEdge(idx, static_cast<uint16_t>(vk_pad), down);
    }
  };
  try_match(REXCVAR_GET(keybind_a), kPadIdxA, VirtualKey::kXInputPadA);
  try_match(REXCVAR_GET(keybind_b), kPadIdxB, VirtualKey::kXInputPadB);
  try_match(REXCVAR_GET(keybind_x), kPadIdxX, VirtualKey::kXInputPadX);
  try_match(REXCVAR_GET(keybind_y), kPadIdxY, VirtualKey::kXInputPadY);
  try_match(REXCVAR_GET(keybind_left_shoulder), kPadIdxLB, VirtualKey::kXInputPadLShoulder);
  try_match(REXCVAR_GET(keybind_right_shoulder), kPadIdxRB, VirtualKey::kXInputPadRShoulder);
  try_match(REXCVAR_GET(keybind_start), kPadIdxStart, VirtualKey::kXInputPadStart);
  try_match(REXCVAR_GET(keybind_back), kPadIdxBack, VirtualKey::kXInputPadBack);
  try_match(REXCVAR_GET(keybind_lstick_press), kPadIdxL3, VirtualKey::kXInputPadLThumbPress);
  try_match(REXCVAR_GET(keybind_rstick_press), kPadIdxR3, VirtualKey::kXInputPadRThumbPress);
  try_match(REXCVAR_GET(keybind_dpad_up), kPadIdxDU, VirtualKey::kXInputPadDpadUp);
  try_match(REXCVAR_GET(keybind_dpad_down), kPadIdxDD, VirtualKey::kXInputPadDpadDown);
  try_match(REXCVAR_GET(keybind_dpad_left), kPadIdxDL, VirtualKey::kXInputPadDpadLeft);
  try_match(REXCVAR_GET(keybind_dpad_right), kPadIdxDR, VirtualKey::kXInputPadDpadRight);
  try_match(REXCVAR_GET(keybind_left_trigger), kPadIdxLT, VirtualKey::kXInputPadLTrigger);
  try_match(REXCVAR_GET(keybind_right_trigger), kPadIdxRT, VirtualKey::kXInputPadRTrigger);
}

void MnkInputDriver::RecomputeLstickDir() {
  bool up = IsBindPressed(key_down_, REXCVAR_GET(keybind_lstick_up));
  bool dn = IsBindPressed(key_down_, REXCVAR_GET(keybind_lstick_down));
  bool lf = IsBindPressed(key_down_, REXCVAR_GET(keybind_lstick_left));
  bool rt = IsBindPressed(key_down_, REXCVAR_GET(keybind_lstick_right));

  uint16_t dir = static_cast<uint16_t>(VirtualKey::kNone);
  if (up && rt)
    dir = static_cast<uint16_t>(VirtualKey::kXInputPadLThumbUpRight);
  else if (up && lf)
    dir = static_cast<uint16_t>(VirtualKey::kXInputPadLThumbUpLeft);
  else if (dn && rt)
    dir = static_cast<uint16_t>(VirtualKey::kXInputPadLThumbDownRight);
  else if (dn && lf)
    dir = static_cast<uint16_t>(VirtualKey::kXInputPadLThumbDownLeft);
  else if (up)
    dir = static_cast<uint16_t>(VirtualKey::kXInputPadLThumbUp);
  else if (dn)
    dir = static_cast<uint16_t>(VirtualKey::kXInputPadLThumbDown);
  else if (rt)
    dir = static_cast<uint16_t>(VirtualKey::kXInputPadLThumbRight);
  else if (lf)
    dir = static_cast<uint16_t>(VirtualKey::kXInputPadLThumbLeft);

  HandleStickDirChange(kPadIdxLStick, dir);
}

void MnkInputDriver::EnqueueRStickIfChanged(int16_t rx, int16_t ry) {
  if (!REXCVAR_GET(mnk_emit_rstick_keystrokes)) {
    return;
  }
  constexpr int16_t kThreshold = 8192;
  bool up = ry > kThreshold;
  bool dn = ry < -kThreshold;
  bool lf = rx < -kThreshold;
  bool rt = rx > kThreshold;

  uint16_t dir = static_cast<uint16_t>(VirtualKey::kNone);
  if (up && rt)
    dir = static_cast<uint16_t>(VirtualKey::kXInputPadRThumbUpRight);
  else if (up && lf)
    dir = static_cast<uint16_t>(VirtualKey::kXInputPadRThumbUpLeft);
  else if (dn && rt)
    dir = static_cast<uint16_t>(VirtualKey::kXInputPadRThumbDownRight);
  else if (dn && lf)
    dir = static_cast<uint16_t>(VirtualKey::kXInputPadRThumbDownLeft);
  else if (up)
    dir = static_cast<uint16_t>(VirtualKey::kXInputPadRThumbUp);
  else if (dn)
    dir = static_cast<uint16_t>(VirtualKey::kXInputPadRThumbDown);
  else if (rt)
    dir = static_cast<uint16_t>(VirtualKey::kXInputPadRThumbRight);
  else if (lf)
    dir = static_cast<uint16_t>(VirtualKey::kXInputPadRThumbLeft);

  HandleStickDirChange(kPadIdxRStick, dir);
}

void MnkInputDriver::TickRepeats() {
  if (!IsEnabled() || !has_focus_) {
    return;
  }
  auto now = std::chrono::steady_clock::now();
  auto delay = std::chrono::milliseconds(REXCVAR_GET(mnk_keystroke_repeat_delay_ms));
  auto rate = std::chrono::milliseconds(REXCVAR_GET(mnk_keystroke_repeat_rate_ms));
  for (auto& s : pad_states_) {
    if (!s.held)
      continue;
    if (now - s.pressed_at < delay)
      continue;
    if (now - s.last_event_at < rate)
      continue;
    EnqueueKeystroke(s.vk_pad, X_INPUT_KEYSTROKE_REPEAT);
    s.last_event_at = now;
  }
}

void MnkInputDriver::CenterCursor() {
  if (!attached_window_)
    return;
  int32_t cx = static_cast<int32_t>(attached_window_->GetActualLogicalWidth() / 2);
  int32_t cy = static_cast<int32_t>(attached_window_->GetActualLogicalHeight() / 2);
  prev_mouse_x_ = cx;
  prev_mouse_y_ = cy;
#if REX_PLATFORM_WIN32
  HWND hwnd = reinterpret_cast<HWND>(attached_window_->GetNativeWindowHandle());
  if (hwnd) {
    POINT pt = {static_cast<LONG>(cx), static_cast<LONG>(cy)};
    ClientToScreen(hwnd, &pt);
    SetCursorPos(pt.x, pt.y);
  }
#endif
}

void MnkInputDriver::UpdateMouseCapture() {
  if (!attached_window_)
    return;

  bool active = is_active();
  bool should_capture = IsEnabled() && has_focus_ && active && !show_mouse_cursor_;

  if (should_capture && !mouse_captured_) {
    mouse_captured_ = true;
    attached_window_->SetCursorVisibility(rex::ui::Window::CursorVisibility::kHidden);
    attached_window_->CaptureMouse();
    mouse_dx_ = 0;
    mouse_dy_ = 0;
  } else if (!should_capture && mouse_captured_) {
    mouse_captured_ = false;
    attached_window_->ReleaseMouse();
  }

  if (should_capture) {
    attached_window_->SetCursorVisibility(rex::ui::Window::CursorVisibility::kHidden);
  } else if (show_mouse_cursor_ || input_mode_ == InputMode::kGame || !active) {
    attached_window_->SetCursorVisibility(rex::ui::Window::CursorVisibility::kVisible);
  }

  if (mouse_captured_) {
    CenterCursor();
  }
}

void MnkInputDriver::ResetInputState() {
  std::memset(key_down_, 0, sizeof(key_down_));
  mouse_dx_ = 0;
  mouse_dy_ = 0;
  std::queue<X_INPUT_KEYSTROKE> empty;
  std::swap(keystroke_queue_, empty);
  for (auto& s : pad_states_) {
    s.held = false;
    s.vk_pad = static_cast<uint16_t>(VirtualKey::kNone);
  }
}

void MnkInputDriver::SetKeyState(uint16_t vk, bool down) {
  if (vk < 256) {
    key_down_[vk] = down;
  }
}

void MnkInputDriver::OnKeyDown(rex::ui::KeyEvent& e) {
  if (!IsEnabled() || !has_focus_ || !is_active())
    return;
  std::lock_guard lock(state_mutex_);
  VirtualKey vk = e.virtual_key();
  uint16_t idx = static_cast<uint16_t>(vk);
  bool was_down = (idx < 256) && key_down_[idx];
  SetKeyState(idx, true);
  if (!was_down) {
    EmitButtonChange(vk, true);
    RecomputeLstickDir();
  }
}

void MnkInputDriver::OnKeyUp(rex::ui::KeyEvent& e) {
  if (!IsEnabled())
    return;
  bool can_emit = has_focus_ && is_active();
  std::lock_guard lock(state_mutex_);
  VirtualKey vk = e.virtual_key();
  uint16_t idx = static_cast<uint16_t>(vk);
  bool was_down = (idx < 256) && key_down_[idx];
  SetKeyState(idx, false);
  if (was_down && can_emit) {
    EmitButtonChange(vk, false);
    RecomputeLstickDir();
  }
}

void MnkInputDriver::OnMouseDown(rex::ui::MouseEvent& e) {
  if (!IsEnabled() || !has_focus_ || !is_active())
    return;
  std::lock_guard lock(state_mutex_);
  VirtualKey vk = VirtualKey::kNone;
  switch (e.button()) {
    case rex::ui::MouseEvent::Button::kLeft:
      vk = VirtualKey::kLButton;
      break;
    case rex::ui::MouseEvent::Button::kRight:
      vk = VirtualKey::kRButton;
      break;
    case rex::ui::MouseEvent::Button::kMiddle:
      vk = VirtualKey::kMButton;
      break;
    case rex::ui::MouseEvent::Button::kX1:
      vk = VirtualKey::kXButton1;
      break;
    case rex::ui::MouseEvent::Button::kX2:
      vk = VirtualKey::kXButton2;
      break;
    default:
      return;
  }
  uint16_t idx = static_cast<uint16_t>(vk);
  bool was_down = (idx < 256) && key_down_[idx];
  SetKeyState(idx, true);
  if (!was_down) {
    EmitButtonChange(vk, true);
    RecomputeLstickDir();
  }
}

void MnkInputDriver::OnMouseUp(rex::ui::MouseEvent& e) {
  if (!IsEnabled())
    return;
  bool can_emit = has_focus_ && is_active();
  std::lock_guard lock(state_mutex_);
  VirtualKey vk = VirtualKey::kNone;
  switch (e.button()) {
    case rex::ui::MouseEvent::Button::kLeft:
      vk = VirtualKey::kLButton;
      break;
    case rex::ui::MouseEvent::Button::kRight:
      vk = VirtualKey::kRButton;
      break;
    case rex::ui::MouseEvent::Button::kMiddle:
      vk = VirtualKey::kMButton;
      break;
    case rex::ui::MouseEvent::Button::kX1:
      vk = VirtualKey::kXButton1;
      break;
    case rex::ui::MouseEvent::Button::kX2:
      vk = VirtualKey::kXButton2;
      break;
    default:
      return;
  }
  uint16_t idx = static_cast<uint16_t>(vk);
  bool was_down = (idx < 256) && key_down_[idx];
  SetKeyState(idx, false);
  if (was_down && can_emit) {
    EmitButtonChange(vk, false);
    RecomputeLstickDir();
  }
}

void MnkInputDriver::OnMouseMove(rex::ui::MouseEvent& e) {
  if (!IsEnabled() || !has_focus_ || !is_active())
    return;
  std::lock_guard lock(state_mutex_);
  int32_t x = e.x();
  int32_t y = e.y();
  mouse_dx_ += x - prev_mouse_x_;
  mouse_dy_ += y - prev_mouse_y_;
  prev_mouse_x_ = x;
  prev_mouse_y_ = y;
}

void MnkInputDriver::OnLostFocus(rex::ui::UISetupEvent&) {
  bool release_mouse = false;
  {
    std::lock_guard lock(state_mutex_);
    has_focus_ = false;
    ResetInputState();
    if (mouse_captured_) {
      mouse_captured_ = false;
      release_mouse = true;
    }
  }
  if (release_mouse && attached_window_) {
    attached_window_->SetCursorVisibility(rex::ui::Window::CursorVisibility::kVisible);
    attached_window_->ReleaseMouse();
  }
}

void MnkInputDriver::OnGotFocus(rex::ui::UISetupEvent&) {
  {
    std::lock_guard lock(state_mutex_);
    has_focus_ = true;
    ResetInputState();
  }
  UpdateMouseCapture();
}

}  // namespace rex::input::mnk
