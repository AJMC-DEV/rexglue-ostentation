#ifndef REX_GRAPHICS_MOD_SHADER_PARAMS_H_
#define REX_GRAPHICS_MOD_SHADER_PARAMS_H_

#include <cstdint>

// Custom parameters exposed to shader mods.
//
// These are uploaded into the tail of the per-draw system-constants cbuffer so
// that any replacement HLSL shader can read them without a bespoke root
// signature. In a mod shader:
//
//   cbuffer xe_system_cbuffer : register(b0) { uint4 xe_system_consts[31]; };
//   #define XE_MOD_TIME  asfloat(xe_system_consts[29].x)   // seconds since start
//   #define XE_CAM_YAW   asfloat(xe_system_consts[29].y)   // radians
//   #define XE_CAM_PITCH asfloat(xe_system_consts[29].z)   // radians
//   #define XE_VP_SIZE   asfloat(xe_system_consts[30].xy)  // viewport px (w,h)
//
// (xe_system_consts[29]/[30] == SystemConstants::mod_params; see dxbc_translator.h.)
//
// The setters are thread-safe and meant to be called once per frame from the
// game side (e.g. a per-frame hook). If never called, the values stay at 0.
// The viewport size is filled by the GPU backend from the current viewport.

namespace rex {
namespace gpu {

// Number of floats in the generic mod-params block (== SystemConstants::mod_params
// size; xe_system_consts[29+k] holds params [4k .. 4k+3], for k = 0..4).
constexpr uint32_t kModShaderParamCount = 20;

// Set/get a single mod-shader parameter by index [0, kModShaderParamCount).
// The game fills these each frame (e.g. 0 = time, 1..3 = camera forward,
// 4..6 = camera right, 7 = fovY, 8..10 = camera up, 12..14 = light dir,
// 16..18 = light colour); the GPU backend copies them into the cbuffer.
void SetModShaderParam(uint32_t index, float value);
float GetModShaderParam(uint32_t index);

}  // namespace gpu
}  // namespace rex

#endif  // REX_GRAPHICS_MOD_SHADER_PARAMS_H_
