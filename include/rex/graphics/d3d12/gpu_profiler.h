/**
 * @file        graphics/d3d12/gpu_profiler.h
 * @brief       Pass-level GPU timestamp profiler for the D3D12 backend
 *
 * @copyright   Copyright (c) 2026 Tom Clay <tomc@tctechstuff.com>
 *              All rights reserved.
 *
 * @license     BSD 3-Clause License
 *              See LICENSE file in the root for full license text.
 */

#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>

#include <rex/ui/d3d12/d3d12_api.h>

namespace rex::graphics::d3d12 {

class DeferredCommandList;

// Coarse buckets of GPU work.
//
// Every bucket here is Xenos EDRAM emulation overhead - none of it corresponds
// to a draw the guest issued. All of it scales with the square of the
// resolution scale, so it is the first thing to look at when scaled rendering
// costs more than the pixel count alone explains.
//
// Guest draw time is intentionally *not* a bucket. It is derived as
// (frame GPU span - sum of the buckets below), because wrapping each guest draw
// in its own timestamp pair overcounts badly: D3D12 timestamp queries do not
// flush the pipeline, and consecutive draws with no barrier between them
// overlap freely on the GPU.
enum class GpuPass : uint32_t {
  // Re-aliasing an EDRAM range to a different render target format. Full
  // pixel-shader draws over the transferred rectangle.
  kOwnershipTransfer,
  // Compute dispatches copying host depth into the EDRAM buffer.
  kHostDepthStore,
  // Compute dispatches copying render targets into the EDRAM buffer so a
  // resolve can read them back out.
  kRenderTargetDump,
  // The resolve copy dispatch itself (EDRAM buffer -> shared memory / scaled
  // resolve buffer).
  kResolveCopy,
  // Clears issued as part of a resolve.
  kResolveClear,

  kCount,
};

const char* GetGpuPassName(GpuPass pass);

// CPU-side counters recorded alongside the GPU buckets. A pass bucket says how
// long ownership transfers took; these say what they were made of.
enum class GpuStat : uint32_t {
  // Real D3DDrawInstanced calls in the transfer path. Note a stencil-bit
  // transfer issues eight, one per bit plane.
  kTransferDraws,
  kTransferStencilBitDraws,
  kTransferRectangles,
  // Guest pixels actually rasterized (rectangle area x draws over it). Divide
  // by the guest framebuffer area to read it as full-screen passes per frame.
  kTransferPixelsRasterized,
  // The subset of the above spent on stencil bit planes.
  kTransferStencilBitPixels,
  // Guest draws submitted and vertices they carried. High vertices/frame with a
  // GPU-bound frame points at geometry throughput (LOD, culling); modest
  // vertices with a GPU-bound frame points at fragment cost (overdraw, ALU).
  kGuestDraws,
  kGuestVertices,

  kCount,
};

const char* GetGpuStatName(GpuStat stat);

// Timestamp-based pass profiler for the D3D12 backend.
//
// Timestamps are written into a query heap from the deferred command list and
// resolved into a readback buffer at the end of each submission. Results are
// only read once that submission's fence has retired, so profiling never stalls
// the GPU and never blocks the command processor.
//
// Accuracy caveat: because timestamp queries do not serialize the pipeline,
// work inside a scope may overlap work outside it. The emulation passes
// measured here are barrier-separated from guest draws, which keeps the error
// small, but treat the numbers as relative attribution rather than an exact
// partition of frame time. If the buckets sum to more than the frame span,
// that is overlap, not a bug.
class GpuProfiler {
 public:
  static constexpr uint32_t kInvalidScope = ~uint32_t(0);

  GpuProfiler() = default;
  GpuProfiler(const GpuProfiler&) = delete;
  GpuProfiler& operator=(const GpuProfiler&) = delete;
  ~GpuProfiler() { Shutdown(); }

  // Failure is non-fatal: the profiler simply stays unavailable and every
  // method below becomes a no-op.
  bool Initialize(ID3D12Device* device, ID3D12CommandQueue* direct_queue);
  void Shutdown();

  bool enabled() const { return enabled_; }

  // Latches the gpu_profile cvar. Call once per frame, before opening scopes.
  void UpdateEnabled();

  // Returns kInvalidScope if profiling is off or no query slots are free; pass
  // that straight to EndScope, which will ignore it.
  uint32_t BeginScope(DeferredCommandList& command_list, GpuPass pass);
  void EndScope(DeferredCommandList& command_list, uint32_t scope);

  // No-op when profiling is off. Unlike the GPU buckets these accumulate at
  // record time rather than at fence retirement, so they lead the frame counter
  // by however many frames are in flight - a ~2% bias over a 120 frame interval.
  void AddStat(GpuStat stat, uint64_t value) {
    if (enabled_) {
      interval_stats_[uint32_t(stat)] += value;
    }
  }

  void BeginFrame(DeferredCommandList& command_list);
  void EndFrame(DeferredCommandList& command_list, uint64_t submission);

  // Resolves the open submission's queries into the readback buffer. Must be
  // called while the deferred command list is still recording, before
  // ExecuteCommandLists.
  void EndSubmission(DeferredCommandList& command_list, uint64_t submission);

  // Consumes results for submissions whose fence has retired.
  void CompletedSubmissionUpdated(uint64_t submission_completed);

 private:
  static constexpr uint32_t kRegionCount = 8;
  // Headroom over the real per-submission pass count. If this is ever hit the
  // report says so, because a clamped count reads like a real measurement.
  static constexpr uint32_t kScopesPerRegion = 2048;
  static constexpr uint32_t kFrameRingCount = 8;
  static constexpr uint32_t kScopeQueryCount = kRegionCount * kScopesPerRegion * 2;
  static constexpr uint32_t kFrameQueryBase = kScopeQueryCount;
  static constexpr uint32_t kQueryCount = kScopeQueryCount + kFrameRingCount * 2;
  static constexpr uint32_t kInvalidRegion = ~uint32_t(0);
  static constexpr uint32_t kInvalidFrameSlot = ~uint32_t(0);
  static constexpr uint32_t kPassCount = uint32_t(GpuPass::kCount);
  static constexpr uint32_t kStatCount = uint32_t(GpuStat::kCount);

  // One submission's worth of scopes. Recycled once its fence retires.
  struct Region {
    uint64_t submission = 0;
    uint32_t scope_count = 0;
    bool pending = false;
    std::array<GpuPass, kScopesPerRegion> passes{};
  };

  static uint32_t ScopeQueryIndex(uint32_t region, uint32_t scope, uint32_t end) {
    return (region * kScopesPerRegion + scope) * 2 + end;
  }
  static uint32_t FrameQueryIndex(uint32_t slot, uint32_t end) {
    return kFrameQueryBase + slot * 2 + end;
  }
  // Scope handles pack the region so EndScope can detect a scope that
  // illegally straddled a submission boundary.
  static uint32_t PackScope(uint32_t region, uint32_t index) { return (region << 16) | index; }
  static uint32_t UnpackScopeRegion(uint32_t scope) { return scope >> 16; }
  static uint32_t UnpackScopeIndex(uint32_t scope) { return scope & 0xFFFF; }

  uint32_t AcquireRegion();
  void ConsumeRegion(uint32_t region_index);
  void ResetAccumulators();
  void Report();

  Microsoft::WRL::ComPtr<ID3D12QueryHeap> query_heap_;
  Microsoft::WRL::ComPtr<ID3D12Resource> readback_;
  const uint64_t* readback_mapping_ = nullptr;
  uint64_t timestamp_frequency_ = 0;
  bool resources_available_ = false;
  bool enabled_ = false;

  std::array<Region, kRegionCount> regions_{};
  uint32_t region_cursor_ = 0;
  uint32_t current_region_ = kInvalidRegion;
  uint32_t current_scope_count_ = 0;
  uint32_t current_scopes_open_ = 0;
  bool current_region_acquire_failed_ = false;

  std::array<uint64_t, kFrameRingCount> frame_submission_{};
  std::array<bool, kFrameRingCount> frame_pending_{};
  uint32_t frame_cursor_ = 0;
  uint32_t open_frame_slot_ = kInvalidFrameSlot;

  // Accumulated across the reporting interval.
  std::array<uint64_t, kPassCount> interval_pass_ticks_{};
  std::array<uint64_t, kPassCount> interval_pass_counts_{};
  std::array<uint64_t, kStatCount> interval_stats_{};
  uint64_t interval_frame_ticks_ = 0;
  uint32_t interval_frames_ = 0;

  // CPU wall-clock frame period, sampled at frame open. Compared against the GPU
  // frame span so the report can say whether the GPU is the bottleneck: a busy
  // percentage near 100 means GPU-bound, well under means the GPU is waiting on
  // the CPU (guest code / draw submission). Accumulated on a different cadence
  // than the GPU frames (record time vs fence retirement), so the two frame
  // counts differ by the frames in flight - a ~2% bias, hence separate counters.
  std::chrono::steady_clock::time_point last_frame_wall_{};
  bool last_frame_wall_valid_ = false;
  uint64_t interval_wall_ns_ = 0;
  uint32_t interval_wall_frames_ = 0;

  uint64_t dropped_scopes_ = 0;
  uint64_t dropped_regions_ = 0;

  std::FILE* csv_file_ = nullptr;
  bool csv_open_attempted_ = false;
};

// Scoped timestamp pair. Safe to construct when profiling is off.
class GpuPassScope {
 public:
  GpuPassScope(GpuProfiler& profiler, DeferredCommandList& command_list, GpuPass pass)
      : profiler_(profiler),
        command_list_(command_list),
        scope_(profiler.BeginScope(command_list, pass)) {}
  ~GpuPassScope() { profiler_.EndScope(command_list_, scope_); }

  GpuPassScope(const GpuPassScope&) = delete;
  GpuPassScope& operator=(const GpuPassScope&) = delete;

 private:
  GpuProfiler& profiler_;
  DeferredCommandList& command_list_;
  uint32_t scope_;
};

}  // namespace rex::graphics::d3d12
