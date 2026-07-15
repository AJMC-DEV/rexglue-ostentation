/**
 * @file        graphics/d3d12/gpu_profiler.cpp
 * @brief       Pass-level GPU timestamp profiler for the D3D12 backend
 *
 * @copyright   Copyright (c) 2026 Tom Clay <tomc@tctechstuff.com>
 *              All rights reserved.
 *
 * @license     BSD 3-Clause License
 *              See LICENSE file in the root for full license text.
 */

#include <rex/graphics/d3d12/gpu_profiler.h>

#include <algorithm>

#include <rex/cvar.h>
#include <rex/filesystem.h>
#include <rex/graphics/d3d12/deferred_command_list.h>
#include <rex/graphics/flags.h>
#include <rex/logging.h>
#include <rex/ui/d3d12/d3d12_util.h>

namespace rex::graphics::d3d12 {

const char* GetGpuPassName(GpuPass pass) {
  switch (pass) {
    case GpuPass::kOwnershipTransfer:
      return "ownership_transfer";
    case GpuPass::kHostDepthStore:
      return "host_depth_store";
    case GpuPass::kRenderTargetDump:
      return "render_target_dump";
    case GpuPass::kResolveCopy:
      return "resolve_copy";
    case GpuPass::kResolveClear:
      return "resolve_clear";
    default:
      return "unknown";
  }
}

const char* GetGpuStatName(GpuStat stat) {
  switch (stat) {
    case GpuStat::kTransferDraws:
      return "transfer_draws";
    case GpuStat::kTransferStencilBitDraws:
      return "transfer_stencil_bit_draws";
    case GpuStat::kTransferRectangles:
      return "transfer_rectangles";
    case GpuStat::kTransferPixelsRasterized:
      return "transfer_pixels_rasterized";
    case GpuStat::kTransferStencilBitPixels:
      return "transfer_stencil_bit_pixels";
    case GpuStat::kGuestDraws:
      return "guest_draws";
    case GpuStat::kGuestVertices:
      return "guest_vertices";
    default:
      return "unknown";
  }
}

bool GpuProfiler::Initialize(ID3D12Device* device, ID3D12CommandQueue* direct_queue) {
  Shutdown();

  if (!device || !direct_queue) {
    return false;
  }

  // A frequency of zero would make every duration meaningless, and some
  // software adapters refuse timestamps outright.
  if (FAILED(direct_queue->GetTimestampFrequency(&timestamp_frequency_)) ||
      timestamp_frequency_ == 0) {
    REXGPU_WARN("GpuProfiler: direct queue does not support timestamps, profiling unavailable");
    timestamp_frequency_ = 0;
    return false;
  }

  D3D12_QUERY_HEAP_DESC heap_desc;
  heap_desc.Type = D3D12_QUERY_HEAP_TYPE_TIMESTAMP;
  heap_desc.Count = kQueryCount;
  heap_desc.NodeMask = 0;
  if (FAILED(device->CreateQueryHeap(&heap_desc, IID_PPV_ARGS(&query_heap_)))) {
    REXGPU_WARN("GpuProfiler: failed to create the timestamp query heap");
    return false;
  }
  query_heap_->SetName(L"GPU Profiler Timestamps");

  constexpr UINT64 kReadbackSize = UINT64(kQueryCount) * sizeof(uint64_t);
  D3D12_RESOURCE_DESC buffer_desc;
  ui::d3d12::util::FillBufferResourceDesc(buffer_desc, kReadbackSize, D3D12_RESOURCE_FLAG_NONE);
  if (FAILED(device->CreateCommittedResource(&ui::d3d12::util::kHeapPropertiesReadback,
                                             D3D12_HEAP_FLAG_NONE, &buffer_desc,
                                             D3D12_RESOURCE_STATE_COPY_DEST, nullptr,
                                             IID_PPV_ARGS(&readback_)))) {
    REXGPU_WARN("GpuProfiler: failed to allocate the timestamp readback buffer");
    query_heap_.Reset();
    return false;
  }
  readback_->SetName(L"GPU Profiler Readback");

  D3D12_RANGE read_range = {0, kReadbackSize};
  void* mapping = nullptr;
  if (FAILED(readback_->Map(0, &read_range, &mapping))) {
    REXGPU_WARN("GpuProfiler: failed to map the timestamp readback buffer");
    readback_.Reset();
    query_heap_.Reset();
    return false;
  }
  readback_mapping_ = reinterpret_cast<const uint64_t*>(mapping);

  resources_available_ = true;
  return true;
}

void GpuProfiler::Shutdown() {
  if (csv_file_) {
    std::fclose(csv_file_);
    csv_file_ = nullptr;
  }
  csv_open_attempted_ = false;

  if (readback_ && readback_mapping_) {
    readback_->Unmap(0, nullptr);
  }
  readback_mapping_ = nullptr;
  readback_.Reset();
  query_heap_.Reset();

  timestamp_frequency_ = 0;
  resources_available_ = false;
  enabled_ = false;

  regions_.fill(Region{});
  region_cursor_ = 0;
  current_region_ = kInvalidRegion;
  current_scope_count_ = 0;
  current_scopes_open_ = 0;
  current_region_acquire_failed_ = false;

  frame_submission_.fill(0);
  frame_pending_.fill(false);
  frame_cursor_ = 0;
  open_frame_slot_ = kInvalidFrameSlot;
  last_frame_wall_valid_ = false;

  ResetAccumulators();
  dropped_scopes_ = 0;
  dropped_regions_ = 0;
}

void GpuProfiler::ResetAccumulators() {
  interval_pass_ticks_.fill(0);
  interval_pass_counts_.fill(0);
  interval_stats_.fill(0);
  interval_frame_ticks_ = 0;
  interval_frames_ = 0;
  interval_wall_ns_ = 0;
  interval_wall_frames_ = 0;
  // Keep last_frame_wall_ so the next interval's first delta stays continuous.
  // Per-interval, not cumulative: a running total says nothing about whether
  // the numbers in the report next to it are trustworthy.
  dropped_scopes_ = 0;
  dropped_regions_ = 0;
}

void GpuProfiler::UpdateEnabled() {
  bool want_enabled = resources_available_ && REXCVAR_GET(gpu_profile);
  if (want_enabled == enabled_) {
    return;
  }
  enabled_ = want_enabled;
  // Numbers from before the toggle would be averaged into the first report.
  ResetAccumulators();
  if (enabled_) {
    REXGPU_INFO("GpuProfiler: enabled (timestamp frequency {} Hz)", timestamp_frequency_);
  }
}

uint32_t GpuProfiler::AcquireRegion() {
  for (uint32_t i = 0; i < kRegionCount; ++i) {
    uint32_t index = (region_cursor_ + i) % kRegionCount;
    if (!regions_[index].pending) {
      region_cursor_ = (index + 1) % kRegionCount;
      return index;
    }
  }
  return kInvalidRegion;
}

uint32_t GpuProfiler::BeginScope(DeferredCommandList& command_list, GpuPass pass) {
  if (!enabled_) {
    return kInvalidScope;
  }

  if (current_region_ == kInvalidRegion) {
    if (current_region_acquire_failed_) {
      return kInvalidScope;
    }
    current_region_ = AcquireRegion();
    if (current_region_ == kInvalidRegion) {
      // Every region is still in flight. Skip this submission entirely rather
      // than corrupt a region that has not been read back yet.
      current_region_acquire_failed_ = true;
      ++dropped_regions_;
      return kInvalidScope;
    }
    current_scope_count_ = 0;
    current_scopes_open_ = 0;
  }

  if (current_scope_count_ >= kScopesPerRegion) {
    ++dropped_scopes_;
    return kInvalidScope;
  }

  uint32_t index = current_scope_count_++;
  ++current_scopes_open_;
  regions_[current_region_].passes[index] = pass;
  command_list.D3DEndQuery(query_heap_.Get(), D3D12_QUERY_TYPE_TIMESTAMP,
                           ScopeQueryIndex(current_region_, index, 0));
  return PackScope(current_region_, index);
}

void GpuProfiler::EndScope(DeferredCommandList& command_list, uint32_t scope) {
  if (scope == kInvalidScope) {
    return;
  }
  uint32_t region = UnpackScopeRegion(scope);
  // A scope that outlived its submission would have had its begin timestamp
  // resolved against an end slot that was never written. Drop it.
  if (region != current_region_) {
    return;
  }
  command_list.D3DEndQuery(query_heap_.Get(), D3D12_QUERY_TYPE_TIMESTAMP,
                           ScopeQueryIndex(region, UnpackScopeIndex(scope), 1));
  --current_scopes_open_;
}

void GpuProfiler::BeginFrame(DeferredCommandList& command_list) {
  if (!enabled_) {
    open_frame_slot_ = kInvalidFrameSlot;
    return;
  }
  // Wall-clock period between frame opens, independent of the GPU query ring so
  // it is captured even on frames whose GPU timing is skipped below.
  auto now = std::chrono::steady_clock::now();
  if (last_frame_wall_valid_) {
    interval_wall_ns_ +=
        uint64_t(std::chrono::duration_cast<std::chrono::nanoseconds>(now - last_frame_wall_)
                     .count());
    ++interval_wall_frames_;
  }
  last_frame_wall_ = now;
  last_frame_wall_valid_ = true;

  uint32_t slot = frame_cursor_ % kFrameRingCount;
  if (frame_pending_[slot]) {
    // The oldest frame in the ring has not retired yet - skip timing this one.
    open_frame_slot_ = kInvalidFrameSlot;
    return;
  }
  ++frame_cursor_;
  open_frame_slot_ = slot;
  command_list.D3DEndQuery(query_heap_.Get(), D3D12_QUERY_TYPE_TIMESTAMP,
                           FrameQueryIndex(slot, 0));
}

void GpuProfiler::EndFrame(DeferredCommandList& command_list, uint64_t submission) {
  if (open_frame_slot_ == kInvalidFrameSlot) {
    return;
  }
  uint32_t slot = open_frame_slot_;
  open_frame_slot_ = kInvalidFrameSlot;

  command_list.D3DEndQuery(query_heap_.Get(), D3D12_QUERY_TYPE_TIMESTAMP,
                           FrameQueryIndex(slot, 1));
  // The begin timestamp may have been written by an earlier command list; query
  // heap contents persist until resolved, so both slots are valid here.
  uint32_t first_query = FrameQueryIndex(slot, 0);
  command_list.D3DResolveQueryData(query_heap_.Get(), D3D12_QUERY_TYPE_TIMESTAMP, first_query, 2,
                                   readback_.Get(), uint64_t(first_query) * sizeof(uint64_t));
  frame_submission_[slot] = submission;
  frame_pending_[slot] = true;
}

void GpuProfiler::EndSubmission(DeferredCommandList& command_list, uint64_t submission) {
  current_region_acquire_failed_ = false;

  if (current_region_ == kInvalidRegion) {
    return;
  }
  uint32_t region_index = current_region_;
  current_region_ = kInvalidRegion;

  // An unbalanced scope means a begin timestamp with no matching end. Its delta
  // would be garbage, so throw the whole region away rather than report noise.
  if (current_scopes_open_ != 0 || current_scope_count_ == 0) {
    if (current_scopes_open_ != 0) {
      ++dropped_regions_;
    }
    current_scope_count_ = 0;
    current_scopes_open_ = 0;
    return;
  }

  Region& region = regions_[region_index];
  region.submission = submission;
  region.scope_count = current_scope_count_;
  region.pending = true;

  uint32_t first_query = ScopeQueryIndex(region_index, 0, 0);
  command_list.D3DResolveQueryData(query_heap_.Get(), D3D12_QUERY_TYPE_TIMESTAMP, first_query,
                                   current_scope_count_ * 2, readback_.Get(),
                                   uint64_t(first_query) * sizeof(uint64_t));

  current_scope_count_ = 0;
  current_scopes_open_ = 0;
}

void GpuProfiler::ConsumeRegion(uint32_t region_index) {
  Region& region = regions_[region_index];
  for (uint32_t i = 0; i < region.scope_count; ++i) {
    uint64_t begin = readback_mapping_[ScopeQueryIndex(region_index, i, 0)];
    uint64_t end = readback_mapping_[ScopeQueryIndex(region_index, i, 1)];
    // Timestamps can go backwards across a GPU clock reset (power state change).
    if (end < begin) {
      continue;
    }
    uint32_t pass = uint32_t(region.passes[i]);
    if (pass >= kPassCount) {
      continue;
    }
    interval_pass_ticks_[pass] += end - begin;
    ++interval_pass_counts_[pass];
  }
  region.pending = false;
  region.scope_count = 0;
}

void GpuProfiler::CompletedSubmissionUpdated(uint64_t submission_completed) {
  if (!resources_available_ || !readback_mapping_) {
    return;
  }

  for (uint32_t index = 0; index < kRegionCount; ++index) {
    const Region& region = regions_[index];
    if (region.pending && region.submission <= submission_completed) {
      ConsumeRegion(index);
    }
  }

  bool frame_retired = false;
  for (uint32_t slot = 0; slot < kFrameRingCount; ++slot) {
    if (!frame_pending_[slot] || frame_submission_[slot] > submission_completed) {
      continue;
    }
    frame_pending_[slot] = false;
    uint64_t begin = readback_mapping_[FrameQueryIndex(slot, 0)];
    uint64_t end = readback_mapping_[FrameQueryIndex(slot, 1)];
    if (end >= begin) {
      interval_frame_ticks_ += end - begin;
      ++interval_frames_;
      frame_retired = true;
    }
  }

  if (!frame_retired || !enabled_) {
    return;
  }
  int32_t interval = std::max(1, REXCVAR_GET(gpu_profile_interval_frames));
  if (interval_frames_ >= uint32_t(interval)) {
    Report();
    ResetAccumulators();
  }
}

void GpuProfiler::Report() {
  if (!interval_frames_ || !timestamp_frequency_) {
    return;
  }

  const double frames = double(interval_frames_);
  const double ticks_to_ms = 1000.0 / double(timestamp_frequency_);

  double frame_ms = double(interval_frame_ticks_) * ticks_to_ms / frames;
  double pass_ms[kPassCount];
  double pass_per_frame[kPassCount];
  double emulation_ms = 0.0;
  for (uint32_t i = 0; i < kPassCount; ++i) {
    pass_ms[i] = double(interval_pass_ticks_[i]) * ticks_to_ms / frames;
    pass_per_frame[i] = double(interval_pass_counts_[i]) / frames;
    emulation_ms += pass_ms[i];
  }

  double emulation_pct = frame_ms > 0.0 ? emulation_ms / frame_ms * 100.0 : 0.0;

  double wall_ms = interval_wall_frames_
                       ? double(interval_wall_ns_) / 1.0e6 / double(interval_wall_frames_)
                       : 0.0;
  // GPU frame span over wall-clock frame period. ~100% => GPU-bound, so attack
  // shading / overdraw / vertex work. Well under => the GPU is idle waiting on
  // the CPU (guest PPC code or draw submission), so batching draws or trimming
  // per-draw CPU work is what moves the frame, not shaders.
  double gpu_busy_pct = wall_ms > 0.0 ? frame_ms / wall_ms * 100.0 : 0.0;

  REXGPU_INFO(
      "GPU profile ({} frames): wall {:.2f} ms ({:.0f} fps) | GPU {:.2f} ms ({:.0f}% busy) | "
      "EDRAM emulation {:.2f} ms ({:.1f}%) | guest draws + everything else {:.2f} ms",
      interval_frames_, wall_ms, wall_ms > 0.0 ? 1000.0 / wall_ms : 0.0, frame_ms, gpu_busy_pct,
      emulation_ms, emulation_pct, frame_ms - emulation_ms);
  for (uint32_t i = 0; i < kPassCount; ++i) {
    if (interval_pass_counts_[i] == 0) {
      continue;
    }
    REXGPU_INFO("  {:<20} {:>8.3f} ms  {:>8.1f} calls/frame", GetGpuPassName(GpuPass(i)), pass_ms[i],
                pass_per_frame[i]);
  }
  for (uint32_t i = 0; i < kStatCount; ++i) {
    if (interval_stats_[i] == 0) {
      continue;
    }
    REXGPU_INFO("  {:<28} {:>12.1f} /frame", GetGpuStatName(GpuStat(i)),
                double(interval_stats_[i]) / frames);
  }
  if (dropped_scopes_ || dropped_regions_) {
    // A dropped scope is untimed GPU work that silently lands in the
    // "guest draws + everything else" residual, and the call counts above are
    // clamped rather than measured. Say so loudly - a clamped count reads
    // exactly like a real one.
    REXGPU_WARN(
        "GpuProfiler: dropped {} scopes (cap is {} per submission) and {} submissions this "
        "interval - every number above is a LOWER BOUND and the call counts are clamped, "
        "not measured",
        dropped_scopes_, kScopesPerRegion, dropped_regions_);
  }

  const std::string& csv_path = REXCVAR_GET(gpu_profile_csv);
  if (csv_path.empty()) {
    return;
  }
  if (!csv_file_ && !csv_open_attempted_) {
    csv_open_attempted_ = true;
    csv_file_ = rex::filesystem::OpenFile(rex::to_path(csv_path), "w");
    if (!csv_file_) {
      REXGPU_WARN("GpuProfiler: failed to open '{}' for the CSV log", csv_path);
      return;
    }
    std::fprintf(csv_file_, "frames,wall_ms,gpu_busy_pct,frame_ms,emulation_ms");
    for (uint32_t i = 0; i < kPassCount; ++i) {
      std::fprintf(csv_file_, ",%s_ms,%s_calls", GetGpuPassName(GpuPass(i)),
                   GetGpuPassName(GpuPass(i)));
    }
    for (uint32_t i = 0; i < kStatCount; ++i) {
      std::fprintf(csv_file_, ",%s", GetGpuStatName(GpuStat(i)));
    }
    std::fprintf(csv_file_, "\n");
  }
  if (!csv_file_) {
    return;
  }
  std::fprintf(csv_file_, "%u,%.4f,%.2f,%.4f,%.4f", interval_frames_, wall_ms, gpu_busy_pct,
               frame_ms, emulation_ms);
  for (uint32_t i = 0; i < kPassCount; ++i) {
    std::fprintf(csv_file_, ",%.4f,%.2f", pass_ms[i], pass_per_frame[i]);
  }
  for (uint32_t i = 0; i < kStatCount; ++i) {
    std::fprintf(csv_file_, ",%.2f", double(interval_stats_[i]) / frames);
  }
  std::fprintf(csv_file_, "\n");
  std::fflush(csv_file_);
}

}  // namespace rex::graphics::d3d12
