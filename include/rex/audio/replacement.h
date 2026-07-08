/**
 * @file        rex/audio/replacement.h
 *
 * @brief       Audio dump and replacement pipeline (the audio analog of
 *              graphics/pipeline/texture/replacement.h).
 *
 *              Sounds are identified by a stable content hash (XXH3 over the
 *              raw guest XMA input bytes, exactly as the Xbox APU would read
 *              them).  The same hash is used both to name dumps and to look up
 *              modder replacements, so a dumped file can be dropped straight
 *              into a mod folder after editing.
 *
 *              Dump layout   (relative to the executable folder):
 *                  dumps/audio/<hash16>_<rate>hz_<ch>ch.wav
 *
 *              Replacement layout (scanned once at init from each enabled mod,
 *              hot-reloadable via Rescan()):
 *                  <mods_data_root>/<mod>/audio/<hash16>.wav
 *
 *              Replacement WAVs are decoded to interleaved 16-bit PCM at their
 *              own native sample rate / channel count; the injection path in
 *              XmaContext resamples and re-interleaves to whatever the guest
 *              context expects.  16/24/32-bit integer and 32-bit float WAVs
 *              (mono or stereo) are accepted.
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <rex/cvar.h>

// CVARs controlling the dump/replace pipeline (defined in replacement.cpp).
REXCVAR_DECLARE(bool, audio_dump_enabled);
REXCVAR_DECLARE(bool, audio_replace_enabled);

namespace rex::audio {

// ---------------------------------------------------------------------------
// Replacement descriptor returned to the injection path
// ---------------------------------------------------------------------------
struct AudioReplacementData {
  // Interleaved 16-bit PCM at the file's native rate/channel count.
  std::vector<int16_t> samples;
  uint32_t sample_rate = 0;
  uint32_t channels    = 0;

  // Number of whole sample frames (samples.size() / channels).
  size_t frame_count() const { return channels ? samples.size() / channels : 0; }
};

// ---------------------------------------------------------------------------
// AudioReplacement
// ---------------------------------------------------------------------------
class AudioReplacement {
 public:
  explicit AudioReplacement(std::filesystem::path root);
  ~AudioReplacement();

  AudioReplacement(const AudioReplacement&)            = delete;
  AudioReplacement& operator=(const AudioReplacement&) = delete;

  // Rescans every enabled mod's audio/ folder and rebuilds the hash->path index.
  void Rescan();

  // ---------------------------------------------------------------------------
  // Dump path
  // ---------------------------------------------------------------------------
  // Writes a decoded stream to dumps/audio/<hash>_<rate>hz_<ch>ch.wav. No-op if
  // the hash was already dumped this session (streams replay constantly).
  //   samples      : interleaved 16-bit PCM, host-endian
  //   frame_count  : number of sample frames (samples covers frame_count*channels)
  void DumpStream(uint64_t content_hash, const int16_t* samples, size_t frame_count,
                  uint32_t sample_rate, uint32_t channels) const;

  // True once DumpStream has written this hash (or it was seen on disk).
  bool AlreadyDumped(uint64_t content_hash) const;

  // ---------------------------------------------------------------------------
  // Injection path
  // ---------------------------------------------------------------------------
  // Returns a pointer into the internal cache (valid until the next Rescan()),
  // or nullptr if no replacement exists for this hash. Loads lazily on first hit.
  [[nodiscard]] const AudioReplacementData* FindReplacement(uint64_t content_hash) const;

  // Fast negative check that never touches the filesystem — lets the hot decode
  // path skip work when no replacement could possibly exist.
  [[nodiscard]] bool HasReplacement(uint64_t content_hash) const {
    return replacements_.find(content_hash) != replacements_.end();
  }

  // ---------------------------------------------------------------------------
  // Hash
  // ---------------------------------------------------------------------------
  static uint64_t HashGuestData(const uint8_t* data, size_t size);

  std::filesystem::path dump_dir() const { return dump_dir_; }

 private:
  std::filesystem::path root_;
  std::filesystem::path dump_dir_;
  std::vector<std::filesystem::path> replace_dirs_;
  std::unordered_map<uint64_t, std::filesystem::path> replacements_;

  // Decoded WAVs are cached so FindReplacement never touches disk after the
  // first hit; hashes that fail to load are remembered so we don't retry.
  mutable std::unordered_map<uint64_t, AudioReplacementData> sample_cache_;
  mutable std::unordered_set<uint64_t> failed_cache_;
  // Hashes already written to dumps/ this session (or pre-existing on disk).
  mutable std::unordered_set<uint64_t> dumped_;

  static bool WriteWav(const std::filesystem::path& path, const int16_t* samples,
                       size_t frame_count, uint32_t sample_rate, uint32_t channels);
  static bool ReadWav(const std::filesystem::path& path, AudioReplacementData& out);
};

}  // namespace rex::audio
