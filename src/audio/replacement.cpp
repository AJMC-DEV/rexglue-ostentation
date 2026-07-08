/**
 * @file        audio/replacement.cpp
 *
 * @brief       Audio dump and replacement pipeline implementation.
 */
#include <rex/audio/replacement.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <system_error>

#include <rex/logging.h>
#include <rex/mods.h>

#ifndef XXH_INLINE_ALL
#define XXH_INLINE_ALL
#endif
#include <xxhash.h>

REXCVAR_DEFINE_BOOL(audio_dump_enabled, false, "MODS/Audio",
                    "Dump every decoded XMA stream to dumps/audio/<hash>.wav");
REXCVAR_DEFINE_BOOL(audio_replace_enabled, false, "MODS/Audio",
                    "Replace decoded XMA streams with matching modder WAVs");

namespace rex::audio {

namespace {

// Little-endian scalar writers for the WAV header.
void PutU16(std::ostream& os, uint16_t v) {
  const uint8_t b[2] = {static_cast<uint8_t>(v), static_cast<uint8_t>(v >> 8)};
  os.write(reinterpret_cast<const char*>(b), 2);
}
void PutU32(std::ostream& os, uint32_t v) {
  const uint8_t b[4] = {static_cast<uint8_t>(v), static_cast<uint8_t>(v >> 8),
                        static_cast<uint8_t>(v >> 16), static_cast<uint8_t>(v >> 24)};
  os.write(reinterpret_cast<const char*>(b), 4);
}

uint16_t GetU16(const uint8_t* p) { return static_cast<uint16_t>(p[0] | (p[1] << 8)); }
uint32_t GetU32(const uint8_t* p) {
  return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

int16_t SaturateFloatToI16(float f) {
  f *= 32767.0f;
  if (f > 32767.0f) f = 32767.0f;
  if (f < -32768.0f) f = -32768.0f;
  return static_cast<int16_t>(f);
}

// Parse the first 16 hex chars of a filename stem into a content hash.
bool StemToHash(const std::string& stem, uint64_t& out) {
  if (stem.size() < 16) return false;
  uint64_t hash = 0;
  for (int i = 0; i < 16; ++i) {
    char c = stem[i];
    uint64_t nibble;
    if (c >= '0' && c <= '9')
      nibble = static_cast<uint64_t>(c - '0');
    else if (c >= 'a' && c <= 'f')
      nibble = static_cast<uint64_t>(c - 'a' + 10);
    else if (c >= 'A' && c <= 'F')
      nibble = static_cast<uint64_t>(c - 'A' + 10);
    else
      return false;
    hash = (hash << 4) | nibble;
  }
  out = hash;
  return true;
}

}  // namespace

// ---------------------------------------------------------------------------
// Construction / scan
// ---------------------------------------------------------------------------
AudioReplacement::AudioReplacement(std::filesystem::path root) : root_(std::move(root)) {
  // Mirror TextureReplacement: mods_data_root drives the per-mod folders,
  // defaulting to <root>/mods. Each enabled mod contributes an audio/ folder.
  std::filesystem::path mods_data_root = REXCVAR_GET(mods_data_root);
  if (mods_data_root.empty()) {
    mods_data_root = root_ / "mods";
  }

  dump_dir_ = root_ / "dumps" / "audio";
  for (auto& mod_dir : GetEnabledModDirs(mods_data_root)) {
    replace_dirs_.push_back(mod_dir / "audio");
  }

  std::error_code ec;
  std::filesystem::create_directories(dump_dir_, ec);
  ec.clear();
  std::filesystem::create_directories(mods_data_root, ec);
  for (auto& dir : replace_dirs_) {
    ec.clear();
    std::filesystem::create_directories(dir, ec);
  }

  // Pre-populate dumped_ from anything already sitting in dumps/audio/ so a
  // resumed session doesn't rewrite files it produced earlier.
  for (auto& entry : std::filesystem::directory_iterator(dump_dir_, ec)) {
    if (ec) break;
    if (!entry.is_regular_file()) continue;
    uint64_t hash;
    if (StemToHash(entry.path().stem().string(), hash)) {
      dumped_.insert(hash);
    }
  }

  Rescan();
}

AudioReplacement::~AudioReplacement() = default;

void AudioReplacement::Rescan() {
  replacements_.clear();
  sample_cache_.clear();
  failed_cache_.clear();

  std::error_code ec;
  // Scan enabled mods in priority order; emplace keeps the first (highest
  // priority) mod's file when a hash appears in more than one.
  for (const auto& dir : replace_dirs_) {
    if (!std::filesystem::exists(dir, ec)) continue;
    for (auto& entry : std::filesystem::directory_iterator(dir, ec)) {
      if (ec) break;
      if (!entry.is_regular_file()) continue;
      const auto& p = entry.path();
      auto ext = p.extension().string();
      std::transform(ext.begin(), ext.end(), ext.begin(),
                     [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
      if (ext != ".wav") continue;

      uint64_t hash;
      if (!StemToHash(p.stem().string(), hash)) continue;
      replacements_.emplace(hash, p);
    }
  }

  REXLOG_INFO("AudioReplacement: {} replacement WAV(s) indexed from {} mod folder(s)",
              replacements_.size(), replace_dirs_.size());
}

// ---------------------------------------------------------------------------
// Hash
// ---------------------------------------------------------------------------
uint64_t AudioReplacement::HashGuestData(const uint8_t* data, size_t size) {
  return XXH3_64bits(data, size);
}

// ---------------------------------------------------------------------------
// Dump
// ---------------------------------------------------------------------------
bool AudioReplacement::AlreadyDumped(uint64_t content_hash) const {
  return dumped_.find(content_hash) != dumped_.end();
}

void AudioReplacement::DumpStream(uint64_t content_hash, const int16_t* samples,
                                  size_t frame_count, uint32_t sample_rate,
                                  uint32_t channels) const {
  if (!samples || !frame_count || !channels) return;
  if (!dumped_.insert(content_hash).second) return;  // already dumped this session

  char name[64];
  std::snprintf(name, sizeof(name), "%016llX_%uhz_%uch.wav",
                static_cast<unsigned long long>(content_hash), sample_rate, channels);
  const auto path = dump_dir_ / name;

  if (WriteWav(path, samples, frame_count, sample_rate, channels)) {
    REXLOG_INFO("AudioReplacement: dumped {} ({} frames, {} Hz, {} ch)", name, frame_count,
                sample_rate, channels);
  } else {
    REXLOG_WARN("AudioReplacement: failed to write {}", path.string());
  }
}

// ---------------------------------------------------------------------------
// Find
// ---------------------------------------------------------------------------
const AudioReplacementData* AudioReplacement::FindReplacement(uint64_t content_hash) const {
  if (auto it = sample_cache_.find(content_hash); it != sample_cache_.end()) {
    return &it->second;
  }
  if (failed_cache_.count(content_hash)) return nullptr;

  auto it = replacements_.find(content_hash);
  if (it == replacements_.end()) {
    failed_cache_.insert(content_hash);
    return nullptr;
  }

  AudioReplacementData data;
  if (!ReadWav(it->second, data) || data.samples.empty() || !data.channels) {
    REXLOG_WARN("AudioReplacement: failed to load {}", it->second.string());
    failed_cache_.insert(content_hash);
    return nullptr;
  }

  REXLOG_INFO("AudioReplacement: loaded replacement {} ({} frames, {} Hz, {} ch)",
              it->second.filename().string(), data.frame_count(), data.sample_rate,
              data.channels);
  auto [ins, ok] = sample_cache_.emplace(content_hash, std::move(data));
  return &ins->second;
}

// ---------------------------------------------------------------------------
// WAV writer — canonical 16-bit PCM
// ---------------------------------------------------------------------------
bool AudioReplacement::WriteWav(const std::filesystem::path& path, const int16_t* samples,
                                size_t frame_count, uint32_t sample_rate, uint32_t channels) {
  std::ofstream os(path, std::ios::binary | std::ios::trunc);
  if (!os) return false;

  const uint32_t data_bytes =
      static_cast<uint32_t>(frame_count * channels * sizeof(int16_t));
  const uint16_t block_align = static_cast<uint16_t>(channels * sizeof(int16_t));
  const uint32_t byte_rate = sample_rate * block_align;

  os.write("RIFF", 4);
  PutU32(os, 36 + data_bytes);
  os.write("WAVE", 4);
  os.write("fmt ", 4);
  PutU32(os, 16);                                    // PCM fmt chunk size
  PutU16(os, 1);                                     // audio format = PCM
  PutU16(os, static_cast<uint16_t>(channels));
  PutU32(os, sample_rate);
  PutU32(os, byte_rate);
  PutU16(os, block_align);
  PutU16(os, 16);                                    // bits per sample
  os.write("data", 4);
  PutU32(os, data_bytes);

  // Stored little-endian. On LE hosts (every target here) this is a raw write.
  os.write(reinterpret_cast<const char*>(samples), data_bytes);
  return static_cast<bool>(os);
}

// ---------------------------------------------------------------------------
// WAV reader — 16/24/32-bit int + 32-bit float, mono/stereo, -> int16
// ---------------------------------------------------------------------------
bool AudioReplacement::ReadWav(const std::filesystem::path& path, AudioReplacementData& out) {
  std::ifstream is(path, std::ios::binary | std::ios::ate);
  if (!is) return false;
  const std::streamoff file_size = is.tellg();
  if (file_size < 44) return false;
  is.seekg(0);

  std::vector<uint8_t> buf(static_cast<size_t>(file_size));
  is.read(reinterpret_cast<char*>(buf.data()), file_size);
  if (!is) return false;

  if (std::memcmp(buf.data(), "RIFF", 4) != 0 || std::memcmp(buf.data() + 8, "WAVE", 4) != 0) {
    return false;
  }

  uint16_t fmt_tag = 0, channels = 0, bits = 0;
  uint32_t sample_rate = 0;
  const uint8_t* data_ptr = nullptr;
  uint32_t data_size = 0;

  // Walk chunks starting after the 12-byte RIFF/WAVE header.
  size_t off = 12;
  while (off + 8 <= buf.size()) {
    const uint8_t* ch = buf.data() + off;
    const uint32_t chunk_size = GetU32(ch + 4);
    const uint8_t* body = ch + 8;
    if (body + chunk_size > buf.data() + buf.size()) break;  // truncated

    if (std::memcmp(ch, "fmt ", 4) == 0 && chunk_size >= 16) {
      fmt_tag = GetU16(body + 0);
      channels = GetU16(body + 2);
      sample_rate = GetU32(body + 4);
      bits = GetU16(body + 14);
      // WAVE_FORMAT_EXTENSIBLE (0xFFFE): real format is in the subformat GUID's
      // first two bytes (1 = PCM, 3 = float).
      if (fmt_tag == 0xFFFE && chunk_size >= 40) {
        fmt_tag = GetU16(body + 24);
      }
    } else if (std::memcmp(ch, "data", 4) == 0) {
      data_ptr = body;
      data_size = chunk_size;
    }

    off += 8 + chunk_size + (chunk_size & 1);  // chunks are word-aligned
  }

  if (!data_ptr || !channels || (channels != 1 && channels != 2)) return false;
  if (fmt_tag != 1 && fmt_tag != 3) return false;  // PCM or IEEE float only

  const uint32_t bytes_per_sample = bits / 8u;
  if (bytes_per_sample == 0) return false;
  const size_t total_samples = data_size / bytes_per_sample;

  out.samples.clear();
  out.samples.reserve(total_samples);
  out.sample_rate = sample_rate;
  out.channels = channels;

  if (fmt_tag == 3 && bits == 32) {
    for (size_t i = 0; i < total_samples; ++i) {
      float f;
      std::memcpy(&f, data_ptr + i * 4, 4);
      out.samples.push_back(SaturateFloatToI16(f));
    }
  } else if (fmt_tag == 1 && bits == 16) {
    for (size_t i = 0; i < total_samples; ++i) {
      out.samples.push_back(static_cast<int16_t>(GetU16(data_ptr + i * 2)));
    }
  } else if (fmt_tag == 1 && bits == 24) {
    for (size_t i = 0; i < total_samples; ++i) {
      const uint8_t* s = data_ptr + i * 3;
      int32_t v = static_cast<int32_t>(s[0]) | (static_cast<int32_t>(s[1]) << 8) |
                  (static_cast<int32_t>(s[2]) << 16);
      if (v & 0x800000) v |= ~0xFFFFFF;  // sign-extend 24 -> 32
      out.samples.push_back(static_cast<int16_t>(v >> 8));
    }
  } else if (fmt_tag == 1 && bits == 32) {
    for (size_t i = 0; i < total_samples; ++i) {
      int32_t v = static_cast<int32_t>(GetU32(data_ptr + i * 4));
      out.samples.push_back(static_cast<int16_t>(v >> 16));
    }
  } else if (fmt_tag == 1 && bits == 8) {
    // 8-bit WAV is unsigned.
    for (size_t i = 0; i < total_samples; ++i) {
      out.samples.push_back(static_cast<int16_t>((static_cast<int>(data_ptr[i]) - 128) << 8));
    }
  } else {
    return false;
  }

  return true;
}

}  // namespace rex::audio
