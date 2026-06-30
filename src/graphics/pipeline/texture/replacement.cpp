#ifdef REXGLUE_ENABLE_TEXTURES
/**
 * @file        graphics/pipeline/texture/replacement.cpp
 *
 * @brief       Texture dump and replacement pipeline implementation.
 *
 */
#include <rex/graphics/pipeline/texture/replacement.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <fstream>
#include <system_error>

extern "C" {
#include "libavcodec/avcodec.h"
#include "libavutil/frame.h"
#include "libavutil/imgutils.h"
}

#include <rex/graphics/pipeline/texture/conversion.h>
#include <rex/graphics/pipeline/texture/info.h>
#include <rex/logging.h>

#ifndef XXH_INLINE_ALL
#define XXH_INLINE_ALL
#endif
#include <xxhash.h>

// stb_image — PNG/JPEG/etc. loader (implementation compiled exactly once here)
// STB_IMAGE_STATIC gives all symbols internal linkage, preventing duplicate
// symbol conflicts if the consuming application also vendors stb_image.
#define STB_IMAGE_STATIC
#define STB_IMAGE_IMPLEMENTATION
#define STBI_NO_STDIO  // we pass memory buffers directly
#include <stb_image.h>

// stb_image_write — PNG writer (implementation compiled exactly once here)
// STB_IMAGE_WRITE_STATIC gives all symbols internal linkage.
#define STB_IMAGE_WRITE_STATIC
#define STB_IMAGE_WRITE_IMPLEMENTATION
#define STBI_WRITE_NO_STDIO  // we use the callback API with std::ofstream
#include <stb_image_write.h>

// ===========================================================================
// VideoDecoder — minimal MP4/H264 decoder for animated texture replacement
// ===========================================================================
//
// Parses the MP4 box tree from disk to build a sample table, then uses
// libavcodec's H264 software decoder (no libavformat needed).  Pixel data
// is stored as RGBA8 in TextureReplacementData::pixels so it plugs directly
// into the existing static-texture upload path.
//
// Frame timing is driven by wall-clock delta_ms passed from BeginFrame.
// When playback reaches the end the video loops seamlessly.

namespace {

static std::string AvErr(int code) {
  char buf[AV_ERROR_MAX_STRING_SIZE];
  av_strerror(code, buf, sizeof(buf));
  return buf;
}

// ---------------------------------------------------------------------------
// MP4 box helpers
// ---------------------------------------------------------------------------

static uint32_t R32BE(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) |
         (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) <<  8) |
         static_cast<uint32_t>(p[3]);
}
static uint64_t R64BE(const uint8_t* p) {
  return (static_cast<uint64_t>(R32BE(p)) << 32) | R32BE(p + 4);
}
static uint32_t BOX4(char a, char b, char c, char d) {
  return (static_cast<uint32_t>(static_cast<uint8_t>(a)) << 24) |
         (static_cast<uint32_t>(static_cast<uint8_t>(b)) << 16) |
         (static_cast<uint32_t>(static_cast<uint8_t>(c)) <<  8) |
         static_cast<uint32_t>(static_cast<uint8_t>(d));
}

struct Mp4Box {
  uint64_t file_offset = 0;
  uint64_t total_size  = 0;
  uint32_t type        = 0;
  uint64_t data_start  = 0;  // byte offset of first data byte (after header)
  uint64_t data_size   = 0;  // total_size - header_bytes
};

static bool ReadBoxAt(std::ifstream& f, uint64_t offset, uint64_t file_size,
                      Mp4Box& out) {
  if (offset + 8 > file_size) return false;
  f.seekg(static_cast<std::streamoff>(offset));
  uint8_t hdr[16];
  f.read(reinterpret_cast<char*>(hdr), 8);
  if (!f.good()) return false;

  uint32_t sz32 = R32BE(hdr);
  out.type        = R32BE(hdr + 4);
  out.file_offset = offset;

  if (sz32 == 1) {
    // Extended 64-bit size
    f.read(reinterpret_cast<char*>(hdr + 8), 8);
    if (!f.good()) return false;
    out.total_size = R64BE(hdr + 8);
    out.data_start = offset + 16;
    out.data_size  = out.total_size > 16 ? out.total_size - 16 : 0;
  } else if (sz32 == 0) {
    // Extends to EOF
    out.total_size = file_size - offset;
    out.data_start = offset + 8;
    out.data_size  = out.total_size > 8 ? out.total_size - 8 : 0;
  } else {
    out.total_size = sz32;
    out.data_start = offset + 8;
    out.data_size  = sz32 > 8 ? sz32 - 8 : 0;
  }
  return out.total_size >= 8;
}

// Iterate child boxes within [parent.data_start, parent.data_start+parent.data_size).
// Returns true and fills `out` on first match of `target_type`.
static bool FindChildBox(std::ifstream& f, const Mp4Box& parent,
                         uint32_t target_type, uint64_t file_size,
                         Mp4Box& out) {
  uint64_t pos = parent.data_start;
  uint64_t end = parent.data_start + parent.data_size;
  while (pos + 8 <= end) {
    Mp4Box box;
    if (!ReadBoxAt(f, pos, file_size, box)) break;
    if (box.total_size == 0) break;
    if (box.type == target_type) { out = box; return true; }
    pos += box.total_size;
  }
  return false;
}

// Read all bytes of a box's data into a vector.
static bool ReadBoxData(std::ifstream& f, const Mp4Box& box,
                        std::vector<uint8_t>& out) {
  if (box.data_size == 0) { out.clear(); return true; }
  out.resize(static_cast<size_t>(box.data_size));
  f.seekg(static_cast<std::streamoff>(box.data_start));
  f.read(reinterpret_cast<char*>(out.data()),
         static_cast<std::streamsize>(box.data_size));
  return f.good();
}

// ---------------------------------------------------------------------------
// Convert AVCC length-prefixed NAL units → Annex B start codes
// ---------------------------------------------------------------------------
static void AvccToAnnexB(const uint8_t* src, size_t src_size,
                         int nalu_len_size, std::vector<uint8_t>& dst) {
  static const uint8_t kSC[4] = {0, 0, 0, 1};
  size_t pos = 0;
  while (pos + static_cast<size_t>(nalu_len_size) <= src_size) {
    uint32_t nalu_size = 0;
    for (int i = 0; i < nalu_len_size; ++i)
      nalu_size = (nalu_size << 8) | src[pos + i];
    pos += static_cast<size_t>(nalu_len_size);
    if (nalu_size == 0 || pos + nalu_size > src_size) break;
    dst.insert(dst.end(), kSC, kSC + 4);
    dst.insert(dst.end(), src + pos, src + pos + nalu_size);
    pos += nalu_size;
  }
}

// ---------------------------------------------------------------------------
// YUV420P → RGBA8 (BT.601 limited range)
// ---------------------------------------------------------------------------
static void Yuv420pToRgba8(const uint8_t* y_plane, const uint8_t* u_plane,
                            const uint8_t* v_plane, int y_stride, int uv_stride,
                            uint8_t* rgba, int width, int height) {
  for (int row = 0; row < height; ++row) {
    for (int col = 0; col < width; ++col) {
      int yv = static_cast<int>(y_plane[row * y_stride + col])       - 16;
      int uv = static_cast<int>(u_plane[(row >> 1) * uv_stride + (col >> 1)]) - 128;
      int vv = static_cast<int>(v_plane[(row >> 1) * uv_stride + (col >> 1)]) - 128;
      int r = (298 * yv + 409 * vv + 128) >> 8;
      int g = (298 * yv - 100 * uv - 208 * vv + 128) >> 8;
      int b = (298 * yv + 516 * uv + 128) >> 8;
      uint8_t* p = rgba + (static_cast<size_t>(row) * static_cast<size_t>(width) + static_cast<size_t>(col)) * 4u;
      p[0] = static_cast<uint8_t>(std::clamp(r, 0, 255));
      p[1] = static_cast<uint8_t>(std::clamp(g, 0, 255));
      p[2] = static_cast<uint8_t>(std::clamp(b, 0, 255));
      p[3] = 255u;
    }
  }
}

// ---------------------------------------------------------------------------
// Per-frame metadata extracted from the MP4 sample table
// ---------------------------------------------------------------------------
struct VideoFrame {
  uint64_t file_offset = 0;
  uint32_t byte_size   = 0;
  bool     is_keyframe = false;
  double   pts_ms      = 0.0;  // presentation start time in ms
};

}  // anonymous namespace

namespace rex::graphics {

// ---------------------------------------------------------------------------
// VideoDecoder
// ---------------------------------------------------------------------------
class VideoDecoder {
 public:
  // Current decoded frame — FindReplacement returns a const ptr into this.
  TextureReplacementData current_data_;

  VideoDecoder() = default;
  ~VideoDecoder() {
    if (av_frame_)  av_frame_free(&av_frame_);
    if (packet_)    av_packet_free(&packet_);
    if (codec_ctx_) avcodec_free_context(&codec_ctx_);
  }
  VideoDecoder(const VideoDecoder&) = delete;
  VideoDecoder& operator=(const VideoDecoder&) = delete;

  bool Open(const std::filesystem::path& path) {
    path_ = path;
    if (!ParseMp4()) return false;
    if (frames_.empty()) return false;
    if (!InitDecoder()) return false;
    // Best-effort first frame; blank is acceptable if decoder is buffering.
    AdvanceToFrame(0);
    return true;
  }

  // Advance playback by delta_ms.  Returns true if the displayed frame changed.
  bool AdvanceDelta(double delta_ms) {
    if (frames_.empty()) return false;
    const double total_ms = frames_.back().pts_ms +
                            (fps_ > 0.0 ? 1000.0 / fps_ : 33.333);
    current_time_ms_ += delta_ms;
    // Loop
    if (current_time_ms_ >= total_ms) {
      current_time_ms_ = std::fmod(current_time_ms_, total_ms);
      // Flush decoder on loop so the keyframe is decoded cleanly.
      avcodec_flush_buffers(codec_ctx_);
      last_decoded_frame_ = -1;
    }
    // Find the target frame by scanning pts
    int target = static_cast<int>(frames_.size()) - 1;
    for (int i = 0; i < static_cast<int>(frames_.size()); ++i) {
      if (i + 1 < static_cast<int>(frames_.size()) &&
          frames_[i + 1].pts_ms > current_time_ms_) {
        target = i;
        break;
      }
      if (i + 1 == static_cast<int>(frames_.size())) {
        target = i;
      }
    }
    if (target == displayed_frame_) return false;
    return AdvanceToFrame(target);
  }

 private:
  std::filesystem::path path_;
  std::vector<VideoFrame> frames_;
  std::vector<uint8_t>    extradata_annexb_;  // SPS + PPS in Annex B
  uint8_t  nalu_length_size_ = 4;
  int      width_  = 0;
  int      height_ = 0;
  double   fps_    = 30.0;
  double   current_time_ms_ = 0.0;
  int      displayed_frame_ = -1;
  int      last_decoded_frame_ = -1;

  const AVCodec*   codec_      = nullptr;
  AVCodecContext*  codec_ctx_  = nullptr;
  AVFrame*         av_frame_   = nullptr;
  AVPacket*        packet_     = nullptr;

  // ---- MP4 parsing -------------------------------------------------------

  bool ParseMp4() {
    std::ifstream f(path_, std::ios::binary | std::ios::ate);
    if (!f.is_open()) {
      REXLOG_WARN("VideoDecoder: cannot open file {}", path_.string());
      return false;
    }
    const uint64_t file_size = static_cast<uint64_t>(f.tellg());
    f.seekg(0);
    REXLOG_DEBUG("VideoDecoder: parsing MP4  {}  ({} bytes)", path_.filename().string(), file_size);

    // Find moov box at the top level
    Mp4Box moov;
    {
      uint64_t pos = 0;
      bool found = false;
      while (pos + 8 <= file_size) {
        Mp4Box b;
        if (!ReadBoxAt(f, pos, file_size, b)) break;
        if (b.type == BOX4('m','o','o','v')) { moov = b; found = true; break; }
        if (b.total_size == 0) break;
        pos += b.total_size;
      }
      if (!found) {
        REXLOG_WARN("VideoDecoder: no moov box found in {}", path_.filename().string());
        return false;
      }
    }

    // Walk trak boxes looking for the video track
    uint64_t pos = moov.data_start;
    uint64_t end = moov.data_start + moov.data_size;
    while (pos + 8 <= end) {
      Mp4Box trak;
      if (!ReadBoxAt(f, pos, file_size, trak)) break;
      if (trak.total_size == 0) break;
      if (trak.type == BOX4('t','r','a','k')) {
        if (ParseTrak(f, trak, file_size)) return true;
      }
      pos += trak.total_size;
    }
    REXLOG_WARN("VideoDecoder: no H264 video track found in {}", path_.filename().string());
    return false;
  }

  bool ParseTrak(std::ifstream& f, const Mp4Box& trak, uint64_t file_size) {
    Mp4Box mdia;
    if (!FindChildBox(f, trak, BOX4('m','d','i','a'), file_size, mdia)) return false;

    // Confirm this is a video track via hdlr
    {
      Mp4Box hdlr;
      if (FindChildBox(f, mdia, BOX4('h','d','l','r'), file_size, hdlr)) {
        std::vector<uint8_t> d;
        if (ReadBoxData(f, hdlr, d) && d.size() >= 12) {
          uint32_t handler = R32BE(d.data() + 8);
          if (handler != BOX4('v','i','d','e')) {
            char hname[5] = {char(handler>>24),char(handler>>16),char(handler>>8),char(handler),0};
            REXLOG_DEBUG("VideoDecoder: skipping non-video track (handler='{}') in {}",
                         hname, path_.filename().string());
            return false;
          }
        }
      }
    }

    // mdhd: media timescale
    uint32_t timescale = 90000;
    {
      Mp4Box mdhd;
      if (FindChildBox(f, mdia, BOX4('m','d','h','d'), file_size, mdhd)) {
        std::vector<uint8_t> d;
        if (ReadBoxData(f, mdhd, d) && d.size() >= 20) {
          uint8_t version = d[0];
          if (version == 1 && d.size() >= 28)
            timescale = R32BE(d.data() + 20);
          else
            timescale = R32BE(d.data() + 12);
        }
      }
    }

    // tkhd: track dimensions
    {
      Mp4Box tkhd;
      if (FindChildBox(f, trak, BOX4('t','k','h','d'), file_size, tkhd)) {
        std::vector<uint8_t> d;
        if (ReadBoxData(f, tkhd, d)) {
          uint8_t version = d.empty() ? 0 : d[0];
          size_t off = (version == 1) ? 84 : 72;
          if (d.size() >= off + 8) {
            // Width and height are 16.16 fixed-point
            width_  = static_cast<int>(R32BE(d.data() + off)     >> 16);
            height_ = static_cast<int>(R32BE(d.data() + off + 4) >> 16);
          }
        }
      }
    }

    // Navigate mdia → minf → stbl
    Mp4Box minf, stbl;
    if (!FindChildBox(f, mdia, BOX4('m','i','n','f'), file_size, minf)) {
      REXLOG_WARN("VideoDecoder: minf box missing in {}", path_.filename().string());
      return false;
    }
    if (!FindChildBox(f, minf, BOX4('s','t','b','l'), file_size, stbl)) {
      REXLOG_WARN("VideoDecoder: stbl box missing in {}", path_.filename().string());
      return false;
    }

    // stsd: sample description → avcC extradata
    {
      Mp4Box stsd;
      if (FindChildBox(f, stbl, BOX4('s','t','s','d'), file_size, stsd)) {
        std::vector<uint8_t> d;
        if (ReadBoxData(f, stsd, d) && d.size() > 16) {
          // stsd has a 8-byte FullBox header (version+flags+entry_count)
          // then one or more sample entries.  avc1/avc3 are at d+8.
          // Each entry: [4 size][4 type][6 reserved][2 data-ref][... codec-specific]
          // avcC box is nested inside avc1 at variable depth.
          ParseAvcC(d.data() + 8, d.size() > 8 ? d.size() - 8 : 0);
        }
      }
    }

    // stts: time-to-sample → per-frame duration
    std::vector<std::pair<uint32_t,uint32_t>> stts;
    {
      Mp4Box box;
      if (FindChildBox(f, stbl, BOX4('s','t','t','s'), file_size, box)) {
        std::vector<uint8_t> d;
        if (ReadBoxData(f, box, d) && d.size() >= 8) {
          uint32_t cnt = R32BE(d.data() + 4);
          for (uint32_t i = 0; i < cnt && 8 + i * 8 + 8 <= d.size(); ++i) {
            uint32_t sc = R32BE(d.data() + 8 + i * 8);
            uint32_t sd = R32BE(d.data() + 8 + i * 8 + 4);
            stts.push_back({sc, sd});
          }
        }
      }
    }

    // stsz: sample sizes
    std::vector<uint32_t> sample_sizes;
    {
      Mp4Box box;
      if (FindChildBox(f, stbl, BOX4('s','t','s','z'), file_size, box)) {
        std::vector<uint8_t> d;
        if (ReadBoxData(f, box, d) && d.size() >= 12) {
          uint32_t default_size = R32BE(d.data() + 4);
          uint32_t sample_count = R32BE(d.data() + 8);
          if (default_size != 0) {
            sample_sizes.assign(sample_count, default_size);
          } else {
            for (uint32_t i = 0; i < sample_count && 12 + i * 4 + 4 <= d.size(); ++i)
              sample_sizes.push_back(R32BE(d.data() + 12 + i * 4));
          }
        }
      }
    }

    // stco / co64: chunk offsets
    std::vector<uint64_t> chunk_offsets;
    {
      Mp4Box box;
      if (FindChildBox(f, stbl, BOX4('s','t','c','o'), file_size, box)) {
        std::vector<uint8_t> d;
        if (ReadBoxData(f, box, d) && d.size() >= 8) {
          uint32_t cnt = R32BE(d.data() + 4);
          for (uint32_t i = 0; i < cnt && 8 + i * 4 + 4 <= d.size(); ++i)
            chunk_offsets.push_back(R32BE(d.data() + 8 + i * 4));
        }
      } else if (FindChildBox(f, stbl, BOX4('c','o','6','4'), file_size, box)) {
        std::vector<uint8_t> d;
        if (ReadBoxData(f, box, d) && d.size() >= 8) {
          uint32_t cnt = R32BE(d.data() + 4);
          for (uint32_t i = 0; i < cnt && 8 + i * 8 + 8 <= d.size(); ++i)
            chunk_offsets.push_back(R64BE(d.data() + 8 + i * 8));
        }
      }
    }

    // stsc: sample-to-chunk (first_chunk 1-based, samples_per_chunk)
    struct StscEntry { uint32_t first_chunk; uint32_t samples_per_chunk; };
    std::vector<StscEntry> stsc;
    {
      Mp4Box box;
      if (FindChildBox(f, stbl, BOX4('s','t','s','c'), file_size, box)) {
        std::vector<uint8_t> d;
        if (ReadBoxData(f, box, d) && d.size() >= 8) {
          uint32_t cnt = R32BE(d.data() + 4);
          for (uint32_t i = 0; i < cnt && 8 + i * 12 + 12 <= d.size(); ++i) {
            stsc.push_back({R32BE(d.data() + 8 + i * 12),
                            R32BE(d.data() + 8 + i * 12 + 4)});
          }
        }
      }
    }

    // stss: sync samples (keyframes), 1-based sample numbers
    std::unordered_set<uint32_t> keyframe_set;
    {
      Mp4Box box;
      if (FindChildBox(f, stbl, BOX4('s','t','s','s'), file_size, box)) {
        std::vector<uint8_t> d;
        if (ReadBoxData(f, box, d) && d.size() >= 8) {
          uint32_t cnt = R32BE(d.data() + 4);
          for (uint32_t i = 0; i < cnt && 8 + i * 4 + 4 <= d.size(); ++i)
            keyframe_set.insert(R32BE(d.data() + 8 + i * 4));
        }
      }
      // If stss is absent every sample is a keyframe
      if (keyframe_set.empty()) {
        for (uint32_t i = 1; i <= static_cast<uint32_t>(sample_sizes.size()); ++i)
          keyframe_set.insert(i);
      }
    }

    if (sample_sizes.empty() || chunk_offsets.empty() || stsc.empty()) {
      REXLOG_WARN("VideoDecoder: incomplete sample table in {} (stsz={} stco={} stsc={})",
                  path_.filename().string(),
                  sample_sizes.size(), chunk_offsets.size(), stsc.size());
      return false;
    }

    // Build flat sample file-offset table
    // For each chunk: find how many samples are in it via stsc, then
    // accumulate byte offsets within the chunk using sample_sizes.
    uint32_t sample_idx = 0;
    uint32_t total_chunks = static_cast<uint32_t>(chunk_offsets.size());
    for (uint32_t chunk = 1; chunk <= total_chunks && sample_idx < sample_sizes.size(); ++chunk) {
      // Find the stsc entry that applies to this chunk
      uint32_t spc = stsc[0].samples_per_chunk;
      for (size_t si = 0; si < stsc.size(); ++si) {
        if (stsc[si].first_chunk <= chunk) {
          spc = stsc[si].samples_per_chunk;
        }
      }
      uint64_t byte_off = chunk_offsets[chunk - 1];
      for (uint32_t s = 0; s < spc && sample_idx < sample_sizes.size(); ++s, ++sample_idx) {
        VideoFrame vf;
        vf.file_offset = byte_off;
        vf.byte_size   = sample_sizes[sample_idx];
        vf.is_keyframe = keyframe_set.count(sample_idx + 1) > 0;
        frames_.push_back(vf);
        byte_off += sample_sizes[sample_idx];
      }
    }

    if (frames_.empty()) {
      REXLOG_WARN("VideoDecoder: sample table built zero frames in {}", path_.filename().string());
      return false;
    }

    // Compute PTS from stts
    double ms_per_tick = timescale > 0 ? 1000.0 / static_cast<double>(timescale) : 0.0;
    uint32_t si = 0;
    double   t  = 0.0;
    for (auto& [count, dur] : stts) {
      for (uint32_t i = 0; i < count && si < frames_.size(); ++i, ++si) {
        frames_[si].pts_ms = t;
        t += static_cast<double>(dur) * ms_per_tick;
      }
    }
    // Fill remaining (shouldn't happen in well-formed MP4)
    while (si < frames_.size()) { frames_[si].pts_ms = t; ++si; }

    double total_dur_ms = t;
    fps_ = (total_dur_ms > 0.0 && frames_.size() > 1)
             ? (static_cast<double>(frames_.size()) / total_dur_ms) * 1000.0
             : 30.0;

    REXLOG_DEBUG("VideoDecoder: parsed {} frames  {:.1f}fps  {:.0f}ms  {}x{}  extradata={}b  in {}",
                 frames_.size(), fps_, total_dur_ms,
                 width_, height_, extradata_annexb_.size(),
                 path_.filename().string());
    return true;
  }

  // Parse avcC record nested somewhere inside the sample-description data.
  // We do a simple scan for the 4-byte tag 'avcC'.
  void ParseAvcC(const uint8_t* data, size_t size) {
    static const uint8_t kSC[4] = {0, 0, 0, 1};
    // Scan for avcC box tag
    for (size_t i = 0; i + 8 <= size; ++i) {
      if (data[i+4] == 'a' && data[i+5] == 'v' && data[i+6] == 'c' && data[i+7] == 'C') {
        uint32_t box_size = R32BE(data + i);
        if (box_size < 8 || i + box_size > size) break;
        const uint8_t* avcc = data + i + 8;
        size_t avcc_size = box_size - 8;
        // avcC layout:
        //   [1] version (always 1)
        //   [1] profile_idc
        //   [1] profile_compat
        //   [1] level_idc
        //   [1] lengthSizeMinusOne (& 0x03) → naluLengthSize
        //   [1] numSequenceParameterSets (& 0x1F)
        //   for each SPS: [2 len][len bytes]
        //   [1] numPictureParameterSets
        //   for each PPS: [2 len][len bytes]
        if (avcc_size < 6) break;
        nalu_length_size_ = static_cast<uint8_t>((avcc[4] & 0x03) + 1);
        uint8_t num_sps = avcc[5] & 0x1Fu;
        size_t pos = 6;
        for (uint8_t s = 0; s < num_sps && pos + 2 <= avcc_size; ++s) {
          uint16_t sps_len = static_cast<uint16_t>((avcc[pos] << 8) | avcc[pos + 1]);
          pos += 2;
          if (pos + sps_len > avcc_size) break;
          extradata_annexb_.insert(extradata_annexb_.end(), kSC, kSC + 4);
          extradata_annexb_.insert(extradata_annexb_.end(), avcc + pos, avcc + pos + sps_len);
          pos += sps_len;
        }
        if (pos >= avcc_size) break;
        uint8_t num_pps = avcc[pos++];
        for (uint8_t p = 0; p < num_pps && pos + 2 <= avcc_size; ++p) {
          uint16_t pps_len = static_cast<uint16_t>((avcc[pos] << 8) | avcc[pos + 1]);
          pos += 2;
          if (pos + pps_len > avcc_size) break;
          extradata_annexb_.insert(extradata_annexb_.end(), kSC, kSC + 4);
          extradata_annexb_.insert(extradata_annexb_.end(), avcc + pos, avcc + pos + pps_len);
          pos += pps_len;
        }
        REXLOG_DEBUG("VideoDecoder: avcC  nalu_len_size={}  extradata={}b  in {}",
                     nalu_length_size_, extradata_annexb_.size(), path_.filename().string());
        return;
      }
    }
    REXLOG_WARN("VideoDecoder: avcC record not found in stsd — decoder may fail for {}",
                path_.filename().string());
  }

  // ---- Decoder init ------------------------------------------------------

  bool InitDecoder() {
    codec_ = avcodec_find_decoder(AV_CODEC_ID_H264);
    if (!codec_) {
      REXLOG_WARN("VideoDecoder: H264 decoder not found — was it registered in codec_list.c?");
      return false;
    }
    REXLOG_DEBUG("VideoDecoder: found codec '{}'", codec_->name);

    codec_ctx_ = avcodec_alloc_context3(codec_);
    if (!codec_ctx_) {
      REXLOG_WARN("VideoDecoder: avcodec_alloc_context3 failed for {}", path_.filename().string());
      return false;
    }

    // Supply SPS/PPS as extradata in Annex B format so the decoder knows
    // the stream parameters before the first keyframe is sent.
    if (!extradata_annexb_.empty()) {
      codec_ctx_->extradata = static_cast<uint8_t*>(
          av_malloc(extradata_annexb_.size() + AV_INPUT_BUFFER_PADDING_SIZE));
      if (codec_ctx_->extradata) {
        std::memcpy(codec_ctx_->extradata, extradata_annexb_.data(),
                    extradata_annexb_.size());
        std::memset(codec_ctx_->extradata + extradata_annexb_.size(), 0,
                    AV_INPUT_BUFFER_PADDING_SIZE);
        codec_ctx_->extradata_size = static_cast<int>(extradata_annexb_.size());
      }
    } else {
      REXLOG_WARN("VideoDecoder: no SPS/PPS extradata — decoder may reject stream for {}",
                  path_.filename().string());
    }

    // Disable frame reorder buffering (B-frame delay) and threading delay
    // so avcodec_receive_frame produces output after each avcodec_send_packet.
    codec_ctx_->flags |= AV_CODEC_FLAG_LOW_DELAY;
    codec_ctx_->thread_count = 1;

    int open_ret = avcodec_open2(codec_ctx_, codec_, nullptr);
    if (open_ret < 0) {
      REXLOG_WARN("VideoDecoder: avcodec_open2 failed ({}) for {}",
                  AvErr(open_ret), path_.filename().string());
      return false;
    }

    av_frame_ = av_frame_alloc();
    packet_   = av_packet_alloc();
    if (!av_frame_ || !packet_) {
      REXLOG_WARN("VideoDecoder: av_frame/packet alloc failed for {}", path_.filename().string());
      return false;
    }

    // Pre-size the RGBA output buffer
    if (width_ > 0 && height_ > 0) {
      current_data_.width      = static_cast<uint32_t>(width_);
      current_data_.height     = static_cast<uint32_t>(height_);
      current_data_.mip_levels = 1;
      current_data_.pixels.assign(
          static_cast<size_t>(width_) * static_cast<size_t>(height_) * 4u, 0u);
    } else {
      REXLOG_WARN("VideoDecoder: tkhd reported zero dimensions ({}x{}) for {} — "
                  "dimensions will be taken from first decoded frame",
                  width_, height_, path_.filename().string());
    }
    REXLOG_INFO("VideoDecoder: decoder ready  {}  {}x{}  {} frames  {:.1f}fps",
                path_.filename().string(), width_, height_, frames_.size(), fps_);
    return true;
  }

  // ---- Frame decoding ----------------------------------------------------

  // Decode frames sequentially up to and including target_idx.
  // H264 is an inter-frame codec — we must decode all frames since the last
  // keyframe in order to obtain the correct picture.
  bool AdvanceToFrame(int target_idx) {
    if (target_idx < 0 || target_idx >= static_cast<int>(frames_.size())) return false;

    // If going backwards (e.g. after a loop flush) restart from the preceding
    // keyframe.
    int start = last_decoded_frame_ + 1;
    if (target_idx < start) {
      // Find the last keyframe at or before target_idx
      int kf = 0;
      for (int i = target_idx; i >= 0; --i) {
        if (frames_[i].is_keyframe) { kf = i; break; }
      }
      start = kf;
      avcodec_flush_buffers(codec_ctx_);
      last_decoded_frame_ = -1;
    }

    std::ifstream f(path_, std::ios::binary);
    if (!f.is_open()) {
      REXLOG_WARN("VideoDecoder: cannot reopen {} for frame decode", path_.filename().string());
      return false;
    }

    bool got_frame = false;
    for (int fi = start; fi <= target_idx; ++fi) {
      const VideoFrame& vf = frames_[fi];
      std::vector<uint8_t> raw(vf.byte_size + AV_INPUT_BUFFER_PADDING_SIZE, 0);
      f.seekg(static_cast<std::streamoff>(vf.file_offset));
      f.read(reinterpret_cast<char*>(raw.data()),
             static_cast<std::streamsize>(vf.byte_size));
      if (!f.good()) {
        REXLOG_WARN("VideoDecoder: read error at frame {} offset {} in {}",
                    fi, vf.file_offset, path_.filename().string());
        continue;
      }

      // Build Annex B packet: prepend SPS+PPS before keyframes
      std::vector<uint8_t> pkt_data;
      if (vf.is_keyframe && !extradata_annexb_.empty())
        pkt_data = extradata_annexb_;
      AvccToAnnexB(raw.data(), vf.byte_size, nalu_length_size_, pkt_data);

      av_packet_unref(packet_);
      packet_->data = pkt_data.data();
      packet_->size = static_cast<int>(pkt_data.size());

      int send_ret = avcodec_send_packet(codec_ctx_, packet_);
      if (send_ret < 0) {
        REXLOG_WARN("VideoDecoder: avcodec_send_packet frame {} failed ({}) in {}",
                    fi, AvErr(send_ret), path_.filename().string());
        continue;
      }

      // Drain all frames the decoder made available from this packet.
      // With AV_CODEC_FLAG_LOW_DELAY + thread_count=1 this is usually one,
      // but the loop handles any residual pipeline depth correctly.
      while (true) {
        int ret = avcodec_receive_frame(codec_ctx_, av_frame_);
        if (ret == AVERROR(EAGAIN) || ret == AVERROR_EOF) break;
        if (ret < 0) break;
        last_decoded_frame_ = fi;
        if (fi == target_idx) {
          UpdateRgba();
          got_frame = true;
        }
      }
    }

    // If the decoder still has frames buffered (pipeline delay), flush them out.
    if (!got_frame) {
      REXLOG_DEBUG("VideoDecoder: flushing decoder to drain frame {} in {}",
                   target_idx, path_.filename().string());
      avcodec_send_packet(codec_ctx_, nullptr);  // signal EOF to drain
      while (true) {
        int ret = avcodec_receive_frame(codec_ctx_, av_frame_);
        if (ret < 0) {
          if (ret != AVERROR_EOF && ret != AVERROR(EAGAIN))
            REXLOG_WARN("VideoDecoder: receive after flush returned ({}) for {}",
                        AvErr(ret), path_.filename().string());
          break;
        }
        UpdateRgba();
        got_frame = true;
      }
      // Reset decoder so it is ready for the next sequential send.
      avcodec_flush_buffers(codec_ctx_);
      last_decoded_frame_ = target_idx;
    }

    if (got_frame) {
      REXLOG_DEBUG("VideoDecoder: decoded frame {}  {}x{}  in {}",
                   target_idx, current_data_.width, current_data_.height,
                   path_.filename().string());
      displayed_frame_ = target_idx;
      return true;
    }
    REXLOG_WARN("VideoDecoder: failed to produce frame {} for {}",
                target_idx, path_.filename().string());
    return false;
  }

  void UpdateRgba() {
    if (!av_frame_) return;
    int w = av_frame_->width;
    int h = av_frame_->height;
    if (w <= 0 || h <= 0) return;

    // Update stored dimensions if the decoder reported different values
    if (w != width_ || h != height_) {
      width_  = w;
      height_ = h;
      current_data_.width  = static_cast<uint32_t>(w);
      current_data_.height = static_cast<uint32_t>(h);
      current_data_.pixels.resize(static_cast<size_t>(w) * static_cast<size_t>(h) * 4u);
    }

    // av_frame format should be AV_PIX_FMT_YUV420P for H264
    if (av_frame_->format == AV_PIX_FMT_YUV420P ||
        av_frame_->format == AV_PIX_FMT_YUVJ420P) {
      Yuv420pToRgba8(av_frame_->data[0], av_frame_->data[1], av_frame_->data[2],
                     av_frame_->linesize[0], av_frame_->linesize[1],
                     current_data_.pixels.data(), w, h);
    }
  }
};

// ---------------------------------------------------------------------------
// DDS constants and structures
// ---------------------------------------------------------------------------

static constexpr uint32_t kDdsMagic        = 0x20534444u;  // "DDS "
static constexpr uint32_t kDdsdCaps        = 0x00000001u;
static constexpr uint32_t kDdsdHeight      = 0x00000002u;
static constexpr uint32_t kDdsdWidth       = 0x00000004u;
static constexpr uint32_t kDdsdPitch       = 0x00000008u;
static constexpr uint32_t kDdsdLinearSize  = 0x00080000u;
static constexpr uint32_t kDdsdPixelFormat = 0x00001000u;
static constexpr uint32_t kDdsPfRgb        = 0x00000040u;
static constexpr uint32_t kDdsPfAlphaPixels= 0x00000001u;
static constexpr uint32_t kDdsPfFourCC    = 0x00000004u;
static constexpr uint32_t kDdsCapsTexture  = 0x00001000u;

static constexpr uint32_t kFourCC_DXT1 = 0x31545844u;  // "DXT1"
static constexpr uint32_t kFourCC_DXT3 = 0x33545844u;  // "DXT3"
static constexpr uint32_t kFourCC_DXT5 = 0x35545844u;  // "DXT5"
static constexpr uint32_t kFourCC_ATI1 = 0x31495441u;  // "ATI1" (BC4 / DXN red)
static constexpr uint32_t kFourCC_ATI2 = 0x32495441u;  // "ATI2" (BC5 / DXN rg)

#pragma pack(push, 1)
struct DdsPixelFormat {
  uint32_t size = 32;
  uint32_t flags        = 0;
  uint32_t four_cc      = 0;
  uint32_t rgb_bit_count= 0;
  uint32_t r_bit_mask   = 0;
  uint32_t g_bit_mask   = 0;
  uint32_t b_bit_mask   = 0;
  uint32_t a_bit_mask   = 0;
};
struct DdsHeader {
  uint32_t      magic             = kDdsMagic;
  uint32_t      size              = 124;
  uint32_t      flags             = 0;
  uint32_t      height            = 0;
  uint32_t      width             = 0;
  uint32_t      pitch_or_linear   = 0;
  uint32_t      depth             = 0;
  uint32_t      mip_map_count     = 1;
  uint32_t      reserved1[11]     = {};
  DdsPixelFormat ddspf;
  uint32_t      caps              = kDdsCapsTexture;
  uint32_t      caps2             = 0;
  uint32_t      caps3             = 0;
  uint32_t      caps4             = 0;
  uint32_t      reserved2         = 0;
};
#pragma pack(pop)
static_assert(sizeof(DdsHeader) == 128);

// ---------------------------------------------------------------------------
// Internal helpers: tiled address decode (mirrors conversion.cpp)
// ---------------------------------------------------------------------------
static uint32_t TiledOffset2DRow(uint32_t y, uint32_t width, uint32_t log2_bpp) {
  uint32_t macro = ((y / 32) * (width / 32)) << (log2_bpp + 7);
  uint32_t micro = ((y & 6) << 2) << log2_bpp;
  return macro + ((micro & ~0xFu) << 1) + (micro & 0xFu) +
         ((y & 8) << (3 + log2_bpp)) + ((y & 1) << 4);
}

static uint32_t TiledOffset2DColumn(uint32_t x, uint32_t y, uint32_t log2_bpp,
                                    uint32_t base_offset) {
  uint32_t macro = (x / 32) << (log2_bpp + 7);
  uint32_t micro = (x & 7) << log2_bpp;
  uint32_t offset = base_offset + (macro + ((micro & ~0xFu) << 1) + (micro & 0xFu));
  return ((offset & ~0x1FFu) << 3) + ((offset & 0x1C0u) << 2) + (offset & 0x3Fu) +
         ((y & 16) << 7) + (((((y & 8) >> 2) + (x >> 3)) & 3) << 6);
}

// Untile a 2-D block-based texture into a linear output buffer.
//   src              : tiled guest bytes
//   dst              : output buffer (row-major, no padding)
//   width_blocks     : visible width in blocks
//   height_blocks    : visible height in blocks
//   pitch_blocks     : row pitch in blocks (aligned to 32 for tiled)
//   bytes_per_block  : bytes per compressed block or texel
static void UntileBlocks(const uint8_t* src, uint8_t* dst,
                         uint32_t width_blocks, uint32_t height_blocks,
                         uint32_t pitch_blocks, uint32_t bytes_per_block) {
  // log2(bytes_per_block / 4) + extra bias matching Xenia's formula
  const uint32_t log2_bpp =
      (bytes_per_block / 4) + ((bytes_per_block / 2) >> (bytes_per_block / 4));

  const uint32_t out_row_bytes = width_blocks * bytes_per_block;

  for (uint32_t y = 0; y < height_blocks; ++y) {
    const uint32_t row_offset = TiledOffset2DRow(y, pitch_blocks, log2_bpp);
    for (uint32_t x = 0; x < width_blocks; ++x) {
      uint32_t src_offset = TiledOffset2DColumn(x, y, log2_bpp, row_offset);
      src_offset >>= log2_bpp;
      std::memcpy(dst + y * out_row_bytes + x * bytes_per_block,
                  src  + src_offset * bytes_per_block,
                  bytes_per_block);
    }
  }
}

// ---------------------------------------------------------------------------
// RGBA8 expansion helpers
// ---------------------------------------------------------------------------
// Each returns an RGBA8 pixel from a pointer into the (already endian-swapped)
// source data.

static uint32_t Expand5To8(uint32_t v) { return (v << 3) | (v >> 2); }
static uint32_t Expand6To8(uint32_t v) { return (v << 2) | (v >> 4); }

// Convert one texel from the given format (already endian-corrected) to RGBA8.
// Returns false for formats that need the BC path (compressed blocks).
static bool TexelToRGBA8(const uint8_t* src, xenos::TextureFormat fmt, uint8_t out[4]) {
  using F = xenos::TextureFormat;
  switch (fmt) {
    case F::k_8_8_8_8:
    case F::k_8_8_8_8_A:
    case F::k_8_8_8_8_GAMMA_EDRAM:
      out[0] = src[0]; out[1] = src[1]; out[2] = src[2]; out[3] = src[3];
      return true;
    case F::k_8:
    case F::k_8_A:
    case F::k_8_B:
      out[0] = out[1] = out[2] = src[0]; out[3] = 255;
      return true;
    case F::k_8_8:
      out[0] = src[0]; out[1] = src[1]; out[2] = 0; out[3] = 255;
      return true;
    case F::k_5_6_5: {
      uint16_t v; std::memcpy(&v, src, 2);
      out[0] = static_cast<uint8_t>(Expand5To8((v >> 11) & 0x1F));
      out[1] = static_cast<uint8_t>(Expand6To8((v >>  5) & 0x3F));
      out[2] = static_cast<uint8_t>(Expand5To8( v        & 0x1F));
      out[3] = 255;
      return true;
    }
    case F::k_1_5_5_5: {
      uint16_t v; std::memcpy(&v, src, 2);
      out[0] = static_cast<uint8_t>(Expand5To8((v >> 10) & 0x1F));
      out[1] = static_cast<uint8_t>(Expand5To8((v >>  5) & 0x1F));
      out[2] = static_cast<uint8_t>(Expand5To8( v        & 0x1F));
      out[3] = static_cast<uint8_t>(((v >> 15) & 1) ? 255 : 0);
      return true;
    }
    case F::k_4_4_4_4: {
      uint16_t v; std::memcpy(&v, src, 2);
      out[0] = static_cast<uint8_t>(((v >> 12) & 0xF) * 17);
      out[1] = static_cast<uint8_t>(((v >>  8) & 0xF) * 17);
      out[2] = static_cast<uint8_t>(((v >>  4) & 0xF) * 17);
      out[3] = static_cast<uint8_t>(( v        & 0xF) * 17);
      return true;
    }
    case F::k_2_10_10_10: {
      uint32_t v; std::memcpy(&v, src, 4);
      out[0] = static_cast<uint8_t>((v >> 22) & 0xFF);
      out[1] = static_cast<uint8_t>((v >> 12) & 0xFF);
      out[2] = static_cast<uint8_t>((v >>  2) & 0xFF);
      out[3] = static_cast<uint8_t>(((v & 3) * 85));
      return true;
    }
    default:
      // Unsupported / compressed — caller should use BC path or skip
      out[0] = out[1] = out[2] = out[3] = 0;
      return false;
  }
}

// ---------------------------------------------------------------------------
// BC block decompressors (used when dumping BC textures as PNG)
// ---------------------------------------------------------------------------

// Decompress one 4x4 DXT1/BC1 block into dst_rgba (row pitch = dst_pitch bytes).
static void DecompressDXT1Block(const uint8_t* src, uint8_t* dst_rgba,
                                uint32_t dst_pitch, bool force_opaque = false) {
  uint16_t c0, c1;
  std::memcpy(&c0, src, 2);
  std::memcpy(&c1, src + 2, 2);
  uint32_t bits;
  std::memcpy(&bits, src + 4, 4);

  uint8_t r[4], g[4], b[4], a[4];
  r[0] = static_cast<uint8_t>(Expand5To8((c0 >> 11) & 0x1F));
  g[0] = static_cast<uint8_t>(Expand6To8((c0 >>  5) & 0x3F));
  b[0] = static_cast<uint8_t>(Expand5To8( c0        & 0x1F));
  a[0] = 255;
  r[1] = static_cast<uint8_t>(Expand5To8((c1 >> 11) & 0x1F));
  g[1] = static_cast<uint8_t>(Expand6To8((c1 >>  5) & 0x3F));
  b[1] = static_cast<uint8_t>(Expand5To8( c1        & 0x1F));
  a[1] = 255;
  if (c0 > c1 || force_opaque) {
    r[2] = (2*r[0] + r[1]) / 3; g[2] = (2*g[0] + g[1]) / 3;
    b[2] = (2*b[0] + b[1]) / 3; a[2] = 255;
    r[3] = (r[0] + 2*r[1]) / 3; g[3] = (g[0] + 2*g[1]) / 3;
    b[3] = (b[0] + 2*b[1]) / 3; a[3] = 255;
  } else {
    r[2] = (r[0] + r[1]) / 2; g[2] = (g[0] + g[1]) / 2;
    b[2] = (b[0] + b[1]) / 2; a[2] = 255;
    r[3] = 0; g[3] = 0; b[3] = 0; a[3] = 0;
  }
  for (int y = 0; y < 4; ++y) {
    for (int x = 0; x < 4; ++x) {
      const int idx = (bits >> (2 * (y * 4 + x))) & 3;
      uint8_t* p = dst_rgba + y * dst_pitch + x * 4;
      p[0] = r[idx]; p[1] = g[idx]; p[2] = b[idx]; p[3] = a[idx];
    }
  }
}

// Decode BC3/DXT5 alpha channel (or BC4/ATI1 single-channel) 8-byte block.
// Writes 4x4 values into out_alpha; stride = out_pitch bytes.
static void DecodeBC4Block(const uint8_t* src, uint8_t* out, uint32_t out_pitch,
                           int channel_offset = 0, int channel_stride = 1) {
  const uint8_t a0 = src[0], a1 = src[1];
  uint8_t alpha[8];
  alpha[0] = a0; alpha[1] = a1;
  if (a0 > a1) {
    alpha[2] = static_cast<uint8_t>((6*a0 + 1*a1) / 7);
    alpha[3] = static_cast<uint8_t>((5*a0 + 2*a1) / 7);
    alpha[4] = static_cast<uint8_t>((4*a0 + 3*a1) / 7);
    alpha[5] = static_cast<uint8_t>((3*a0 + 4*a1) / 7);
    alpha[6] = static_cast<uint8_t>((2*a0 + 5*a1) / 7);
    alpha[7] = static_cast<uint8_t>((1*a0 + 6*a1) / 7);
  } else {
    alpha[2] = static_cast<uint8_t>((4*a0 + 1*a1) / 5);
    alpha[3] = static_cast<uint8_t>((3*a0 + 2*a1) / 5);
    alpha[4] = static_cast<uint8_t>((2*a0 + 3*a1) / 5);
    alpha[5] = static_cast<uint8_t>((1*a0 + 4*a1) / 5);
    alpha[6] = 0; alpha[7] = 255;
  }
  // 48-bit index table packed as 6 bytes starting at src[2]
  uint64_t bits = 0;
  for (int i = 0; i < 6; ++i) bits |= static_cast<uint64_t>(src[2 + i]) << (8 * i);
  for (int y = 0; y < 4; ++y) {
    for (int x = 0; x < 4; ++x) {
      const int idx = static_cast<int>((bits >> (3 * (y * 4 + x))) & 7);
      out[y * out_pitch + x * channel_stride + channel_offset] = alpha[idx];
    }
  }
}

// Decompress one 4x4 DXT3/BC2 block into dst_rgba (16 bytes/block).
static void DecompressDXT3Block(const uint8_t* src, uint8_t* dst_rgba,
                                uint32_t dst_pitch) {
  // First 8 bytes: explicit 4-bit alpha values (2 pixels per byte, row-major)
  for (int y = 0; y < 4; ++y) {
    for (int x = 0; x < 4; ++x) {
      const uint8_t packed = src[y * 2 + x / 2];
      const uint8_t nibble = (x & 1) ? (packed >> 4) : (packed & 0xF);
      dst_rgba[y * dst_pitch + x * 4 + 3] = static_cast<uint8_t>(nibble * 17);
    }
  }
  // Last 8 bytes: DXT1 color block (force-opaque so we don't overwrite alpha)
  uint8_t tmp[4 * 4 * 4];
  DecompressDXT1Block(src + 8, tmp, 4 * 4, /*force_opaque=*/true);
  for (int y = 0; y < 4; ++y) {
    for (int x = 0; x < 4; ++x) {
      uint8_t* p = dst_rgba + y * dst_pitch + x * 4;
      const uint8_t* s = tmp + y * (4 * 4) + x * 4;
      p[0] = s[0]; p[1] = s[1]; p[2] = s[2];
      // p[3] already written above
    }
  }
}

// Decompress one 4x4 DXT5/BC3 block into dst_rgba (16 bytes/block).
static void DecompressDXT5Block(const uint8_t* src, uint8_t* dst_rgba,
                                uint32_t dst_pitch) {
  // First 8 bytes: BC4-style alpha block
  uint8_t alpha_row[4 * 4];  // 1-channel scratch
  DecodeBC4Block(src, alpha_row, 4, 0, 1);
  // Last 8 bytes: DXT1 color (force-opaque)
  uint8_t tmp[4 * 4 * 4];
  DecompressDXT1Block(src + 8, tmp, 4 * 4, /*force_opaque=*/true);
  for (int y = 0; y < 4; ++y) {
    for (int x = 0; x < 4; ++x) {
      uint8_t* p = dst_rgba + y * dst_pitch + x * 4;
      const uint8_t* s = tmp + y * (4 * 4) + x * 4;
      p[0] = s[0]; p[1] = s[1]; p[2] = s[2];
      p[3] = alpha_row[y * 4 + x];
    }
  }
}

// Decompress an entire 2D BC texture into a tightly-packed RGBA8 buffer.
// Returns false if the format is not supported for PNG output.
static bool DecompressBCToRGBA8(xenos::TextureFormat format,
                                 const uint8_t* blocks,
                                 uint32_t width, uint32_t height,
                                 uint32_t w_blocks, uint32_t h_blocks,
                                 std::vector<uint8_t>& rgba_out) {
  using F = xenos::TextureFormat;
  rgba_out.assign(static_cast<size_t>(width) * height * 4, 0);

  // Per-block scratch for 4x4 RGBA8 tile
  uint8_t tile[4 * 4 * 4];

  for (uint32_t by = 0; by < h_blocks; ++by) {
    for (uint32_t bx = 0; bx < w_blocks; ++bx) {
      const uint32_t block_idx = by * w_blocks + bx;
      const uint8_t* src = nullptr;

      switch (format) {
        case F::k_DXT1:
        case F::k_DXT1_AS_16_16_16_16:
          src = blocks + block_idx * 8;
          DecompressDXT1Block(src, tile, 4 * 4);
          break;
        case F::k_DXT2_3:
        case F::k_DXT2_3_AS_16_16_16_16:
        case F::k_DXT3A:
        case F::k_DXT3A_AS_1_1_1_1:
          src = blocks + block_idx * 16;
          DecompressDXT3Block(src, tile, 4 * 4);
          break;
        case F::k_DXT4_5:
        case F::k_DXT4_5_AS_16_16_16_16:
          src = blocks + block_idx * 16;
          DecompressDXT5Block(src, tile, 4 * 4);
          break;
        case F::k_DXT5A: {
          // BC4: single red channel → replicate to RGB, alpha=255
          src = blocks + block_idx * 8;
          uint8_t r_row[4 * 4];
          DecodeBC4Block(src, r_row, 4, 0, 1);
          for (int i = 0; i < 16; ++i) {
            tile[i * 4 + 0] = r_row[i]; tile[i * 4 + 1] = r_row[i];
            tile[i * 4 + 2] = r_row[i]; tile[i * 4 + 3] = 255;
          }
          break;
        }
        case F::k_DXN: {
          // BC5: red + green channels, blue=0, alpha=255
          src = blocks + block_idx * 16;
          uint8_t rg[4 * 4 * 2];
          // Row pitch = 4 pixels * 2 bytes/pixel = 8; stride=2 for interleaved RG
          DecodeBC4Block(src,     rg, 8, 0, 2);  // red   at offset 0
          DecodeBC4Block(src + 8, rg, 8, 1, 2);  // green at offset 1
          for (int i = 0; i < 16; ++i) {
            tile[i * 4 + 0] = rg[i * 2 + 0]; tile[i * 4 + 1] = rg[i * 2 + 1];
            tile[i * 4 + 2] = 0;              tile[i * 4 + 3] = 255;
          }
          break;
        }
        default:
          return false;  // unsupported BC variant
      }

      // Blit the 4x4 tile into rgba_out, clamping to visible dimensions
      const uint32_t px0 = bx * 4, py0 = by * 4;
      for (uint32_t ty = 0; ty < 4; ++ty) {
        const uint32_t py = py0 + ty;
        if (py >= height) break;
        for (uint32_t tx = 0; tx < 4; ++tx) {
          const uint32_t px = px0 + tx;
          if (px >= width) break;
          uint8_t* dst = rgba_out.data() + (py * width + px) * 4;
          const uint8_t* tsrc = tile + ty * (4 * 4) + tx * 4;
          dst[0] = tsrc[0]; dst[1] = tsrc[1]; dst[2] = tsrc[2]; dst[3] = tsrc[3];
        }
      }
    }
  }
  return true;
}

// ---------------------------------------------------------------------------
// DDS file writers
// ---------------------------------------------------------------------------

bool TextureReplacement::WriteDDS_RGBA8(const std::filesystem::path& path,
                                        uint32_t width, uint32_t height,
                                        const uint8_t* rgba8_rows,
                                        uint32_t row_pitch_bytes) {
  std::error_code ec;
  std::filesystem::create_directories(path.parent_path(), ec);

  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  if (!f.is_open()) return false;

  DdsHeader hdr;
  hdr.flags           = kDdsdCaps | kDdsdHeight | kDdsdWidth | kDdsdPixelFormat | kDdsdPitch;
  hdr.height          = height;
  hdr.width           = width;
  hdr.pitch_or_linear = width * 4;
  hdr.ddspf.flags     = kDdsPfRgb | kDdsPfAlphaPixels;
  hdr.ddspf.rgb_bit_count = 32;
  hdr.ddspf.r_bit_mask    = 0x000000FFu;
  hdr.ddspf.g_bit_mask    = 0x0000FF00u;
  hdr.ddspf.b_bit_mask    = 0x00FF0000u;
  hdr.ddspf.a_bit_mask    = 0xFF000000u;

  f.write(reinterpret_cast<const char*>(&hdr), sizeof(hdr));

  const uint32_t row_bytes = width * 4;
  for (uint32_t y = 0; y < height; ++y) {
    f.write(reinterpret_cast<const char*>(rgba8_rows + y * row_pitch_bytes), row_bytes);
  }
  return f.good();
}

bool TextureReplacement::WriteDDS_BC(const std::filesystem::path& path,
                                     uint32_t width, uint32_t height,
                                     const uint8_t* bc_blocks,
                                     uint32_t bytes_per_block,
                                     uint32_t fourcc) {
  std::error_code ec;
  std::filesystem::create_directories(path.parent_path(), ec);

  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  if (!f.is_open()) return false;

  const uint32_t w_blocks = (width  + 3) / 4;
  const uint32_t h_blocks = (height + 3) / 4;
  const uint32_t linear_size = w_blocks * h_blocks * bytes_per_block;

  DdsHeader hdr;
  hdr.flags           = kDdsdCaps | kDdsdHeight | kDdsdWidth | kDdsdPixelFormat | kDdsdLinearSize;
  hdr.height          = height;
  hdr.width           = width;
  hdr.pitch_or_linear = linear_size;
  hdr.ddspf.flags     = kDdsPfFourCC;
  hdr.ddspf.four_cc   = fourcc;

  f.write(reinterpret_cast<const char*>(&hdr), sizeof(hdr));
  f.write(reinterpret_cast<const char*>(bc_blocks), linear_size);
  return f.good();
}

// ---------------------------------------------------------------------------
// PNG file writer
// ---------------------------------------------------------------------------

// stb_image_write callback that appends data to a std::ofstream.
static void StbiWriteOstream(void* context, void* data, int size) {
  auto* f = static_cast<std::ofstream*>(context);
  f->write(static_cast<const char*>(data), size);
}

bool TextureReplacement::WritePNG_RGBA8(const std::filesystem::path& path,
                                        uint32_t width, uint32_t height,
                                        const uint8_t* rgba8_rows,
                                        uint32_t row_pitch_bytes) {
  std::error_code ec;
  std::filesystem::create_directories(path.parent_path(), ec);

  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  if (!f.is_open()) return false;

  const int ok = stbi_write_png_to_func(
      StbiWriteOstream, &f,
      static_cast<int>(width), static_cast<int>(height),
      4,  // RGBA
      rgba8_rows,
      static_cast<int>(row_pitch_bytes));
  return ok != 0 && f.good();
}

// ---------------------------------------------------------------------------
// DDS reader (RGBA8 only — what tools export for replacements)
// ---------------------------------------------------------------------------
bool TextureReplacement::ReadDDS(const std::filesystem::path& path,
                                  TextureReplacementData& out) {
  std::ifstream f(path, std::ios::binary);
  if (!f.is_open()) return false;

  DdsHeader hdr{};
  f.read(reinterpret_cast<char*>(&hdr), sizeof(hdr));
  if (!f || hdr.magic != kDdsMagic || hdr.size != 124) return false;

  out.width      = hdr.width;
  out.height     = hdr.height;
  out.mip_levels = std::max(1u, hdr.mip_map_count);

  if (hdr.ddspf.rgb_bit_count != 32 ||
      hdr.ddspf.r_bit_mask    != 0x000000FFu ||
      hdr.ddspf.g_bit_mask    != 0x0000FF00u ||
      hdr.ddspf.b_bit_mask    != 0x00FF0000u) {
    REXLOG_WARN("TextureReplacement: {} has unsupported pixel format - must be RGBA8",
                path.filename().string());
    return false;
  }

  const size_t pixel_bytes = static_cast<size_t>(out.width) * out.height * 4;
  out.pixels.resize(pixel_bytes);
  f.read(reinterpret_cast<char*>(out.pixels.data()), static_cast<std::streamsize>(pixel_bytes));
  return f.good();
}

// ---------------------------------------------------------------------------
// TextureReplacement — construction / rescan
// ---------------------------------------------------------------------------

TextureReplacement::~TextureReplacement() = default;

TextureReplacement::TextureReplacement(std::filesystem::path root)
    : root_(std::move(root)) {
  dump_dir_ = root_ / "dumps" / "textures";
  replace_dir_ = root_ / "mods" / "textures";

  std::error_code ec;
  std::filesystem::create_directories(dump_dir_, ec);
  ec.clear();
  std::filesystem::create_directories(replace_dir_, ec);

  Rescan();
}

void TextureReplacement::Rescan() {
  replacements_.clear();
  pixel_cache_.clear();
  failed_cache_.clear();
  video_decoders_.clear();

  std::error_code ec;
  if (!std::filesystem::exists(replace_dir(), ec)) return;

  size_t video_count = 0;
  for (auto& entry : std::filesystem::directory_iterator(replace_dir(), ec)) {
    if (ec) break;
    if (!entry.is_regular_file()) continue;
    auto& p = entry.path();
    const auto ext = p.extension();
    if (ext != ".dds" && ext != ".png" && ext != ".mp4") continue;

    const std::string stem = p.stem().string();
    if (stem.size() < 16) continue;

    uint64_t hash = 0;
    bool ok = true;
    for (int i = 0; i < 16; ++i) {
      char c = stem[i];
      uint64_t nibble = 0;
      if      (c >= '0' && c <= '9') nibble = static_cast<uint64_t>(c - '0');
      else if (c >= 'a' && c <= 'f') nibble = static_cast<uint64_t>(c - 'a' + 10);
      else if (c >= 'A' && c <= 'F') nibble = static_cast<uint64_t>(c - 'A' + 10);
      else { ok = false; break; }
      hash = (hash << 4) | nibble;
    }
    if (!ok) continue;

    if (ext == ".mp4") {
      auto dec = std::make_unique<VideoDecoder>();
      if (dec->Open(p)) {
        video_decoders_.emplace(hash, std::move(dec));
        ++video_count;
        REXLOG_INFO("TextureReplacement: loaded video {}  ({}x{})",
                    p.filename().string(),
                    video_decoders_.at(hash)->current_data_.width,
                    video_decoders_.at(hash)->current_data_.height);
      } else {
        REXLOG_WARN("TextureReplacement: failed to open video {}",
                    p.filename().string());
      }
    } else {
      replacements_[hash] = p;
    }
  }

  REXLOG_INFO("TextureReplacement: {} static + {} video replacement(s) indexed from {}",
              replacements_.size(), video_count, replace_dir().string());
}

// ---------------------------------------------------------------------------
// Hash
// ---------------------------------------------------------------------------
uint64_t TextureReplacement::HashGuestData(const uint8_t* data, size_t size) {
  return XXH3_64bits(data, size);
}

// ---------------------------------------------------------------------------
// DumpTexture — untile + endian-swap + write DDS or PNG
// ---------------------------------------------------------------------------
void TextureReplacement::DumpTexture(uint64_t content_hash,
                                      uint32_t width, uint32_t height,
                                      uint32_t pitch_blocks,
                                      bool tiled,
                                      xenos::TextureFormat format,
                                      xenos::Endian endianness,
                                      const uint8_t* guest_bytes,
                                      uint32_t guest_size) const {
  using F = xenos::TextureFormat;

  const FormatInfo* fi = FormatInfo::Get(format);
  if (!fi) return;

  // Skip video/cutscene-sized textures when the blacklist cvar is set
  if (REXCVAR_GET(texture_dump_skip_video_sizes)) {
    if ((width == 640  && height == 360) ||
        (width == 1280 && height == 720)) {
      return;
    }
  }

  // Determine output format from cvar (default: "dds")
  const bool use_png = (REXCVAR_GET(texture_dump_format) == "png");
  const std::string ext = use_png ? ".png" : ".dds";

  // Build filename: <hash16>_<w>x<h>_<format_name>.<ext>
  char name[128];
  std::snprintf(name, sizeof(name), "%016llx_%ux%u_%s%s",
                static_cast<unsigned long long>(content_hash),
                width, height, fi->name, ext.c_str());
  const auto dest = dump_dir() / name;

  // Only write once per unique texture to avoid hammering the disk.
  if (std::filesystem::exists(dest)) return;

  const uint32_t bpb          = fi->bytes_per_block();
  const uint32_t w_blocks     = (width  + fi->block_width  - 1) / fi->block_width;
  const uint32_t h_blocks     = (height + fi->block_height - 1) / fi->block_height;
  // pitch_blocks is in units of 32 texels, convert to block units
  const uint32_t pitch_b32    = pitch_blocks * 32;            // pitch in texels
  const uint32_t pitch_blk    = (pitch_b32 + fi->block_width - 1) / fi->block_width;

  // Step 1 — allocate a linear staging buffer and untile (or copy linear)
  const uint32_t linear_bytes = w_blocks * h_blocks * bpb;
  std::vector<uint8_t> linear(linear_bytes);

  if (tiled) {
    UntileBlocks(guest_bytes, linear.data(), w_blocks, h_blocks, pitch_blk, bpb);
  } else {
    // Linear: rows are already in order but may have pitch padding — copy
    // only the visible region.
    const uint32_t src_row_bytes = pitch_blk * bpb;
    const uint32_t dst_row_bytes = w_blocks  * bpb;
    for (uint32_t y = 0; y < h_blocks; ++y) {
      const uint32_t src_off = y * src_row_bytes;
      if (src_off + dst_row_bytes > guest_size) break;
      std::memcpy(linear.data() + y * dst_row_bytes,
                  guest_bytes   + src_off,
                  dst_row_bytes);
    }
  }

  // Step 2 — endian-swap the staging buffer in-place using CopySwapBlock
  if (endianness != xenos::Endian::kNone) {
    texture_conversion::CopySwapBlock(endianness, linear.data(), linear.data(), linear_bytes);
  }

  // Step 3 — write to the chosen format
  if (fi->type == FormatType::kCompressed) {
    if (use_png) {
      // Decompress BC blocks to RGBA8, then encode as PNG
      std::vector<uint8_t> rgba;
      if (!DecompressBCToRGBA8(format, linear.data(), width, height,
                                w_blocks, h_blocks, rgba)) {
        // Unsupported BC variant — fall back silently to DDS
        auto dds_dest = dump_dir() / (std::string(name, std::strlen(name) - 4) + ".dds");
        uint32_t fourcc = kFourCC_DXT5;
        if (!WriteDDS_BC(dds_dest, width, height, linear.data(), bpb, fourcc)) {
          REXLOG_WARN("TextureReplacement: failed to write BC dump {}", dds_dest.string());
        } else {
          REXLOG_DEBUG("TextureReplacement: dumped BC (DDS fallback) {}",
                       dds_dest.filename().string());
        }
        return;
      }
      const uint32_t out_row_bytes = width * 4;
      if (!WritePNG_RGBA8(dest, width, height, rgba.data(), out_row_bytes)) {
        REXLOG_WARN("TextureReplacement: failed to write BC PNG dump {}", dest.string());
      } else {
        REXLOG_DEBUG("TextureReplacement: dumped BC→PNG {}", dest.filename().string());
      }
    } else {
      // DDS mode: write raw BC blocks
      uint32_t fourcc = 0;
      switch (format) {
        case F::k_DXT1:
        case F::k_DXT1_AS_16_16_16_16: fourcc = kFourCC_DXT1; break;
        case F::k_DXT2_3:
        case F::k_DXT2_3_AS_16_16_16_16: fourcc = kFourCC_DXT3; break;
        case F::k_DXT4_5:
        case F::k_DXT4_5_AS_16_16_16_16: fourcc = kFourCC_DXT5; break;
        case F::k_DXN:                  fourcc = kFourCC_ATI2; break;
        case F::k_DXT5A:                fourcc = kFourCC_ATI1; break;
        case F::k_DXT3A:
        case F::k_DXT3A_AS_1_1_1_1:    fourcc = kFourCC_DXT3; break;
        default:                        fourcc = kFourCC_DXT5; break;
      }
      if (!WriteDDS_BC(dest, width, height, linear.data(), bpb, fourcc)) {
        REXLOG_WARN("TextureReplacement: failed to write BC dump {}", dest.string());
      } else {
        REXLOG_DEBUG("TextureReplacement: dumped BC  {}", dest.filename().string());
      }
    }
  } else {
    // Uncompressed — expand each texel to RGBA8
    const uint32_t out_row_bytes = w_blocks * 4;  // w_blocks == width for uncompressed
    std::vector<uint8_t> rgba(static_cast<size_t>(w_blocks) * h_blocks * 4);

    for (uint32_t y = 0; y < h_blocks; ++y) {
      for (uint32_t x = 0; x < w_blocks; ++x) {
        const uint8_t* src = linear.data() + (y * w_blocks + x) * bpb;
        uint8_t* dst = rgba.data() + y * out_row_bytes + x * 4;
        if (!TexelToRGBA8(src, format, dst)) {
          // Unsupported format — write raw bytes zero-padded to RGBA8 as
          // a best-effort so at least something useful shows up.
          dst[0] = bpb > 0 ? src[0] : 0;
          dst[1] = bpb > 1 ? src[1] : 0;
          dst[2] = bpb > 2 ? src[2] : 0;
          dst[3] = bpb > 3 ? src[3] : 255;
        }
      }
    }

    if (use_png) {
      if (!WritePNG_RGBA8(dest, width, height, rgba.data(), out_row_bytes)) {
        REXLOG_WARN("TextureReplacement: failed to write PNG dump {}", dest.string());
      } else {
        REXLOG_DEBUG("TextureReplacement: dumped PNG  {}", dest.filename().string());
      }
    } else {
      if (!WriteDDS_RGBA8(dest, width, height, rgba.data(), out_row_bytes)) {
        REXLOG_WARN("TextureReplacement: failed to write RGBA8 dump {}", dest.string());
      } else {
        REXLOG_DEBUG("TextureReplacement: dumped RGBA8 {}", dest.filename().string());
      }
    }
  }
}

// ---------------------------------------------------------------------------
// PNG reader (RGBA8 — via stb_image)
// ---------------------------------------------------------------------------
bool TextureReplacement::ReadPNG(const std::filesystem::path& path,
                                  TextureReplacementData& out) {
  // Read the whole file into memory first so we can use stbi_load_from_memory
  // (avoids any stdio FILE* locale issues on Windows).
  std::ifstream f(path, std::ios::binary | std::ios::ate);
  if (!f.is_open()) return false;

  const auto file_size = static_cast<size_t>(f.tellg());
  f.seekg(0);
  std::vector<uint8_t> buf(file_size);
  f.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(file_size));
  if (!f) return false;

  int w = 0, h = 0, channels = 0;
  uint8_t* data = stbi_load_from_memory(buf.data(),
                                         static_cast<int>(file_size),
                                         &w, &h, &channels, 4 /*RGBA*/);
  if (!data) {
    REXLOG_WARN("TextureReplacement: stb_image failed to load {}: {}",
                path.filename().string(), stbi_failure_reason());
    return false;
  }

  out.width      = static_cast<uint32_t>(w);
  out.height     = static_cast<uint32_t>(h);
  out.mip_levels = 1;
  out.pixels.assign(data, data + static_cast<size_t>(w) * h * 4);
  stbi_image_free(data);
  return true;
}

// ---------------------------------------------------------------------------
// FindReplacement
// ---------------------------------------------------------------------------
const TextureReplacementData* TextureReplacement::FindReplacement(uint64_t content_hash) const {
  // Video replacement — return a pointer to the decoder's current frame.
  {
    auto it = video_decoders_.find(content_hash);
    if (it != video_decoders_.end()) {
      return &it->second->current_data_;
    }
  }

  // Already cached (success)?
  {
    auto it = pixel_cache_.find(content_hash);
    if (it != pixel_cache_.end()) {
      return &it->second;
    }
  }

  // Known failure — don't retry.
  if (failed_cache_.count(content_hash)) return nullptr;

  auto it = replacements_.find(content_hash);
  if (it == replacements_.end()) {
    failed_cache_.insert(content_hash);
    return nullptr;
  }

  const auto& p = it->second;
  const auto ext = p.extension();
  TextureReplacementData loaded;
  bool ok = false;
  if (ext == ".png") {
    ok = ReadPNG(p, loaded);
  } else {
    ok = ReadDDS(p, loaded);
  }

  if (!ok) {
    REXLOG_WARN("TextureReplacement: failed to load {}", p.filename().string());
    failed_cache_.insert(content_hash);
    return nullptr;
  }

  auto [ins, _] = pixel_cache_.emplace(content_hash, std::move(loaded));
  return &ins->second;
}

// ---------------------------------------------------------------------------
// IsVideoReplacement / AdvanceVideoFrames
// ---------------------------------------------------------------------------
bool TextureReplacement::IsVideoReplacement(uint64_t content_hash) const {
  return video_decoders_.count(content_hash) > 0;
}

bool TextureReplacement::AdvanceVideoFrames(double delta_ms) {
  bool any_changed = false;
  for (auto& [hash, dec] : video_decoders_) {
    if (dec->AdvanceDelta(delta_ms)) any_changed = true;
  }
  return any_changed;
}

}  // namespace rex::graphics
#endif  // REXGLUE_ENABLE_TEXTURES
