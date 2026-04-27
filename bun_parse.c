#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>
#include <limits.h>

#include "bun.h"

static void bun_add_violation(BunParseContext *ctx, const char *fmt, ...);

/**
 * Example helper: convert 4 bytes in `buf`, positioned at `offset`,
 * into a little-endian u32.
 */
static u32 read_u32_le(const u8 *buf, size_t offset) {
  return (u32)buf[offset]
     | (u32)buf[offset + 1] << 8
     | (u32)buf[offset + 2] << 16
     | (u32)buf[offset + 3] << 24;
}

static u64 read_u64_le(const u8 *buf, size_t offset) {
  return (u64)buf[offset]
     | (u64)buf[offset + 1] << 8
     | (u64)buf[offset + 2] << 16
     | (u64)buf[offset + 3] << 24
     | (u64)buf[offset + 4] << 32
     | (u64)buf[offset + 5] << 40
     | (u64)buf[offset + 6] << 48
     | (u64)buf[offset + 7] << 56;
}

static int u64_add_overflow(u64 a, u64 b, u64 *out) {
  if (a > UINT64_MAX - b) {
    return 1;
  }
  *out = a + b;
  return 0;
}

static int u64_mul_overflow(u64 a, u64 b, u64 *out) {
  if (a != 0 && b > UINT64_MAX / a) {
    return 1;
  }
  *out = a * b;
  return 0;
}

static int seek_to(FILE *file, u64 offset) {
  if (offset > (u64)LONG_MAX) {
    return 0;
  }
  return fseek(file, (long)offset, SEEK_SET) == 0;
}

static int read_exact(FILE *file, void *buf, size_t size) {
  return fread(buf, 1, size, file) == size;
}

static int is_printable_ascii(const char *buf, size_t len) {
  for (size_t i = 0; i < len; i++) {
    unsigned char ch = (unsigned char)buf[i];
    if (ch < 0x20u || ch > 0x7eu) {
      return 0;
    }
  }
  return 1;
}

static u32 crc32_update(u32 crc, const u8 *data, size_t len) {
  /* CRC32 (IEEE 802.3), table-driven for speed.
   * Polynomial matches the previous bitwise implementation: 0xEDB88320.
   */
  static u32 table[256];
  static int have_table = 0;

  if (!have_table) {
    for (u32 i = 0; i < 256; i++) {
      u32 c = i;
      for (int bit = 0; bit < 8; bit++) {
        c = (c >> 1) ^ (0xedb88320u & (u32)-(int)(c & 1u));
      }
      table[i] = c;
    }
    have_table = 1;
  }

  crc = ~crc;
  for (size_t i = 0; i < len; i++) {
    crc = table[(crc ^ data[i]) & 0xffu] ^ (crc >> 8);
  }
  return ~crc;
}

static bun_result_t validate_uncompressed_asset(
    BunParseContext *ctx,
    const BunHeader *header,
    const BunAssetRecord *record,
    size_t asset_index) {
  if (record->uncompressed_size != 0 && record->uncompressed_size != record->data_size) {
    bun_add_violation(ctx,
                      "asset %zu: uncompressed asset has inconsistent uncompressed_size",
                      asset_index);
    return BUN_MALFORMED;
  }

  if (record->checksum == 0) {
    return BUN_OK;
  }

  u64 absolute = 0;
  if (u64_add_overflow(header->data_section_offset, record->data_offset, &absolute) ||
      !seek_to(ctx->file, absolute)) {
    bun_add_violation(ctx, "asset %zu: could not seek to payload", asset_index);
    return BUN_ERR_IO;
  }

  u8 buffer[4096];
  u64 remaining = record->data_size;
  u32 crc = 0;

  while (remaining > 0) {
    size_t chunk = (remaining > (u64)sizeof(buffer)) ? sizeof(buffer) : (size_t)remaining;
    if (!read_exact(ctx->file, buffer, chunk)) {
      bun_add_violation(ctx, "asset %zu: could not read payload", asset_index);
      return BUN_ERR_IO;
    }
    crc = crc32_update(crc, buffer, chunk);
    remaining -= (u64)chunk;
  }

  if (crc != record->checksum) {
    bun_add_violation(ctx, "asset %zu: checksum mismatch", asset_index);
    return BUN_MALFORMED;
  }

  return BUN_OK;
}

static bun_result_t validate_rle_asset(
    BunParseContext *ctx,
    const BunHeader *header,
    const BunAssetRecord *record,
    size_t asset_index) {
  if (record->uncompressed_size == 0) {
    bun_add_violation(ctx, "asset %zu: RLE asset must declare uncompressed_size", asset_index);
    return BUN_MALFORMED;
  }

  u64 absolute = 0;
  if (u64_add_overflow(header->data_section_offset, record->data_offset, &absolute) ||
      !seek_to(ctx->file, absolute)) {
    bun_add_violation(ctx, "asset %zu: could not seek to RLE payload", asset_index);
    return BUN_ERR_IO;
  }

  u64 remaining = record->data_size;
  u64 produced = 0;
  u32 crc = 0;

  while (remaining > 0) {
    u8 pair[2];
    if (remaining < 2) {
      bun_add_violation(ctx, "asset %zu: malformed RLE stream", asset_index);
      return BUN_MALFORMED;
    }
    if (!read_exact(ctx->file, pair, sizeof(pair))) {
      bun_add_violation(ctx, "asset %zu: could not read RLE pair", asset_index);
      return BUN_ERR_IO;
    }
    remaining -= 2;

    u8 count = pair[0];
    u8 value = pair[1];
    if (count == 0) {
      bun_add_violation(ctx, "asset %zu: malformed RLE run length 0", asset_index);
      return BUN_MALFORMED;
    }
    if (produced > UINT64_MAX - (u64)count) {
      bun_add_violation(ctx, "asset %zu: RLE expansion overflow", asset_index);
      return BUN_MALFORMED;
    }

    produced += (u64)count;
    for (u8 i = 0; i < count; i++) {
      crc = crc32_update(crc, &value, 1);
    }
  }

  if (produced != record->uncompressed_size) {
    bun_add_violation(ctx, "asset %zu: RLE size mismatch", asset_index);
    return BUN_MALFORMED;
  }

  if (record->checksum != 0 && crc != record->checksum) {
    bun_add_violation(ctx, "asset %zu: checksum mismatch", asset_index);
    return BUN_MALFORMED;
  }

  return BUN_OK;
}

//
// API implementation
//



bun_result_t bun_open(const char *path, BunParseContext *ctx) {
  // we open the file; seek to the end, to get the size; then jump back to the
  // beginning, ready to start parsing.

  ctx->file = fopen(path, "rb");
  if (!ctx->file) {
    return BUN_ERR_IO;
  }

  if (fseek(ctx->file, 0, SEEK_END) != 0) {
    fclose(ctx->file);
    return BUN_ERR_IO;
  }
  ctx->file_size = ftell(ctx->file);
  if (ctx->file_size < 0) {
    fclose(ctx->file);
    return BUN_ERR_IO;
  }
  rewind(ctx->file);

  return BUN_OK;
}

//to list errors together
static void bun_add_violation(BunParseContext *ctx, const char *fmt, ...) {
    if (ctx->violation_count == ctx->violation_capacity) {
        size_t new_cap = (ctx->violation_capacity == 0) ? 8 : ctx->violation_capacity * 2;

        BunViolation *new_block =
            realloc(ctx->violations, new_cap * sizeof(BunViolation));

        if (!new_block)
            return; // fail silently 

        ctx->violations = new_block;
        ctx->violation_capacity = new_cap;
    }

    va_list args;
    va_start(args, fmt);

    vsnprintf(
        ctx->violations[ctx->violation_count].message,
        256,
        fmt,
        args
    );

    va_end(args);

    ctx->violation_count++;
}

bun_result_t bun_parse_header(BunParseContext *ctx, BunHeader *header) {
  u8 buf[BUN_HEADER_SIZE];
  bun_result_t result = BUN_OK;

  // 1. Check file is large enough
  if (ctx->file_size < (long)BUN_HEADER_SIZE) {
    return BUN_MALFORMED;
  }

  // 2. Read header into buffer
  if (fread(buf, 1, BUN_HEADER_SIZE, ctx->file) != BUN_HEADER_SIZE) {
    return BUN_ERR_IO;
  }

  // Helper for u16
  #define READ_U16_LE(b, off) ((u16)(b[off] | (b[off+1] << 8)))

  // 3. Populate header (read fields in order)
  size_t off = 0;

  header->magic = read_u32_le(buf, off);
  off += 4;

  header->version_major = READ_U16_LE(buf, off);
  off += 2;

  header->version_minor = READ_U16_LE(buf, off);
  off += 2;

  header->asset_count = read_u32_le(buf, off);
  off += 4;

  header->asset_table_offset = read_u64_le(buf, off);
  off += 8;

  header->string_table_offset = read_u64_le(buf, off);
  off += 8;

  header->string_table_size = read_u64_le(buf, off);
  off += 8;

  header->data_section_offset = read_u64_le(buf, off);
  off += 8;

  header->data_section_size = read_u64_le(buf, off);
  off += 8;

  header->reserved = read_u64_le(buf, off);
  off += 8;

  // 4. VALIDATION

  if (header->magic != BUN_MAGIC) {
      bun_add_violation(ctx, "invalid magic number");
      result = BUN_MALFORMED;
    }

    if (header->version_major != 1 || header->version_minor != 0) {
      return BUN_UNSUPPORTED; // allowed immediate stop per spec
    }

    if ((header->asset_table_offset % 4 != 0) ||
        (header->string_table_offset % 4 != 0) ||
        (header->data_section_offset % 4 != 0) ||
        (header->string_table_size % 4 != 0) ||
        (header->data_section_size % 4 != 0)) {

      bun_add_violation(ctx, "unaligned section offset or size");
      result = BUN_MALFORMED;
    }

    u64 file_size = (u64)ctx->file_size;
    u64 asset_table_size = 0;
    if (u64_mul_overflow((u64)header->asset_count, (u64)BUN_ASSET_RECORD_SIZE, &asset_table_size)) {
      bun_add_violation(ctx, "asset table size overflow");
      return BUN_MALFORMED;
    }

    u64 asset_start = header->asset_table_offset;
    u64 string_start = header->string_table_offset;
    u64 data_start = header->data_section_offset;

    u64 asset_end = 0;
    u64 string_end = 0;
    u64 data_end = 0;

    if (u64_add_overflow(asset_start, asset_table_size, &asset_end) ||
        u64_add_overflow(string_start, header->string_table_size, &string_end) ||
        u64_add_overflow(data_start, header->data_section_size, &data_end)) {
      bun_add_violation(ctx, "section end offset overflow");
      return BUN_MALFORMED;
    }

    if (asset_end > file_size) {
      bun_add_violation(ctx, "asset table exceeds file bounds");
      result = BUN_MALFORMED;
    }

    if (string_end > file_size) {
      bun_add_violation(ctx, "string table exceeds file bounds");
      result = BUN_MALFORMED;
    }

    if (data_end > file_size) {
      bun_add_violation(ctx, "data section exceeds file bounds");
      result = BUN_MALFORMED;
    }

    if (asset_start < string_end && string_start < asset_end) {
      bun_add_violation(ctx, "asset table overlaps string table");
      result = BUN_MALFORMED;
    }

    if (asset_start < data_end && data_start < asset_end) {
      bun_add_violation(ctx, "asset table overlaps data section");
      result = BUN_MALFORMED;
    }

    if (string_start < data_end && data_start < string_end) {
      bun_add_violation(ctx, "string table overlaps data section");
      result = BUN_MALFORMED;
    }

    ctx->header = *header;
    ctx->header_parsed = 1;
    return result;
  }

bun_result_t bun_parse_assets(BunParseContext *ctx, const BunHeader *header) {
  if (!header) {
    return BUN_MALFORMED;
  }

  free(ctx->assets);
  ctx->assets = NULL;
  ctx->parsed_asset_count = 0;

  if (header->asset_count == 0) {
    return BUN_OK;
  }

  ctx->assets = calloc(header->asset_count, sizeof(BunAssetRecord));
  if (!ctx->assets) {
    return BUN_ERR_IO;
  }

  for (u32 i = 0; i < header->asset_count; i++) {
    u64 record_offset = 0;
    if (u64_mul_overflow((u64)i, (u64)BUN_ASSET_RECORD_SIZE, &record_offset) ||
        u64_add_overflow(header->asset_table_offset, record_offset, &record_offset) ||
        !seek_to(ctx->file, record_offset)) {
      bun_add_violation(ctx, "asset %u: invalid record offset", i);
      return BUN_ERR_IO;
    }

    u8 buf[BUN_ASSET_RECORD_SIZE];
    if (!read_exact(ctx->file, buf, sizeof(buf))) {
      bun_add_violation(ctx, "asset %u: could not read asset record", i);
      return BUN_ERR_IO;
    }

    BunAssetRecord *record = &ctx->assets[i];
    size_t off = 0;
    record->name_offset = read_u32_le(buf, off); off += 4;
    record->name_length = read_u32_le(buf, off); off += 4;
    record->data_offset = read_u64_le(buf, off); off += 8;
    record->data_size = read_u64_le(buf, off); off += 8;
    record->uncompressed_size = read_u64_le(buf, off); off += 8;
    record->compression = read_u32_le(buf, off); off += 4;
    record->type = read_u32_le(buf, off); off += 4;
    record->checksum = read_u32_le(buf, off); off += 4;
    record->flags = read_u32_le(buf, off); off += 4;

    if (record->name_length == 0) {
      bun_add_violation(ctx, "asset %u: empty asset name", i);
      return BUN_MALFORMED;
    }

    u64 name_end = 0;
    if (u64_add_overflow((u64)record->name_offset, (u64)record->name_length, &name_end) ||
        name_end > header->string_table_size) {
      bun_add_violation(ctx, "asset %u: name range outside string table", i);
      return BUN_MALFORMED;
    }

    u64 data_end = 0;
    if (u64_add_overflow(record->data_offset, record->data_size, &data_end) ||
        data_end > header->data_section_size) {
      bun_add_violation(ctx, "asset %u: data range outside data section", i);
      return BUN_MALFORMED;
    }

    if ((record->flags & ~BUN_KNOWN_FLAGS) != 0u) {
      bun_add_violation(ctx, "asset %u: unsupported flags 0x%x", i, record->flags);
      return BUN_UNSUPPORTED;
    }

    u64 name_absolute = 0;
    if (u64_add_overflow(header->string_table_offset, (u64)record->name_offset, &name_absolute) ||
        !seek_to(ctx->file, name_absolute)) {
      bun_add_violation(ctx, "asset %u: could not seek to asset name", i);
      return BUN_ERR_IO;
    }

    char *name_buf = malloc((size_t)record->name_length);
    if (!name_buf) {
      return BUN_ERR_IO;
    }
    if (!read_exact(ctx->file, name_buf, (size_t)record->name_length)) {
      free(name_buf);
      bun_add_violation(ctx, "asset %u: could not read asset name", i);
      return BUN_ERR_IO;
    }
    if (!is_printable_ascii(name_buf, (size_t)record->name_length)) {
      free(name_buf);
      bun_add_violation(ctx, "asset %u: asset name contains non-printable ASCII", i);
      return BUN_MALFORMED;
    }
    free(name_buf);

    bun_result_t compression_result = BUN_OK;
    switch (record->compression) {
      case BUN_COMPRESS_NONE:
        compression_result = validate_uncompressed_asset(ctx, header, record, (size_t)i);
        break;
      case BUN_COMPRESS_RLE:
        compression_result = validate_rle_asset(ctx, header, record, (size_t)i);
        break;
      case BUN_COMPRESS_ZLIB:
        bun_add_violation(ctx, "asset %u: zlib compression is unsupported", i);
        return BUN_UNSUPPORTED;
      default:
        bun_add_violation(ctx, "asset %u: unknown compression %u", i, record->compression);
        return BUN_UNSUPPORTED;
    }

    if (compression_result != BUN_OK) {
      return compression_result;
    }

    ctx->parsed_asset_count = i + 1;
  }

  return BUN_OK;
}





bun_result_t bun_close(BunParseContext *ctx) {
  assert(ctx->file);

  int res = fclose(ctx->file);
  if (res) {
    return BUN_ERR_IO;
  } else {
    ctx->file = NULL;
    free(ctx->assets);
    ctx->assets = NULL;
    ctx->parsed_asset_count = 0;
    free(ctx->violations);
    ctx->violations = NULL;
    ctx->violation_count = 0;
    ctx->violation_capacity = 0;
    return BUN_OK;
  }
}
