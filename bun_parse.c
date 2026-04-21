#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "bun.h"

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

//BASIC LOGIC IS DONE
//TODO: ADD SAFETEY CHECKS
//TODO: check tasks spreadsheet: Task ID: H5,H6,H7
bun_result_t bun_parse_header(BunParseContext *ctx, BunHeader *header) {
  u8 buf[BUN_HEADER_SIZE];

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

  // Helper for u64
  #define READ_U64_LE(b, off) \
    ((u64)b[off] \
    | (u64)b[off+1] << 8 \
    | (u64)b[off+2] << 16 \
    | (u64)b[off+3] << 24 \
    | (u64)b[off+4] << 32 \
    | (u64)b[off+5] << 40 \
    | (u64)b[off+6] << 48 \
    | (u64)b[off+7] << 56)

  // 3. Populate header 
  size_t off = 0;

  header->magic = read_u32_le(buf, off);
  off += 4;

  header->version_major = READ_U16_LE(buf, off);
  off += 2;

  header->version_minor = READ_U16_LE(buf, off);
  off += 2;

  header->asset_count = read_u32_le(buf, off);
  off += 4;

  header->asset_table_offset = READ_U64_LE(buf, off);
  off += 8;

  header->string_table_offset = READ_U64_LE(buf, off);
  off += 8;

  header->string_table_size = READ_U64_LE(buf, off);
  off += 8;

  header->data_section_offset = READ_U64_LE(buf, off);
  off += 8;

  header->data_section_size = READ_U64_LE(buf, off);
  off += 8;

  header->reserved = READ_U64_LE(buf, off);
  off += 8;

  // 4. VALIDATION

  // Magic check
  if (header->magic != BUN_MAGIC) {
    return BUN_MALFORMED;
  }

  // Version check
  if (header->version_major != 1 || header->version_minor != 0) {
    return BUN_UNSUPPORTED;
  }

  // Alignment check (must be divisible by 4)
  if ((header->asset_table_offset % 4 != 0) ||
      (header->string_table_offset % 4 != 0) ||
      (header->data_section_offset % 4 != 0) ||
      (header->string_table_size % 4 != 0) ||
      (header->data_section_size % 4 != 0)) {
    return BUN_MALFORMED;
  }

  // Bounds check (must be within file)
  u64 file_size = (u64)ctx->file_size;

  if (header->asset_table_offset > file_size ||
      header->string_table_offset > file_size ||
      header->data_section_offset > file_size) {
    return BUN_MALFORMED;
  }

  // Section overflow check (offset + size should not exceed file)
  if (header->string_table_offset + header->string_table_size > file_size ||
      header->data_section_offset + header->data_section_size > file_size) {
    return BUN_MALFORMED;
  }

  return BUN_OK;
}

bun_result_t bun_parse_assets(BunParseContext *ctx, const BunHeader *header) {

  // TODO: implement asset record parsing and validation

  return BUN_OK;
}

bun_result_t bun_close(BunParseContext *ctx) {
  assert(ctx->file);

  int res = fclose(ctx->file);
  if (res) {
    return BUN_ERR_IO;
  } else {
    ctx->file = NULL;
    return BUN_OK;
  }
}
