#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <stdarg.h>

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

// Read one asset name from the string table.
// Assumes the asset's name_offset and name_length have already been validated.
static bun_result_t bun_read_asset_name(
    BunParseContext *ctx,
    const BunHeader *header,
    const BunAssetRecord *asset,
    char **out_name
) {
    u64 file_offset = header->string_table_offset + asset->name_offset;
    size_t name_len = (size_t) asset->name_length;
    char *name = NULL;

    if (out_name == NULL) {
        return BUN_ERR_IO;
    }

    *out_name = NULL;

    if (file_offset > (u64) LONG_MAX) {
        return BUN_ERR_IO;
    }

    name = malloc(name_len + 1);
    if (name == NULL) {
        return BUN_ERR_IO;
    }

    if (fseek(ctx->file, (long) file_offset, SEEK_SET) != 0) {
        free(name);
        return BUN_ERR_IO;
    }

    if (fread(name, 1, name_len, ctx->file) != name_len) {
        free(name);
        return BUN_ERR_IO;
    }

    name[name_len] = '\0';
    *out_name = name;

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


//BASIC LOGIC IS DONE
//TODO: ADD SAFETEY CHECKS
//TODO: check tasks spreadsheet: Task ID: H6
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
    u64 asset_table_size = (u64)header->asset_count * 48;

    u64 asset_start = header->asset_table_offset;
    u64 string_start = header->string_table_offset;
    u64 data_start = header->data_section_offset;

    u64 asset_end = asset_start + asset_table_size;
    u64 string_end = string_start + header->string_table_size;
    u64 data_end = data_start + header->data_section_size;

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

    return result;
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
