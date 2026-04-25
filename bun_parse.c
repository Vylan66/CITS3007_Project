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
static u16 read_u16_le(const u8 *buf, size_t offset) {
    return (u16)((u16)buf[offset]
         | ((u16)buf[offset + 1] << 8));
}

static u32 read_u32_le(const u8 *buf, size_t offset) {
  return (u32)buf[offset]
       | (u32)buf[offset + 1] << 8
       | (u32)buf[offset + 2] << 16
       | (u32)buf[offset + 3] << 24;
}

static u64 read_u64_le(const u8 *buf, size_t offset) {
    return ((u64)buf[offset])
         | ((u64)buf[offset + 1] << 8)
         | ((u64)buf[offset + 2] << 16)
         | ((u64)buf[offset + 3] << 24)
         | ((u64)buf[offset + 4] << 32)
         | ((u64)buf[offset + 5] << 40)
         | ((u64)buf[offset + 6] << 48)
         | ((u64)buf[offset + 7] << 56);
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

    name = (char *) malloc(name_len + 1);
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
            (BunViolation *) realloc(ctx->violations, new_cap * sizeof(BunViolation));

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

  // 3. Populate header (read fields in order)
  size_t off = 0;

  header->magic = read_u32_le(buf, off);
  off += 4;

  header->version_major = read_u16_le(buf, off);
  off += 2;

  header->version_minor = read_u16_le(buf, off);
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
    u32 i;

    if (ctx == NULL || header == NULL) {
        return BUN_ERR_IO;
    }

    ctx->assets = NULL;
    ctx->asset_names = NULL;
    ctx->parsed_asset_count = 0;

    // No assets → nothing to do
    if (header->asset_count == 0) {
        return BUN_OK;
    }

    // Allocate storage for parsed asset records
    ctx->assets = calloc(header->asset_count, sizeof(BunAssetRecord));
    if (ctx->assets == NULL) {
        return BUN_ERR_IO;
    }

    // Allocate storage for asset name pointers
    ctx->asset_names = calloc(header->asset_count, sizeof(char *));
    if (ctx->asset_names == NULL) {
        free(ctx->assets);
        ctx->assets = NULL;
        return BUN_ERR_IO;
    }

    // Ensure offset is safe to cast to long for fseek
    if (header->asset_table_offset > (u64)LONG_MAX) {
        free(ctx->asset_names);
        free(ctx->assets);
        ctx->asset_names = NULL;
        ctx->assets = NULL;
        return BUN_ERR_IO;
    }

    // Seek to the start of the asset table
    if (fseek(ctx->file, (long)header->asset_table_offset, SEEK_SET) != 0) {
        free(ctx->asset_names);
        free(ctx->assets);
        ctx->asset_names = NULL;
        ctx->assets = NULL;
        return BUN_ERR_IO;
    }

    // Iterate over each asset record
    for (i = 0; i < header->asset_count; i++) {
        BunAssetRecord *asset = &ctx->assets[i];
        u8 buf[BUN_ASSET_RECORD_SIZE];
        bun_result_t name_result;

        // Read raw asset record bytes from file
        if (fread(buf, 1, BUN_ASSET_RECORD_SIZE, ctx->file) != BUN_ASSET_RECORD_SIZE) {
            /* TODO A1: read asset records safely (handle malformed/truncated files) */
            goto fail_io;
        }

        // Decode little-endian fields into struct
        asset->name_offset       = read_u32_le(buf, 0);
        asset->name_length       = read_u32_le(buf, 4);
        asset->data_offset       = read_u64_le(buf, 8);
        asset->data_size         = read_u64_le(buf, 16);
        asset->uncompressed_size = read_u64_le(buf, 24);
        asset->compression       = read_u32_le(buf, 32);
        asset->type              = read_u32_le(buf, 36);
        asset->checksum          = read_u32_le(buf, 40);
        asset->flags             = read_u32_le(buf, 44);

        ctx->parsed_asset_count++;

        // Future validation tasks 
        /* TODO A2: validate name bounds */
        /* TODO A3: validate name rules */
        /* TODO A4: validate data bounds */
        /* TODO A5: validate unsupported checksum handling */
        /* TODO A6: validate flags */

        // Load asset name from string table using helper (D1b)
        name_result = bun_read_asset_name(ctx, header, asset, &ctx->asset_names[i]);
        if (name_result != BUN_OK) {
            goto fail_io;
        }
    }

    return BUN_OK;

fail_io:
    // Clean up partially allocated data on failure
    for (i = 0; i < header->asset_count; i++) {
        free(ctx->asset_names[i]);
        ctx->asset_names[i] = NULL;
    }

    free(ctx->asset_names);
    free(ctx->assets);
    ctx->asset_names = NULL;
    ctx->assets = NULL;
    ctx->parsed_asset_count = 0;

    return BUN_ERR_IO;
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
