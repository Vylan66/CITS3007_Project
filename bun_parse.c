#define _LARGEFILE64_SOURCE // TODO: check if this is entirely necessary. See: man fseeko, man lseek

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
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

bun_result_t bun_read_data(BunHeader *header, BunParseContext *ctx, BunAssetRecord *entry, FILE *out_fptr) {
  // FUNCTION: take in a single asset record and output the decompressed version into *out_fptr.
  // ENSURE THE FILE POINTER IS SECURE. ANYONE WITH THE SAME PERMS MAY READ IT OTHERWISE.
  // See tmpfile() and the lecture/lab content on this.
  // Returns errors for the following scenarios: 
  //     * BUN_MALFORMED   data section out of bounds
  //     * BUN_MALFORMED   asset record start out of bounds
  //     * BUN_MALFORMED   asset record end out of bounds
  //     * BUN_MALFORMED   fread cannot read from ctx->file (all cases)
  //     * BUN_MALFORMED   fwrite cannot write to out_fptr (all cases)
  //     * BUN_MALFORMED   RLE count byte is 0 (RLE case)              <- this one can be argued against
  //     * BUN_UNSUPPORTED compression unsupported (default case)

  if (header->data_section_offset >= (u64)ctx->file_size) {return BUN_MALFORMED;}
  if (entry->data_offset > (u64)ctx->file_size - header->data_section_offset) {return BUN_MALFORMED;} 

  u64 actual_offset = header->data_section_offset + entry->data_offset;

  if (entry->data_size > (u64)ctx->file_size - actual_offset) {return BUN_MALFORMED;}

  if (fseeko(ctx->file, (off_t)actual_offset, SEEK_SET) != 0) {
    return BUN_ERR_IO;
  }
   
  switch (entry->compression) {
  case 0: { /* raw copy */
    u64 remaining = entry->data_size;
    u8 buf[64*1024];
    while (remaining > 0) {
        size_t toread = (size_t)(remaining < sizeof(buf) ? remaining : sizeof(buf));
        size_t n = fread(buf, 1, toread, ctx->file);
        if (n == 0) {return BUN_MALFORMED;}
        if (fwrite(buf, 1, n, out_fptr) != n) {return BUN_MALFORMED;}
        remaining -= n;
    }
    break;
  }
  case 1: { /* RLE decompression */
    if (entry->data_size % 2 != 0) { return BUN_MALFORMED; }
    u64 remaining = entry->data_size;  
    BunRlePair pair;

    while (remaining > 0) {
      if (fread(&pair, sizeof(BunRlePair), 1, ctx->file) != 1) { return BUN_MALFORMED; }
      if (pair.count == 0) { return BUN_MALFORMED; }
      if (fwrite(&pair.value, sizeof(u8), pair.count, out_fptr) != pair.count) { return BUN_MALFORMED; }
      remaining -= (u64) sizeof(BunRlePair);
    }
    break;
  }
  case 2: { /* zlib decompression */
    // ZLIB MAY OR MAY NOT BE SUPPORTED!
    return BUN_UNSUPPORTED;
    break;
  }
  default:
    return BUN_UNSUPPORTED;
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
  
  // RELEVANT VALIDATIONS
  // At position asset_table_offset, there must be asset_count many valid Asset Entry Table records.
  // No two file sections may overlap (either a.offset + a.size <= b.start or b.offset + b.size <= a.start)

  // Calculate the size of the asset entry table = BunHeader->AssetCount * sizeof(BunAssetRecord)
  // Allocate space for an array of BunAssetRecord structs this large. Make sure you don't run out of memory.
  // Nove BunParseContext->file to BunHeader->asset_table_offset
  // Loop for BunHeader->AssetCount times
      // if (fread(&BunAssetRecord->X, sizeof(Y), 1, fp) != 1) return -1; where X is a field and Y is the size of the field.
      // NOTE: read each section in little-endian
  // validate that you have AssetCount number of assets

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
