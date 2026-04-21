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
//TODO: check tasks spreadsheet: Task ID: H6
//TODO: currently all printing takes place inside parser and error detection happens one at a time. what i need to do is store all errors each time it is encountered, continue reading header till the end. print all errors together from main(task H7)
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

  u64 file_size = (u64)ctx->file_size;

  //Compute asset table size safely
  u64 asset_table_size = (u64)header->asset_count * 48;

  // Section starts 
  u64 asset_start = header->asset_table_offset;
  u64 string_start = header->string_table_offset;
  u64 data_start = header->data_section_offset;

  // Section ends (with overflow protection) 
  u64 asset_end, string_end, data_end;

  if (asset_start > UINT64_MAX - asset_table_size) {
      printf("Error: asset table end overflow\n");
      return BUN_MALFORMED;
  }
  asset_end = asset_start + asset_table_size;

  if (string_start > UINT64_MAX - header->string_table_size) {
      printf("Error: string table end overflow\n");
      return BUN_MALFORMED;
  }
  string_end = string_start + header->string_table_size;

  if (data_start > UINT64_MAX - header->data_section_size) {
      printf("Error: data section end overflow\n");
      return BUN_MALFORMED;
  }
  data_end = data_start + header->data_section_size;

  //Bounds check
  if (asset_end > file_size) {
      printf("Error: asset table exceeds file bounds\n");
      return BUN_MALFORMED;
  }
  if (string_end > file_size) {
      printf("Error: string table exceeds file bounds\n");
      return BUN_MALFORMED;
  }
  if (data_end > file_size) {
      printf("Error: data section exceeds file bounds\n");
      return BUN_MALFORMED;
  }

  //Overlap checks
  if (asset_start < string_end && string_start < asset_end) {
      printf("Error: asset table overlaps string table\n");
      return BUN_MALFORMED;
  }

  if (asset_start < data_end && data_start < asset_end) {
      printf("Error: asset table overlaps data section\n");
      return BUN_MALFORMED;
  }

  if (string_start < data_end && data_start < string_end) {
      printf("Error: string table overlaps data section\n");
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
