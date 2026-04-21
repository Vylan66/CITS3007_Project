#define _LARGEFILE64_SOURCE // TODO: check if this is entirely necessary. See: man fseeko, man lseek

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>

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
  // Cases: data section out of bounds, asset record start out of bounds, 
  // asset record end out of bounds, compression unsupported
  if (header->data_section_offset >= (uint64_t)ctx->file_size) {return BUN_MALFORMED;}
  if (entry->data_offset > (uint64_t)ctx->file_size - header->data_section_offset) {return BUN_MALFORMED;} 

  uint64_t actual_offset = header->data_section_offset + entry->data_offset;

  if (entry->data_size > (uint64_t)ctx->file_size - actual_offset) {return BUN_MALFORMED;}
  if (entry->compression > 1) {return BUN_UNSUPPORTED;}

  if (fseeko(ctx->file, (off_t)actual_offset, SEEK_SET) != 0) {
    return BUN_ERR_IO;
  }
  uint64_t remaining = entry->data_size;
  uint8_t buf[64*1024];
    
  switch (entry->compression) {
  case 0: /* raw copy */
      while (remaining > 0) {
          size_t toread = (size_t)(remaining < sizeof(buf) ? remaining : sizeof(buf));
          size_t n = fread(buf, 1, toread, ctx->file);
          if (n == 0) {return BUN_MALFORMED;}
          if (fwrite(buf, 1, n, out_fptr) != n) {return BUN_MALFORMED;}
          remaining -= n;
      }
      break;
  case 1: /* RLE decode */
    printf("RLE SECTION IS NOT DONE YET. BE WITH YOU SOON!");
    return BUN_UNSUPPORTED;
    break;
  case 2: /* zlib decode */
    printf("ZLIB MAY NOT BE SUPPORTED!");
    return BUN_UNSUPPORTED;
    break;
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

bun_result_t bun_parse_header(BunParseContext *ctx, BunHeader *header) {
  u8 buf[BUN_HEADER_SIZE];

  // our file is far too short, and cannot be valid!
  // (query: how do we let `main` know that "file was too short"
  // was the exact problem? Where can we put details about the
  // exact validation problem that occurred?)
  if (ctx->file_size < (long)BUN_HEADER_SIZE) {
    return BUN_MALFORMED;
  }

  // slurp the header into `buf`
  if (fread(buf, 1, BUN_HEADER_SIZE, ctx->file) != BUN_HEADER_SIZE) {
    return BUN_ERR_IO;
  }

  // TODO: populate `header` from `buf`.

  // TODO: validate fields and return BUN_MALFORMED or BUN_UNSUPPORTED
  // as required by the spec. The magic check is a good place to start.

  if (header->magic != BUN_MAGIC) {
    return BUN_MALFORMED;
  }

  return BUN_OK;
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
