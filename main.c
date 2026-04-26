#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include "bun.h"

static void print_header(const BunHeader *header) {
    printf("Header:\n");
    printf("  magic: 0x%08" PRIx32 "\n", header->magic);
    printf("  version_major: %" PRIu16 "\n", header->version_major);
    printf("  version_minor: %" PRIu16 "\n", header->version_minor);
    printf("  asset_count: %" PRIu32 "\n", header->asset_count);
    printf("  asset_table_offset: %" PRIu64 "\n", header->asset_table_offset);
    printf("  string_table_offset: %" PRIu64 "\n", header->string_table_offset);
    printf("  string_table_size: %" PRIu64 "\n", header->string_table_size);
    printf("  data_section_offset: %" PRIu64 "\n", header->data_section_offset);
    printf("  data_section_size: %" PRIu64 "\n", header->data_section_size);
    printf("  reserved: %" PRIu64 "\n", header->reserved);
}

static void print_assets(const BunParseContext *ctx) {
    printf("\nAssets:\n");

    for (u32 i = 0; i < ctx->parsed_asset_count; i++) {
        const BunAssetRecord *asset = &ctx->assets[i];

        printf("  Asset %" PRIu32 ":\n", i);
        printf("    name: %s\n",
               ctx->asset_names != NULL && ctx->asset_names[i] != NULL
                   ? ctx->asset_names[i]
                   : "(not loaded)");
        printf("    name_offset: %" PRIu32 "\n", asset->name_offset);
        printf("    name_length: %" PRIu32 "\n", asset->name_length);
        printf("    data_offset: %" PRIu64 "\n", asset->data_offset);
        printf("    data_size: %" PRIu64 "\n", asset->data_size);
        printf("    uncompressed_size: %" PRIu64 "\n", asset->uncompressed_size);
        printf("    compression: %" PRIu32 "\n", asset->compression);
        printf("    type: %" PRIu32 "\n", asset->type);
        printf("    checksum: %" PRIu32 "\n", asset->checksum);
        printf("    flags: %" PRIu32 "\n", asset->flags);
        printf("    preview: ");
        print_payload_preview(ctx->payload_previews[i],
                              ctx->payload_preview_lengths[i]);
        printf("\n");
    }
}

static void print_violations(const BunParseContext *ctx) {
    for (size_t i = 0; i < ctx->violation_count; i++) {
        fprintf(stderr, "%s\n", ctx->violations[i].message);
    }
}

static void print_parse_error(const BunParseContext *ctx, const char *fallback) {
    if (ctx->violation_count > 0) {
        print_violations(ctx);
    } else {
        fprintf(stderr, "%s\n", fallback);
    }
}

static int is_printable_buffer(const u8 *buf, u32 len) {
    for (u32 i = 0; i < len; i++) {
        if (buf[i] < 32 || buf[i] > 126) {
            return 0;
        }
    }
    return 1;
}

static void print_payload_preview(const u8 *buf, u32 len) {
    if (buf == NULL || len == 0) {
        printf("(empty)");
        return;
    }

    if (is_printable_buffer(buf, len)) {
        printf("\"");
        for (u32 i = 0; i < len; i++) {
            putchar(buf[i]);
        }
        printf("\"");
    } else {
        for (u32 i = 0; i < len; i++) {
            printf("%02x ", buf[i]);

            if (i + 1 < len) {
                printf(" ");
            }  
        }
    }    
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <file.bun>\n", argv[0]);
    return BUN_ERR_USAGE;
  }
  const char *path = argv[1];

  BunParseContext ctx = {0};
  BunHeader header  = {0};

  bun_result_t result = bun_open(path, &ctx);
  if (result != BUN_OK) {
    fprintf(stderr, "Error: could not open '%s'\n", path);
    return result;
  }

  result = bun_parse_header(&ctx, &header);
  

  if (result != BUN_OK) {
    print_parse_error(&ctx, "Error: header invalid or unsupported");
    bun_free_context(&ctx);
    bun_close(&ctx);
    return result;
  }

  printf("Magic: 0x%x\n", header.magic);
  printf("Version: %u.%u\n", header.version_major, header.version_minor);
  printf("Asset count: %u\n", header.asset_count);
  printf("Asset table offset: %" PRIu64 "\n", header.asset_table_offset);
  printf("String table offset: %" PRIu64 "\n", header.string_table_offset);
  printf("Data section offset: %" PRIu64 "\n", header.data_section_offset);


  result = bun_parse_assets(&ctx, &header);
  if (result != BUN_OK) {
    print_parse_error(&ctx, "Error: asset parsing failed");
    bun_free_context(&ctx);
    bun_close(&ctx);
    return result;
  }

  print_header(&header);
  print_assets(&ctx);
  bun_free_context(&ctx);
  bun_close(&ctx);
  return BUN_OK;
}
