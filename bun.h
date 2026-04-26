#ifndef BUN_H
#define BUN_H

#include <stdint.h>
#include <stdio.h>
#include <stddef.h>

//
// Result codes (per BUN spec section 2)
//

typedef enum {
    BUN_OK              = 0,
    BUN_MALFORMED       = 1,
    BUN_UNSUPPORTED     = 2,
    BUN_ERR_IO          = 3,
    BUN_ERR_USAGE       = 4,
    BUN_ERR_INTERNAL    = 5,
} bun_result_t;

//
// Data types (per BUN spec section 2)
// All multi-byte integers are little-endian on disk.
//

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

//
// On-disk structures (per BUN spec sections 4 and 5)
//

#define BUN_MAGIC         0x304E5542u   // "BUN0" in little-endian
#define BUN_VERSION_MAJOR 1
#define BUN_VERSION_MINOR 0

#define BUN_FLAG_ENCRYPTED  0x1u
#define BUN_FLAG_EXECUTABLE 0x2u

#define BUN_MAX_ERRORS 32
#define BUN_ERROR_MSG_LEN 256

#define BUN_PAYLOAD_PREVIEW_LEN 60

typedef struct {
    u32 magic;
    u16 version_major;
    u16 version_minor;
    u32 asset_count;
    u64 asset_table_offset;
    u64 string_table_offset;
    u64 string_table_size;
    u64 data_section_offset;
    u64 data_section_size;
    u64 reserved;
} BunHeader;

typedef struct {
    char message[256];
} BunViolation; //for listing violations or errors

typedef struct {
    u32 name_offset;
    u32 name_length;
    u64 data_offset;
    u64 data_size;
    u64 uncompressed_size;
    u32 compression;
    u32 type;
    u32 checksum;
    u32 flags;
} BunAssetRecord;

//
// Expected on-disk sizes -- these can be used in assertions or static_asserts.
//

#define BUN_HEADER_SIZE       60
#define BUN_ASSET_RECORD_SIZE 48

//
// Parse context
//
// A struct to store information about the state of your parser (rather than
// passing multiple arguments to every function).
//
// You will likely want to add fields to it as your implementation grows.
//

typedef struct {
    FILE   *file;
    long    file_size;

    BunHeader header;
    int header_parsed;

    BunAssetRecord *assets;      // dynamically allocated array of parsed asset records
    u32      parsed_asset_count; // number of asset records stored in assets
    char   **asset_names;        // dynamically allocated array of parsed asset names
    u8 **payload_previews;
    u32 *payload_preview_lengths;

    BunViolation *violations;
    size_t violation_count;
    size_t violation_capacity;
} BunParseContext;

//
// Public API
//
// The function declarations below define the public API for your parser;
// you implement them in the `bun_parse.c` file.
//
// A note on I/O and output:
//   The functions below return result codes; the intention is that they
//   should not print to stdout or stderr themselves.
//   Keeping I/O out of these functions makes them much easier to test (your
//   tests can call them and inspect the return value without terminal output
//   getting cluttered with other content).
//   If you need to pass additional information in or out, `ctx` is a good place
//   to put it.
//
//   So printing (human-readable output for valid files and error messages
//   for invalid ones) should happen in main.c, based on the result code and
//   the content of `ctx`.
//
//   (This is a suggestion, not a requirement. But mixing output deeply into
//   parsing logic tends to make both harder to maintain.)

/**
 * Open a BUN file and populate ctx. Returns BUN_ERR_IO if the file cannot
 * be opened or its size determined.
 */
bun_result_t bun_open(const char *path, BunParseContext *ctx);

/**
 * Parse and validate the BUN header from ctx->file, populating *header.
 * Returns BUN_OK, BUN_MALFORMED, or BUN_UNSUPPORTED.
 */
bun_result_t bun_parse_header(BunParseContext *ctx, BunHeader *header);

/**
 * Parse and validate all asset records. Called after bun_parse_header().
 * Returns BUN_OK, BUN_MALFORMED, or BUN_UNSUPPORTED.
 *
 * You will probably want to extend this signature -- for instance, to pass
 * in the header (needed for offset calculations) or to return the parsed
 * records to the caller.
 */

bun_result_t bun_parse_assets(BunParseContext *ctx, const BunHeader *header) {
    u32 i;

    if (ctx == NULL || header == NULL) {
        return BUN_ERR_IO;
    }

    ctx->assets = NULL;
    ctx->asset_names = NULL;
    ctx->payload_previews = NULL;
    ctx->payload_preview_lengths = NULL;
    ctx->parsed_asset_count = 0;

    if (header->asset_count == 0) {
        return BUN_OK;
    }

    ctx->assets = calloc(header->asset_count, sizeof(BunAssetRecord));
    if (ctx->assets == NULL) {
        return BUN_ERR_IO;
    }

    ctx->asset_names = calloc(header->asset_count, sizeof(char *));
    if (ctx->asset_names == NULL) {
        goto fail_io;
    }

    ctx->payload_previews = calloc(header->asset_count, sizeof(u8 *));
    if (ctx->payload_previews == NULL) {
        goto fail_io;
    }

    ctx->payload_preview_lengths = calloc(header->asset_count, sizeof(u32));
    if (ctx->payload_preview_lengths == NULL) {
        goto fail_io;
    }

    if (header->asset_table_offset > (u64)LONG_MAX) {
        goto fail_io;
    }

    if (fseek(ctx->file, (long)header->asset_table_offset, SEEK_SET) != 0) {
        goto fail_io;
    }

    for (i = 0; i < header->asset_count; i++) {
        BunAssetRecord *asset = &ctx->assets[i];
        u8 buf[BUN_ASSET_RECORD_SIZE];
        bun_result_t name_result;
        u32 preview_len;
        u64 payload_offset;

        if (fread(buf, 1, BUN_ASSET_RECORD_SIZE, ctx->file) != BUN_ASSET_RECORD_SIZE) {
            /* TODO A1: read asset records safely (handle malformed/truncated files) */
            goto fail_io;
        }

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

        /* TODO A2: validate name bounds */
        /* TODO A3: validate name rules */
        /* TODO A4: validate data bounds */
        /* TODO A5: validate unsupported checksum handling */
        /* TODO A6: validate flags */

        name_result = bun_read_asset_name(ctx, header, asset, &ctx->asset_names[i]);
        if (name_result != BUN_OK) {
            goto fail_io;
        }

        preview_len = asset->data_size < BUN_PAYLOAD_PREVIEW_LEN
                    ? (u32)asset->data_size
                    : BUN_PAYLOAD_PREVIEW_LEN;

        ctx->payload_preview_lengths[i] = preview_len;

        if (preview_len > 0) {
            ctx->payload_previews[i] = malloc(preview_len);
            if (ctx->payload_previews[i] == NULL) {
                goto fail_io;
            }

            payload_offset = header->data_section_offset + asset->data_offset;

            if (payload_offset > (u64)LONG_MAX) {
                goto fail_io;
            }

            if (fseek(ctx->file, (long)payload_offset, SEEK_SET) != 0) {
                goto fail_io;
            }

            if (fread(ctx->payload_previews[i], 1, preview_len, ctx->file) != preview_len) {
                goto fail_io;
            }

            /*
             * Return to the next asset record, because reading the payload
             * moves the file position away from the asset table.
             */
            if (fseek(ctx->file,
                      (long)(header->asset_table_offset + ((u64)(i + 1) * BUN_ASSET_RECORD_SIZE)),
                      SEEK_SET) != 0) {
                goto fail_io;
            }
        }
    }

    return BUN_OK;

fail_io:
    if (ctx->asset_names != NULL) {
        for (i = 0; i < header->asset_count; i++) {
            free(ctx->asset_names[i]);
            ctx->asset_names[i] = NULL;
        }
    }

    if (ctx->payload_previews != NULL) {
        for (i = 0; i < header->asset_count; i++) {
            free(ctx->payload_previews[i]);
            ctx->payload_previews[i] = NULL;
        }
    }

    free(ctx->payload_preview_lengths);
    free(ctx->payload_previews);
    free(ctx->asset_names);
    free(ctx->assets);

    ctx->payload_preview_lengths = NULL;
    ctx->payload_previews = NULL;
    ctx->asset_names = NULL;
    ctx->assets = NULL;
    ctx->parsed_asset_count = 0;

    return BUN_ERR_IO;
}

void bun_free_context(BunParseContext *ctx);

bun_result_t bun_close(BunParseContext *ctx);

#endif // BUN_H
