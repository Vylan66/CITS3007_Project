#define _LARGEFILE64_SOURCE // TODO: check if this is entirely necessary. See: man fseeko, man lseek
#define _POSIX_C_SOURCE 200809L
#define TMPDIR_TEMPLATE "/tmp/bunproc.XXXXXXXXXX"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <limits.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
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

bun_result_t bun_read_data(const BunHeader *header, BunParseContext *ctx, BunAssetRecord *entry, FILE *out_fptr) {
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
  if (entry->checksum != 0) { return BUN_UNSUPPORTED; }

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
    u64 decompressed_total = 0;
    BunRlePair pair;

    while (remaining > 0) {
      if (fread(&pair, sizeof(BunRlePair), 1, ctx->file) != 1) { return BUN_MALFORMED; }
      if (pair.count == 0) { return BUN_MALFORMED; }
      if (decompressed_total >= entry->uncompressed_size) { return BUN_MALFORMED; }
      if (fwrite(&pair.value, sizeof(u8), pair.count, out_fptr) != pair.count) { return BUN_MALFORMED; }
      remaining -= (u64) sizeof(BunRlePair);
    }

    if (decompressed_total != entry->uncompressed_size) { return BUN_MALFORMED; }
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

static int create_secure_tmpdir(char **out_path) {
    char tmpl[] = TMPDIR_TEMPLATE;

    mode_t old_mask = umask(0077);
    char *d = mkdtemp(tmpl); // 0700 drwx------ by default.
    umask(old_mask);
    
    if (!d) { return -1; }

    // set 0700 to be doubly sure, in case a race condition makes umask different globally.
    if (chmod(d, S_IRWXU) != 0) {
        int saved_errno = errno;
        rmdir(d);
        errno = saved_errno;
        return -1;
    }

    *out_path = strdup(d);
    if (!*out_path) {
        rmdir(d);
        return -1;
    }

    return 0;
}

static int create_secure_tmpfile_in_dir(const char *dir_path, FILE **out_fp) {
    char path[PATH_MAX]; // TODO: POSIX-only behaviour. Take down #define _POSIX_C_SOURCE 200809L if swapping to multi-OS. 
    int fd = -1;
    FILE *fp = NULL;

    if (!dir_path || !out_fp) { return -1; }

    if (snprintf(path, sizeof(path), "%s/asset.XXXXXX", dir_path) >= (int)sizeof(path)) { return -1; }

    mode_t old_mask = umask(0077); // umask needed for default
    fd = mkstemp(path); // 0600 rw------- by default
    umask(old_mask);

    if (fd < 0) { return -1; }

    // set 0600 to be doubly sure, in case a race condition makes umask different globally.
    if (fchmod(fd, S_IRUSR | S_IWUSR) != 0) { 
        close(fd);
        unlink(path);
        return -1;
    }

    /* Convert to buffered I/O stream */
    fp = fdopen(fd, "wb+");
    if (!fp) {
        close(fd);
        unlink(path);
        return -1;
    }

    // unlink. File will close once fp is closed.
    if (unlink(path) != 0) { 
        fclose(fp);
        return -1;
    }

    *out_fp = fp;
    return 0;
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
    char *tmpdir_path = NULL;

    if (ctx == NULL || header == NULL) {
        return BUN_ERR_IO;
    }

    ctx->assets = NULL;
    ctx->asset_names = NULL;
    ctx->payload_previews = NULL;
    ctx->payload_preview_lengths = NULL;
    ctx->parsed_asset_count = 0;

    // No assets → nothing to do
    if (header->asset_count == 0) {
        return BUN_OK;
    }

    // No secure directory → nowhere to put temp files
    if (create_secure_tmpdir(&tmpdir_path) != 0) {
        return BUN_ERR_IO;
    }

    // Allocate storage
    ctx->assets = (BunAssetRecord *) calloc(header->asset_count, sizeof(BunAssetRecord));
    ctx->asset_names = (char **) calloc(header->asset_count, sizeof(char *));
    ctx->asset_files = (FILE **) calloc(header->asset_count, sizeof(FILE *));

    if (!ctx->assets || !ctx->asset_names || !ctx->asset_files) { goto fail_io; }

    ctx->payload_previews = calloc(header->asset_count, sizeof(u8 *));
    if (ctx->payload_previews == NULL) {
        goto fail_io;
    }

    ctx->payload_preview_lengths = calloc(header->asset_count, sizeof(u32));
    if (ctx->payload_preview_lengths == NULL) {
        goto fail_io;
    }

    // Ensure offset is safe to cast to long for fseek
    if (header->asset_table_offset > (u64)LONG_MAX) { goto fail_io; }
    // TODO: TOCTOU possibility to swap out the file here. Use fd via fileno(). See lect 7 "file-descriptor–based functions".

    // Seek to the start of the asset table
    if (fseek(ctx->file, (long)header->asset_table_offset, SEEK_SET) != 0) { goto fail_io; }

    // Iterate over each asset record
    for (i = 0; i < header->asset_count; i++) {
        BunAssetRecord *asset = &ctx->assets[i];
        u8 buf[BUN_ASSET_RECORD_SIZE];
        bun_result_t name_result;

        u64 record_offset = header->asset_table_offset + (i * sizeof(BunAssetRecord));
        if (fseek(ctx->file, (long)record_offset, SEEK_SET) != 0) { 
            goto fail_io;
        }

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

        if (create_secure_tmpfile_in_dir(tmpdir_path, &ctx->asset_files[i]) != 0) {
            goto fail_io;
        }

        if (bun_read_data(header, ctx, asset, ctx->asset_files[i]) != BUN_OK) {
            goto fail_io;
        }

        /*
         * Read only a short prefix for preview output.
         * The full payload handling is done by bun_read_data().
         */
        rewind(ctx->asset_files[i]);

        ctx->payload_previews[i] = malloc(BUN_PAYLOAD_PREVIEW_LEN);
        if (ctx->payload_previews[i] == NULL) {
            goto fail_io;
        }

        ctx->payload_preview_lengths[i] =
            (u32)fread(ctx->payload_previews[i],
                       1,
                       BUN_PAYLOAD_PREVIEW_LEN,
                       ctx->asset_files[i]);

        rewind(ctx->asset_files[i]);

    }

    free(tmpdir_path); // the PATH can be freed, but not the file or directory.
    return BUN_OK;

fail_io:
// Close any opened temp files
    if (ctx->asset_files != NULL) {
        for (i = 0; i < ctx->parsed_asset_count; i++) {
            if (ctx->asset_files[i] != NULL) {
                fclose(ctx->asset_files[i]);
                ctx->asset_files[i] = NULL;
            }
        }
        free(ctx->asset_files);
        ctx->asset_files = NULL;
    }

    // Free loaded asset names
    if (ctx->asset_names != NULL) {
        for (i = 0; i < ctx->parsed_asset_count; i++) {
            free(ctx->asset_names[i]);
            ctx->asset_names[i] = NULL;
        }
    }

    // Free payload preview buffers
    if (ctx->payload_previews != NULL) {
        for (i = 0; i < ctx->parsed_asset_count; i++) {
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
    
    free(tmpdir_path);
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

void bun_free_context(BunParseContext *ctx) {
    if (ctx == NULL) {
        return;
    }

    if (ctx->asset_names != NULL) {
        for (u32 i = 0; i < ctx->parsed_asset_count; i++) {
            if (ctx->asset_files[i] != NULL) {
                fclose(ctx->asset_files[i]);
            }
        }
        free(ctx->asset_names);
    }

    if (ctx->payload_previews != NULL) {
        for (u32 i = 0; i < ctx->parsed_asset_count; i++) {
            free(ctx->payload_previews[i]);
        }
        free(ctx->payload_previews);
    }

    free(ctx->payload_preview_lengths);
    free(ctx->assets);
    free(ctx->violations);

    ctx->asset_names = NULL;
    ctx->payload_previews = NULL;
    ctx->payload_preview_lengths = NULL;
    ctx->assets = NULL;
    ctx->violations = NULL;
    ctx->asset_files = NULL;

    ctx->parsed_asset_count = 0;
    ctx->violation_count = 0;
    ctx->violation_capacity = 0;
}
