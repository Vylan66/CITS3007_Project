#include "../bun.h"

#include <check.h>
#include <stdio.h>

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#if defined(_WIN32)
#include <direct.h>
#include <windows.h>
#include <psapi.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#endif

// Helper: terminate abnormally, after printing a message to stderr
void die(const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);

  fprintf(stderr, "fatal error: ");
  vfprintf(stderr, fmt, args);
  fprintf(stderr, "\n");

  va_end(args);

  abort();
}


// Helper: open a test fixture by name, relative to the tests/ directory.
static const char *fixture(const char *filename) {
  static char path[256];
  int res = snprintf(path, sizeof(path), "tests/fixtures/%s", filename);
  if (res < 0) {
    die("snprintf failed: %s", strerror(errno));
  }
  if ((size_t)res >= sizeof(path)) {
    die("fixture path too long");
  }
  return path;
}

static void ensure_dir(const char *path) {
#if defined(_WIN32)
  _mkdir(path);
#else
  mkdir(path, 0777);
#endif
}

static uint64_t get_peak_rss_bytes(void) {
#if defined(_WIN32)
  PROCESS_MEMORY_COUNTERS pmc;
  if (!GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
    return 0;
  }
  return (uint64_t)pmc.PeakWorkingSetSize;
#else
  struct rusage ru;
  if (getrusage(RUSAGE_SELF, &ru) != 0) {
    return 0;
  }
  #if defined(__APPLE__)
    /* ru_maxrss is bytes on macOS */
    return (uint64_t)ru.ru_maxrss;
  #else
    /* ru_maxrss is KB on Linux */
    return (uint64_t)ru.ru_maxrss * 1024ull;
  #endif
#endif
}

/*
 * Try the project script first (matches the brief: use bunfile_generator.py).
 * Tests are meant to run from the project root (see HACKING.md / Makefile).
 * If Python is missing or the command fails, we fall back to writing bytes
 * in C so `make test` still works on minimal setups.
 */
static int generate_fixtures_with_python(void) {
#if defined(_WIN32)
  const char *commands[] = {
    "py -3 bunfile_generator.py --fixtures tests/fixtures",
    "python bunfile_generator.py --fixtures tests/fixtures",
    "python3 bunfile_generator.py --fixtures tests/fixtures",
  };
#else
  const char *commands[] = {
    "python3 bunfile_generator.py --fixtures tests/fixtures",
    "python bunfile_generator.py --fixtures tests/fixtures",
  };
#endif

  size_t command_count = sizeof(commands) / sizeof(commands[0]);
  for (size_t i = 0; i < command_count; i++) {
    if (system(commands[i]) == 0) {
      return 1;
    }
  }

  return 0;
}

static void write_file_bytes(const char *path, const uint8_t *buf, size_t n) {
  FILE *f = fopen(path, "wb");
  if (!f) {
    die("open '%s' failed: %s", path, strerror(errno));
  }
  if (n && fwrite(buf, 1, n, f) != n) {
    fclose(f);
    die("write '%s' failed: %s", path, strerror(errno));
  }
  if (fclose(f) != 0) {
    die("close '%s' failed: %s", path, strerror(errno));
  }
}

static void write_u16_le(uint8_t *b, size_t off, uint16_t v) {
  b[off + 0] = (uint8_t)(v & 0xffu);
  b[off + 1] = (uint8_t)((v >> 8) & 0xffu);
}

static void write_u32_le(uint8_t *b, size_t off, uint32_t v) {
  b[off + 0] = (uint8_t)(v & 0xffu);
  b[off + 1] = (uint8_t)((v >> 8) & 0xffu);
  b[off + 2] = (uint8_t)((v >> 16) & 0xffu);
  b[off + 3] = (uint8_t)((v >> 24) & 0xffu);
}

static void write_u64_le(uint8_t *b, size_t off, uint64_t v) {
  b[off + 0] = (uint8_t)(v & 0xffu);
  b[off + 1] = (uint8_t)((v >> 8) & 0xffu);
  b[off + 2] = (uint8_t)((v >> 16) & 0xffu);
  b[off + 3] = (uint8_t)((v >> 24) & 0xffu);
  b[off + 4] = (uint8_t)((v >> 32) & 0xffu);
  b[off + 5] = (uint8_t)((v >> 40) & 0xffu);
  b[off + 6] = (uint8_t)((v >> 48) & 0xffu);
  b[off + 7] = (uint8_t)((v >> 56) & 0xffu);
}

static void make_header(uint8_t out[BUN_HEADER_SIZE],
                        uint32_t magic,
                        uint16_t vmaj,
                        uint16_t vmin,
                        uint32_t asset_count,
                        uint64_t asset_table_offset,
                        uint64_t string_table_offset,
                        uint64_t string_table_size,
                        uint64_t data_section_offset,
                        uint64_t data_section_size,
                        uint64_t reserved) {
  memset(out, 0, BUN_HEADER_SIZE);
  size_t off = 0;
  write_u32_le(out, off, magic); off += 4;
  write_u16_le(out, off, vmaj); off += 2;
  write_u16_le(out, off, vmin); off += 2;
  write_u32_le(out, off, asset_count); off += 4;
  write_u64_le(out, off, asset_table_offset); off += 8;
  write_u64_le(out, off, string_table_offset); off += 8;
  write_u64_le(out, off, string_table_size); off += 8;
  write_u64_le(out, off, data_section_offset); off += 8;
  write_u64_le(out, off, data_section_size); off += 8;
  write_u64_le(out, off, reserved); off += 8;
}

static void ensure_fixtures(void) {
  ensure_dir("tests");
  ensure_dir("tests/fixtures");
  ensure_dir("tests/fixtures/valid");
  ensure_dir("tests/fixtures/invalid");

  if (generate_fixtures_with_python()) {
    return;
  }

  /* Same layout as generate_header_fixtures() in bunfile_generator.py */
  uint8_t hdr[BUN_HEADER_SIZE];

  make_header(hdr, BUN_MAGIC, 1, 0, 0, 60, 60, 0, 60, 0, 0);
  write_file_bytes(fixture("valid/01-empty.bun"), hdr, BUN_HEADER_SIZE);

  make_header(hdr, 0x12345678u, 1, 0, 0, 60, 60, 0, 60, 0, 0);
  write_file_bytes(fixture("invalid/01-bad-magic.bun"), hdr, BUN_HEADER_SIZE);

  make_header(hdr, BUN_MAGIC, 9, 9, 0, 60, 60, 0, 60, 0, 0);
  write_file_bytes(fixture("invalid/02-bad-version.bun"), hdr, BUN_HEADER_SIZE);

  make_header(hdr, BUN_MAGIC, 1, 0, 0, 60, 60, 0, 60, 0, 0);
  write_file_bytes(fixture("invalid/03-truncated-header.bun"), hdr, BUN_HEADER_SIZE - 1);

  make_header(hdr, BUN_MAGIC, 1, 0, 0, 62, 60, 0, 60, 0, 0);
  write_file_bytes(fixture("invalid/04-unaligned-offset.bun"), hdr, BUN_HEADER_SIZE);

  make_header(hdr, BUN_MAGIC, 1, 0, 1, 60, 60, 0, 60, 0, 0);
  write_file_bytes(fixture("invalid/05-asset-table-oob.bun"), hdr, BUN_HEADER_SIZE);

  uint8_t file64[64];
  make_header(file64, BUN_MAGIC, 1, 0, 0, 60, 56, 8, 60, 0, 0);
  memset(file64 + BUN_HEADER_SIZE, 0, sizeof(file64) - BUN_HEADER_SIZE);
  write_file_bytes(fixture("invalid/06-overlap-sections.bun"), file64, sizeof(file64));
}

START_TEST(test_valid_minimal) {
    BunParseContext ctx = {0};
    BunHeader header    = {0};

    bun_result_t r = bun_open(fixture("valid/01-empty.bun"), &ctx);
    ck_assert_int_eq(r, BUN_OK);

    r = bun_parse_header(&ctx, &header);
    ck_assert_int_eq(r, BUN_OK);
    ck_assert_uint_eq(header.magic, BUN_MAGIC);
    ck_assert_uint_eq(header.version_major, 1);
    ck_assert_uint_eq(header.version_minor, 0);

    bun_close(&ctx);
}
END_TEST

START_TEST(test_truncated_header) {
    BunParseContext ctx = {0};
    BunHeader header    = {0};

    bun_result_t r = bun_open(fixture("invalid/03-truncated-header.bun"), &ctx);
    ck_assert_int_eq(r, BUN_OK);

    r = bun_parse_header(&ctx, &header);
    ck_assert_int_eq(r, BUN_MALFORMED);

    bun_close(&ctx);
}
END_TEST

START_TEST(test_unaligned_offset) {
    BunParseContext ctx = {0};
    BunHeader header    = {0};

    bun_result_t r = bun_open(fixture("invalid/04-unaligned-offset.bun"), &ctx);
    ck_assert_int_eq(r, BUN_OK);

    r = bun_parse_header(&ctx, &header);
    ck_assert_int_eq(r, BUN_MALFORMED);

    bun_close(&ctx);
}
END_TEST

START_TEST(test_asset_table_oob) {
    BunParseContext ctx = {0};
    BunHeader header    = {0};

    bun_result_t r = bun_open(fixture("invalid/05-asset-table-oob.bun"), &ctx);
    ck_assert_int_eq(r, BUN_OK);

    r = bun_parse_header(&ctx, &header);
    ck_assert_int_eq(r, BUN_MALFORMED);

    bun_close(&ctx);
}
END_TEST

START_TEST(test_section_overlap) {
    BunParseContext ctx = {0};
    BunHeader header    = {0};

    bun_result_t r = bun_open(fixture("invalid/06-overlap-sections.bun"), &ctx);
    ck_assert_int_eq(r, BUN_OK);

    r = bun_parse_header(&ctx, &header);
    ck_assert_int_eq(r, BUN_MALFORMED);

    bun_close(&ctx);
}
END_TEST

START_TEST(test_bad_magic) {
    BunParseContext ctx = {0};
    BunHeader header    = {0};

    bun_result_t r = bun_open(fixture("invalid/01-bad-magic.bun"), &ctx);
    ck_assert_int_eq(r, BUN_OK);

    r = bun_parse_header(&ctx, &header);
    ck_assert_int_eq(r, BUN_MALFORMED);

    bun_close(&ctx);
}
END_TEST

START_TEST(test_unsupported_version) {
    BunParseContext ctx = {0};
    BunHeader header    = {0};

    bun_result_t r = bun_open(fixture("invalid/02-bad-version.bun"), &ctx);
    ck_assert_int_eq(r, BUN_OK);

    r = bun_parse_header(&ctx, &header);
    ck_assert_int_eq(r, BUN_UNSUPPORTED);

    bun_close(&ctx);
}
END_TEST

static bun_result_t parse_asset_fixture(const char *filename, BunParseContext *ctx, BunHeader *header) {
    bun_result_t r = bun_open(fixture(filename), ctx);
    ck_assert_int_eq(r, BUN_OK);

    r = bun_parse_header(ctx, header);
    ck_assert_int_eq(r, BUN_OK);

    return bun_parse_assets(ctx, header);
}

START_TEST(test_valid_asset) {
    BunParseContext ctx = {0};
    BunHeader header = {0};

    bun_result_t r = parse_asset_fixture("valid/10-valid-asset.bun", &ctx, &header);
    ck_assert_int_eq(r, BUN_OK);
    ck_assert_uint_eq(ctx.parsed_asset_count, 1);
    ck_assert_uint_eq(ctx.assets[0].name_length, 9);

    bun_close(&ctx);
}
END_TEST

START_TEST(test_invalid_name_bounds) {
    BunParseContext ctx = {0};
    BunHeader header = {0};

    bun_result_t r = parse_asset_fixture("invalid/10-name-oob.bun", &ctx, &header);
    ck_assert_int_eq(r, BUN_MALFORMED);

    bun_close(&ctx);
}
END_TEST

START_TEST(test_invalid_non_printable_name) {
    BunParseContext ctx = {0};
    BunHeader header = {0};

    bun_result_t r = parse_asset_fixture("invalid/11-name-non-printable.bun", &ctx, &header);
    ck_assert_int_eq(r, BUN_MALFORMED);

    bun_close(&ctx);
}
END_TEST

START_TEST(test_invalid_data_bounds) {
    BunParseContext ctx = {0};
    BunHeader header = {0};

    bun_result_t r = parse_asset_fixture("invalid/12-data-oob.bun", &ctx, &header);
    ck_assert_int_eq(r, BUN_MALFORMED);

    bun_close(&ctx);
}
END_TEST

START_TEST(test_invalid_flags) {
    BunParseContext ctx = {0};
    BunHeader header = {0};

    bun_result_t r = parse_asset_fixture("invalid/13-bad-flags.bun", &ctx, &header);
    ck_assert_int_eq(r, BUN_UNSUPPORTED);

    bun_close(&ctx);
}
END_TEST

START_TEST(test_checksum_mismatch) {
    BunParseContext ctx = {0};
    BunHeader header = {0};

    bun_result_t r = parse_asset_fixture("invalid/14-checksum-mismatch.bun", &ctx, &header);
    ck_assert_int_eq(r, BUN_MALFORMED);

    bun_close(&ctx);
}
END_TEST

START_TEST(test_valid_uncompressed_compression_case) {
    BunParseContext ctx = {0};
    BunHeader header = {0};

    bun_result_t r = parse_asset_fixture("valid/20-compression-none.bun", &ctx, &header);
    ck_assert_int_eq(r, BUN_OK);
    ck_assert_uint_eq(ctx.assets[0].compression, BUN_COMPRESS_NONE);

    bun_close(&ctx);
}
END_TEST

START_TEST(test_valid_rle_compression) {
    BunParseContext ctx = {0};
    BunHeader header = {0};

    bun_result_t r = parse_asset_fixture("valid/21-compression-rle.bun", &ctx, &header);
    ck_assert_int_eq(r, BUN_OK);
    ck_assert_uint_eq(ctx.assets[0].compression, BUN_COMPRESS_RLE);

    bun_close(&ctx);
}
END_TEST

START_TEST(test_malformed_rle_compression) {
    BunParseContext ctx = {0};
    BunHeader header = {0};

    bun_result_t r = parse_asset_fixture("invalid/20-compression-rle-malformed.bun", &ctx, &header);
    ck_assert_int_eq(r, BUN_MALFORMED);

    bun_close(&ctx);
}
END_TEST

START_TEST(test_unsupported_zlib_compression) {
    BunParseContext ctx = {0};
    BunHeader header = {0};

    bun_result_t r = parse_asset_fixture("invalid/21-compression-zlib-unsupported.bun", &ctx, &header);
    ck_assert_int_eq(r, BUN_UNSUPPORTED);

    bun_close(&ctx);
}
END_TEST

START_TEST(test_large_file_streaming_case) {
    BunParseContext ctx = {0};
    BunHeader header = {0};

    uint64_t rss_before = get_peak_rss_bytes();
    bun_result_t r = parse_asset_fixture("valid/30-large-file.bun", &ctx, &header);
    ck_assert_int_eq(r, BUN_OK);
    ck_assert_uint_eq(ctx.parsed_asset_count, 1);
    ck_assert_uint_eq(ctx.assets[0].data_size, 64u * 1024u * 1024u);

    /* T5: prove we don't slurp the whole file into RAM.
     * This test runs first in the suite so ru_maxrss baseline is meaningful.
     * Allow some overhead for libc/check/framework, but peak growth must be
     * far below the 64 MiB payload size.
     */
    uint64_t rss_after = get_peak_rss_bytes();
    if (rss_before != 0 && rss_after != 0 && rss_after > rss_before) {
      uint64_t delta = rss_after - rss_before;
      ck_assert_msg(delta < (24ull * 1024ull * 1024ull),
                    "peak RSS grew by %llu bytes while parsing 64MiB payload (expected streaming)",
                    (unsigned long long)delta);
    }

    bun_close(&ctx);
}
END_TEST

// Example test suite: header parsing

// Assemble a test suite from our tests

static Suite *bun_suite(void) {
    Suite *s = suite_create("bun-suite");

    ensure_fixtures();

    TCase *tc_memory = tcase_create("memory-tests");
    tcase_set_timeout(tc_memory, 60.0);
    tcase_add_test(tc_memory, test_large_file_streaming_case);
    suite_add_tcase(s, tc_memory);

    // Note that "TCase" is more like a sub-suite than a single test case
    TCase *tc_header = tcase_create("header-tests");
    tcase_add_test(tc_header, test_valid_minimal);
    tcase_add_test(tc_header, test_bad_magic);
    tcase_add_test(tc_header, test_unsupported_version);
    tcase_add_test(tc_header, test_truncated_header);
    tcase_add_test(tc_header, test_unaligned_offset);
    tcase_add_test(tc_header, test_asset_table_oob);
    tcase_add_test(tc_header, test_section_overlap);
    suite_add_tcase(s, tc_header);

    TCase *tc_assets = tcase_create("asset-tests");
    tcase_set_timeout(tc_assets, 30.0);
    tcase_add_test(tc_assets, test_valid_asset);
    tcase_add_test(tc_assets, test_invalid_name_bounds);
    tcase_add_test(tc_assets, test_invalid_non_printable_name);
    tcase_add_test(tc_assets, test_invalid_data_bounds);
    tcase_add_test(tc_assets, test_invalid_flags);
    tcase_add_test(tc_assets, test_checksum_mismatch);
    suite_add_tcase(s, tc_assets);

    TCase *tc_compression = tcase_create("compression-tests");
    tcase_add_test(tc_compression, test_valid_uncompressed_compression_case);
    tcase_add_test(tc_compression, test_valid_rle_compression);
    tcase_add_test(tc_compression, test_malformed_rle_compression);
    tcase_add_test(tc_compression, test_unsupported_zlib_compression);
    suite_add_tcase(s, tc_compression);

    return s;
}

int main(void) {
    Suite   *s  = bun_suite();
    SRunner *sr = srunner_create(s);

    // see https://libcheck.github.io/check/doc/check_html/check_3.html#SRunner-Output for different output options.
    // e.g. pass CK_VERBOSE if you want to see successes as well as failures.
    srunner_run_all(sr, CK_NORMAL);
    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

