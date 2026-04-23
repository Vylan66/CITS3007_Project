#include "../bun.h"

#include <check.h>

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#if defined(_WIN32)
#include <direct.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif

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

static int generate_fixtures_with_python(void) {
#if defined(_WIN32)
  const char *commands[] = {
    "py -3 bunfile_generator.py --header-fixtures tests/fixtures",
    "python bunfile_generator.py --header-fixtures tests/fixtures",
    "python3 bunfile_generator.py --header-fixtures tests/fixtures",
  };
#else
  const char *commands[] = {
    "python3 bunfile_generator.py --header-fixtures tests/fixtures",
    "python bunfile_generator.py --header-fixtures tests/fixtures",
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

// Assemble a test suite from our tests

static Suite *bun_suite(void) {
    Suite *s = suite_create("bun-suite");

    TCase *tc_header = tcase_create("header-tests");
    ensure_fixtures();
    tcase_add_test(tc_header, test_valid_minimal);
    tcase_add_test(tc_header, test_bad_magic);
    tcase_add_test(tc_header, test_unsupported_version);
    tcase_add_test(tc_header, test_truncated_header);
    tcase_add_test(tc_header, test_unaligned_offset);
    tcase_add_test(tc_header, test_asset_table_oob);
    tcase_add_test(tc_header, test_section_overlap);
    suite_add_tcase(s, tc_header);

    return s;
}

int main(void) {
    Suite   *s  = bun_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

