#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include "bun.h"

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <file.bun>\n", argv[0]);
    return BUN_ERR_IO;
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
    for (size_t i = 0; i < ctx.violation_count; i++) {
        fprintf(stderr, "%s\n", ctx.violations[i].message);
    }

    fprintf(stderr, "Error: header invalid or unsupported (code %d)\n", result);

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
  // TODO: implement asset record parsing
  

  // TODO: on BUN_OK, print human-readable summary to stdout.
  //     on BUN_MALFORMED / BUN_UNSUPPORTED, print violation list to stderr.
  //     See project brief for output requirements.

  bun_close(&ctx);
  return result;
}
