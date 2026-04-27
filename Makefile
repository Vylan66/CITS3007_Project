CC      = gcc
CFLAGS  = -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wconversion
SANFLAGS =
VALGRIND ?= valgrind
PKG_CONFIG ?= pkg-config

# Flags passed to the linker. You will likely need to define this if you use
# additional libraries.
LDFLAGS =

# Sanitizer flags - uncomment during development and testing.
# Do not leave them enabled in a "release" build as they affect performance.
#
# CFLAGS += -fsanitize=address,undefined -fno-omit-frame-pointer -g

ifeq ($(SAN),1)
SANFLAGS += -fsanitize=address,undefined -fno-omit-frame-pointer -g
endif

LIB     = bun_parse.c
MAIN    = main.c
TEST    = tests/test_bun.c

.PHONY: all test clean valgrind

all: bun_parser

bun_parser: $(MAIN) $(LIB)
	$(CC) $(CFLAGS) $(SANFLAGS) $(LDFLAGS) -o $@ $^

# The test binary links the same source files, but not main.c (which has its
# own main()). libcheck provides the test runner's main() instead.
test: tests/test_runner
	./tests/test_runner

tests/test_runner: $(TEST) $(LIB)
	$(CC) $(CFLAGS) $(SANFLAGS) $(LDFLAGS) -o $@ $^ $$($(PKG_CONFIG) --cflags --libs check)

valgrind: tests/test_runner
	$(VALGRIND) --leak-check=full --show-leak-kinds=all --track-origins=yes ./tests/test_runner

clean:
	-rm -f bun_parser tests/test_runner *.o
