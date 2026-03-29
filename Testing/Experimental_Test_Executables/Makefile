# ─────────────────────────────────────────────────────────────────
# Makefile for Experimental Test Executables
#
# Platform assumptions:
#   - Primary target: Windows PE x64 via MinGW-w64 cross-compiler
#   - Fallback: native gcc / clang on macOS / Linux (compiles the
#     non-Windows stubs so the code structure is preserved)
#   - anti_analysis_suite_test.c uses Windows API -- requires
#     x86_64-w64-mingw32-gcc for full functionality
#
# Conventions:
#   - Follows the same build patterns as Prototype_Test_Executables/
#   - Standard binaries: <name>.exe
#   - GCC-variant binaries: <name>_gcc.exe
#   - CFLAGS_COMMON applies to all targets
#   - Individual targets may add extra flags (e.g., -O0 for
#     unoptimized variants, -s for stripped)
#
# Usage:
#   make                 Build all baseline binaries
#   make all-gcc         Build all GCC-variant binaries
#   make all-with-gcc    Build baseline + GCC variants
#   make upx             Build UPX-packed variant of embedded_payload
#   make clean           Remove all compiled binaries
#   make help            Show available targets
# ─────────────────────────────────────────────────────────────────

# Compiler selection -- same logic as Prototype_Test_Executables
DEFAULT_MINGW_CC := x86_64-w64-mingw32-gcc

ifeq ($(origin CC), default)
  CC := $(DEFAULT_MINGW_CC)
endif

GCC_CC      ?= gcc
CFLAGS_COMMON ?= -Wall -Wextra

# Windows libraries needed for anti_analysis_suite_test
LDFLAGS_WIN  = -lkernel32

# ─────────────────────────────────────────────────────────────────
# Baseline binaries (built with $(CC))
# ─────────────────────────────────────────────────────────────────

BINARIES = \
	basic_loops_test.exe \
	string_table_test.exe \
	callback_dispatch_test.exe \
	config_decoder_test.exe \
	multilayer_encode_test.exe \
	hash_dispatch_test.exe \
	embedded_payload_test.exe \
	anti_analysis_suite_test.exe

# ─────────────────────────────────────────────────────────────────
# GCC-variant binaries (built with $(GCC_CC))
# ─────────────────────────────────────────────────────────────────

GCC_BINARIES = \
	basic_loops_test_gcc.exe \
	string_table_test_gcc.exe \
	callback_dispatch_test_gcc.exe \
	config_decoder_test_gcc.exe \
	multilayer_encode_test_gcc.exe \
	hash_dispatch_test_gcc.exe \
	embedded_payload_test_gcc.exe \
	anti_analysis_suite_test_gcc.exe

# ─────────────────────────────────────────────────────────────────
# Phony targets
# ─────────────────────────────────────────────────────────────────

.PHONY: all all-gcc all-with-gcc upx clean help

all: $(BINARIES)

all-gcc: $(GCC_BINARIES)

all-with-gcc: all all-gcc

help:
	@echo "Targets:"
	@echo "  all            Build baseline binaries with $(CC)"
	@echo "  all-gcc        Build GCC-variant binaries with $(GCC_CC)"
	@echo "  all-with-gcc   Build both sets"
	@echo "  upx            Build UPX-packed embedded_payload_test_upx.exe"
	@echo "  clean          Remove all compiled binaries"
	@echo ""
	@echo "Variables:"
	@echo "  CC=$(CC)  GCC_CC=$(GCC_CC)"

# ─────────────────────────────────────────────────────────────────
# EASY: basic_loops_test  (-O2)
# ─────────────────────────────────────────────────────────────────

basic_loops_test.exe: basic_loops_test.c
	$(CC) $(CFLAGS_COMMON) -O2 $< -o $@

basic_loops_test_gcc.exe: basic_loops_test.c
	$(GCC_CC) $(CFLAGS_COMMON) -O2 $< -o $@

# ─────────────────────────────────────────────────────────────────
# EASY: string_table_test  (-O2)
# ─────────────────────────────────────────────────────────────────

string_table_test.exe: string_table_test.c
	$(CC) $(CFLAGS_COMMON) -O2 $< -o $@

string_table_test_gcc.exe: string_table_test.c
	$(GCC_CC) $(CFLAGS_COMMON) -O2 $< -o $@

# ─────────────────────────────────────────────────────────────────
# MEDIUM: callback_dispatch_test  (-O2)
# ─────────────────────────────────────────────────────────────────

callback_dispatch_test.exe: callback_dispatch_test.c
	$(CC) $(CFLAGS_COMMON) -O2 $< -o $@

callback_dispatch_test_gcc.exe: callback_dispatch_test.c
	$(GCC_CC) $(CFLAGS_COMMON) -O2 $< -o $@

# ─────────────────────────────────────────────────────────────────
# MEDIUM: config_decoder_test  (-O0 to preserve decode loop)
# ─────────────────────────────────────────────────────────────────

config_decoder_test.exe: config_decoder_test.c
	$(CC) $(CFLAGS_COMMON) -O0 $< -o $@

config_decoder_test_gcc.exe: config_decoder_test.c
	$(GCC_CC) $(CFLAGS_COMMON) -O0 $< -o $@

# ─────────────────────────────────────────────────────────────────
# HARD: multilayer_encode_test  (-O2)
# ─────────────────────────────────────────────────────────────────

multilayer_encode_test.exe: multilayer_encode_test.c
	$(CC) $(CFLAGS_COMMON) -O2 $< -o $@

multilayer_encode_test_gcc.exe: multilayer_encode_test.c
	$(GCC_CC) $(CFLAGS_COMMON) -O2 $< -o $@

# ─────────────────────────────────────────────────────────────────
# HARD: hash_dispatch_test  (-O2)
# ─────────────────────────────────────────────────────────────────

hash_dispatch_test.exe: hash_dispatch_test.c
	$(CC) $(CFLAGS_COMMON) -O2 $< -o $@

hash_dispatch_test_gcc.exe: hash_dispatch_test.c
	$(GCC_CC) $(CFLAGS_COMMON) -O2 $< -o $@

# ─────────────────────────────────────────────────────────────────
# HARD: embedded_payload_test  (-O2)
# Also: UPX-packed variant for upxmcp testing
# ─────────────────────────────────────────────────────────────────

embedded_payload_test.exe: embedded_payload_test.c
	$(CC) $(CFLAGS_COMMON) -O2 $< -o $@

embedded_payload_test_gcc.exe: embedded_payload_test.c
	$(GCC_CC) $(CFLAGS_COMMON) -O2 $< -o $@

# UPX target: pack the baseline binary.  Requires upx on PATH.
# This produces a separate _upx.exe file that exercises upxmcp.
upx: embedded_payload_test.exe
	cp embedded_payload_test.exe embedded_payload_test_upx.exe
	upx --best embedded_payload_test_upx.exe || \
		echo "WARNING: upx not found or packing failed. Install upx to build this target."

# ─────────────────────────────────────────────────────────────────
# HARD: anti_analysis_suite_test  (-O2, needs Windows libs when
#       cross-compiling with MinGW)
# ─────────────────────────────────────────────────────────────────

anti_analysis_suite_test.exe: anti_analysis_suite_test.c
	$(CC) $(CFLAGS_COMMON) -O2 $< -o $@ $(LDFLAGS_WIN) 2>/dev/null || \
	$(CC) $(CFLAGS_COMMON) -O2 $< -o $@

anti_analysis_suite_test_gcc.exe: anti_analysis_suite_test.c
	$(GCC_CC) $(CFLAGS_COMMON) -O2 $< -o $@ 2>/dev/null || \
	$(GCC_CC) $(CFLAGS_COMMON) -O2 $< -o $@

# ─────────────────────────────────────────────────────────────────
# Cleanup
# ─────────────────────────────────────────────────────────────────

clean:
	rm -f $(BINARIES) $(GCC_BINARIES) embedded_payload_test_upx.exe
