# ─────────────────────────────────────────────────────────────────
# Makefile for Experimental Test Source
# ─────────────────────────────────────────────────────────────────

DEFAULT_MINGW_CC := x86_64-w64-mingw32-gcc

ifeq ($(origin CC), default)
CC := $(DEFAULT_MINGW_CC)
endif

GCC_CC ?= gcc
CFLAGS_COMMON ?= -Wall -Wextra
LDFLAGS_WIN = -lkernel32
OUT_DIR ?= ../build/experimental

BINARIES = \
	$(OUT_DIR)/basic_loops_test.exe \
	$(OUT_DIR)/string_table_test.exe \
	$(OUT_DIR)/callback_dispatch_test.exe \
	$(OUT_DIR)/config_decoder_test.exe \
	$(OUT_DIR)/multilayer_encode_test.exe \
	$(OUT_DIR)/hash_dispatch_test.exe \
	$(OUT_DIR)/embedded_payload_test.exe \
	$(OUT_DIR)/anti_analysis_suite_test.exe

GCC_BINARIES = \
	$(OUT_DIR)/basic_loops_test_gcc.exe \
	$(OUT_DIR)/string_table_test_gcc.exe \
	$(OUT_DIR)/callback_dispatch_test_gcc.exe \
	$(OUT_DIR)/config_decoder_test_gcc.exe \
	$(OUT_DIR)/multilayer_encode_test_gcc.exe \
	$(OUT_DIR)/hash_dispatch_test_gcc.exe \
	$(OUT_DIR)/embedded_payload_test_gcc.exe \
	$(OUT_DIR)/anti_analysis_suite_test_gcc.exe

UPX_OUTPUT = $(OUT_DIR)/embedded_payload_test_upx.exe

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
	@echo "  clean          Remove all compiled binaries from $(OUT_DIR)"
	@echo ""
	@echo "Variables:"
	@echo "  OUT_DIR=$(OUT_DIR)"
	@echo "  CC=$(CC)  GCC_CC=$(GCC_CC)"

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

$(OUT_DIR)/basic_loops_test.exe: basic_loops_test.c | $(OUT_DIR)
	$(CC) $(CFLAGS_COMMON) -O2 $< -o $@

$(OUT_DIR)/basic_loops_test_gcc.exe: basic_loops_test.c | $(OUT_DIR)
	$(GCC_CC) $(CFLAGS_COMMON) -O2 $< -o $@

$(OUT_DIR)/string_table_test.exe: string_table_test.c | $(OUT_DIR)
	$(CC) $(CFLAGS_COMMON) -O2 $< -o $@

$(OUT_DIR)/string_table_test_gcc.exe: string_table_test.c | $(OUT_DIR)
	$(GCC_CC) $(CFLAGS_COMMON) -O2 $< -o $@

$(OUT_DIR)/callback_dispatch_test.exe: callback_dispatch_test.c | $(OUT_DIR)
	$(CC) $(CFLAGS_COMMON) -O2 $< -o $@

$(OUT_DIR)/callback_dispatch_test_gcc.exe: callback_dispatch_test.c | $(OUT_DIR)
	$(GCC_CC) $(CFLAGS_COMMON) -O2 $< -o $@

$(OUT_DIR)/config_decoder_test.exe: config_decoder_test.c | $(OUT_DIR)
	$(CC) $(CFLAGS_COMMON) -O0 $< -o $@

$(OUT_DIR)/config_decoder_test_gcc.exe: config_decoder_test.c | $(OUT_DIR)
	$(GCC_CC) $(CFLAGS_COMMON) -O0 $< -o $@

$(OUT_DIR)/multilayer_encode_test.exe: multilayer_encode_test.c | $(OUT_DIR)
	$(CC) $(CFLAGS_COMMON) -O2 $< -o $@

$(OUT_DIR)/multilayer_encode_test_gcc.exe: multilayer_encode_test.c | $(OUT_DIR)
	$(GCC_CC) $(CFLAGS_COMMON) -O2 $< -o $@

$(OUT_DIR)/hash_dispatch_test.exe: hash_dispatch_test.c | $(OUT_DIR)
	$(CC) $(CFLAGS_COMMON) -O2 $< -o $@

$(OUT_DIR)/hash_dispatch_test_gcc.exe: hash_dispatch_test.c | $(OUT_DIR)
	$(GCC_CC) $(CFLAGS_COMMON) -O2 $< -o $@

$(OUT_DIR)/embedded_payload_test.exe: embedded_payload_test.c | $(OUT_DIR)
	$(CC) $(CFLAGS_COMMON) -O2 $< -o $@

$(OUT_DIR)/embedded_payload_test_gcc.exe: embedded_payload_test.c | $(OUT_DIR)
	$(GCC_CC) $(CFLAGS_COMMON) -O2 $< -o $@

upx: $(OUT_DIR)/embedded_payload_test.exe
	cp $(OUT_DIR)/embedded_payload_test.exe $(UPX_OUTPUT)
	command -v upx >/dev/null 2>&1 || { rm -f $(UPX_OUTPUT); echo "ERROR: upx not found on PATH"; exit 2; }
	upx --best $(UPX_OUTPUT) >/dev/null 2>&1 || { rm -f $(UPX_OUTPUT); echo "ERROR: failed to pack $(UPX_OUTPUT) with upx"; exit 2; }

$(OUT_DIR)/anti_analysis_suite_test.exe: anti_analysis_suite_test.c | $(OUT_DIR)
	$(CC) $(CFLAGS_COMMON) -O2 $< -o $@ $(LDFLAGS_WIN) 2>/dev/null || \
	$(CC) $(CFLAGS_COMMON) -O2 $< -o $@

$(OUT_DIR)/anti_analysis_suite_test_gcc.exe: anti_analysis_suite_test.c | $(OUT_DIR)
	$(GCC_CC) $(CFLAGS_COMMON) -O2 $< -o $@ 2>/dev/null || \
	$(GCC_CC) $(CFLAGS_COMMON) -O2 $< -o $@

clean:
	rm -f $(BINARIES) $(GCC_BINARIES) $(UPX_OUTPUT)
