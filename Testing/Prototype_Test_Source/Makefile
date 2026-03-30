DEFAULT_MINGW_CC := x86_64-w64-mingw32-gcc
ifeq ($(origin CC), default)
CC := $(DEFAULT_MINGW_CC)
endif

GCC_CC ?= gcc
CFLAGS_COMMON ?= -Wall -Wextra
LDFLAGS ?=
OUT_DIR ?= ../build/prototype

BINARIES := \
	$(OUT_DIR)/test.exe \
	$(OUT_DIR)/floss_test.exe \
	$(OUT_DIR)/floss_test_02.exe \
	$(OUT_DIR)/floss_test_stripped.exe \
	$(OUT_DIR)/test_easy_stripped.exe \
	$(OUT_DIR)/anti_debug_test.exe \
	$(OUT_DIR)/anti_debug_medium_stripped.exe \
	$(OUT_DIR)/winapi_behavior_test.exe \
	$(OUT_DIR)/control_flow_flattened_test.exe \
	$(OUT_DIR)/api_hash_resolver_test.exe \
	$(OUT_DIR)/resource_blob_loader_test.exe \
	$(OUT_DIR)/resource_blob_loader_hard_stripped.exe

GCC_BINARIES := \
	$(OUT_DIR)/test_gcc.exe \
	$(OUT_DIR)/floss_test_gcc.exe \
	$(OUT_DIR)/floss_test_02_gcc.exe \
	$(OUT_DIR)/floss_test_stripped_gcc.exe \
	$(OUT_DIR)/anti_debug_test_gcc.exe \
	$(OUT_DIR)/winapi_behavior_test_gcc.exe \
	$(OUT_DIR)/control_flow_flattened_test_gcc.exe \
	$(OUT_DIR)/api_hash_resolver_test_gcc.exe \
	$(OUT_DIR)/resource_blob_loader_test_gcc.exe

UPX_BINARIES := \
	$(OUT_DIR)/test_easy_upx.exe \
	$(OUT_DIR)/anti_debug_medium_upx.exe \
	$(OUT_DIR)/resource_blob_loader_hard_upx.exe

.PHONY: all all-gcc all-with-gcc upx clean help

all: $(BINARIES)

all-gcc: $(GCC_BINARIES)

all-with-gcc: all all-gcc

help:
	@echo "Targets:"
	@echo "  make all               Build baseline executables with CC ($(CC))"
	@echo "  make all-gcc           Build *_gcc.exe variants with GCC_CC ($(GCC_CC))"
	@echo "  make all-with-gcc      Build both baseline and gcc-suffixed variants"
	@echo "  make upx               Build easy/medium/hard UPX-packed variants"
	@echo "  make clean             Remove built executables from $(OUT_DIR)"
	@echo ""
	@echo "Variables:"
	@echo "  OUT_DIR=$(OUT_DIR)"
	@echo "  CC=$(CC)  GCC_CC=$(GCC_CC)"

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

$(OUT_DIR)/test.exe: test.c | $(OUT_DIR)
	$(CC) $(CFLAGS_COMMON) -O2 $< -o $@ $(LDFLAGS)

$(OUT_DIR)/floss_test.exe: floss_test.c | $(OUT_DIR)
	$(CC) $(CFLAGS_COMMON) -O0 $< -o $@ $(LDFLAGS)

$(OUT_DIR)/floss_test_02.exe: floss_test.c | $(OUT_DIR)
	$(CC) $(CFLAGS_COMMON) -O2 -fno-inline $< -o $@ $(LDFLAGS)

$(OUT_DIR)/floss_test_stripped.exe: floss_test.c | $(OUT_DIR)
	$(CC) $(CFLAGS_COMMON) -O2 -s $< -o $@ $(LDFLAGS)

$(OUT_DIR)/test_easy_stripped.exe: test.c | $(OUT_DIR)
	$(CC) $(CFLAGS_COMMON) -O2 -s $< -o $@ $(LDFLAGS)

$(OUT_DIR)/anti_debug_test.exe: anti_debug_test.c | $(OUT_DIR)
	$(CC) $(CFLAGS_COMMON) -O2 $< -o $@ $(LDFLAGS)

$(OUT_DIR)/anti_debug_medium_stripped.exe: anti_debug_test.c | $(OUT_DIR)
	$(CC) $(CFLAGS_COMMON) -O2 -s $< -o $@ $(LDFLAGS)

$(OUT_DIR)/winapi_behavior_test.exe: winapi_behavior_test.c | $(OUT_DIR)
	$(CC) $(CFLAGS_COMMON) -O2 $< -o $@ $(LDFLAGS)

$(OUT_DIR)/control_flow_flattened_test.exe: control_flow_flattened_test.c | $(OUT_DIR)
	$(CC) $(CFLAGS_COMMON) -O2 $< -o $@ $(LDFLAGS)

$(OUT_DIR)/api_hash_resolver_test.exe: api_hash_resolver_test.c | $(OUT_DIR)
	$(CC) $(CFLAGS_COMMON) -O2 $< -o $@ $(LDFLAGS)

$(OUT_DIR)/resource_blob_loader_test.exe: resource_blob_loader_test.c | $(OUT_DIR)
	$(CC) $(CFLAGS_COMMON) -O2 $< -o $@ $(LDFLAGS)

$(OUT_DIR)/resource_blob_loader_hard_stripped.exe: resource_blob_loader_test.c | $(OUT_DIR)
	$(CC) $(CFLAGS_COMMON) -O2 -s $< -o $@ $(LDFLAGS)

$(OUT_DIR)/test_gcc.exe: test.c | $(OUT_DIR)
	$(GCC_CC) $(CFLAGS_COMMON) -O2 $< -o $@ $(LDFLAGS)

$(OUT_DIR)/floss_test_gcc.exe: floss_test.c | $(OUT_DIR)
	$(GCC_CC) $(CFLAGS_COMMON) -O0 $< -o $@ $(LDFLAGS)

$(OUT_DIR)/floss_test_02_gcc.exe: floss_test.c | $(OUT_DIR)
	$(GCC_CC) $(CFLAGS_COMMON) -O2 -fno-inline $< -o $@ $(LDFLAGS)

$(OUT_DIR)/floss_test_stripped_gcc.exe: floss_test.c | $(OUT_DIR)
	$(GCC_CC) $(CFLAGS_COMMON) -O2 -s $< -o $@ $(LDFLAGS)

$(OUT_DIR)/anti_debug_test_gcc.exe: anti_debug_test.c | $(OUT_DIR)
	$(GCC_CC) $(CFLAGS_COMMON) -O2 $< -o $@ $(LDFLAGS)

$(OUT_DIR)/winapi_behavior_test_gcc.exe: winapi_behavior_test.c | $(OUT_DIR)
	$(GCC_CC) $(CFLAGS_COMMON) -O2 $< -o $@ $(LDFLAGS)

$(OUT_DIR)/control_flow_flattened_test_gcc.exe: control_flow_flattened_test.c | $(OUT_DIR)
	$(GCC_CC) $(CFLAGS_COMMON) -O2 $< -o $@ $(LDFLAGS)

$(OUT_DIR)/api_hash_resolver_test_gcc.exe: api_hash_resolver_test.c | $(OUT_DIR)
	$(GCC_CC) $(CFLAGS_COMMON) -O2 $< -o $@ $(LDFLAGS)

$(OUT_DIR)/resource_blob_loader_test_gcc.exe: resource_blob_loader_test.c | $(OUT_DIR)
	$(GCC_CC) $(CFLAGS_COMMON) -O2 $< -o $@ $(LDFLAGS)

upx: $(UPX_BINARIES)

$(OUT_DIR)/test_easy_upx.exe: $(OUT_DIR)/test.exe | $(OUT_DIR)
	command -v upx >/dev/null 2>&1 || { rm -f $@; echo "ERROR: upx not found on PATH"; exit 2; }
	cp $< $@
	upx --best $@ >/dev/null 2>&1 || { rm -f $@; echo "ERROR: failed to pack $@ with upx"; exit 2; }

$(OUT_DIR)/anti_debug_medium_upx.exe: $(OUT_DIR)/anti_debug_test.exe | $(OUT_DIR)
	command -v upx >/dev/null 2>&1 || { rm -f $@; echo "ERROR: upx not found on PATH"; exit 2; }
	cp $< $@
	upx --best $@ >/dev/null 2>&1 || { rm -f $@; echo "ERROR: failed to pack $@ with upx"; exit 2; }

$(OUT_DIR)/resource_blob_loader_hard_upx.exe: $(OUT_DIR)/resource_blob_loader_test.exe | $(OUT_DIR)
	command -v upx >/dev/null 2>&1 || { rm -f $@; echo "ERROR: upx not found on PATH"; exit 2; }
	cp $< $@
	upx --best $@ >/dev/null 2>&1 || { rm -f $@; echo "ERROR: failed to pack $@ with upx"; exit 2; }

clean:
	rm -f $(BINARIES) $(GCC_BINARIES) $(UPX_BINARIES)
