DEFAULT_MINGW_CC := x86_64-w64-mingw32-gcc
ifeq ($(origin CC), default)
CC := $(DEFAULT_MINGW_CC)
endif

GCC_CC ?= gcc
CFLAGS_COMMON ?= -Wall -Wextra
LDFLAGS ?=
OUT_DIR ?= ../../build/prototype
ifeq ($(OS),Windows_NT)
ifneq ($(wildcard /ucrt64/bin/upx),)
UPX_BIN ?= /ucrt64/bin/upx
else
UPX_BIN ?= upx.exe
endif
else
UPX_BIN ?= upx
endif
UPX_DEBUG ?= 0

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
	$(OUT_DIR)/anti_debug_test_gcc.exe \
	$(OUT_DIR)/winapi_behavior_test_gcc.exe \
	$(OUT_DIR)/control_flow_flattened_test_gcc.exe \
	$(OUT_DIR)/api_hash_resolver_test_gcc.exe \
	$(OUT_DIR)/resource_blob_loader_test_gcc.exe

UPX_BINARIES := \
	$(OUT_DIR)/test_easy_upx.exe \
	$(OUT_DIR)/anti_debug_medium_upx.exe \
	$(OUT_DIR)/resource_blob_loader_hard_upx.exe

.PHONY: all all-gcc all-with-gcc upx upx-debug clean help

define debug_upx_env
	@if [ "$(UPX_DEBUG)" = "1" ]; then \
		echo "UPX debug: SHELL=$(SHELL)"; \
		echo "UPX debug: CURDIR=$(CURDIR)"; \
		echo "UPX debug: PATH=$$PATH"; \
		echo "UPX debug: UPX_BIN=$(UPX_BIN)"; \
		echo "UPX debug: env UPX=$${UPX-<unset>}"; \
		echo "UPX debug: source=$(1)"; \
		echo "UPX debug: output=$(2)"; \
		if [ -f "$(1)" ]; then echo "UPX debug: source exists"; else echo "UPX debug: source missing"; fi; \
		command -v upx >/dev/null 2>&1 && echo "UPX debug: command -v upx -> $$(command -v upx)" || echo "UPX debug: command -v upx -> not found"; \
		command -v upx.exe >/dev/null 2>&1 && echo "UPX debug: command -v upx.exe -> $$(command -v upx.exe)" || echo "UPX debug: command -v upx.exe -> not found"; \
		UPX= "$(UPX_BIN)" --version || true; \
	fi
endef

define pack_with_upx
	@$(call debug_upx_env,$<,$@)
	@cp "$<" "$@"
	@[ -f "$@" ] || { rm -f "$@"; echo "ERROR: expected $@ to exist before running UPX"; exit 2; }
	@UPX= "$(UPX_BIN)" --version >/dev/null 2>&1 || { rm -f "$@"; echo "ERROR: could not execute '$(UPX_BIN)' from make. Set UPX_BIN=/full/path/to/upx.exe or rerun with UPX_DEBUG=1."; exit 2; }
	@UPX= "$(UPX_BIN)" --best "$@" || { rc=$$?; rm -f "$@"; echo "ERROR: failed to pack $@ with $(UPX_BIN) (exit $$rc)"; exit $$rc; }
endef

all: $(BINARIES)

all-gcc: $(GCC_BINARIES)

all-with-gcc: all all-gcc

help:
	@echo "Targets:"
	@echo "  make all               Build baseline executables with CC ($(CC))"
	@echo "  make all-gcc           Build *_gcc.exe variants with GCC_CC ($(GCC_CC))"
	@echo "  make all-with-gcc      Build both baseline and gcc-suffixed variants"
	@echo "  make upx               Build easy/medium/hard UPX-packed variants"
	@echo "  make upx-debug         Build UPX-packed variants with shell/PATH diagnostics"
	@echo "  make clean             Remove built executables from $(OUT_DIR)"
	@echo ""
	@echo "Variables:"
	@echo "  OUT_DIR=$(OUT_DIR)"
	@echo "  CC=$(CC)  GCC_CC=$(GCC_CC)"
	@echo "  UPX_BIN=$(UPX_BIN)  UPX_DEBUG=$(UPX_DEBUG)"

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

upx-debug: UPX_DEBUG=1
upx-debug: upx

$(OUT_DIR)/test_easy_upx.exe: $(OUT_DIR)/test.exe | $(OUT_DIR)
	$(call pack_with_upx)

$(OUT_DIR)/anti_debug_medium_upx.exe: $(OUT_DIR)/anti_debug_test.exe | $(OUT_DIR)
	$(call pack_with_upx)

$(OUT_DIR)/resource_blob_loader_hard_upx.exe: $(OUT_DIR)/resource_blob_loader_test.exe | $(OUT_DIR)
	$(call pack_with_upx)

clean:
	rm -f $(BINARIES) $(GCC_BINARIES) $(UPX_BINARIES)
