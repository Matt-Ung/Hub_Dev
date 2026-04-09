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
OUT_DIR ?= ../../build/experimental
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

BINARIES = \
	$(OUT_DIR)/basic_loops_test.exe \
	$(OUT_DIR)/maintenance_orchestrator_test.exe \
	$(OUT_DIR)/maintenance_orchestrator_test_stripped.exe \
	$(OUT_DIR)/callback_dispatch_test.exe \
	$(OUT_DIR)/config_decoder_test.exe \
	$(OUT_DIR)/config_decoder_test_stripped.exe \
	$(OUT_DIR)/signal_router_report_test.exe \
	$(OUT_DIR)/stack_notice_scheduler_test.exe \
	$(OUT_DIR)/multilayer_encode_test.exe \
	$(OUT_DIR)/hash_dispatch_test.exe \
	$(OUT_DIR)/hash_dispatch_test_stripped.exe \
	$(OUT_DIR)/embedded_payload_test.exe \
	$(OUT_DIR)/branch_weave_snapshot_test.exe \
	$(OUT_DIR)/branch_weave_snapshot_test_stripped.exe \
	$(OUT_DIR)/anti_analysis_suite_test.exe

GCC_BINARIES = \
	$(OUT_DIR)/basic_loops_test_gcc.exe \
	$(OUT_DIR)/maintenance_orchestrator_test_gcc.exe \
	$(OUT_DIR)/callback_dispatch_test_gcc.exe \
	$(OUT_DIR)/config_decoder_test_gcc.exe \
	$(OUT_DIR)/signal_router_report_test_gcc.exe \
	$(OUT_DIR)/stack_notice_scheduler_test_gcc.exe \
	$(OUT_DIR)/multilayer_encode_test_gcc.exe \
	$(OUT_DIR)/hash_dispatch_test_gcc.exe \
	$(OUT_DIR)/embedded_payload_test_gcc.exe \
	$(OUT_DIR)/branch_weave_snapshot_test_gcc.exe \
	$(OUT_DIR)/anti_analysis_suite_test_gcc.exe

UPX_OUTPUTS = \
	$(OUT_DIR)/embedded_payload_test_upx.exe \
	$(OUT_DIR)/config_decoder_test_upx_stripped.exe

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
	@echo "  all            Build baseline binaries with $(CC)"
	@echo "  all-gcc        Build GCC-variant binaries with $(GCC_CC)"
	@echo "  all-with-gcc   Build both sets"
	@echo "  upx            Build UPX-packed sample variants"
	@echo "  upx-debug      Build the UPX-packed variants with shell/PATH diagnostics"
	@echo "  clean          Remove all compiled binaries from $(OUT_DIR)"
	@echo ""
	@echo "Variables:"
	@echo "  OUT_DIR=$(OUT_DIR)"
	@echo "  CC=$(CC)  GCC_CC=$(GCC_CC)"
	@echo "  UPX_BIN=$(UPX_BIN)  UPX_DEBUG=$(UPX_DEBUG)"

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

$(OUT_DIR)/basic_loops_test.exe: basic_loops_test.c | $(OUT_DIR)
	$(CC) $(CFLAGS_COMMON) -O2 $< -o $@

$(OUT_DIR)/basic_loops_test_gcc.exe: basic_loops_test.c | $(OUT_DIR)
	$(GCC_CC) $(CFLAGS_COMMON) -O2 $< -o $@

$(OUT_DIR)/maintenance_orchestrator_test.exe: maintenance_orchestrator_test.c | $(OUT_DIR)
	$(CC) $(CFLAGS_COMMON) -O2 $< -o $@

$(OUT_DIR)/maintenance_orchestrator_test_stripped.exe: maintenance_orchestrator_test.c | $(OUT_DIR)
	$(CC) $(CFLAGS_COMMON) -O2 -s $< -o $@

$(OUT_DIR)/maintenance_orchestrator_test_gcc.exe: maintenance_orchestrator_test.c | $(OUT_DIR)
	$(GCC_CC) $(CFLAGS_COMMON) -O2 $< -o $@

$(OUT_DIR)/callback_dispatch_test.exe: callback_dispatch_test.c | $(OUT_DIR)
	$(CC) $(CFLAGS_COMMON) -O2 $< -o $@

$(OUT_DIR)/callback_dispatch_test_gcc.exe: callback_dispatch_test.c | $(OUT_DIR)
	$(GCC_CC) $(CFLAGS_COMMON) -O2 $< -o $@

$(OUT_DIR)/config_decoder_test.exe: config_decoder_test.c | $(OUT_DIR)
	$(CC) $(CFLAGS_COMMON) -O0 $< -o $@

$(OUT_DIR)/config_decoder_test_stripped.exe: config_decoder_test.c | $(OUT_DIR)
	$(CC) $(CFLAGS_COMMON) -O0 -s $< -o $@

$(OUT_DIR)/config_decoder_test_gcc.exe: config_decoder_test.c | $(OUT_DIR)
	$(GCC_CC) $(CFLAGS_COMMON) -O0 $< -o $@

$(OUT_DIR)/signal_router_report_test.exe: signal_router_report_test.c | $(OUT_DIR)
	$(CC) $(CFLAGS_COMMON) -O2 $< -o $@

$(OUT_DIR)/signal_router_report_test_gcc.exe: signal_router_report_test.c | $(OUT_DIR)
	$(GCC_CC) $(CFLAGS_COMMON) -O2 $< -o $@

$(OUT_DIR)/stack_notice_scheduler_test.exe: stack_notice_scheduler_test.c | $(OUT_DIR)
	$(CC) $(CFLAGS_COMMON) -O2 $< -o $@

$(OUT_DIR)/stack_notice_scheduler_test_gcc.exe: stack_notice_scheduler_test.c | $(OUT_DIR)
	$(GCC_CC) $(CFLAGS_COMMON) -O2 $< -o $@

$(OUT_DIR)/multilayer_encode_test.exe: multilayer_encode_test.c | $(OUT_DIR)
	$(CC) $(CFLAGS_COMMON) -O2 $< -o $@

$(OUT_DIR)/multilayer_encode_test_gcc.exe: multilayer_encode_test.c | $(OUT_DIR)
	$(GCC_CC) $(CFLAGS_COMMON) -O2 $< -o $@

$(OUT_DIR)/hash_dispatch_test.exe: hash_dispatch_test.c | $(OUT_DIR)
	$(CC) $(CFLAGS_COMMON) -O2 $< -o $@

$(OUT_DIR)/hash_dispatch_test_stripped.exe: hash_dispatch_test.c | $(OUT_DIR)
	$(CC) $(CFLAGS_COMMON) -O2 -s $< -o $@

$(OUT_DIR)/hash_dispatch_test_gcc.exe: hash_dispatch_test.c | $(OUT_DIR)
	$(GCC_CC) $(CFLAGS_COMMON) -O2 $< -o $@

$(OUT_DIR)/embedded_payload_test.exe: embedded_payload_test.c | $(OUT_DIR)
	$(CC) $(CFLAGS_COMMON) -O2 $< -o $@

$(OUT_DIR)/embedded_payload_test_gcc.exe: embedded_payload_test.c | $(OUT_DIR)
	$(GCC_CC) $(CFLAGS_COMMON) -O2 $< -o $@

$(OUT_DIR)/branch_weave_snapshot_test.exe: branch_weave_snapshot_test.c | $(OUT_DIR)
	$(CC) $(CFLAGS_COMMON) -O2 $< -o $@

$(OUT_DIR)/branch_weave_snapshot_test_stripped.exe: branch_weave_snapshot_test.c | $(OUT_DIR)
	$(CC) $(CFLAGS_COMMON) -O2 -s $< -o $@

$(OUT_DIR)/branch_weave_snapshot_test_gcc.exe: branch_weave_snapshot_test.c | $(OUT_DIR)
	$(GCC_CC) $(CFLAGS_COMMON) -O2 $< -o $@

upx: $(UPX_OUTPUTS)

upx-debug: UPX_DEBUG=1
upx-debug: upx

$(OUT_DIR)/embedded_payload_test_upx.exe: $(OUT_DIR)/embedded_payload_test.exe | $(OUT_DIR)
	$(call pack_with_upx)

$(OUT_DIR)/config_decoder_test_upx_stripped.exe: $(OUT_DIR)/config_decoder_test_stripped.exe | $(OUT_DIR)
	$(call pack_with_upx)

$(OUT_DIR)/anti_analysis_suite_test.exe: anti_analysis_suite_test.c | $(OUT_DIR)
	$(CC) $(CFLAGS_COMMON) -O2 $< -o $@ $(LDFLAGS_WIN) 2>/dev/null || \
	$(CC) $(CFLAGS_COMMON) -O2 $< -o $@

$(OUT_DIR)/anti_analysis_suite_test_gcc.exe: anti_analysis_suite_test.c | $(OUT_DIR)
	$(GCC_CC) $(CFLAGS_COMMON) -O2 $< -o $@ 2>/dev/null || \
	$(GCC_CC) $(CFLAGS_COMMON) -O2 $< -o $@

clean:
	rm -f $(BINARIES) $(GCC_BINARIES) $(UPX_OUTPUTS) \
		$(OUT_DIR)/string_table_test.exe \
		$(OUT_DIR)/string_table_test_gcc.exe
