# Final-round build pipeline for the maintained final-round source corpus
#
# This Makefile is intentionally opinionated:
# - builds release-oriented Windows PE samples
# - strips them explicitly
# - packs them explicitly with UPX
# - emits opaque final names (sample1.exe .. sample5.exe)
# - writes a manifest + reference bundle under Testing/build/deepseek_final/
#
# It assumes GNU make plus a POSIX-like shell (MSYS2 / Git Bash / WSL shell).

DEFAULT_MINGW_CXX := x86_64-w64-mingw32-g++
DEFAULT_MINGW_CC := x86_64-w64-mingw32-gcc

ifeq ($(origin CXX), default)
CXX := $(DEFAULT_MINGW_CXX)
endif

ifeq ($(origin CC), default)
CC := $(DEFAULT_MINGW_CC)
endif

ifeq ($(origin STRIP), undefined)
# Prefer the strip binary associated with the active compiler toolchain.
# This matches MSYS2 installs from:
#   pacman -S mingw-w64-x86_64-toolchain
DETECTED_STRIP := $(strip $(shell $(CC) -print-prog-name=strip 2>/dev/null))
ifeq ($(DETECTED_STRIP),)
STRIP := strip
else
STRIP := $(DETECTED_STRIP)
endif
endif

ifeq ($(OS),Windows_NT)
ifneq ($(wildcard /ucrt64/bin/upx),)
UPX_BIN ?= /ucrt64/bin/upx
else
UPX_BIN ?= upx.exe
endif
else
UPX_BIN ?= upx
endif

SOURCE_DATE_EPOCH ?= 1700000000

OUT_DIR ?= ../../build/deepseek_final
OBJDIR := $(OUT_DIR)/obj
RELEASE_DIR := $(OUT_DIR)/release
STRIPPED_DIR := $(OUT_DIR)/stripped
OUTPUT_DIR := $(OUT_DIR)/output
REFERENCE_DIR := $(OUT_DIR)/reference

MANIFEST := $(OUT_DIR)/final_test_manifest.json
MAPPING := $(OUT_DIR)/sample_name_mapping.json
REFERENCE_STAMP := $(REFERENCE_DIR)/.generated.stamp
STATIC_MANIFEST := final_test_manifest.json
STATIC_MAPPING := sample_name_mapping.json
STATIC_REFERENCE_DIR := reference

COMMON_DEFS := -DWIN32_LEAN_AND_MEAN -DNDEBUG
COMMON_OPT := -O2 -ffunction-sections -fdata-sections -fno-ident
COMMON_WARN := -Wall -Wextra -Wno-unused-parameter
COMMON_CPPFLAGS := $(COMMON_DEFS)
COMMON_CXXFLAGS := $(COMMON_OPT) $(COMMON_WARN) -std=c++17
COMMON_CFLAGS := $(COMMON_OPT) $(COMMON_WARN) -std=c11
COMMON_LDFLAGS := -static -static-libgcc -static-libstdc++ -Wl,--gc-sections -Wl,--build-id=none -Wl,--no-insert-timestamp
UPX_FLAGS := --best --lzma --force

WINDOWS_LIBS := -lkernel32 -luser32 -ladvapi32 -lshell32
COM_LIBS := -lole32 -loleaut32 -luuid

EMOTET_RELEASE := $(RELEASE_DIR)/emotet_release.exe
QAKBOT_RELEASE := $(RELEASE_DIR)/qakbot_release.exe
TRICKBOT_RELEASE := $(RELEASE_DIR)/trickbot_release.exe
WANNACRY_RELEASE := $(RELEASE_DIR)/wannacry_release.exe
PLUGX_RELEASE := $(RELEASE_DIR)/plugx_release.exe

EMOTET_STRIPPED := $(STRIPPED_DIR)/emotet_release.exe
QAKBOT_STRIPPED := $(STRIPPED_DIR)/qakbot_release.exe
TRICKBOT_STRIPPED := $(STRIPPED_DIR)/trickbot_release.exe
WANNACRY_STRIPPED := $(STRIPPED_DIR)/wannacry_release.exe
PLUGX_STRIPPED := $(STRIPPED_DIR)/plugx_release.exe

FINAL_SAMPLE_1 := $(OUTPUT_DIR)/sample1.exe
FINAL_SAMPLE_2 := $(OUTPUT_DIR)/sample2.exe
FINAL_SAMPLE_3 := $(OUTPUT_DIR)/sample3.exe
FINAL_SAMPLE_4 := $(OUTPUT_DIR)/sample4.exe
FINAL_SAMPLE_5 := $(OUTPUT_DIR)/sample5.exe

FINAL_OUTPUTS := \
	$(FINAL_SAMPLE_1) \
	$(FINAL_SAMPLE_2) \
	$(FINAL_SAMPLE_3) \
	$(FINAL_SAMPLE_4) \
	$(FINAL_SAMPLE_5)

REFERENCE_OUTPUTS := \
	$(REFERENCE_DIR)/sample1.json \
	$(REFERENCE_DIR)/sample1.md \
	$(REFERENCE_DIR)/sample2.json \
	$(REFERENCE_DIR)/sample2.md \
	$(REFERENCE_DIR)/sample3.json \
	$(REFERENCE_DIR)/sample3.md \
	$(REFERENCE_DIR)/sample4.json \
	$(REFERENCE_DIR)/sample4.md \
	$(REFERENCE_DIR)/sample5.json \
	$(REFERENCE_DIR)/sample5.md

REFERENCE_SOURCE_FILES := \
	$(STATIC_MANIFEST) \
	$(STATIC_MAPPING) \
	$(STATIC_REFERENCE_DIR)/sample1.json \
	$(STATIC_REFERENCE_DIR)/sample1.md \
	$(STATIC_REFERENCE_DIR)/sample2.json \
	$(STATIC_REFERENCE_DIR)/sample2.md \
	$(STATIC_REFERENCE_DIR)/sample3.json \
	$(STATIC_REFERENCE_DIR)/sample3.md \
	$(STATIC_REFERENCE_DIR)/sample4.json \
	$(STATIC_REFERENCE_DIR)/sample4.md \
	$(STATIC_REFERENCE_DIR)/sample5.json \
	$(STATIC_REFERENCE_DIR)/sample5.md

EMOTET_OBJS := $(OBJDIR)/emotet_main.o $(OBJDIR)/emotet_utils.o
QAKBOT_OBJS := $(OBJDIR)/qbot_main.o $(OBJDIR)/qbot_utils.o
TRICKBOT_OBJS := $(OBJDIR)/trick_main.o $(OBJDIR)/trick_antidebug.o
WANNACRY_OBJS := $(OBJDIR)/wannacry_main.o $(OBJDIR)/wannacry_worm.o
PLUGX_OBJS := $(OBJDIR)/plugx_main.o $(OBJDIR)/plugx_shellcode.o

SOURCE_FILES := \
	Emotet/main.cpp Emotet/utils.cpp Emotet/config.h \
	Qakbot/qbot_main.cpp Qakbot/qbot_utils.cpp Qakbot/qakbot_config.h \
	TrickBot/trick_main.cpp TrickBot/trick_antidebug.cpp TrickBot/trick_config.h \
	Wannacry/wannacry_main.cpp Wannacry/wannacry_worm.cpp Wannacry/wannacry_config.h \
	Plugx/plugx_main.cpp Plugx/plugx_shellcode.c Plugx/plugx_config.h

.PHONY: all all-with-gcc final-round upx check-tools clean manifest references help sample1 sample2 sample3 sample4 sample5

all: final-round
all-with-gcc: final-round
upx: final-round

final-round: check-tools $(FINAL_OUTPUTS) references
	@echo "============================================================"
	@echo "Final testing samples built successfully."
	@echo "Opaque outputs: $(OUTPUT_DIR)/sample1.exe .. sample5.exe"
	@echo "Manifest:       $(MANIFEST)"
	@echo "References:     $(REFERENCE_DIR)/"
	@echo "============================================================"

sample1: check-tools $(FINAL_SAMPLE_1)
sample2: check-tools $(FINAL_SAMPLE_2)
sample3: check-tools $(FINAL_SAMPLE_3)
sample4: check-tools $(FINAL_SAMPLE_4)
sample5: check-tools $(FINAL_SAMPLE_5)

references: $(REFERENCE_STAMP)

manifest: references

check-tools:
	@command -v "$(CXX)" >/dev/null 2>&1 || { echo "ERROR: compiler '$(CXX)' not found. Install the MinGW-w64 C++ toolchain in the Windows VM or override CXX=..."; exit 1; }
	@command -v "$(CC)" >/dev/null 2>&1 || { echo "ERROR: compiler '$(CC)' not found. Install the MinGW-w64 C toolchain in the Windows VM or override CC=..."; exit 1; }
	@command -v "$(STRIP)" >/dev/null 2>&1 || { echo "ERROR: strip tool '$(STRIP)' not found. Install the matching binutils package or override STRIP=..."; exit 1; }
	@command -v "$(UPX_BIN)" >/dev/null 2>&1 || { echo "ERROR: packer '$(UPX_BIN)' not found. Install UPX in the Windows VM or override UPX_BIN=..."; exit 1; }

$(OBJDIR) $(RELEASE_DIR) $(STRIPPED_DIR) $(OUTPUT_DIR) $(REFERENCE_DIR):
	@mkdir -p "$@"

$(OBJDIR)/emotet_main.o: Emotet/main.cpp Emotet/config.h | $(OBJDIR)
	$(CXX) $(COMMON_CPPFLAGS) $(COMMON_CXXFLAGS) -c "$<" -o "$@"

$(OBJDIR)/emotet_utils.o: Emotet/utils.cpp Emotet/config.h | $(OBJDIR)
	$(CXX) $(COMMON_CPPFLAGS) $(COMMON_CXXFLAGS) -c "$<" -o "$@"

$(OBJDIR)/qbot_main.o: Qakbot/qbot_main.cpp Qakbot/qakbot_config.h | $(OBJDIR)
	$(CXX) $(COMMON_CPPFLAGS) $(COMMON_CXXFLAGS) -c "$<" -o "$@"

$(OBJDIR)/qbot_utils.o: Qakbot/qbot_utils.cpp Qakbot/qakbot_config.h | $(OBJDIR)
	$(CXX) $(COMMON_CPPFLAGS) $(COMMON_CXXFLAGS) -c "$<" -o "$@"

$(OBJDIR)/trick_main.o: TrickBot/trick_main.cpp TrickBot/trick_config.h | $(OBJDIR)
	$(CXX) $(COMMON_CPPFLAGS) $(COMMON_CXXFLAGS) -c "$<" -o "$@"

$(OBJDIR)/trick_antidebug.o: TrickBot/trick_antidebug.cpp TrickBot/trick_config.h | $(OBJDIR)
	$(CXX) $(COMMON_CPPFLAGS) $(COMMON_CXXFLAGS) -c "$<" -o "$@"

$(OBJDIR)/wannacry_main.o: Wannacry/wannacry_main.cpp Wannacry/wannacry_config.h | $(OBJDIR)
	$(CXX) $(COMMON_CPPFLAGS) $(COMMON_CXXFLAGS) -c "$<" -o "$@"

$(OBJDIR)/wannacry_worm.o: Wannacry/wannacry_worm.cpp Wannacry/wannacry_config.h | $(OBJDIR)
	$(CXX) $(COMMON_CPPFLAGS) $(COMMON_CXXFLAGS) -c "$<" -o "$@"

$(OBJDIR)/plugx_main.o: Plugx/plugx_main.cpp Plugx/plugx_config.h | $(OBJDIR)
	$(CXX) $(COMMON_CPPFLAGS) $(COMMON_CXXFLAGS) -c "$<" -o "$@"

$(OBJDIR)/plugx_shellcode.o: Plugx/plugx_shellcode.c | $(OBJDIR)
	$(CC) $(COMMON_CPPFLAGS) $(COMMON_CFLAGS) -c "$<" -o "$@"

$(EMOTET_RELEASE): $(EMOTET_OBJS) | $(RELEASE_DIR)
	$(CXX) $(COMMON_LDFLAGS) -mwindows $^ -o "$@" $(WINDOWS_LIBS) -lwinhttp

$(QAKBOT_RELEASE): $(QAKBOT_OBJS) | $(RELEASE_DIR)
	$(CXX) $(COMMON_LDFLAGS) -mwindows -municode $^ -o "$@" $(WINDOWS_LIBS) $(COM_LIBS) -ltaskschd

$(TRICKBOT_RELEASE): $(TRICKBOT_OBJS) | $(RELEASE_DIR)
	$(CXX) $(COMMON_LDFLAGS) -mwindows $^ -o "$@" $(WINDOWS_LIBS) $(COM_LIBS) -lwbemuuid -lwinhttp

$(WANNACRY_RELEASE): $(WANNACRY_OBJS) | $(RELEASE_DIR)
	$(CXX) $(COMMON_LDFLAGS) -mwindows $^ -o "$@" $(WINDOWS_LIBS) -lws2_32 -lwininet

$(PLUGX_RELEASE): $(PLUGX_OBJS) | $(RELEASE_DIR)
	$(CXX) $(COMMON_LDFLAGS) -mwindows $^ -o "$@" $(WINDOWS_LIBS) -lws2_32 -lgdi32

$(EMOTET_STRIPPED): $(EMOTET_RELEASE) | $(STRIPPED_DIR)
	@cp "$<" "$@"
	@$(STRIP) --strip-all "$@" || { echo "ERROR: strip failed for $<"; rm -f "$@"; exit 1; }

$(QAKBOT_STRIPPED): $(QAKBOT_RELEASE) | $(STRIPPED_DIR)
	@cp "$<" "$@"
	@$(STRIP) --strip-all "$@" || { echo "ERROR: strip failed for $<"; rm -f "$@"; exit 1; }

$(TRICKBOT_STRIPPED): $(TRICKBOT_RELEASE) | $(STRIPPED_DIR)
	@cp "$<" "$@"
	@$(STRIP) --strip-all "$@" || { echo "ERROR: strip failed for $<"; rm -f "$@"; exit 1; }

$(WANNACRY_STRIPPED): $(WANNACRY_RELEASE) | $(STRIPPED_DIR)
	@cp "$<" "$@"
	@$(STRIP) --strip-all "$@" || { echo "ERROR: strip failed for $<"; rm -f "$@"; exit 1; }

$(PLUGX_STRIPPED): $(PLUGX_RELEASE) | $(STRIPPED_DIR)
	@cp "$<" "$@"
	@$(STRIP) --strip-all "$@" || { echo "ERROR: strip failed for $<"; rm -f "$@"; exit 1; }

$(FINAL_SAMPLE_1): $(EMOTET_STRIPPED) | $(OUTPUT_DIR)
	@cp "$<" "$@"
	@$(UPX_BIN) $(UPX_FLAGS) "$@" >/dev/null || { echo "ERROR: UPX packing failed for $@"; rm -f "$@"; exit 1; }

$(FINAL_SAMPLE_2): $(QAKBOT_STRIPPED) | $(OUTPUT_DIR)
	@cp "$<" "$@"
	@$(UPX_BIN) $(UPX_FLAGS) "$@" >/dev/null || { echo "ERROR: UPX packing failed for $@"; rm -f "$@"; exit 1; }

$(FINAL_SAMPLE_3): $(TRICKBOT_STRIPPED) | $(OUTPUT_DIR)
	@cp "$<" "$@"
	@$(UPX_BIN) $(UPX_FLAGS) "$@" >/dev/null || { echo "ERROR: UPX packing failed for $@"; rm -f "$@"; exit 1; }

$(FINAL_SAMPLE_4): $(WANNACRY_STRIPPED) | $(OUTPUT_DIR)
	@cp "$<" "$@"
	@$(UPX_BIN) $(UPX_FLAGS) "$@" >/dev/null || { echo "ERROR: UPX packing failed for $@"; rm -f "$@"; exit 1; }

$(FINAL_SAMPLE_5): $(PLUGX_STRIPPED) | $(OUTPUT_DIR)
	@cp "$<" "$@"
	@$(UPX_BIN) $(UPX_FLAGS) "$@" >/dev/null || { echo "ERROR: UPX packing failed for $@"; rm -f "$@"; exit 1; }

$(REFERENCE_STAMP): $(FINAL_OUTPUTS) $(REFERENCE_SOURCE_FILES) | $(REFERENCE_DIR)
	@cp "$(STATIC_MANIFEST)" "$(MANIFEST)"
	@cp "$(STATIC_MAPPING)" "$(MAPPING)"
	@cp "$(STATIC_REFERENCE_DIR)"/*.json "$(REFERENCE_DIR)/"
	@cp "$(STATIC_REFERENCE_DIR)"/*.md "$(REFERENCE_DIR)/"
	@touch "$@"

$(MANIFEST) $(MAPPING) $(REFERENCE_OUTPUTS): $(REFERENCE_STAMP)

clean:
	@rm -rf "$(OUT_DIR)" bin malware_simulations.zip
	@echo "Removed DeepSeek final-round outputs and legacy build directories."

help:
	@echo "Final-round build targets"
	@echo ""
	@echo "  make final-round   Build all final opaque samples and references"
	@echo "  make sample1       Build only sample1.exe (Emotet mapping in manifest)"
	@echo "  make sample2       Build only sample2.exe (QakBot mapping in manifest)"
	@echo "  make sample3       Build only sample3.exe (TrickBot mapping in manifest)"
	@echo "  make sample4       Build only sample4.exe (WannaCry mapping in manifest)"
	@echo "  make sample5       Build only sample5.exe (PlugX mapping in manifest)"
	@echo "  make references    Regenerate manifest + per-sample reference files"
	@echo "  make clean         Remove $(OUT_DIR) and legacy bin/ outputs"
	@echo ""
	@echo "Tool overrides:"
	@echo "  OUT_DIR=$(OUT_DIR)"
	@echo "  CXX=$(CXX)  CC=$(CC)  STRIP=$(STRIP)"
	@echo "  UPX_BIN=$(UPX_BIN)  PYTHON=$(PYTHON)"
	@echo ""
	@echo "Output layout:"
	@echo "  $(RELEASE_DIR)/   release-oriented intermediates"
	@echo "  $(STRIPPED_DIR)/  stripped intermediates"
	@echo "  $(OUTPUT_DIR)/    final packed opaque executables"
	@echo "  $(REFERENCE_DIR)/ generated JSON + Markdown references"
	@echo "  $(MANIFEST)"
	@echo "  $(MAPPING)"
