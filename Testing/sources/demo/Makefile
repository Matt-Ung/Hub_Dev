DEFAULT_MINGW_CC := x86_64-w64-mingw32-gcc

ifeq ($(origin CC), default)
CC := $(DEFAULT_MINGW_CC)
endif

GCC_CC ?= gcc
CFLAGS_COMMON ?= -Wall -Wextra
LDFLAGS ?=
OUT_DIR ?= ../../build/demo

BINARIES := \
	$(OUT_DIR)/demo.exe \
	$(OUT_DIR)/demo_stripped.exe

GCC_BINARIES := \
	$(OUT_DIR)/demo_gcc.exe

.PHONY: all stripped all-gcc all-with-gcc clean help

all: $(BINARIES)

stripped: $(OUT_DIR)/demo_stripped.exe

all-gcc: $(GCC_BINARIES)

all-with-gcc: all all-gcc

help:
	@echo "Targets:"
	@echo "  make all               Build demo.exe and demo_stripped.exe with CC ($(CC))"
	@echo "  make stripped          Build only demo_stripped.exe"
	@echo "  make all-gcc           Build demo_gcc.exe with GCC_CC ($(GCC_CC))"
	@echo "  make all-with-gcc      Build both MinGW and GCC variants"
	@echo "  make clean             Remove built demo binaries from $(OUT_DIR)"
	@echo ""
	@echo "Variables:"
	@echo "  OUT_DIR=$(OUT_DIR)"
	@echo "  CC=$(CC)  GCC_CC=$(GCC_CC)"

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

$(OUT_DIR)/demo.exe: demo.c | $(OUT_DIR)
	$(CC) $(CFLAGS_COMMON) -O1 $< -o $@ $(LDFLAGS)

$(OUT_DIR)/demo_stripped.exe: demo.c | $(OUT_DIR)
	$(CC) $(CFLAGS_COMMON) -O1 -s $< -o $@ $(LDFLAGS)

$(OUT_DIR)/demo_gcc.exe: demo.c | $(OUT_DIR)
	$(GCC_CC) $(CFLAGS_COMMON) -O1 $< -o $@ $(LDFLAGS)

clean:
	rm -f $(BINARIES) $(GCC_BINARIES)
