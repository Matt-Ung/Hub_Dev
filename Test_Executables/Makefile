DEFAULT_MINGW_CC := x86_64-w64-mingw32-gcc
ifeq ($(origin CC), default)
CC := $(DEFAULT_MINGW_CC)
endif
GCC_CC ?= gcc
CFLAGS_COMMON ?= -Wall -Wextra
LDFLAGS ?=

BINARIES := \
	test.exe \
	floss_test.exe \
	floss_test_02.exe \
	floss_test_stripped.exe \
	anti_debug_test.exe \
	winapi_behavior_test.exe \
	control_flow_flattened_test.exe \
	api_hash_resolver_test.exe \
	resource_blob_loader_test.exe

GCC_BINARIES := \
	test_gcc.exe \
	floss_test_gcc.exe \
	floss_test_02_gcc.exe \
	floss_test_stripped_gcc.exe \
	anti_debug_test_gcc.exe \
	winapi_behavior_test_gcc.exe \
	control_flow_flattened_test_gcc.exe \
	api_hash_resolver_test_gcc.exe \
	resource_blob_loader_test_gcc.exe

.PHONY: all all-gcc all-with-gcc clean help

all: $(BINARIES)

all-gcc: $(GCC_BINARIES)

all-with-gcc: all all-gcc

help:
	@echo "Targets:"
	@echo "  make all               Build baseline executables with CC ($(CC))"
	@echo "  make all-gcc           Build *_gcc.exe variants with GCC_CC ($(GCC_CC))"
	@echo "  make all-with-gcc      Build both baseline and gcc-suffixed variants"
	@echo "  make clean             Remove built executables"
	@echo ""
	@echo "Examples:"
	@echo "  make all CC=x86_64-w64-mingw32-gcc"
	@echo "  make all-with-gcc CC=x86_64-w64-mingw32-gcc GCC_CC=gcc"

test.exe: test.c
	$(CC) $(CFLAGS_COMMON) -O2 $< -o $@ $(LDFLAGS)

floss_test.exe: floss_test.c
	$(CC) $(CFLAGS_COMMON) -O0 $< -o $@ $(LDFLAGS)

floss_test_02.exe: floss_test.c
	$(CC) $(CFLAGS_COMMON) -O2 -fno-inline $< -o $@ $(LDFLAGS)

floss_test_stripped.exe: floss_test.c
	$(CC) $(CFLAGS_COMMON) -O2 -s $< -o $@ $(LDFLAGS)

anti_debug_test.exe: anti_debug_test.c
	$(CC) $(CFLAGS_COMMON) -O2 $< -o $@ $(LDFLAGS)

winapi_behavior_test.exe: winapi_behavior_test.c
	$(CC) $(CFLAGS_COMMON) -O2 $< -o $@ $(LDFLAGS)

control_flow_flattened_test.exe: control_flow_flattened_test.c
	$(CC) $(CFLAGS_COMMON) -O2 $< -o $@ $(LDFLAGS)

api_hash_resolver_test.exe: api_hash_resolver_test.c
	$(CC) $(CFLAGS_COMMON) -O2 $< -o $@ $(LDFLAGS)

resource_blob_loader_test.exe: resource_blob_loader_test.c
	$(CC) $(CFLAGS_COMMON) -O2 $< -o $@ $(LDFLAGS)

test_gcc.exe: test.c
	$(GCC_CC) $(CFLAGS_COMMON) -O2 $< -o $@ $(LDFLAGS)

floss_test_gcc.exe: floss_test.c
	$(GCC_CC) $(CFLAGS_COMMON) -O0 $< -o $@ $(LDFLAGS)

floss_test_02_gcc.exe: floss_test.c
	$(GCC_CC) $(CFLAGS_COMMON) -O2 -fno-inline $< -o $@ $(LDFLAGS)

floss_test_stripped_gcc.exe: floss_test.c
	$(GCC_CC) $(CFLAGS_COMMON) -O2 -s $< -o $@ $(LDFLAGS)

anti_debug_test_gcc.exe: anti_debug_test.c
	$(GCC_CC) $(CFLAGS_COMMON) -O2 $< -o $@ $(LDFLAGS)

winapi_behavior_test_gcc.exe: winapi_behavior_test.c
	$(GCC_CC) $(CFLAGS_COMMON) -O2 $< -o $@ $(LDFLAGS)

control_flow_flattened_test_gcc.exe: control_flow_flattened_test.c
	$(GCC_CC) $(CFLAGS_COMMON) -O2 $< -o $@ $(LDFLAGS)

api_hash_resolver_test_gcc.exe: api_hash_resolver_test.c
	$(GCC_CC) $(CFLAGS_COMMON) -O2 $< -o $@ $(LDFLAGS)

resource_blob_loader_test_gcc.exe: resource_blob_loader_test.c
	$(GCC_CC) $(CFLAGS_COMMON) -O2 $< -o $@ $(LDFLAGS)

clean:
	rm -f $(BINARIES) $(GCC_BINARIES)
