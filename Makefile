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

.PHONY: all all-exes prototype experimental prototype-upx experimental-upx prototype-upx-debug experimental-upx-debug test-catalog test-catalog-all clean clean-test-results clean-test-results-all help require-mingw

all: all-exes

all-exes: prototype experimental prototype-upx experimental-upx
	@echo "Finished building available test executables under Testing/build/"

require-mingw:
	@command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1 || { \
		echo "ERROR: x86_64-w64-mingw32-gcc not found."; \
		echo "       Canonical corpus builds require the MinGW-w64 cross-compiler because the maintained benchmark uses Windows PE binaries."; \
		echo "       Install MinGW-w64 and rerun make all-exes."; \
		exit 2; \
	}

prototype: require-mingw
	$(MAKE) -C Testing/Prototype_Test_Source all-with-gcc

experimental: require-mingw
	$(MAKE) -C Testing/Experimental_Test_Source all-with-gcc

prototype-upx:
	@if UPX= "$(UPX_BIN)" --version >/dev/null 2>&1; then \
		$(MAKE) -C Testing/Prototype_Test_Source upx UPX_BIN="$(UPX_BIN)" UPX_DEBUG="$(UPX_DEBUG)"; \
	else \
		echo "WARNING: could not execute UPX command '$(UPX_BIN)'; skipping prototype packed variants"; \
		echo "         Try: make prototype-upx-debug UPX_BIN=/full/path/to/upx.exe"; \
	fi

experimental-upx:
	@if UPX= "$(UPX_BIN)" --version >/dev/null 2>&1; then \
		$(MAKE) -C Testing/Experimental_Test_Source upx UPX_BIN="$(UPX_BIN)" UPX_DEBUG="$(UPX_DEBUG)"; \
	else \
		echo "WARNING: could not execute UPX command '$(UPX_BIN)'; skipping experimental packed variants"; \
		echo "         Try: make experimental-upx-debug UPX_BIN=/full/path/to/upx.exe"; \
	fi

prototype-upx-debug:
	$(MAKE) -C Testing/Prototype_Test_Source upx-debug UPX_BIN="$(UPX_BIN)" UPX_DEBUG=1

experimental-upx-debug:
	$(MAKE) -C Testing/Experimental_Test_Source upx-debug UPX_BIN="$(UPX_BIN)" UPX_DEBUG=1

test-catalog:
	python3 Testing/render_test_catalog.py --corpus experimental

test-catalog-all:
	python3 Testing/render_test_catalog.py --corpus experimental
	python3 Testing/render_test_catalog.py --corpus prototype

clean:
	$(MAKE) -C Testing/Prototype_Test_Source clean
	$(MAKE) -C Testing/Experimental_Test_Source clean

clean-test-results:
	bash Testing/clean_results.sh

clean-test-results-all:
	bash Testing/clean_results.sh --include-catalog --include-logs

help:
	@echo "Targets:"
	@echo "  make all-exes     Build prototype + experimental executables, including GCC variants"
	@echo "  make prototype    Build the prototype corpus only"
	@echo "  make experimental Build the experimental corpus only"
	@echo "  make test-catalog Generate the experimental testing catalog/dashboard"
	@echo "  make test-catalog-all Generate catalog outputs for both corpora"
	@echo "  make clean        Remove built executables from Testing/build/"
	@echo "  make clean-test-results Remove generated doctor/run/experiment/lineage state"
	@echo "  make clean-test-results-all Remove generated testing state plus catalog/log outputs"
	@echo ""
	@echo "Canonical corpus builds require x86_64-w64-mingw32-gcc on PATH."
	@echo "UPX-packed variants are attempted automatically when UPX_BIN can be executed."
	@echo "Override the command with UPX_BIN=/full/path/to/upx.exe and use *-upx-debug to print shell/PATH diagnostics."
