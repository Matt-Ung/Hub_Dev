.PHONY: all all-exes prototype experimental prototype-upx experimental-upx test-catalog test-catalog-all clean help

all: all-exes

all-exes: prototype experimental prototype-upx experimental-upx
	@echo "Finished building available test executables under Testing/build/"

prototype:
	$(MAKE) -C Testing/Prototype_Test_Source all-with-gcc

experimental:
	$(MAKE) -C Testing/Experimental_Test_Source all-with-gcc

prototype-upx:
	@if command -v upx >/dev/null 2>&1; then \
		$(MAKE) -C Testing/Prototype_Test_Source upx; \
	else \
		echo "WARNING: upx not found on PATH; skipping prototype packed variants"; \
	fi

experimental-upx:
	@if command -v upx >/dev/null 2>&1; then \
		$(MAKE) -C Testing/Experimental_Test_Source upx; \
	else \
		echo "WARNING: upx not found on PATH; skipping experimental packed variants"; \
	fi

test-catalog:
	python3 Testing/render_test_catalog.py --corpus experimental

test-catalog-all:
	python3 Testing/render_test_catalog.py --corpus experimental
	python3 Testing/render_test_catalog.py --corpus prototype

clean:
	$(MAKE) -C Testing/Prototype_Test_Source clean
	$(MAKE) -C Testing/Experimental_Test_Source clean

help:
	@echo "Targets:"
	@echo "  make all-exes     Build prototype + experimental executables, including GCC variants"
	@echo "  make prototype    Build the prototype corpus only"
	@echo "  make experimental Build the experimental corpus only"
	@echo "  make test-catalog Generate the experimental testing catalog/dashboard"
	@echo "  make test-catalog-all Generate catalog outputs for both corpora"
	@echo "  make clean        Remove built executables from Testing/build/"
	@echo ""
	@echo "UPX-packed variants are attempted automatically when upx is installed."
