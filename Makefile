# mips64rt Phase 0 build driver.
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0

.DEFAULT_GOAL := help

NIX_A64_GCC := /nix/store/82ac69jwkpj68v4mx22yxnwzqj0ql4l5-aarch64-unknown-linux-musl-gcc-wrapper-15.2.0/bin/aarch64-unknown-linux-musl-gcc
ifeq ($(origin CC),default)
ifeq ($(wildcard $(NIX_A64_GCC)),$(NIX_A64_GCC))
CC := $(NIX_A64_GCC)
else
CC := $(shell command -v aarch64-unknown-linux-musl-gcc 2>/dev/null || echo cc)
endif
endif
CROSS_CC ?= aarch64-unknown-linux-musl-gcc
# Host-native tools (tests/check_abi_invariants) always build with the host
# C compiler, even when CC resolves to the aarch64-musl cross compiler.
HOST_CC ?= cc
# `-pthread` for the Phase 4 thread runtime; glibc >= 2.34 and macOS link
# without it, older glibc needs it.
CFLAGS := -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -pthread
INCLUDES := -Isrc -Isrc/rt64
BUILD := _build

# Phase 0 bootstrap binary: CLI + engine dispatch + signal-contract stub.
# The copied `src/rt64/` substrate wires into later phases (L1c the Linux
# layer, L2b the DBT); it is line-limit checked here, not yet linked.
BOOT_SRCS := src/main.c \
	src/rt64/runtime/worker_loop.c \
	src/rt64/linux/signal_core.c \
	src/interp/decode.c \
	src/interp/interp.c \
	src/interp/unaligned.c \
	src/interp/fpmove.c \
	src/os/mem.c \
	src/os/syscall_min.c \
	src/loader.c

.PHONY: help build build-cross check check-line-limits check-abi-invariants clean

help:
	@echo "Targets:"
	@echo "  build                 build $(BUILD)/mips64rt with \$$(CC)"
	@echo "  build-cross           build static-PIE with \$$(CROSS_CC)"
	@echo "  check                 build + check-line-limits + self-checks"
	@echo "  check-line-limits     every .c/.h/.S under src/ is <= 900 lines"
	@echo "  check-abi-invariants  build+run tests/check_abi_invariants (lane L0b)"
	@echo "  clean                 remove $(BUILD)"

build: $(BUILD)/mips64rt

$(BUILD)/mips64rt: $(BOOT_SRCS) src/core/cpu.h src/os/syscall_nr.h
	@mkdir -p $(BUILD)
	$(CC) -static-pie -fPIE $(CFLAGS) $(INCLUDES) $(BOOT_SRCS) -o $@

build-cross:
	@mkdir -p $(BUILD)
	$(CROSS_CC) -static-pie -fPIE $(CFLAGS) $(INCLUDES) $(BOOT_SRCS) -o $(BUILD)/mips64rt-aarch64

check: build check-line-limits
	@$(CC) $(CFLAGS) $(INCLUDES) -fsyntax-only src/core/cpu.h src/os/syscall_nr.h
	@if [ "$$(uname -s)" = "Linux" ] && [ "$$(uname -m)" = "aarch64" ]; then \
		$(BUILD)/mips64rt --version; \
		$(BUILD)/mips64rt --help >/dev/null; \
	else \
		echo "check: skipping native --version/--help (host $$(uname -s)/$$(uname -m) cannot execute the aarch64-musl binary; use Docker)"; \
	fi
	@if [ -f tests/check_abi_invariants.c ]; then $(MAKE) check-abi-invariants; fi
	@if [ -f tests/test_decode.c ]; then \
		$(HOST_CC) -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Isrc tests/test_decode.c src/interp/decode.c src/os/mem.c -o $(BUILD)/test_decode && $(BUILD)/test_decode; \
	fi

check-line-limits:
	@fail=0; \
	for f in $$(find src -name '*.c' -o -name '*.h' -o -name '*.S'); do \
		n=$$(wc -l < "$$f"); \
		if [ "$$n" -gt 900 ]; then echo "OVER LIMIT ($$n): $$f"; fail=1; fi; \
	done; \
	if [ "$$fail" -ne 0 ]; then exit 1; fi; \
	echo "check-line-limits: all files <= 900 lines"

check-abi-invariants:
	@mkdir -p $(BUILD)
	$(HOST_CC) -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Isrc tests/check_abi_invariants.c -o $(BUILD)/check_abi_invariants
	$(BUILD)/check_abi_invariants

clean:
	rm -rf $(BUILD)
