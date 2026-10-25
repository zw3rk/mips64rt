# mips64rt Phase 0 build driver.
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0

.DEFAULT_GOAL := help

CC ?= cc
CROSS_CC ?= aarch64-unknown-linux-musl-gcc
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
	src/rt64/linux/signal_core.c

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
	$(CC) $(CFLAGS) $(INCLUDES) $(BOOT_SRCS) -o $@

build-cross:
	@mkdir -p $(BUILD)
	$(CROSS_CC) -static-pie -fPIE $(CFLAGS) $(INCLUDES) $(BOOT_SRCS) -o $(BUILD)/mips64rt-aarch64

check: build check-line-limits
	@$(CC) $(CFLAGS) $(INCLUDES) -fsyntax-only src/core/cpu.h src/os/syscall_nr.h
	@$(BUILD)/mips64rt --version
	@$(BUILD)/mips64rt --help >/dev/null
	@if [ -f tests/check_abi_invariants.c ]; then $(MAKE) check-abi-invariants; fi

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
	$(CC) $(CFLAGS) $(INCLUDES) tests/check_abi_invariants.c -o $(BUILD)/check_abi_invariants
	$(BUILD)/check_abi_invariants

clean:
	rm -rf $(BUILD)
