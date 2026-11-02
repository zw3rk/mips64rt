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
CFLAGS := -O2 -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -pthread
INCLUDES := -Isrc
BUILD := _build

# Phase 2 binary: CLI + engine dispatch + interp + AArch64 DBT.
# RC2 integration wires the L2a static-libc layer, the L2b DBT core
# (encoder, dispatcher, trampoline) and the L2c integer emitter.
# RC3 integration adds the L3a FPU interpreter and L3b FP emitter.
# RC4 integration adds the L4a signal, L4b thread/futex, L4c exec seams.
# RC6 integration adds the L6a host-contract surface (arg parsing) and
# the Class-B cache/family providers it consumes (digest, leaf,
# broker rendezvous).
# Unified U0+U12: exactly one OS backend links into the binary (U0),
# and the AOT digest/identity TUs live under `src/dbt/aot/` with the
# host-contract runtime TUs under `src/os/` (U12, no `src/rt64/`).
# The backend follows the compiler TARGET triple, never the build
# host: a Linux cross build on macOS must link the Linux backend.
OS_BACKEND := src/os/backend_linux.c
ifeq ($(findstring darwin,$(shell $(CC) -dumpmachine 2>/dev/null)),darwin)
OS_BACKEND := src/os/backend_darwin.c
endif
HOST_BACKEND := src/os/backend_linux.c
ifeq ($(findstring darwin,$(shell $(HOST_CC) -dumpmachine 2>/dev/null)),darwin)
HOST_BACKEND := src/os/backend_darwin.c
endif
BOOT_COMMON := src/main.c \
	src/os/host_args.c \
	src/dbt/aot/sha256.c \
	src/dbt/aot/identity.c \
	src/dbt/aot/sites.c \
	src/os/family_broker.c \
	src/os/worker_loop.c \
	src/os/signal_core.c \
	src/interp/decode.c \
	src/interp/interp.c \
	src/interp/unaligned.c \
	src/interp/fpmove.c \
	src/interp/fp.c \
	src/interp/fp_cvt.c \
	src/interp/fp_ps.c \
	src/os/mem.c \
	src/os/mem_table.c \
	src/os/backend_state.c \
	src/os/proc.c \
	src/os/syscall_min.c \
	src/os/syscalls.c \
	src/os/syscalls_extra.c \
	src/os/syscalls_stat.c \
	src/os/syscalls_sync.c \
	src/os/syscalls_time.c \
	src/os/sigact.c \
	src/os/sigframe.c \
	src/os/threads.c \
	src/os/futex.c \
	src/os/exec.c \
	src/os/quiesce.c \
	src/vm/vm64.c \
	src/vm/vm_file.c \
	src/vm/vm_pages.c \
	src/dbt/a64_emit.c \
	src/dbt/dbt.c \
	src/dbt/arena.c \
	src/dbt/mem_recover.c \
	src/dbt/emit_int.c \
	src/dbt/emit_enc.c \
	src/dbt/emit_alu.c \
	src/dbt/emit_mem.c \
	src/dbt/emit_fpmem.c \
	src/dbt/emit_fp.c \
	src/dbt/trampoline_a64.S \
	src/loader.c
# Each artifact links the backend matching the compiler that builds
# it: the cross/static-PIE binary uses OS_BACKEND (selected from CC),
# the host-native Darwin binary uses HOST_BACKEND (from HOST_CC).
BOOT_SRCS := $(BOOT_COMMON) $(OS_BACKEND)
DARWIN_SRCS := $(BOOT_COMMON) $(HOST_BACKEND)

.PHONY: help build build-cross build-darwin check check-line-limits check-abi-invariants clean

help:
	@echo "Targets:"
	@echo "  build                 build $(BUILD)/mips64rt with \$$(CC)"
	@echo "  build-cross           build static-PIE with \$$(CROSS_CC)"
	@echo "  build-darwin          build $(BUILD)/mips64rt-darwin + test_u0_delay_tlb with \$$(HOST_CC) (no -static-pie)"
	@echo "  check                 build + check-line-limits + self-checks"
	@echo "  check-line-limits     every .c/.h/.S under src/ is <= 900 lines"
	@echo "  check-abi-invariants  build+run tests/check_abi_invariants (lane L0b)"
	@echo "  clean                 remove $(BUILD)"

build: $(BUILD)/mips64rt

$(BUILD)/mips64rt: $(BOOT_SRCS) src/core/cpu.h src/os/syscall_nr.h src/os/host_compat.h src/dbt/emit_mem.h
	@mkdir -p $(BUILD)
	$(CC) -static-pie -fPIE $(CFLAGS) $(INCLUDES) $(BOOT_SRCS) -o $@

build-cross:
	@mkdir -p $(BUILD)
	$(CROSS_CC) -static-pie -fPIE $(CFLAGS) $(INCLUDES) $(BOOT_SRCS) -o $(BUILD)/mips64rt-aarch64

# Lane L-U0-C: native host build of the delay-slot + TIF_FIXADE
# prototype gate (no cross toolchain, no guest execution; the DBT
# words are asserted structurally, never executed).
U0_SRCS := tests/test_u0_delay_tlb.c \
	src/os/mem.c \
	src/os/mem_table.c \
	src/os/backend_state.c \
	src/os/quiesce.c \
	src/os/signal_core.c \
	$(HOST_BACKEND) \
	src/vm/vm64.c \
	src/vm/vm_file.c \
	src/vm/vm_pages.c \
	src/dbt/aot/sites.c \
	src/interp/decode.c \
	src/dbt/a64_emit.c \
	src/dbt/emit_enc.c \
	src/dbt/emit_alu.c \
	src/dbt/emit_mem.c \
	src/dbt/emit_fpmem.c \
	src/dbt/emit_int.c \
	src/dbt/emit_fp.c \
	src/dbt/arena.c \
	src/dbt/dbt.c \
	src/dbt/mem_recover.c \
	src/dbt/trampoline_a64.S

# Fill-and-retry regression gate: same TU list as the U0 gate with
# the fill_retry driver swapped in.
FILL_SRCS := tests/test_u0_fill_retry.c \
	$(filter-out tests/test_u0_delay_tlb.c,$(U0_SRCS))

# Write-gate + Provider A gate: the U0 TU set plus the real
# interpreter core (the gate test single-steps through recover with
# interp_step, so the interp stubs used elsewhere will not do).
GATE_SRCS := tests/test_u0_gate.c \
	$(filter-out tests/test_u0_delay_tlb.c,$(U0_SRCS)) \
	src/interp/interp.c \
	src/interp/unaligned.c \
	src/interp/fpmove.c \
	src/interp/fp.c \
	src/interp/fp_cvt.c \
	src/interp/fp_ps.c

# Wave P12: focused GPR-cache regression gate (host-native; same TU as
# the U0 gate with the driver swapped, so it links the real emitter).
GPR_SRCS := tests/test_gpr_cache.c \
	$(filter-out tests/test_u0_delay_tlb.c,$(U0_SRCS))

# Wave P13: focused FPR-cache regression gate (host-native; same TU as
# the GPR gate with the driver swapped, so it links the real emitter).
FPR_SRCS := tests/test_fpr_cache.c \
	$(filter-out tests/test_u0_delay_tlb.c,$(U0_SRCS))

# Lane U12: host-native sibling of `build` for macOS/Apple Silicon.
# Same TU list, host C compiler, PIE without `-static-pie` (the macOS
# linker rejects it). AArch64-only (the trampoline is A64 assembly).
build-darwin: $(BUILD)/mips64rt-darwin $(BUILD)/test_u0_delay_tlb $(BUILD)/test_u0_fill_retry $(BUILD)/test_u0_gate $(BUILD)/test_gpr_cache $(BUILD)/test_fpr_cache

$(BUILD)/mips64rt-darwin: $(DARWIN_SRCS) src/core/cpu.h src/os/syscall_nr.h src/os/host_compat.h src/dbt/emit_mem.h
	@mkdir -p $(BUILD)
	$(HOST_CC) -fPIE $(CFLAGS) $(INCLUDES) $(DARWIN_SRCS) -o $@

$(BUILD)/test_u0_delay_tlb: $(U0_SRCS) src/core/cpu.h src/os/backend.h src/vm/vm64.h src/vm/vm_file.h src/dbt/dbt.h
	@mkdir -p $(BUILD)
	$(HOST_CC) -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -pthread $(INCLUDES) $(U0_SRCS) -o $@

$(BUILD)/test_u0_fill_retry: $(FILL_SRCS) src/core/cpu.h src/os/backend.h src/vm/vm64.h src/vm/vm_file.h src/dbt/dbt.h
	@mkdir -p $(BUILD)
	$(HOST_CC) -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -pthread $(INCLUDES) $(FILL_SRCS) -o $@

$(BUILD)/test_u0_gate: $(GATE_SRCS) src/core/cpu.h src/os/backend.h src/vm/vm64.h src/vm/vm_file.h src/vm/vm_pages.h src/dbt/dbt.h
	@mkdir -p $(BUILD)
	$(HOST_CC) -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -pthread $(INCLUDES) $(GATE_SRCS) -o $@

$(BUILD)/test_gpr_cache: $(GPR_SRCS) src/core/cpu.h src/os/backend.h src/vm/vm64.h src/vm/vm_file.h src/dbt/dbt.h
	@mkdir -p $(BUILD)
	$(HOST_CC) -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -pthread $(INCLUDES) $(GPR_SRCS) -o $@
	$(BUILD)/test_gpr_cache

$(BUILD)/test_fpr_cache: $(FPR_SRCS) src/core/cpu.h src/os/backend.h src/vm/vm64.h src/vm/vm_file.h src/dbt/dbt.h
	@mkdir -p $(BUILD)
	$(HOST_CC) -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -pthread $(INCLUDES) $(FPR_SRCS) -o $@
	$(BUILD)/test_fpr_cache

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
		$(HOST_CC) -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -pthread -Isrc tests/test_decode.c src/interp/decode.c src/os/mem.c src/os/mem_table.c src/os/backend_state.c src/vm/vm_pages.c $(HOST_BACKEND) tests/stubs_signal.c -o $(BUILD)/test_decode && $(BUILD)/test_decode; \
	fi

check-line-limits:
	@fail=0; \
	for f in $$(find src tests -name '*.c' -o -name '*.h' -o -name '*.S'); do \
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
