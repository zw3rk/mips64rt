/* ABI invariant suite: verifies every SPEC 2.1 mips64_ctx_t offset/size
 * (via the frozen MIPS64_CTX_*_OFFSET macros) and every
 * sigframe/ucontext/stat offset/size from experiments/E03/FINDINGS.md,
 * both at compile time (_Static_assert) and at runtime (printf per
 * check). Exit 0 only if all pass.
 *
 * Part of mips64rt, Apache-2.0, Copyright 2026 Moritz Angermann
 * <moritz@zw3rk.com>, zw3rk pte. ltd.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "core/cpu.h"
#include "os/sigframe_mips64rt.h"

static int failures = 0;
static int checks = 0;

#define CHECK_SIZE(type, want) do { \
		checks++; \
		if (sizeof(type) == (size_t)(want)) { \
			printf("ok: sizeof(%s) == %u\n", #type, (unsigned)(want)); \
		} else { \
			printf("FAIL: sizeof(%s) == %u, want %u\n", \
			    #type, (unsigned)sizeof(type), (unsigned)(want)); \
			failures++; \
		} \
	} while (0)

#define CHECK_OFF(type, member, want) do { \
		checks++; \
		if (offsetof(type, member) == (size_t)(want)) { \
			printf("ok: offsetof(%s, %s) == %u\n", \
			    #type, #member, (unsigned)(want)); \
		} else { \
			printf("FAIL: offsetof(%s, %s) == %u, want %u\n", \
			    #type, #member, \
			    (unsigned)offsetof(type, member), (unsigned)(want)); \
			failures++; \
		} \
	} while (0)

/* SPEC 2.1 mips64_ctx_t layout: the ABI-locked prefix ends at 0x260;
 * a C-only tail may follow (see src/core/cpu.h), so total sizeof is >=. */
_Static_assert(offsetof(mips64_ctx_t, fpr) + sizeof(((mips64_ctx_t *)0)->fpr) == 0x260,
    "locked prefix ends at 0x260");
_Static_assert(sizeof(mips64_ctx_t) >= 0x260, "ctx spans locked prefix");
_Static_assert(offsetof(mips64_ctx_t, gpr) == MIPS64_CTX_GPR_OFFSET, "gpr macro");
_Static_assert(offsetof(mips64_ctx_t, pc) == MIPS64_CTX_PC_OFFSET, "pc macro");
_Static_assert(offsetof(mips64_ctx_t, next_pc) == MIPS64_CTX_NEXT_PC_OFFSET, "next_pc macro");
_Static_assert(offsetof(mips64_ctx_t, hi) == MIPS64_CTX_HI_OFFSET, "hi macro");
_Static_assert(offsetof(mips64_ctx_t, lo) == MIPS64_CTX_LO_OFFSET, "lo macro");
_Static_assert(offsetof(mips64_ctx_t, ulr) == MIPS64_CTX_ULR_OFFSET, "ulr macro");
_Static_assert(offsetof(mips64_ctx_t, fcsr) == MIPS64_CTX_FCSR_OFFSET, "fcsr macro");
_Static_assert(offsetof(mips64_ctx_t, in_delay_slot) == MIPS64_CTX_IN_DELAY_SLOT_OFFSET, "ids macro");
_Static_assert(offsetof(mips64_ctx_t, fr_mode) == MIPS64_CTX_FR_MODE_OFFSET, "fr macro");
_Static_assert(offsetof(mips64_ctx_t, llbit) == MIPS64_CTX_LLBIT_OFFSET, "llbit macro");
_Static_assert(offsetof(mips64_ctx_t, nan2008) == MIPS64_CTX_NAN2008_OFFSET, "nan2008 macro");
_Static_assert(offsetof(mips64_ctx_t, lladdr) == MIPS64_CTX_LLADDR_OFFSET, "lladdr macro");
_Static_assert(offsetof(mips64_ctx_t, llval) == MIPS64_CTX_LLVAL_OFFSET, "llval macro");
_Static_assert(offsetof(mips64_ctx_t, is_be) == MIPS64_CTX_IS_BE_OFFSET, "is_be macro");
_Static_assert(offsetof(mips64_ctx_t, is_n32) == MIPS64_CTX_IS_N32_OFFSET, "is_n32 macro");
_Static_assert(offsetof(mips64_ctx_t, exit_reason) == MIPS64_CTX_EXIT_REASON_OFFSET, "exit macro");
_Static_assert(offsetof(mips64_ctx_t, exit_info) == MIPS64_CTX_EXIT_INFO_OFFSET, "info macro");
_Static_assert(offsetof(mips64_ctx_t, ibtc_ptr) == MIPS64_CTX_IBTC_PTR_OFFSET, "ibtc macro");
_Static_assert(offsetof(mips64_ctx_t, fpr) == MIPS64_CTX_FPR_OFFSET, "fpr macro");
_Static_assert(sizeof(((mips64_ctx_t *)0)->gpr) == 256, "gpr is 256 bytes");
_Static_assert(sizeof(((mips64_ctx_t *)0)->fpr) == 256, "fpr is 256 bytes");

/* Frozen UAPI sizes (E03 sections 3, 4, 7). */
_Static_assert(sizeof(mips64_n64_sigset_t) == 16, "N64 sigset 16");
_Static_assert(sizeof(mips64_n32_sigset_t) == 16, "N32 sigset 16");
_Static_assert(sizeof(mips64_siginfo_t) == 128, "siginfo 128");
_Static_assert(sizeof(mips64_n64_stack_t) == 24, "N64 stack 24");
_Static_assert(sizeof(mips64_n32_stack_t) == 12, "N32 stack 12");
_Static_assert(sizeof(mips64_n64_sigaction_t) == 32, "N64 sigaction 32");
_Static_assert(sizeof(mips64_n32_sigaction_t) == 24, "N32 sigaction 24");
_Static_assert(sizeof(mips64_sigcontext_t) == 600, "sigcontext 600");
_Static_assert(sizeof(mips64_mcontext_t) == 600, "mcontext 600");
_Static_assert(sizeof(mips64_n64_ucontext_t) == 656, "N64 ucontext 656");
_Static_assert(sizeof(mips64_n32_ucontext_t) == 640, "N32 ucontext 640");
_Static_assert(sizeof(mips64_n64_rt_sigframe_t) == 808, "N64 sigframe 808");
_Static_assert(sizeof(mips64_n32_rt_sigframe_t) == 792, "N32 sigframe 792");
_Static_assert(sizeof(mips64_n64_stat_t) == 104, "N64 stat 104");
_Static_assert(sizeof(mips64_n32_stat_t) == 144, "N32 stat 144");
_Static_assert(sizeof(mips64_n32_stat64_t) == 104, "N32 stat64 104");

int main(void)
{
	/* SPEC 2.1 context: locked prefix ends at 0x260, tail allowed. */
	checks++;
	if (offsetof(mips64_ctx_t, fpr) + sizeof(((mips64_ctx_t *)0)->fpr) == 0x260 &&
	    sizeof(mips64_ctx_t) >= 0x260) {
		printf("ok: locked ctx prefix ends at 0x260 (sizeof %u)\n",
		    (unsigned)sizeof(mips64_ctx_t));
	} else {
		printf("FAIL: ctx prefix end %u, sizeof %u, want prefix 0x260\n",
		    (unsigned)(offsetof(mips64_ctx_t, fpr) +
		    sizeof(((mips64_ctx_t *)0)->fpr)),
		    (unsigned)sizeof(mips64_ctx_t));
		failures++;
	}
	CHECK_OFF(mips64_ctx_t, gpr, MIPS64_CTX_GPR_OFFSET);
	CHECK_OFF(mips64_ctx_t, pc, MIPS64_CTX_PC_OFFSET);
	CHECK_OFF(mips64_ctx_t, next_pc, MIPS64_CTX_NEXT_PC_OFFSET);
	CHECK_OFF(mips64_ctx_t, hi, MIPS64_CTX_HI_OFFSET);
	CHECK_OFF(mips64_ctx_t, lo, MIPS64_CTX_LO_OFFSET);
	CHECK_OFF(mips64_ctx_t, ulr, MIPS64_CTX_ULR_OFFSET);
	CHECK_OFF(mips64_ctx_t, fcsr, MIPS64_CTX_FCSR_OFFSET);
	CHECK_OFF(mips64_ctx_t, in_delay_slot, MIPS64_CTX_IN_DELAY_SLOT_OFFSET);
	CHECK_OFF(mips64_ctx_t, fr_mode, MIPS64_CTX_FR_MODE_OFFSET);
	CHECK_OFF(mips64_ctx_t, llbit, MIPS64_CTX_LLBIT_OFFSET);
	CHECK_OFF(mips64_ctx_t, nan2008, MIPS64_CTX_NAN2008_OFFSET);
	CHECK_OFF(mips64_ctx_t, lladdr, MIPS64_CTX_LLADDR_OFFSET);
	CHECK_OFF(mips64_ctx_t, llval, MIPS64_CTX_LLVAL_OFFSET);
	CHECK_OFF(mips64_ctx_t, is_be, MIPS64_CTX_IS_BE_OFFSET);
	CHECK_OFF(mips64_ctx_t, is_n32, MIPS64_CTX_IS_N32_OFFSET);
	CHECK_OFF(mips64_ctx_t, exit_reason, MIPS64_CTX_EXIT_REASON_OFFSET);
	CHECK_OFF(mips64_ctx_t, exit_info, MIPS64_CTX_EXIT_INFO_OFFSET);
	CHECK_OFF(mips64_ctx_t, ibtc_ptr, MIPS64_CTX_IBTC_PTR_OFFSET);
	CHECK_OFF(mips64_ctx_t, fpr, MIPS64_CTX_FPR_OFFSET);
	checks++;
	if (sizeof(((mips64_ctx_t *)0)->gpr) == 256 &&
	    sizeof(((mips64_ctx_t *)0)->fpr) == 256) {
		printf("ok: gpr/fpr arrays are 256 bytes each\n");
	} else {
		printf("FAIL: gpr %u fpr %u, want 256/256\n",
		    (unsigned)sizeof(((mips64_ctx_t *)0)->gpr),
		    (unsigned)sizeof(((mips64_ctx_t *)0)->fpr));
		failures++;
	}

	/* Sigset / siginfo / stack / sigaction. */
	CHECK_SIZE(mips64_n64_sigset_t, MIPS64RT_SIGSETSIZE);
	CHECK_SIZE(mips64_n32_sigset_t, MIPS64RT_SIGSETSIZE);
	CHECK_SIZE(mips64_siginfo_t, 128);
	CHECK_OFF(mips64_siginfo_t, si_signo, 0);
	CHECK_OFF(mips64_siginfo_t, si_code, 4);
	CHECK_OFF(mips64_siginfo_t, si_errno, 8);
	CHECK_SIZE(mips64_n64_stack_t, 24);
	CHECK_OFF(mips64_n64_stack_t, ss_sp, 0);
	CHECK_OFF(mips64_n64_stack_t, ss_size, 8);
	CHECK_OFF(mips64_n64_stack_t, ss_flags, 16);
	CHECK_SIZE(mips64_n32_stack_t, 12);
	CHECK_OFF(mips64_n32_stack_t, ss_sp, 0);
	CHECK_OFF(mips64_n32_stack_t, ss_size, 4);
	CHECK_OFF(mips64_n32_stack_t, ss_flags, 8);
	CHECK_SIZE(mips64_n64_sigaction_t, 32);
	CHECK_OFF(mips64_n64_sigaction_t, sa_flags, 0);
	CHECK_OFF(mips64_n64_sigaction_t, sa_handler, 8);
	CHECK_OFF(mips64_n64_sigaction_t, sa_mask, 16);
	CHECK_SIZE(mips64_n32_sigaction_t, 24);
	CHECK_OFF(mips64_n32_sigaction_t, sa_flags, 0);
	CHECK_OFF(mips64_n32_sigaction_t, sa_handler, 4);
	CHECK_OFF(mips64_n32_sigaction_t, sa_mask, 8);

	/* Sigcontext / mcontext (E03 section 4; shared N64+N32, no sc_cause). */
	CHECK_SIZE(mips64_sigcontext_t, 600);
	CHECK_SIZE(mips64_mcontext_t, 600);
	CHECK_OFF(mips64_sigcontext_t, sc_regs, 0);
	CHECK_OFF(mips64_sigcontext_t, sc_fpregs, 256);
	CHECK_OFF(mips64_sigcontext_t, sc_mdhi, 512);
	CHECK_OFF(mips64_sigcontext_t, sc_hi1, 520);
	CHECK_OFF(mips64_sigcontext_t, sc_hi2, 528);
	CHECK_OFF(mips64_sigcontext_t, sc_hi3, 536);
	CHECK_OFF(mips64_sigcontext_t, sc_mdlo, 544);
	CHECK_OFF(mips64_sigcontext_t, sc_lo1, 552);
	CHECK_OFF(mips64_sigcontext_t, sc_lo2, 560);
	CHECK_OFF(mips64_sigcontext_t, sc_lo3, 568);
	CHECK_OFF(mips64_sigcontext_t, sc_pc, 576);
	CHECK_OFF(mips64_sigcontext_t, sc_fpc_csr, 584);
	CHECK_OFF(mips64_sigcontext_t, sc_used_math, 588);
	CHECK_OFF(mips64_sigcontext_t, sc_dsp, 592);
	CHECK_OFF(mips64_sigcontext_t, sc_reserved, 596);

	/* Kernel ucontext (E03 section 7). */
	CHECK_SIZE(mips64_n64_ucontext_t, 656);
	CHECK_OFF(mips64_n64_ucontext_t, uc_flags, 0);
	CHECK_OFF(mips64_n64_ucontext_t, uc_link, 8);
	CHECK_OFF(mips64_n64_ucontext_t, uc_stack, 16);
	CHECK_OFF(mips64_n64_ucontext_t, uc_mcontext, 40);
	CHECK_OFF(mips64_n64_ucontext_t, uc_sigmask, 640);
	CHECK_SIZE(mips64_n32_ucontext_t, 640);
	CHECK_OFF(mips64_n32_ucontext_t, uc_flags, 0);
	CHECK_OFF(mips64_n32_ucontext_t, uc_link, 4);
	CHECK_OFF(mips64_n32_ucontext_t, uc_stack, 8);
	CHECK_OFF(mips64_n32_ucontext_t, uc_mcontext, 24);
	CHECK_OFF(mips64_n32_ucontext_t, uc_sigmask, 624);

	/* rt_sigframe (kernel signal.c; UNVERIFIED by execution). */
	CHECK_SIZE(mips64_n64_rt_sigframe_t, 808);
	CHECK_OFF(mips64_n64_rt_sigframe_t, rs_ass, 0);
	CHECK_OFF(mips64_n64_rt_sigframe_t, rs_pad, 16);
	CHECK_OFF(mips64_n64_rt_sigframe_t, rs_info, 24);
	CHECK_OFF(mips64_n64_rt_sigframe_t, rs_uc, 152);
	CHECK_SIZE(mips64_n32_rt_sigframe_t, 792);
	CHECK_OFF(mips64_n32_rt_sigframe_t, rs_ass, 0);
	CHECK_OFF(mips64_n32_rt_sigframe_t, rs_pad, 16);
	CHECK_OFF(mips64_n32_rt_sigframe_t, rs_info, 24);
	CHECK_OFF(mips64_n32_rt_sigframe_t, rs_uc, 152);

	/* Kernel stat (asm/stat.h UAPI). */
	CHECK_SIZE(mips64_n64_stat_t, 104);
	CHECK_OFF(mips64_n64_stat_t, st_dev, 0);
	CHECK_OFF(mips64_n64_stat_t, st_ino, 16);
	CHECK_OFF(mips64_n64_stat_t, st_mode, 24);
	CHECK_OFF(mips64_n64_stat_t, st_nlink, 28);
	CHECK_OFF(mips64_n64_stat_t, st_uid, 32);
	CHECK_OFF(mips64_n64_stat_t, st_gid, 36);
	CHECK_OFF(mips64_n64_stat_t, st_rdev, 40);
	CHECK_OFF(mips64_n64_stat_t, st_size, 56);
	CHECK_OFF(mips64_n64_stat_t, st_atime, 64);
	CHECK_OFF(mips64_n64_stat_t, st_blksize, 88);
	CHECK_OFF(mips64_n64_stat_t, st_blocks, 96);
	CHECK_SIZE(mips64_n32_stat_t, 144);
	CHECK_OFF(mips64_n32_stat_t, st_dev, 0);
	CHECK_OFF(mips64_n32_stat_t, st_ino, 16);
	CHECK_OFF(mips64_n32_stat_t, st_mode, 20);
	CHECK_OFF(mips64_n32_stat_t, st_nlink, 24);
	CHECK_OFF(mips64_n32_stat_t, st_uid, 28);
	CHECK_OFF(mips64_n32_stat_t, st_gid, 32);
	CHECK_OFF(mips64_n32_stat_t, st_rdev, 36);
	CHECK_OFF(mips64_n32_stat_t, st_size, 48);
	CHECK_OFF(mips64_n32_stat_t, st_atime, 56);
	CHECK_OFF(mips64_n32_stat_t, st_blksize, 80);
	CHECK_OFF(mips64_n32_stat_t, st_blocks, 84);
	CHECK_SIZE(mips64_n32_stat64_t, 104);
	CHECK_OFF(mips64_n32_stat64_t, st_dev, 0);
	CHECK_OFF(mips64_n32_stat64_t, st_ino, 16);
	CHECK_OFF(mips64_n32_stat64_t, st_mode, 24);
	CHECK_OFF(mips64_n32_stat64_t, st_nlink, 28);
	CHECK_OFF(mips64_n32_stat64_t, st_uid, 32);
	CHECK_OFF(mips64_n32_stat64_t, st_gid, 36);
	CHECK_OFF(mips64_n32_stat64_t, st_size, 56);
	CHECK_OFF(mips64_n32_stat64_t, st_blksize, 88);
	CHECK_OFF(mips64_n32_stat64_t, st_blocks, 96);

	printf("%d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
