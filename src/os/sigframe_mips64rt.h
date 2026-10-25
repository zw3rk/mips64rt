/* Frozen target N64/N32 Linux UAPI signal-frame types for mips64rt.
 *
 * Models the MIPS64 kernel ABI (arch/mips/include/uapi/asm/):
 * N64: 808-byte rt_sigframe (24-byte trampoline prefix, 128-byte
 * siginfo_t, 656-byte kernel ucontext holding the 600-byte sigcontext);
 * N32: 792-byte rt_sigframe (same prefix, 128-byte siginfo_t, 640-byte
 * kernel ucontext holding the same 600-byte sigcontext); 16-byte kernel
 * sigset_t on both ABIs (_NSIG=128, sigsetsize=16); plus the 104-byte
 * N64 kernel stat and the 144-byte N32 kernel stat (with the 104-byte
 * N32 stat64). The ABI64/N32 sigcontext is sc_regs/sc_fpregs/sc_mdhi/
 * sc_hi1..3/sc_mdlo/sc_lo1..3/sc_pc/sc_fpc_csr/sc_used_math/sc_dsp/
 * sc_reserved: there is NO sc_cause field on MIPS64 (the O32-only
 * sc_cause slot is sc_hi1 here).
 *
 * Ground truth: N64 sizes/offsets executed under qemu-mips64el
 * (Debian gcc 14.2.0, qemu 10.0.13); N32 sizes/offsets compile-verified
 * with the mips64el cross-CC (-mabi=n32) against the installed 6.12
 * UAPI headers (this toolchain cannot statically link N32, so the N32
 * probe was not executed); the rt_sigframe trampoline prefix matches
 * arch/mips/kernel/signal.c (setup_rt_sigframe).
 *
 * NOTE: the kernel rt_sigframe reconstruction itself was NOT observed
 * at runtime (qemu-user cannot execute kernel signal.c); it is derived
 * from the installed UAPI headers plus signal.c, as with O32.
 *
 * Part of mips64rt, Apache-2.0, Copyright 2026 Moritz Angermann
 * <moritz@zw3rk.com>, zw3rk pte. ltd.
 */
#ifndef SIGFRAME_MIPS64RT_H
#define SIGFRAME_MIPS64RT_H

#include <stddef.h>
#include <stdint.h>

/* 128 signals on both ABIs; the KERNEL mask is 16 bytes (never the
 * 128-byte glibc sigset_t). rt_sigprocmask rejects any sigsetsize
 * other than 16 with EINVAL on N64 and N32 alike. */
#define MIPS64RT_NSIG 128
#define MIPS64RT_SIGSETSIZE 16

/* Kernel sigset_t N64: _NSIG_WORDS x 8 = 16 bytes. */
typedef struct {
	uint64_t sig[2];
} mips64_n64_sigset_t;

_Static_assert(sizeof(mips64_n64_sigset_t) == 16, "N64 kernel sigset_t must be 16 bytes");
_Static_assert(offsetof(mips64_n64_sigset_t, sig) == 0, "sig word array at 0");

/* Kernel sigset_t N32: _NSIG_WORDS x 4 = 16 bytes. */
typedef struct {
	uint32_t sig[4];
} mips64_n32_sigset_t;

_Static_assert(sizeof(mips64_n32_sigset_t) == 16, "N32 kernel sigset_t must be 16 bytes");
_Static_assert(offsetof(mips64_n32_sigset_t, sig) == 0, "sig word array at 0");

/* Kernel siginfo_t: 128 bytes, signo@0 code@4 errno@8, identical on
 * N64 and N32. si_code comes BEFORE si_errno. */
typedef struct {
	int32_t si_signo;
	int32_t si_code;
	int32_t si_errno;
	uint8_t sifields[116];
} mips64_siginfo_t;

_Static_assert(sizeof(mips64_siginfo_t) == 128, "siginfo_t must be 128 bytes");
_Static_assert(offsetof(mips64_siginfo_t, si_signo) == 0, "si_signo at 0");
_Static_assert(offsetof(mips64_siginfo_t, si_code) == 4, "si_code at 4");
_Static_assert(offsetof(mips64_siginfo_t, si_errno) == 8, "si_errno at 8");

/* Kernel stack_t N64: 24 bytes, sp@0 size@8 flags@16. */
typedef struct {
	uint64_t ss_sp;
	uint64_t ss_size;
	int32_t ss_flags;
	uint32_t ss_pad;
} mips64_n64_stack_t;

_Static_assert(sizeof(mips64_n64_stack_t) == 24, "N64 stack_t must be 24 bytes");
_Static_assert(offsetof(mips64_n64_stack_t, ss_sp) == 0, "ss_sp at 0");
_Static_assert(offsetof(mips64_n64_stack_t, ss_size) == 8, "ss_size at 8");
_Static_assert(offsetof(mips64_n64_stack_t, ss_flags) == 16, "ss_flags at 16");

/* Kernel stack_t N32: 12 bytes, sp@0 size@4 flags@8. */
typedef struct {
	uint32_t ss_sp;
	uint32_t ss_size;
	int32_t ss_flags;
} mips64_n32_stack_t;

_Static_assert(sizeof(mips64_n32_stack_t) == 12, "N32 stack_t must be 12 bytes");
_Static_assert(offsetof(mips64_n32_stack_t, ss_sp) == 0, "ss_sp at 0");
_Static_assert(offsetof(mips64_n32_stack_t, ss_size) == 4, "ss_size at 4");
_Static_assert(offsetof(mips64_n32_stack_t, ss_flags) == 8, "ss_flags at 8");

/* Kernel struct sigaction N64: 32 bytes, flags@0 handler@8 mask@16. */
typedef struct {
	uint32_t sa_flags;
	uint32_t sa_pad;
	uint64_t sa_handler;
	mips64_n64_sigset_t sa_mask;
} mips64_n64_sigaction_t;

_Static_assert(sizeof(mips64_n64_sigaction_t) == 32, "N64 sigaction must be 32 bytes");
_Static_assert(offsetof(mips64_n64_sigaction_t, sa_flags) == 0, "sa_flags at 0");
_Static_assert(offsetof(mips64_n64_sigaction_t, sa_handler) == 8, "sa_handler at 8");
_Static_assert(offsetof(mips64_n64_sigaction_t, sa_mask) == 16, "sa_mask at 16");

/* Kernel struct sigaction N32: 24 bytes, flags@0 handler@4 mask@8. */
typedef struct {
	uint32_t sa_flags;
	uint32_t sa_handler;
	mips64_n32_sigset_t sa_mask;
} mips64_n32_sigaction_t;

_Static_assert(sizeof(mips64_n32_sigaction_t) == 24, "N32 sigaction must be 24 bytes");
_Static_assert(offsetof(mips64_n32_sigaction_t, sa_flags) == 0, "sa_flags at 0");
_Static_assert(offsetof(mips64_n32_sigaction_t, sa_handler) == 4, "sa_handler at 4");
_Static_assert(offsetof(mips64_n32_sigaction_t, sa_mask) == 8, "sa_mask at 8");

/* ABI64/N32 sigcontext (= mcontext layout): 600 bytes, shared by N64
 * and N32. sc_regs and sc_fpregs use 64-bit slots on both ABIs.
 * There is NO sc_cause field: the old O32 sc_cause slot is sc_hi1. */
typedef struct {
	uint64_t sc_regs[32];
	uint64_t sc_fpregs[32];
	uint64_t sc_mdhi;
	uint64_t sc_hi1;
	uint64_t sc_hi2;
	uint64_t sc_hi3;
	uint64_t sc_mdlo;
	uint64_t sc_lo1;
	uint64_t sc_lo2;
	uint64_t sc_lo3;
	uint64_t sc_pc;
	uint32_t sc_fpc_csr;
	uint32_t sc_used_math;
	uint32_t sc_dsp;
	uint32_t sc_reserved;
} mips64_sigcontext_t;

typedef mips64_sigcontext_t mips64_mcontext_t;

_Static_assert(sizeof(mips64_sigcontext_t) == 600, "sigcontext must be 600 bytes");
_Static_assert(sizeof(mips64_mcontext_t) == 600, "mcontext must be 600 bytes");
_Static_assert(offsetof(mips64_sigcontext_t, sc_regs) == 0, "sc_regs at 0");
_Static_assert(offsetof(mips64_sigcontext_t, sc_fpregs) == 256, "sc_fpregs at 256");
_Static_assert(offsetof(mips64_sigcontext_t, sc_mdhi) == 512, "sc_mdhi at 512");
_Static_assert(offsetof(mips64_sigcontext_t, sc_hi1) == 520, "sc_hi1 at 520 (was O32 sc_cause)");
_Static_assert(offsetof(mips64_sigcontext_t, sc_hi2) == 528, "sc_hi2 at 528");
_Static_assert(offsetof(mips64_sigcontext_t, sc_hi3) == 536, "sc_hi3 at 536");
_Static_assert(offsetof(mips64_sigcontext_t, sc_mdlo) == 544, "sc_mdlo at 544");
_Static_assert(offsetof(mips64_sigcontext_t, sc_lo1) == 552, "sc_lo1 at 552");
_Static_assert(offsetof(mips64_sigcontext_t, sc_lo2) == 560, "sc_lo2 at 560");
_Static_assert(offsetof(mips64_sigcontext_t, sc_lo3) == 568, "sc_lo3 at 568");
_Static_assert(offsetof(mips64_sigcontext_t, sc_pc) == 576, "sc_pc at 576");
_Static_assert(offsetof(mips64_sigcontext_t, sc_fpc_csr) == 584, "sc_fpc_csr at 584");
_Static_assert(offsetof(mips64_sigcontext_t, sc_used_math) == 588, "sc_used_math at 588");
_Static_assert(offsetof(mips64_sigcontext_t, sc_dsp) == 592, "sc_dsp at 592");
_Static_assert(offsetof(mips64_sigcontext_t, sc_reserved) == 596, "sc_reserved at 596");

/* Kernel struct ucontext N64: 656 bytes, flags@0 link@8 stack@16
 * mcontext@40 sigmask@640. */
typedef struct {
	uint64_t uc_flags;
	uint64_t uc_link;
	mips64_n64_stack_t uc_stack;
	mips64_sigcontext_t uc_mcontext;
	mips64_n64_sigset_t uc_sigmask;
} mips64_n64_ucontext_t;

_Static_assert(sizeof(mips64_n64_ucontext_t) == 656, "N64 kernel ucontext must be 656 bytes");
_Static_assert(offsetof(mips64_n64_ucontext_t, uc_flags) == 0, "uc_flags at 0");
_Static_assert(offsetof(mips64_n64_ucontext_t, uc_link) == 8, "uc_link at 8");
_Static_assert(offsetof(mips64_n64_ucontext_t, uc_stack) == 16, "uc_stack at 16");
_Static_assert(offsetof(mips64_n64_ucontext_t, uc_mcontext) == 40, "uc_mcontext at 40");
_Static_assert(offsetof(mips64_n64_ucontext_t, uc_sigmask) == 640, "uc_sigmask at 640");

/* Kernel struct ucontext N32: 640 bytes, flags@0 link@4 stack@8
 * mcontext@24 sigmask@624. The 12-byte stack_t needs 8-byte alignment
 * for the 600-byte sigcontext, so a 4-byte pad follows it. */
typedef struct {
	uint32_t uc_flags;
	uint32_t uc_link;
	mips64_n32_stack_t uc_stack;
	uint32_t uc_pad;
	mips64_sigcontext_t uc_mcontext;
	mips64_n32_sigset_t uc_sigmask;
} mips64_n32_ucontext_t;

_Static_assert(sizeof(mips64_n32_ucontext_t) == 640, "N32 kernel ucontext must be 640 bytes");
_Static_assert(offsetof(mips64_n32_ucontext_t, uc_flags) == 0, "uc_flags at 0");
_Static_assert(offsetof(mips64_n32_ucontext_t, uc_link) == 4, "uc_link at 4");
_Static_assert(offsetof(mips64_n32_ucontext_t, uc_stack) == 8, "uc_stack at 8");
_Static_assert(offsetof(mips64_n32_ucontext_t, uc_mcontext) == 24, "uc_mcontext at 24");
_Static_assert(offsetof(mips64_n32_ucontext_t, uc_sigmask) == 624, "uc_sigmask at 624");

/* Kernel rt_sigframe N64: 808 bytes (prefix + siginfo + ucontext).
 * The 24-byte prefix is shared with the O32 frame; rs_info sits at 24
 * and the ucontext at 152, both 8-byte aligned. Reconstruction from
 * arch/mips/kernel/signal.c, NOT observed at runtime. */
typedef struct {
	uint32_t rs_ass[4];
	uint32_t rs_pad[2];
	mips64_siginfo_t rs_info;
	mips64_n64_ucontext_t rs_uc;
} mips64_n64_rt_sigframe_t;

_Static_assert(sizeof(mips64_n64_rt_sigframe_t) == 808, "N64 rt_sigframe must be 808 bytes");
_Static_assert(offsetof(mips64_n64_rt_sigframe_t, rs_ass) == 0, "rs_ass at 0");
_Static_assert(offsetof(mips64_n64_rt_sigframe_t, rs_pad) == 16, "rs_pad at 16");
_Static_assert(offsetof(mips64_n64_rt_sigframe_t, rs_info) == 24, "rs_info at 24");
_Static_assert(offsetof(mips64_n64_rt_sigframe_t, rs_uc) == 152, "rs_uc at 152");

/* Kernel rt_sigframe N32: 792 bytes (prefix + siginfo + ucontext).
 * Reconstruction from arch/mips/kernel/signal.c, NOT observed at
 * runtime. */
typedef struct {
	uint32_t rs_ass[4];
	uint32_t rs_pad[2];
	mips64_siginfo_t rs_info;
	mips64_n32_ucontext_t rs_uc;
} mips64_n32_rt_sigframe_t;

_Static_assert(sizeof(mips64_n32_rt_sigframe_t) == 792, "N32 rt_sigframe must be 792 bytes");
_Static_assert(offsetof(mips64_n32_rt_sigframe_t, rs_ass) == 0, "rs_ass at 0");
_Static_assert(offsetof(mips64_n32_rt_sigframe_t, rs_pad) == 16, "rs_pad at 16");
_Static_assert(offsetof(mips64_n32_rt_sigframe_t, rs_info) == 24, "rs_info at 24");
_Static_assert(offsetof(mips64_n32_rt_sigframe_t, rs_uc) == 152, "rs_uc at 152");

/* Kernel UAPI struct stat (asm/stat.h, _MIPS_SIM_ABI64): 104 bytes.
 * The memory layout is the same as struct stat64 of the 32-bit kernel. */
typedef struct {
	uint32_t st_dev;
	uint32_t st_pad0[3];
	uint64_t st_ino;
	uint32_t st_mode;
	uint32_t st_nlink;
	uint32_t st_uid;
	uint32_t st_gid;
	uint32_t st_rdev;
	uint32_t st_pad1[3];
	int64_t st_size;
	uint32_t st_atime;
	uint32_t st_atime_nsec;
	uint32_t st_mtime;
	uint32_t st_mtime_nsec;
	uint32_t st_ctime;
	uint32_t st_ctime_nsec;
	uint32_t st_blksize;
	uint32_t st_pad2;
	uint64_t st_blocks;
} mips64_n64_stat_t;

_Static_assert(sizeof(mips64_n64_stat_t) == 104, "N64 kernel stat must be 104 bytes");
_Static_assert(offsetof(mips64_n64_stat_t, st_dev) == 0, "st_dev at 0");
_Static_assert(offsetof(mips64_n64_stat_t, st_ino) == 16, "st_ino at 16");
_Static_assert(offsetof(mips64_n64_stat_t, st_mode) == 24, "st_mode at 24");
_Static_assert(offsetof(mips64_n64_stat_t, st_nlink) == 28, "st_nlink at 28");
_Static_assert(offsetof(mips64_n64_stat_t, st_uid) == 32, "st_uid at 32");
_Static_assert(offsetof(mips64_n64_stat_t, st_gid) == 36, "st_gid at 36");
_Static_assert(offsetof(mips64_n64_stat_t, st_rdev) == 40, "st_rdev at 40");
_Static_assert(offsetof(mips64_n64_stat_t, st_size) == 56, "st_size at 56");
_Static_assert(offsetof(mips64_n64_stat_t, st_atime) == 64, "st_atime at 64");
_Static_assert(offsetof(mips64_n64_stat_t, st_blksize) == 88, "st_blksize at 88");
_Static_assert(offsetof(mips64_n64_stat_t, st_blocks) == 96, "st_blocks at 96");

/* Kernel UAPI struct stat (asm/stat.h, _MIPS_SIM_NABI32): 144 bytes.
 * long is 32 bits here; st_ino stays 32 bits on N32. */
typedef struct {
	uint32_t st_dev;
	uint32_t st_pad1[3];
	uint32_t st_ino;
	uint32_t st_mode;
	uint32_t st_nlink;
	uint32_t st_uid;
	uint32_t st_gid;
	uint32_t st_rdev;
	uint32_t st_pad2[2];
	int32_t st_size;
	int32_t st_pad3;
	int32_t st_atime;
	uint32_t st_atime_nsec;
	int32_t st_mtime;
	uint32_t st_mtime_nsec;
	int32_t st_ctime;
	uint32_t st_ctime_nsec;
	int32_t st_blksize;
	int32_t st_blocks;
	int32_t st_pad4[14];
} mips64_n32_stat_t;

_Static_assert(sizeof(mips64_n32_stat_t) == 144, "N32 kernel stat must be 144 bytes");
_Static_assert(offsetof(mips64_n32_stat_t, st_dev) == 0, "st_dev at 0");
_Static_assert(offsetof(mips64_n32_stat_t, st_ino) == 16, "st_ino at 16");
_Static_assert(offsetof(mips64_n32_stat_t, st_mode) == 20, "st_mode at 20");
_Static_assert(offsetof(mips64_n32_stat_t, st_nlink) == 24, "st_nlink at 24");
_Static_assert(offsetof(mips64_n32_stat_t, st_uid) == 28, "st_uid at 28");
_Static_assert(offsetof(mips64_n32_stat_t, st_gid) == 32, "st_gid at 32");
_Static_assert(offsetof(mips64_n32_stat_t, st_rdev) == 36, "st_rdev at 36");
_Static_assert(offsetof(mips64_n32_stat_t, st_size) == 48, "st_size at 48");
_Static_assert(offsetof(mips64_n32_stat_t, st_atime) == 56, "st_atime at 56");
_Static_assert(offsetof(mips64_n32_stat_t, st_blksize) == 80, "st_blksize at 80");
_Static_assert(offsetof(mips64_n32_stat_t, st_blocks) == 84, "st_blocks at 84");

/* Kernel UAPI struct stat64 (asm/stat.h, N32 only): 104 bytes. This is
 * the layout the N32 stat64/lstat64/fstat64 syscalls fill. */
typedef struct {
	uint32_t st_dev;
	uint32_t st_pad0[3];
	uint64_t st_ino;
	uint32_t st_mode;
	uint32_t st_nlink;
	uint32_t st_uid;
	uint32_t st_gid;
	uint32_t st_rdev;
	uint32_t st_pad1[3];
	int64_t st_size;
	int32_t st_atime;
	uint32_t st_atime_nsec;
	int32_t st_mtime;
	uint32_t st_mtime_nsec;
	int32_t st_ctime;
	uint32_t st_ctime_nsec;
	uint32_t st_blksize;
	uint32_t st_pad2;
	int64_t st_blocks;
} mips64_n32_stat64_t;

_Static_assert(sizeof(mips64_n32_stat64_t) == 104, "N32 kernel stat64 must be 104 bytes");
_Static_assert(offsetof(mips64_n32_stat64_t, st_dev) == 0, "st_dev at 0");
_Static_assert(offsetof(mips64_n32_stat64_t, st_ino) == 16, "st_ino at 16");
_Static_assert(offsetof(mips64_n32_stat64_t, st_mode) == 24, "st_mode at 24");
_Static_assert(offsetof(mips64_n32_stat64_t, st_nlink) == 28, "st_nlink at 28");
_Static_assert(offsetof(mips64_n32_stat64_t, st_uid) == 32, "st_uid at 32");
_Static_assert(offsetof(mips64_n32_stat64_t, st_gid) == 36, "st_gid at 36");
_Static_assert(offsetof(mips64_n32_stat64_t, st_size) == 56, "st_size at 56");
_Static_assert(offsetof(mips64_n32_stat64_t, st_blksize) == 88, "st_blksize at 88");
_Static_assert(offsetof(mips64_n32_stat64_t, st_blocks) == 96, "st_blocks at 96");

#endif
