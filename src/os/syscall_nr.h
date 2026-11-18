/*
 * src/os/syscall_nr.h — MIPS N64/N32 Linux syscall numbers for mips64rt
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * N64 numbers are offsets from __NR_Linux = 5000, N32 numbers from
 * __NR_Linux = 6000 (SPEC 2.2: the syscall instruction 0x0000000c takes
 * its number in $v0; args in $a0..$a5; $a3 = 0/$v0 on success,
 * $a3 = 1/$v0 = +errno on error).
 *
 * Source: Linux arch/mips/include/uapi/asm/unistd_n64.h /
 * unistd_n32.h as shipped in libc6-dev-mips64el-cross and
 * libc6-dev-mipsn32-mips64el-cross (Debian trixie, linux/arm64); every
 * entry below was extracted mechanically from those headers (number =
 * base + index, quoted in the per-line comment). Lane L2a re-verified
 * each Phase 2 number against those two headers inside a
 * debian:stable-slim container (grep of the __NR rows) and executed
 * the N64/N32 fills live under qemu-mips64el / qemu-mipsn32el 10.0.13
 * (stat family, timespec, statx, getdents64, glibc -strace selection).
 * Spot checks against qemu ground truth: read 5000/6000, write
 * 5001/6001, mmap 5009/6009, getpid 5038/6038, exit 5058/6058,
 * set_thread_area 5242/6246 (experiments/E01, E06).
 *
 * MIPS N64/N32 define no vfork entry (verified absent from both headers):
 * glibc vfork lowers to clone (lane L4b); see the proc layer in Phase 4
 * for the documented fork-equivalent.
 */

#ifndef MIPS64RT_OS_SYSCALL_NR_H
#define MIPS64RT_OS_SYSCALL_NR_H

#include <stdint.h>

#define MIPS64_NR_LINUX_BASE  5000
#define MIPS64_NR32_LINUX_BASE 6000

/* Process lifecycle */
#define MIPS64_NR_exit        5058 /* n64 index 58:  sys_exit */
#define MIPS64_NR32_exit      6058
#define MIPS64_NR_exit_group  5205 /* n64 index 205: sys_exit_group */
#define MIPS64_NR32_exit_group 6205
#define MIPS64_NR_fork        5056 /* n64 index 56:  __sys_fork */
#define MIPS64_NR32_fork      6056
#define MIPS64_NR_clone       5055 /* n64 index 55:  __sys_clone */
#define MIPS64_NR32_clone     6055
#define MIPS64_NR_execve      5057 /* n64 index 57:  sys_execve */
#define MIPS64_NR32_execve    6057
#define MIPS64_NR_execveat    5316 /* n64 index 316: sys_execveat */
#define MIPS64_NR32_execveat  6320
/* Basic I/O */
#define MIPS64_NR_read    5000 /* n64 index 0: sys_read */
#define MIPS64_NR32_read  6000
#define MIPS64_NR_write   5001 /* n64 index 1: sys_write */
#define MIPS64_NR32_write 6001
#define MIPS64_NR_open     5002 /* n64 index 2: sys_open (compat) */
#define MIPS64_NR32_open   6002
#define MIPS64_NR_openat   5247 /* n64 index 247: sys_openat */
#define MIPS64_NR32_openat 6251
#define MIPS64_NR_openat2   5437 /* n64 index 437: sys_openat2 */
#define MIPS64_NR32_openat2 6437
#define MIPS64_NR_close     5003 /* n64 index 3: sys_close */
#define MIPS64_NR32_close   6003
#define MIPS64_NR_close_range 5436 /* n64 index 436: sys_close_range */
#define MIPS64_NR32_close_range 6436
#define MIPS64_NR_lseek    5008 /* n64 index 8: sys_lseek */
#define MIPS64_NR32_lseek  6008
#define MIPS64_NR_pread64  5016 /* n64 index 16: sys_pread64 */
#define MIPS64_NR32_pread64 6016
#define MIPS64_NR_pwrite64  5017 /* n64 index 17: sys_pwrite64 */
#define MIPS64_NR32_pwrite64 6017
#define MIPS64_NR_readv    5018 /* n64 index 18: sys_readv */
#define MIPS64_NR32_readv  6018
#define MIPS64_NR_writev   5019 /* n64 index 19: sys_writev */
#define MIPS64_NR32_writev 6019
#define MIPS64_NR_preadv   5289 /* n64 index 289: sys_preadv */
#define MIPS64_NR32_preadv 6293
#define MIPS64_NR_pwritev  5290 /* n64 index 290: sys_pwritev */
#define MIPS64_NR32_pwritev 6294
#define MIPS64_NR_dup      5031 /* n64 index 31: sys_dup */
#define MIPS64_NR32_dup    6031
#define MIPS64_NR_dup2     5032 /* n64 index 32: sys_dup2 (n32: dup3 alias) */
#define MIPS64_NR32_dup2   6032
#define MIPS64_NR_dup3     5286 /* n64 index 286: sys_dup3 */
#define MIPS64_NR32_dup3   6290
#define MIPS64_NR_pipe     5021 /* n64 index 21: sysm_pipe */
#define MIPS64_NR32_pipe   6021
#define MIPS64_NR_pipe2    5287 /* n64 index 287: sys_pipe2 */
#define MIPS64_NR32_pipe2  6291
#define MIPS64_NR_fcntl    5070 /* n64 index 70: sys_fcntl */
#define MIPS64_NR32_fcntl  6070
#define MIPS64_NR_ioctl    5015 /* n64 index 15: sys_ioctl (compat) */
#define MIPS64_NR32_ioctl  6015
#define MIPS64_NR_sendfile 5039 /* n64 index 39: sys_sendfile */
#define MIPS64_NR32_sendfile 6039
#define MIPS64_NR_copy_file_range 5320 /* n64 index 320 */
#define MIPS64_NR32_copy_file_range 6324
#define MIPS64_NR_splice   5263 /* n64 index 263: sys_splice */
#define MIPS64_NR32_splice 6267
#define MIPS64_NR_tee      5265 /* n64 index 265: sys_tee */
#define MIPS64_NR32_tee    6269
/* File metadata */
#define MIPS64_NR_stat     5004 /* n64 index 4: sys_stat (compat) */
#define MIPS64_NR32_stat   6004
#define MIPS64_NR_fstat    5005 /* n64 index 5: sys_fstat (compat) */
#define MIPS64_NR32_fstat  6005
#define MIPS64_NR_lstat    5006 /* n64 index 6: sys_lstat (compat) */
#define MIPS64_NR32_lstat  6006
#define MIPS64_NR_newfstatat 5252 /* n64 index 252: sys_newfstatat */
#define MIPS64_NR32_newfstatat 6256
#define MIPS64_NR_statx    5326 /* n64 index 326: sys_statx */
#define MIPS64_NR32_statx  6330
#define MIPS64_NR_statfs   5134 /* n64 index 134: sys_statfs */
#define MIPS64_NR32_statfs 6134
#define MIPS64_NR_fstatfs  5135 /* n64 index 135: sys_fstatfs */
#define MIPS64_NR32_fstatfs 6135
/* Directory / link / access */
#define MIPS64_NR_getdents64 5308 /* n64 index 308: sys_getdents64 */
#define MIPS64_NR32_getdents64 6299
#define MIPS64_NR_readlink   5087 /* n64 index 87: sys_readlink */
#define MIPS64_NR32_readlink 6087
#define MIPS64_NR_readlinkat 5257 /* n64 index 257: sys_readlinkat */
#define MIPS64_NR32_readlinkat 6261
#define MIPS64_NR_access     5020 /* n64 index 20: sys_access */
#define MIPS64_NR32_access   6020
#define MIPS64_NR_faccessat  5259 /* n64 index 259: sys_faccessat */
#define MIPS64_NR32_faccessat 6263
#define MIPS64_NR_faccessat2 5439 /* n64 index 439: sys_faccessat2 */
#define MIPS64_NR32_faccessat2 6439
#define MIPS64_NR_getcwd     5077 /* n64 index 77: sys_getcwd */
#define MIPS64_NR32_getcwd   6077
#define MIPS64_NR_chdir      5078 /* n64 index 78: sys_chdir */
#define MIPS64_NR32_chdir    6078
#define MIPS64_NR_fchdir     5079 /* n64 index 79: sys_fchdir */
#define MIPS64_NR32_fchdir   6079 /* n32 index 79: sys_fchdir */
#define MIPS64_NR_unlink     5085 /* n64 index 85: sys_unlink */
#define MIPS64_NR32_unlink   6085
#define MIPS64_NR_unlinkat   5253 /* n64 index 253: sys_unlinkat */
#define MIPS64_NR32_unlinkat 6257
#define MIPS64_NR_mkdirat    5248 /* n64 index 248: sys_mkdirat */
#define MIPS64_NR32_mkdirat  6252
#define MIPS64_NR_mknodat    5249 /* n64 index 249: sys_mknodat */
#define MIPS64_NR32_mknodat  6253
#define MIPS64_NR_symlinkat  5256 /* n64 index 256: sys_symlinkat */
#define MIPS64_NR32_symlinkat 6260
#define MIPS64_NR_linkat     5255 /* n64 index 255: sys_linkat */
#define MIPS64_NR32_linkat   6259
#define MIPS64_NR_renameat   5254 /* n64 index 254: sys_renameat */
#define MIPS64_NR32_renameat 6258
#define MIPS64_NR_renameat2  5311 /* n64 index 311: sys_renameat2 */
#define MIPS64_NR32_renameat2 6315
#define MIPS64_NR_chmod      5088 /* n64 index 88: sys_chmod */
#define MIPS64_NR32_chmod    6088
#define MIPS64_NR_fchmod     5089 /* n64 index 89: sys_fchmod */
#define MIPS64_NR32_fchmod   6089
#define MIPS64_NR_fchmodat   5258 /* n64 index 258: sys_fchmodat */
#define MIPS64_NR32_fchmodat 6262
#define MIPS64_NR_chown      5090 /* n64 index 90 */
#define MIPS64_NR32_chown    6090
#define MIPS64_NR_fchown     5091 /* n64 index 91 */
#define MIPS64_NR32_fchown   6091
#define MIPS64_NR_lchown     5092 /* n64 index 92 */
#define MIPS64_NR32_lchown   6092
#define MIPS64_NR_fchownat   5250 /* n64 index 250 */
#define MIPS64_NR32_fchownat 6254
#define MIPS64_NR_truncate   5074 /* n64 index 74 */
#define MIPS64_NR32_truncate 6074
#define MIPS64_NR_ftruncate  5075 /* n64 index 75 */
#define MIPS64_NR32_ftruncate 6075
#define MIPS64_NR_fallocate  5279 /* n64 index 279: sys_fallocate */
#define MIPS64_NR32_fallocate 6283
/* Time, randomness, futex */
#define MIPS64_NR_nanosleep        5034 /* n64 index 34 */
#define MIPS64_NR32_nanosleep      6034
#define MIPS64_NR_clock_gettime    5222 /* n64 index 222 */
#define MIPS64_NR32_clock_gettime  6226
#define MIPS64_NR_clock_getres     5223 /* n64 index 223 */
#define MIPS64_NR32_clock_getres   6227
#define MIPS64_NR_clock_nanosleep  5224 /* n64 index 224 */
#define MIPS64_NR32_clock_nanosleep 6228
#define MIPS64_NR_getrandom        5313 /* n64 index 313 */
#define MIPS64_NR32_getrandom      6317
#define MIPS64_NR_futex            5194 /* n64 index 194: sys_futex */
#define MIPS64_NR32_futex          6194
/* Robust futex lists (recorded in ctx; woken by Phase 4) */
#define MIPS64_NR_set_robust_list 5268 /* n64 index 268 */
#define MIPS64_NR32_set_robust_list 6272
#define MIPS64_NR_get_robust_list 5269 /* n64 index 269 */
#define MIPS64_NR32_get_robust_list 6273
#define MIPS64_NR_set_tid_address 5212 /* n64 index 212 */
#define MIPS64_NR32_set_tid_address 6213
/* Memory management */
#define MIPS64_NR_brk      5012 /* n64 index 12: sys_brk */
#define MIPS64_NR32_brk    6012
#define MIPS64_NR_mmap     5009 /* n64 index 9:  sys_mmap (n64 offset arg) */
#define MIPS64_NR32_mmap   6009
#define MIPS64_NR_munmap   5011 /* n64 index 11: sys_munmap */
#define MIPS64_NR32_munmap 6011
#define MIPS64_NR_mprotect 5010 /* n64 index 10: sys_mprotect */
#define MIPS64_NR32_mprotect 6010
#define MIPS64_NR_mremap   5024 /* n64 index 24: sys_mremap */
#define MIPS64_NR32_mremap 6024
#define MIPS64_NR_msync    5025 /* n64 index 25 */
#define MIPS64_NR32_msync  6025
#define MIPS64_NR_madvise  5027 /* n64 index 27 */
#define MIPS64_NR32_madvise 6027
#define MIPS64_NR_mlock    5146 /* n64 index 146 */
#define MIPS64_NR32_mlock  6146
#define MIPS64_NR_munlock  5147 /* n64 index 147 */
#define MIPS64_NR32_munlock 6147
#define MIPS64_NR_membarrier 5318 /* n64 index 318 */
#define MIPS64_NR32_membarrier 6322
/* Identity / uname */
#define MIPS64_NR_getpid  5038 /* n64 index 38: sys_getpid */
#define MIPS64_NR32_getpid 6038
#define MIPS64_NR_getppid 5108 /* n64 index 108 */
#define MIPS64_NR32_getppid 6108
#define MIPS64_NR_getuid  5100 /* n64 index 100 */
#define MIPS64_NR32_getuid 6100
#define MIPS64_NR_geteuid 5105 /* n64 index 105 */
#define MIPS64_NR32_geteuid 6105
#define MIPS64_NR_getgid  5102 /* n64 index 102 */
#define MIPS64_NR32_getgid 6102
#define MIPS64_NR_getegid 5106 /* n64 index 106 */
#define MIPS64_NR32_getegid 6106
#define MIPS64_NR_gettid  5178 /* n64 index 178 */
#define MIPS64_NR32_gettid 6178
#define MIPS64_NR_uname   5061 /* n64 index 61: sys_newuname */
#define MIPS64_NR32_uname 6061
/* Signals (wired in Phase 4; numbers frozen here) */
#define MIPS64_NR_kill            5060 /* n64 index 60: sys_kill */
#define MIPS64_NR32_kill          6060
#define MIPS64_NR_tkill           5192 /* n64 index 192 */
#define MIPS64_NR32_tkill         6192
#define MIPS64_NR_tgkill          5225 /* n64 index 225 */
#define MIPS64_NR32_tgkill        6229
#define MIPS64_NR_rt_sigaction    5013 /* n64 index 13 */
#define MIPS64_NR32_rt_sigaction  6013
#define MIPS64_NR_rt_sigprocmask  5014 /* n64 index 14 */
#define MIPS64_NR32_rt_sigprocmask 6014
#define MIPS64_NR_rt_sigreturn    5211 /* n64 index 211 */
#define MIPS64_NR32_rt_sigreturn  6211
#define MIPS64_NR_rt_sigpending   5125 /* n64 index 125 */
#define MIPS64_NR32_rt_sigpending 6125
#define MIPS64_NR_rt_sigtimedwait 5126 /* n64 index 126 */
#define MIPS64_NR32_rt_sigtimedwait 6126
#define MIPS64_NR_rt_sigqueueinfo 5127 /* n64 index 127 */
#define MIPS64_NR32_rt_sigqueueinfo 6127
#define MIPS64_NR_rt_tgsigqueueinfo 5291 /* n64 index 291 */
#define MIPS64_NR32_rt_tgsigqueueinfo 6295
#define MIPS64_NR_sigaltstack     5129 /* n64 index 129 */
#define MIPS64_NR32_sigaltstack   6129
#define MIPS64_NR_sigtimedwait    5126 /* alias of rt_sigtimedwait */

/* Thread pointer (E06: sets ctx->ulr; N64 5242 / N32 6246) */
#define MIPS64_NR_set_thread_area 5242 /* n64 index 242 */
#define MIPS64_NR32_set_thread_area 6246
/* Cache maintenance (Phase 7 SMC: invalidate translated blocks) */
#define MIPS64_NR_cacheflush 5197 /* n64 index 197: sys_cacheflush */
#define MIPS64_NR32_cacheflush 6197
#define MIPS64_NR_cachectl   5198 /* n64 index 198 */
#define MIPS64_NR32_cachectl 6198
/* Process wait (Phase 4 fork/exec/wait4) */
#define MIPS64_NR_wait4  5059 /* n64 index 59: sys_wait4 */
#define MIPS64_NR32_wait4 6059
#define MIPS64_NR_waitid 5237 /* n64 index 237: sys_waitid */
#define MIPS64_NR32_waitid 6241
/* Scheduling / polling (Phase 2 static libc + Phase 4 threads) */
#define MIPS64_NR_sched_yield 5023 /* n64 index 23 */
#define MIPS64_NR32_sched_yield 6023
#define MIPS64_NR_nanosleep_alias 5034
#define MIPS64_NR_pselect6 5260 /* n64 index 260 */
#define MIPS64_NR32_pselect6 6264
#define MIPS64_NR_ppoll    5261 /* n64 index 261 */
#define MIPS64_NR32_ppoll  6265
#define MIPS64_NR_epoll_create  5207 /* n64 index 207 */
#define MIPS64_NR32_epoll_create 6207
#define MIPS64_NR_epoll_ctl     5208 /* n64 index 208 */
#define MIPS64_NR32_epoll_ctl   6208
#define MIPS64_NR_epoll_wait    5209 /* n64 index 209 (old) */
#define MIPS64_NR32_epoll_wait  6209
#define MIPS64_NR_epoll_pwait   5272 /* n64 index 272 */
#define MIPS64_NR32_epoll_pwait 6276
/* Sockets (Phase 2 static libc coverage) */
#define MIPS64_NR_socket      5040 /* n64 index 40 */
#define MIPS64_NR32_socket    6040
#define MIPS64_NR_socketpair  5052 /* n64 index 52 */
#define MIPS64_NR32_socketpair 6052
#define MIPS64_NR_bind        5048 /* n64 index 48 */
#define MIPS64_NR32_bind      6048
#define MIPS64_NR_connect     5041 /* n64 index 41 */
#define MIPS64_NR32_connect   6041
#define MIPS64_NR_listen      5049 /* n64 index 49 */
#define MIPS64_NR32_listen    6049
#define MIPS64_NR_accept      5042 /* n64 index 42 */
#define MIPS64_NR32_accept    6042
#define MIPS64_NR_accept4     5293 /* n64 index 293 */
#define MIPS64_NR32_accept4   6297
#define MIPS64_NR_getsockname 5050 /* n64 index 50 */
#define MIPS64_NR32_getsockname 6050
#define MIPS64_NR_getpeername 5051 /* n64 index 51 */
#define MIPS64_NR32_getpeername 6051
#define MIPS64_NR_sendto      5043 /* n64 index 43 */
#define MIPS64_NR32_sendto    6043
#define MIPS64_NR_recvfrom    5044 /* n64 index 44 */
#define MIPS64_NR32_recvfrom  6044
#define MIPS64_NR_sendmsg     5045 /* n64 index 45 */
#define MIPS64_NR32_sendmsg   6045
#define MIPS64_NR_recvmsg     5046 /* n64 index 46 */
#define MIPS64_NR32_recvmsg   6046
#define MIPS64_NR_shutdown    5047 /* n64 index 47 */
#define MIPS64_NR32_shutdown  6047
#define MIPS64_NR_setsockopt  5053 /* n64 index 53 */
#define MIPS64_NR32_setsockopt 6053
#define MIPS64_NR_getsockopt  5054 /* n64 index 54 */
#define MIPS64_NR32_getsockopt 6054
#define MIPS64_NR_recvmmsg    5294 /* n64 index 294 */
#define MIPS64_NR32_recvmmsg  6298
#define MIPS64_NR_sendmmsg    5302 /* n64 index 302 */
#define MIPS64_NR32_sendmmsg  6307
/* Resource limits / misc process (Phase 4/5) */
#define MIPS64_NR_prlimit64 5297 /* n64 index 297 */
#define MIPS64_NR32_prlimit64 6302
#define MIPS64_NR_getrlimit 5095 /* n64 index 95 (compat) */
#define MIPS64_NR32_getrlimit 6095
#define MIPS64_NR_personality 5132 /* n64 index 132 */
#define MIPS64_NR32_personality 6132
/* N32 time64 variants (64-bit time_t on the 32-bit-pointer ABI). */
#define MIPS64_NR32_clock_gettime64  6403 /* n32 index 403 */
#define MIPS64_NR32_clock_settime64  6404 /* n32 index 404 */
#define MIPS64_NR32_clock_getres_time64 6406 /* n32 index 406 */
/* L2a: glibc nanosleep() lowers to clock_nanosleep(_time64) (observed
 * via qemu -strace), so the N32 time64 companion is wired too. */
#define MIPS64_NR32_clock_nanosleep_time64 6407 /* n32 index 407 */
#define MIPS64_NR32_futex_time64     6422 /* n32 index 422 */

/* Guest trap encoding: `syscall 0`. */
#define MIPS64_SYSCALL_INSN UINT32_C(0x0000000c)

/* Negative errno range returned in `v0` with `a3 = 1` on failure. */
#define MIPS64_ERRNO_MAX 4095

#endif /* MIPS64RT_OS_SYSCALL_NR_H */
