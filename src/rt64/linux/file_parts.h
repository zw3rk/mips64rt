/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef MIPS64RT_FILE_PARTS_H
#define MIPS64RT_FILE_PARTS_H

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#endif

_Static_assert(sizeof(off_t) == 8, "runtime requires native 64-bit file offsets");

typedef struct {
    mips64_linux_file_t *files;
    const mips64_linux_file_io_t *io;
    bool confirmed;
} open_truncate_context_t;

typedef struct {
    mips64_linux_file_t *files;
    bool positioned;
    int64_t position;
    mips64_linux_write_fn writer;
    void *writer_context;
} managed_write_t;

typedef struct {
    mips64_linux_write_request_fn callback;
    void *context;
} canonical_writev_context_t;
/* Cross-part prototypes (Phase 0 mechanical split). */
#include "linux/file.h"
#include "runtime/owned_io.h"
#include "linux/codec.h"
#include "linux/error.h"
#include "linux/io.h"
#include "linux/metadata.h"
#include "linux/directory.h"
#include "linux/path.h"
#include "linux/pipe.h"
#include "linux/poll.h"
#include "linux/socket.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#define G_AT_FDCWD UINT32_C(0xffffff9c)
#define IO_STAGE ((size_t)65536)
#define MAX_RW_COUNT UINT64_C(0x7ffff000)

 bool fifo_identity(int directory_fd, const char *path,
                          mips64_linux_fifo_identity_t *identity);

bool mips64_linux_file_reserve_fifo(mips64_linux_file_t *files);

void mips64_linux_file_record_fifo(mips64_linux_file_t *files, int directory_fd,
                               const char *leaf);

 bool created_fifo_fd(mips64_linux_file_t *files, int descriptor);

 uint64_t mips64_file_failure(unsigned int linux_errno);

 uint64_t mips64_file_host_failure(int host_errno);

/* Preserve the borrowed open description when a configured canonical callback
 * falls back to the ordinary nonregular-file route. Reacquiring by guest FD
 * after unborrow could select a close/reuse replacement. */
 int mips64_file_duplicate_borrowed_fd(const mips64_fd_borrow_t *borrowed);

 int64_t mips64_file_signed_word(uint64_t word);

/* Preflight all possible mapped targets before native O_TRUNC chooses an inode.
 * No allocation/epoch mips64_file_failure is allowed after that irreversible side effect. */
 bool truncate_capacity(mips64_space_t *space);

 int open_truncate_adapter(int descriptor, int *native_errno,
                                 void *opaque);

 uint64_t open_truncate_result(open_truncate_context_t *context,
                                     uint32_t reserved_guest_fd,
                                     uint64_t result);

 bool file_init(mips64_linux_file_t *files, mips64_space_t *space,
                       const char *sysroot, mips64_fd_initial_t **initial);

bool mips64_linux_file_init(mips64_linux_file_t *files, mips64_space_t *space, const char *sysroot);

bool mips64_linux_file_init_initial(mips64_linux_file_t *files, mips64_space_t *space,
                                 const char *sysroot, mips64_fd_initial_t **initial);

void mips64_linux_file_destroy(mips64_linux_file_t *files);

int mips64_linux_file_fork_child_resolver_rebase(mips64_linux_file_t *files);

int mips64_linux_file_bind_child_image(mips64_linux_file_t *files, mips64_space_t *space,
                                   mips64_file_registry_t *registry);

uint64_t mips64_linux_file_mmap(mips64_linux_file_t *files, mips64_linux_memory_t *memory,
                           const uint64_t arguments[6]);

 uint64_t mips64_file_open_file(mips64_linux_file_t *files,
                          const mips64_linux_file_io_t *io,
                          const uint64_t arguments[6]);

/* Guest threads share FS state (CLONE_FS), and the family guard serializes
 * this change with every translated relative path walk. Open through the
 * private-inode resolver first: chdir must not enter a runtime-owned directory
 * or follow a pathname replacement after the checked open. The native cwd is
 * already the relative-path base used by file, metadata and exec dispatch. */
 uint64_t mips64_file_change_directory(mips64_linux_file_t *files, uint64_t address);

 bool mips64_file_path_descriptor(int flags);

 ssize_t mips64_file_managed_write(int native_fd, const void *bytes, size_t size, void *opaque);

 uint64_t mips64_file_transfer(mips64_linux_file_t *files, const mips64_linux_file_io_t *io,
                          const uint64_t arguments[6],
                          bool writing, bool positioned);

 uint64_t mips64_file_get_status(mips64_linux_file_t *files, const uint64_t arguments[6]);

 uint64_t seek_file(mips64_linux_file_t *files, const uint64_t arguments[6]);

 uint64_t control_file(mips64_linux_file_t *files, const uint64_t arguments[6]);

 ssize_t canonical_writev_request(int descriptor,
                                        const mips64_linux_write_request_t *request,
                                        void *opaque);

 uint64_t write_vectors(mips64_linux_file_t *files,
                              const mips64_linux_file_io_t *io,
                              const uint64_t arguments[6]);

 uint64_t resize_file(mips64_linux_file_t *files,
                            const mips64_linux_file_io_t *io,
                            const uint64_t arguments[6]);

 uint64_t ioctl_file(mips64_linux_file_t *files, const uint64_t arguments[6]);

bool mips64_linux_file_dispatch(mips64_linux_file_t *files, uint64_t number,
                            const uint64_t arguments[6], uint64_t *result);

bool mips64_linux_file_dispatch_io(mips64_linux_file_t *files,
                               const mips64_linux_file_io_t *io, uint64_t number,
                               const uint64_t arguments[6], uint64_t *result);
#endif /* MIPS64RT_FILE_PARTS_H */
