/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef MIPS64RT_RT64_MEMORY_SPACE_H
#define MIPS64RT_RT64_MEMORY_SPACE_H

#include "core/atomic.h"
#include "core/cpu.h"
#include "runtime/measure.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* `MIPS64_PAGE_SIZE` comes from frozen `core/cpu.h` (SPEC 1.1, 4096). */
#define MIPS64_R1_MAX_PAGES ((size_t)65536)
#define MIPS64_RESERVATION_GRANULE ((size_t)16)
#define MIPS64_PAGE_GRANULES ((size_t)256)

enum { MIPS64_MEM_READ = 1, MIPS64_MEM_WRITE = 2, MIPS64_MEM_EXEC = 4 };
typedef enum {
    MIPS64_FAULT_NONE, MIPS64_FAULT_RANGE, MIPS64_FAULT_UNMAPPED, MIPS64_FAULT_PERMISSION,
    MIPS64_FAULT_BUS, MIPS64_FAULT_RESOURCE, MIPS64_FAULT_INTERNAL
} mips64_fault_reason_t;

/* RESOURCE is a pre-publication allocation/size limit. INTERNAL denotes a
 * broken guard, redo/refresh, or exhausted monotonic correctness counter. */
static inline bool mips64_fault_is_runtime(mips64_fault_reason_t reason)
{
    return reason == MIPS64_FAULT_RESOURCE || reason == MIPS64_FAULT_INTERNAL;
}

typedef struct mips64_space mips64_space_t;
typedef struct mips64_backing mips64_backing_t;
typedef struct mips64_page_payload mips64_page_payload_t;
typedef struct mips64_file_source mips64_file_source_t;
typedef struct mips64_copyout mips64_copyout_t;
typedef struct mips64_io_copyout mips64_io_copyout_t;

typedef enum {
    MIPS64_PAYLOAD_HEAP,
    MIPS64_PAYLOAD_MANAGED
} mips64_payload_backend_t;

/* The factory creates one owned payload with references=1, zero-filled 4 KiB
 * bytes, zeroed 256 16-byte write epochs, and a disposer. Bytes/epochs stay aligned for
 * unsigned char/uint64_t access until the last reference is released. A
 * family-backed factory may place many payloads in one retained host view. */
struct mips64_page_payload {
    unsigned char *bytes;
    uint64_t *epochs;
    size_t references;
    void (*dispose)(mips64_page_payload_t *payload);
    /* Set when the payload is created. Every alias retains this identity.
     * Legacy private file pages are heap owned; canonical imports are managed. */
    mips64_payload_backend_t backend;
    /* Managed file state is read from the freshly guarded canonical mirror,
     * rather than any one alias's projected private_cow flag. Heap/custom
     * anonymous payloads leave this NULL. */
    const uint32_t *canonical_private_cow;
};

typedef struct {
    mips64_page_payload_t *(*create)(void *context);
    void *context; /* Must outlive every payload produced by this factory. */
} mips64_page_factory_t;

typedef struct {
    mips64_page_payload_t *payload;
    unsigned char bytes[MIPS64_PAGE_SIZE];
    uint64_t epochs[MIPS64_PAGE_GRANULES];
    bool make_private_cow;
} mips64_managed_page_update_t;

typedef struct {
    bool (*check_guard)(void *context);
    /* A changed snapshot must not publish when code-generation capacity is
     * exhausted; a later access must still see that pending change. */
    bool (*refresh)(void *context, mips64_page_payload_t *payload,
                    bool can_publish, bool *changed,
                    mips64_measure_observer_t *measure);
    /* Origin resolution may allocate during full-span preflight only. A
     * retained-I/O completion passes allow_resolve=false after native input. */
    bool (*check_write)(void *context, mips64_page_payload_t *payload,
                         bool expected_file, bool allow_resolve);
    bool (*commitv)(void *context, const mips64_managed_page_update_t *updates,
                    size_t count);
    void *context;
} mips64_managed_page_ops_t;

/* File-backed pages keep a retained source. Its implementation owns native
 * file identity and checked reads; the sparse core stays independent of native
 * filesystem APIs. refresh may publish clean bytes but must not recurse into
 * guest writes, allocate pages, or mark a page COW. Sources are space-owned. */
struct mips64_file_source {
    mips64_space_t *space;
    void (*retain)(mips64_file_source_t *source);
    void (*release)(mips64_file_source_t *source);
    bool (*refresh)(mips64_file_source_t *source, mips64_backing_t *backing, uint64_t address);
};

struct mips64_backing {
    /* Process-local view. Shared bytes/epochs live in the retained payload;
     * file refresh/COW state belongs to this view. */
    unsigned char *bytes;
    uint64_t *epochs;
    mips64_page_payload_t *payload;
    size_t references;
    mips64_file_source_t *file;
    uint64_t file_offset;
    /* Granules already invalidated by successful native file writes. Refresh
     * publishes their bytes without consuming a second epoch/generation. */
    uint64_t file_notified[4];
    bool private_cow;
    /* Immutable mapped BUS view: bytes/epochs/payload/file are all NULL.
     * Permission checks still apply; there is no fabricated data identity. */
    bool bus_fault;
};

typedef struct {
    uint64_t address;
    unsigned int permissions;
    mips64_backing_t *backing;
    uint64_t binding_base;
} mips64_page_t;

/* The default factory creates heap-backed private pages. Factory/view
 * reference counts are process-local and require external serialization.
 * A managed space uses the caller's uninterrupted family guard for the whole
 * operation, including any heap-backed private file pages. */
struct mips64_space {
    /* Optional process-local observation, never part of guest/shared state. */
    mips64_measure_observer_t *measure;
    mips64_page_t *pages;
    mips64_page_factory_t page_factory;
    mips64_managed_page_ops_t managed;
    /* Reusable process-local preflight scratch. A successful prepare_write
     * reserves enough space for the matching commit without another malloc. */
    void *epoch_scratch;
    size_t epoch_scratch_capacity;
    size_t count, capacity;
    uint64_t limit;
    /* Conservative code-visibility generation. Advance before any mutation;
     * current R2 blocks never survive a guest write or mapping operation. */
    uint64_t generation;
    uint64_t next_binding;
    uint64_t fault_address;
    mips64_fault_reason_t fault_reason;
    bool internal_failure; /* Sticky: a later successful access cannot hide it. */
    /* Sticky conservative fallback until JIT file-source guards are present. */
    bool has_file_pages;
};

/* The translator never truncates a 64-bit guest address into a 4 GiB
 * window. `mips64_space_init` selects the N64 window (SPEC 1.1/2.1);
 * `mips64_space_init_abi` selects N64 (`is_n32 == 0`) or N32
 * (`is_n32 != 0`) from the frozen `core/cpu.h` task sizes. */
void mips64_space_init(mips64_space_t *space);
void mips64_space_init_abi(mips64_space_t *space, int is_n32);
/* True when `limit` is the N32 (32-bit-pointer) guest window. Callers
 * that only retain a limit (mm views, poll/select) use this instead of
 * comparing against a hard-coded 4 GiB bound. */
static inline bool mips64_space_is_n32_limit(uint64_t limit)
{
    return limit == MIPS64_N32_TASK_SIZE;
}
void mips64_space_destroy(mips64_space_t *space);
/* Select a factory only while no pages are mapped. A failed switch leaves the
 * old factory in place. The default heap factory needs no external context. */
bool mips64_space_set_page_factory(mips64_space_t *space, mips64_page_factory_t factory);
/* Select a managed anonymous factory on an empty space. File-private pages
 * retain heap ownership. Every access still requires the current family guard.
 * Architectural stores touching at most two distinct managed payloads use one
 * redo commit; larger copies progress through bounded redo batches. */
bool mips64_space_set_managed_factory(mips64_space_t *space, mips64_page_factory_t factory,
                                  mips64_managed_page_ops_t managed);
/* Retain/release a process-local view; DATA retains one payload and optional
 * file source, while a BUS view owns no payload or file-source reference. */
bool mips64_backing_retain(mips64_backing_t *backing);
void mips64_backing_release(mips64_backing_t *backing);
/* Page-aligned ranges. Mapping changes are transactional: failure preserves
 * existing pages, permissions, bindings and generation (fault fields change).
 * merge unions loader permissions; replace discards old bytes in the range.
 * Anonymous aliases now share payload bytes/epochs. Concurrent family use
 * still requires the R5 execution token and packed shared storage. */
bool mips64_space_map(mips64_space_t *space, uint64_t address, uint64_t size,
                  unsigned int permissions, bool merge);
/* Mapped address/permissions with no data payload. Every nonempty checked
 * access faults BUS after range/permissions and managed guard validation,
 * including SC with no valid reservation. Transactional like ordinary mapping;
 * aliases/moved pages preserve the fault. Does not enable shared-growth ABI by itself. */
bool mips64_space_map_bus(mips64_space_t *space, uint64_t address, uint64_t size,
                      unsigned int permissions, bool replace);
bool mips64_space_replace(mips64_space_t *space, uint64_t address, uint64_t size,
                      unsigned int permissions);
/* Retains source once per new backing. File offsets are page-aligned. Beyond
 * EOF is mapped successfully and checked on access. Caller retains its source
 * reference independently; failed mapping preserves all existing ownership. */
bool mips64_space_map_file(mips64_space_t *space, uint64_t address, uint64_t size,
                       unsigned int permissions, bool replace,
                       mips64_file_source_t *source, uint64_t file_offset);
/* Alias a complete anonymous source range at an unused destination. Views are
 * distinct; bytes/epochs are shared. Failure changes no mapping or references.
 * Fresh binding IDs make an old LR reservation invalid after mapping changes. */
bool mips64_space_alias(mips64_space_t *space, uint64_t source, uint64_t destination,
                    uint64_t size, unsigned int permissions);
/* Install a retained managed payload at one vacant guest page with a fresh
 * view and binding. The caller must establish that the payload belongs to
 * this space's managed context; the family adapter checks canonical ownership.
 * The caller retains its own payload reference. Failure
 * leaves the registry, generation, bindings and references unchanged. */
bool mips64_space_map_shared_payload(mips64_space_t *space, uint64_t address,
                                 unsigned int permissions,
                                 mips64_page_payload_t *payload);
/* Same atomic vacant-page import, with a retained managed file source. This is
 * an adapter primitive: the caller proves key/source/offset association and
 * implements canonical refresh. It must not pass a legacy heap-file source. */
bool mips64_space_map_managed_file_payload(mips64_space_t *space, uint64_t address,
                                        unsigned int permissions,
                                        mips64_page_payload_t *payload,
                                        mips64_file_source_t *source, uint64_t offset);
/* Unpublished candidate only: source stays bound to its stable final owner.
 * Both spaces must have the same managed context/limit. The adapter checks the
 * exact guard. Never access candidate bytes/atomics before its page registry
 * is moved into that stable owner; discard may release views without access. */
bool mips64_space_stage_managed_file_payload(mips64_space_t *space, uint64_t address,
                                          unsigned int permissions,
                                          mips64_page_payload_t *payload,
                                          mips64_file_source_t *source, uint64_t offset);
/* unmap tolerates holes. protect requires every page to be mapped. */
bool mips64_space_unmap(mips64_space_t *space, uint64_t address, uint64_t size);
bool mips64_space_protect(mips64_space_t *space, uint64_t address, uint64_t size,
                      unsigned int permissions);
/* Transactional private-backing move/resize. Ranges must be identical-start
 * or disjoint, and every source page must exist. Replaces destination pages;
 * preserves source bytes without consulting guest permissions. New pages are
 * zero, and moved bindings invalidate reservations. */
bool mips64_space_remap(mips64_space_t *space, uint64_t source, uint64_t old_size,
                    uint64_t destination, uint64_t new_size,
                    unsigned int permissions);
/* Find a page-aligned gap at or above start; never allocate host VA at the
 * guest address. Does not mutate the address space, including fault fields. */
bool mips64_space_find_hole(const mips64_space_t *space, uint64_t start, uint64_t size,
                        uint64_t *address);
bool mips64_space_read(mips64_space_t *space, uint64_t address, void *bytes,
                   size_t size, unsigned int permissions);
bool mips64_space_write(mips64_space_t *space, uint64_t address, const void *bytes,
                    size_t size);
/* A guard-held four-byte write with one external transaction boundary.
 * After complete access/counter preflight, commit is called exactly once with
 * 0..2 distinct managed payload updates (zero for heap-only writes). It must
 * publish those updates and their mirrors on success, without other guest
 * writes, mapping changes or releasing the guard. On failure no write is
 * published locally.
 * Set errno=ENOMEM only for a recoverable precommit resource failure; every
 * other failure is internal, including any failure after shared publication.
 * The callback and context are never retained or installed in the space. */
typedef bool (*mips64_space_word_commit_fn)(void *context,
                                        const mips64_managed_page_update_t *updates,
                                        size_t count);
bool mips64_space_write_word_commit(mips64_space_t *space, uint64_t address,
                                const unsigned char bytes[4],
                                mips64_space_word_commit_fn commit, void *context);
/* Check destination access and all write-counter capacity before irreversible
 * native I/O. Does not COW or consume write epochs. Caller preserves ownership
 * of mappings/state through the subsequent write. File refresh still applies. */
bool mips64_space_prepare_write(mips64_space_t *space, uint64_t address, size_t size);
/* Establish private ownership of the writable file page containing address,
 * without a guest store. Refresh precedes COW. Bytes and mapping bindings stay
 * unchanged; whole-page reservation epochs and code generation advance once.
 * Existing COW/anonymous pages are no-ops after checked write access. This is
 * the ownership side effect of a Linux writable page pin, not a lifetime pin. */
bool mips64_space_cow_file_page(mips64_space_t *space, uint64_t address);
/* A native read may consume input before its guest copyout. Prepare the entire
 * possible destination while the caller still owns that input: refresh files,
 * check permissions and all alias/write counters, allocate metadata, and pin
 * local backing views. The caller must hold one uninterrupted worker/family
 * guard and leave guest mappings, contents, and file sources unchanged until
 * commit/discard. This does not make concurrent external file writers safe.
 *
 * Commit is one-shot, copies only actual bytes (<= maximum), and never
 * allocates, refreshes a file, or performs native I/O. Stale state or a failed
 * managed commit is sticky INTERNAL; callers must not replay consumed input.
 * Managed payloads are each patched once in VA order and committed in batches
 * of at most two. Failure after an earlier batch is terminal: its effects are
 * committed batches, not a contiguous guest-VA prefix.
 * A zero-byte commit succeeds without mutation. Discard every token before
 * destroying its space, including after a failed commit. Input bytes must be
 * separate staging storage, not an overlapping guest backing. */
mips64_copyout_t *mips64_space_copyout_prepare(mips64_space_t *space, uint64_t address,
                                       size_t maximum);
bool mips64_space_copyout_commit(mips64_copyout_t *copyout, const void *bytes,
                              size_t actual);
void mips64_space_copyout_discard(mips64_copyout_t *copyout);
/* Owned I/O completion plan, distinct from the uninterrupted copyout above.
 * Prepare under the family guard before native input is consumed. The space
 * and all file-source owners must outlive this plan; discard under the guard.
 * The plan pins original views and reserves all copyout metadata. The caller
 * may release the guard, but must reacquire it before commit or discard.
 *
 * Commit refreshes CURRENT backing state and checks original mapping bindings
 * and current WRITE permission for the completed prefix only. Unrelated writes
 * are preserved. A changed mapping, protection or file BUS fault stops copying
 * at that page; false with *committed>0 reports a valid guest-VA prefix, false
 * with zero reports EFAULT. The native read may already have consumed more
 * input than that prefix: never replay it. Refresh can perform file I/O, but
 * commit allocates no metadata. Failed counters/guards/managed publication are
 * sticky INTERNAL, not an ordinary partial result; the caller must terminate.
 * Every commit attempt is one-shot, including failed/zero-byte attempts. */
mips64_io_copyout_t *mips64_space_io_copyout_prepare(mips64_space_t *space, uint64_t address,
                                            size_t maximum);
bool mips64_space_io_copyout_commit(mips64_io_copyout_t *copyout, const void *bytes,
                                 size_t actual, size_t *committed);
void mips64_space_io_copyout_discard(mips64_io_copyout_t *copyout);
/* Loader-only: requires mapped pages but permits initialization of RX data. */
bool mips64_space_write_initial(mips64_space_t *space, uint64_t address,
                            const void *bytes, size_t size);
/* R3 is single-threaded. R5 must hold the managed-family token around this
 * entire operation and every other guest memory write. */
bool mips64_space_atomic(mips64_space_t *space, const mips64_atomic_request_t *request,
                      mips64_atomic_result_t *result);

#endif

/* MIPS64 Class-B dual address windows (SPEC 1.1/1.2/2.1, frozen
 * `core/cpu.h`): N64 xuseg is 1 TiB (`MIPS64_N64_TASK_SIZE`), N32 useg is
 * 2 GiB (`MIPS64_N32_TASK_SIZE`, all pointers fit in signed 32-bit).
 * Stack top, unhinted-mmap base, PT_INTERP bias, and the signal
 * trampoline live in `core/cpu.h` (`MIPS64_N64_*`/`MIPS64_N32_*`); this
 * header only carries the window limit itself. */
