/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef MIPS64RT_FAMILY_PARTS_H
#define MIPS64RT_FAMILY_PARTS_H

#define _GNU_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1
#include "runtime/family.h"
#include "runtime/family_wait.h"
#include "runtime/file_catalog.h"
#include "runtime/family_file_index.h"
#include "runtime/family_file_index_internal.h"
#include "runtime/family_file_recovery.h"
#include "runtime/family_zero_segment.h"
#include "aot/authority.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <unistd.h>
#include <dirent.h>

#define MIPS64_FAMILY_MAGIC UINT64_C(0x5256525446414d31)
#define MIPS64_PAGE_MAGIC UINT64_C(0x5256525447504731)
#define MIPS64_OBJECT_MAGIC UINT64_C(0x52565254474f4232)
#define MIPS64_FAMILY_VERSION 11u
#define MIPS64_LOG_EMPTY 0u
#define MIPS64_LOG_PREPARED 1u
#define MIPS64_LOG_COMMITTED 2u
#define MIPS64_LOG_PAGE 0u
#define MIPS64_LOG_OBJECT 1u
#define MIPS64_LOG_OBJECT_PAIR 2u
#define MIPS64_LOG_WAIT 3u
#define MIPS64_LOG_WAIT_OBJECT 4u
#define MIPS64_LOG_WAIT_PAIR 5u
#define MIPS64_LOG_FILE 6u
#define MIPS64_OBJECT_HEADER_SIZE 16384u
#define MIPS64_OBJECT_SLOT_SIZE 8192u
#define MIPS64_WAIT_BANK_MAGIC UINT64_C(0x5256525457414954)
#define MIPS64_WAIT_BANK_VERSION 1u
#define MIPS64_WAIT_INITIAL_CAPACITY 64u
#define MIPS64_WAIT_MAX_ROWS 65536u
#define MIPS64_ZERO_CONTROL_HEAD_SIZE (1024u * 1024u)
#define MIPS64_ZERO_CONTROL_FRAGMENT_SIZE (2u * 1024u * 1024u)
#define MIPS64_ZERO_CONTROL_MAX_FRAGMENTS 16u

typedef struct {
    uint64_t magic;
    uint32_t version;
    uint32_t size;
    uint64_t next_incarnation;
    uint64_t next_object_id;
    uint64_t recovery_epoch;
    uint64_t active_incarnation;
    uint32_t active;
    uint32_t retired;
    _Alignas(8) _Atomic uint32_t log_marker;
    uint32_t log_kind;
    mips64_family_page_key_t log_key;
    mips64_family_page_state_t log_target;
    mips64_family_page_key_t log_second_key;
    mips64_family_page_state_t log_second_target;
    uint64_t next_wait_id;
    uint64_t next_mm_id;
    uint64_t wait_bank_base;
    uint64_t wait_bank_capacity;
    uint64_t wait_count;
    uint64_t wait_revision;
    uint32_t wait_bank_index;
    uint32_t wait_bank_reserved;
    uint64_t wait_target_base;
    uint64_t wait_target_capacity;
    uint64_t wait_target_count;
    uint64_t wait_target_revision;
    uint32_t wait_target_index;
    uint32_t wait_reserved;
    uint64_t inode_pin_attempts;
    uint64_t file_count;
    uint64_t next_file_id;
    uint64_t file_target_slot;
    uint64_t file_target_count;
    mips64_file_catalog_record_t file_target;
    uint64_t next_source_id;
    uint64_t source_attempts;
    uint32_t source_mode, source_reserved;
    uint64_t file_index_object;
} mips64_family_control_t;

typedef struct {
    uint64_t magic;
    uint32_t version;
    uint32_t header_size;
    uint64_t capacity;
    uint64_t count;
    uint64_t revision;
    uint64_t checksum;
    uint64_t reserved;
} mips64_family_wait_bank_header_t;

typedef struct {
    mips64_family_page_state_t state;
    uint64_t magic;
    uint32_t version;
    uint32_t size;
    mips64_family_page_key_t key;
} mips64_family_page_file_t;

typedef struct {
    mips64_family_page_state_t state;
    unsigned char padding[MIPS64_OBJECT_SLOT_SIZE - sizeof(mips64_family_page_state_t)];
} mips64_family_object_slot_t;

typedef struct {
    uint64_t magic;
    uint32_t version;
    uint32_t header_size;
    uint64_t object_id;
    uint32_t slot_count;
    uint32_t reserved;
} mips64_family_object_header_t;

typedef struct {
    uint64_t magic;
    uint32_t version;
    uint32_t header_size;
    uint64_t object_id;
    uint32_t slot_count;
    uint32_t reserved;
    unsigned char header_padding[MIPS64_OBJECT_HEADER_SIZE - 32u];
    mips64_family_object_slot_t slots[];
} mips64_family_object_file_t;

_Static_assert(sizeof(mips64_family_page_state_t) == 6192,
               "family page state is a fixed-width record");
_Static_assert(offsetof(mips64_family_control_t, log_marker) == 56,
               "commit marker must retain its aligned control offset");
_Static_assert(offsetof(mips64_family_control_t, file_count) % 8 == 0 &&
               offsetof(mips64_family_control_t, next_file_id) % 8 == 0,
               "catalog publication counters retain native aligned64 stores");
_Static_assert(offsetof(mips64_family_control_t, next_source_id) % 8 == 0 &&
               offsetof(mips64_family_control_t, source_attempts) % 8 == 0,
               "source admission counters are aligned64 stores");
_Static_assert(sizeof(mips64_family_control_t) % 8 == 0,
               "family control record is naturally aligned");
_Static_assert(sizeof(mips64_family_wait_row_t) == 64,
               "wait rows are fixed-width pointer-free records");
_Static_assert(sizeof(mips64_family_wait_bank_header_t) == 56,
               "wait bank header is a fixed-width record");
_Static_assert(sizeof(mips64_family_page_file_t) == 6224,
               "managed page file is a fixed-width versioned record");
_Static_assert(offsetof(mips64_family_page_file_t, state) == 0,
               "managed guest payload starts at the host-page-aligned view");
_Static_assert(sizeof(mips64_family_object_slot_t) == MIPS64_OBJECT_SLOT_SIZE,
               "packed slot is a fixed-width page-aligned record");
_Static_assert(MIPS64_OBJECT_HEADER_SIZE % MIPS64_FAMILY_PAGE_SIZE == 0 &&
               MIPS64_OBJECT_SLOT_SIZE % MIPS64_FAMILY_PAGE_SIZE == 0,
               "every packed guest page begins at a guest-page file offset");
_Static_assert(sizeof(mips64_family_object_header_t) == 32,
               "packed header prefix is a fixed-width record");
_Static_assert(offsetof(mips64_family_object_slot_t, state.bytes) == 0,
               "packed guest bytes begin at the slot boundary");
_Static_assert(offsetof(mips64_family_object_file_t, slots) == MIPS64_OBJECT_HEADER_SIZE,
               "packed object header is a fixed-width versioned record");

struct mips64_family {
    int control_fd;
    int dir_fd;
    mips64_inode_pins_t pins;
    mips64_file_caps_client_t sources;
    mips64_family_control_t *control;
    mips64_family_zero_segment_t zero_control;
    mips64_family_zero_segment_t zero_fragments[MIPS64_ZERO_CONTROL_MAX_FRAGMENTS];
    size_t zero_fragment_count;
    int zero_fragment_pending_fd;
    struct mips64_zero_object_segment *zero_objects;
    bool zero_backing;
    mips64_family_storage_authority_t storage_authority;
    pthread_mutex_t local_mutex;
    mips64_family_guard_t *active_guard;
    pid_t local_pid;
    uint64_t incarnation;
    bool initialized;
    bool creator;
    bool destroying;
    bool cleaned;
    bool poisoned;
    bool exec_active;
    mips64_family_exec_t *exec_prepared;
    mips64_family_inode_observer_t inode_observer;
    void *inode_observer_context;
    atomic_size_t live_views;
    char directory[64];
#ifdef MIPS64_FAMILY_TESTING
    mips64_family_test_hook_t hook;
    void *hook_context;
    bool test_fail_file_recovery_once;
    bool test_fail_unlock_once;
    bool test_fail_child_transfer_attach;
    bool test_fail_exec_activation;
    size_t test_fail_exec_activation_index;
    bool test_fail_wait_replay_once;
#endif
};

typedef struct mips64_zero_object_segment {
    struct mips64_zero_object_segment *next;
    mips64_family_zero_segment_t segment;
    uint64_t object_id;
    size_t size;
} mips64_zero_object_segment_t;

typedef struct {
    mips64_family_zero_segment_t control;
    mips64_zero_object_segment_t root;
    mips64_family_storage_authority_t storage_authority;
} mips64_zero_service_retained_t;

struct mips64_family_exec {
    mips64_family_t *family;
    mips64_family_guard_t *guard;
    mips64_family_exec_state_t state;
    int flags[6];
    size_t capability_count;
    bool active;
};

struct mips64_family_page {
    mips64_family_t *family;
    int fd;
    size_t mapping_size;
    mips64_family_page_file_t *mapping;
    mips64_family_page_key_t key;
};

struct mips64_family_object {
    mips64_family_t *family;
    int fd;
    size_t mapping_size;
    mips64_family_object_file_t *mapping;
    uint64_t object_id;
    uint32_t slot_count;
};
/* Cross-part prototypes (Phase 0 mechanical split). */

 bool mips64_family_key_equal(mips64_family_page_key_t left, mips64_family_page_key_t right);

 bool mips64_family_authority_valid(mips64_family_storage_authority_t authority);

 bool mips64_family_family_authorize_fd(int fd, bool directory,
                                mips64_family_storage_authority_t authority);

 int mips64_family_family_control_extent(const mips64_family_t *family, uint64_t *out);

 mips64_zero_object_segment_t *find_zero_object(mips64_family_t *family,
                                                   uint64_t object_id);

 void mips64_family_close_owned_fds(int control_fd, int dir_fd);

 void mips64_family_close_family_sources(int control_fd, int dir_fd, mips64_inode_pins_t pins,
                                  mips64_file_caps_client_t sources);

void mips64_family_close_capabilities(int control_fd, int dir_fd, mips64_inode_pins_t pins);

void mips64_family_close_source_capabilities(int control_fd, int dir_fd,
                                          mips64_inode_pins_t pins,
                                          mips64_file_caps_client_t sources);

 bool mips64_family_source_caps_present(mips64_file_caps_client_t sources);

 bool mips64_family_distinct_source_fds(int control_fd, int dir_fd, mips64_inode_pins_t pins,
                                mips64_file_caps_client_t sources);

 void mips64_family_family_fds(const mips64_family_t *family, int descriptors[4]);

 size_t mips64_family_family_all_fds(const mips64_family_t *family, int descriptors[6]);

 int mips64_family_lock_file(int fd, short type);

/* Byte zero is the execution token. A nonreused incarnation owns one later
 * byte for its complete attachment lifetime, even while not executing guest
 * code. Locks beyond EOF are POSIX byte locks; no guest data lives here.
 * Never use another control descriptor: closing any such descriptor drops
 * ALL this process's POSIX locks for the inode. */
 bool mips64_family_owner_lease_offset(uint64_t incarnation, off_t *offset);

 int mips64_family_acquire_owner_lease(mips64_family_t *family, uint64_t incarnation);

 int mips64_family_unlock_family_file(mips64_family_t *family);

 bool mips64_family_guard_valid_observed(const mips64_family_guard_t *guard,
                                 mips64_measure_observer_t *measure);

 bool mips64_family_guard_valid(const mips64_family_guard_t *guard);

 int mips64_family_recover_file_state(mips64_family_guard_t *guard);

bool mips64_family_guard_matches(const mips64_family_guard_t *guard,
                             const mips64_family_t *family);

bool mips64_family_guard_matches_observed(const mips64_family_guard_t *guard,
                                      const mips64_family_t *family,
                                      mips64_measure_observer_t *measure);

 int mips64_family_normalize_owned_fd(int *fd_pointer);

 int mips64_family_page_name(mips64_family_page_key_t key, char output[48]);

 int mips64_family_object_name(uint64_t object_id, char output[48]);

 int control_fragment_name(size_t index, char output[48]);

 bool mips64_family_object_file_size(uint32_t slot_count, size_t *size);

 int mips64_family_observe_open_inode(mips64_family_t *family, int fd);

/* A zero-size inode is an identity/authority handle, never the payload. Keep
 * one family attachment for every named object, including between short-lived
 * views and redo replay. The first phase has no cross-process family attach. */
 mips64_family_object_t *map_zero_object(mips64_family_t *family,
                                           uint64_t object_id,
                                           uint32_t requested_count, int fd,
                                           bool initialize);

 mips64_family_object_t *mips64_family_map_object(mips64_family_t *family, uint64_t object_id,
                                      uint32_t requested_count, int fd,
                                      bool initialize);

 mips64_family_page_t *mips64_family_map_page(mips64_family_t *family, mips64_family_page_key_t key,
                                  int fd, bool initialize);

 void mips64_family_apply_absolute_state(mips64_family_page_state_t *destination,
                                 const mips64_family_page_state_t *target,
                                 mips64_family_t *family, bool recovery);

 mips64_family_object_t *mips64_family_open_logged_object(mips64_family_t *family,
                                               mips64_family_page_key_t key);

 uint64_t mips64_family_wait_checksum(const void *data, size_t size);

 bool mips64_family_wait_bank_size(uint64_t capacity, size_t *size);

 bool mips64_family_wait_pair_end(uint64_t base, uint64_t capacity, uint64_t *end);

 bool mips64_family_wait_offset(uint64_t base, uint32_t index, uint64_t capacity,
                        uint64_t *offset);

 int mips64_family_wait_pread_full(int fd, void *buffer, size_t size, uint64_t offset);

 int mips64_family_wait_pwrite_full(int fd, const void *buffer, size_t size, uint64_t offset);

/* Every fragment has its own zero-length authority inode and one marked
 * segment. Keep the attachment until family destruction: the descriptor is
 * only a locator and cannot revive a segment after its final detach. */
 int create_control_fragment(mips64_family_t *family);

 int mips64_family_ensure_control_extent(mips64_family_t *family, uint64_t end);

 int control_span(mips64_family_t *family, uint64_t offset,
                        unsigned char **address, size_t *available);

 int mips64_family_family_control_read(mips64_family_t *family, void *buffer,
                               size_t size, uint64_t offset);

 int mips64_family_family_control_write(mips64_family_t *family, const void *buffer,
                                size_t size, uint64_t offset);

 int mips64_family_read_wait_bank(mips64_family_t *family, uint64_t base, uint32_t index,
                          uint64_t capacity, uint64_t count, uint64_t revision,
                          mips64_family_wait_row_t **rows_out);

 int mips64_family_write_wait_bank(mips64_family_t *family, uint64_t base, uint32_t index,
                           uint64_t capacity, uint64_t count, uint64_t revision,
                           const mips64_family_wait_row_t *rows);

 int mips64_family_replay_committed(mips64_family_t *family);

 int mips64_family_initialize_family(mips64_family_t **out, int control_fd, int dir_fd,
                             mips64_inode_pins_t pins, mips64_file_caps_client_t sources,
                             bool creator, const char *directory,
                             bool terminal_sources,
                             mips64_family_storage_authority_t authority);

int mips64_family_attach(mips64_family_t **out, int owned_control_fd, int owned_dir_fd,
                       mips64_inode_pins_t owned_pins);

int mips64_family_attach_with_sources(mips64_family_t **out, int owned_control_fd,
                                    int owned_dir_fd, mips64_inode_pins_t owned_pins,
                                    mips64_file_caps_client_t owned_sources);

 bool exec_guard_valid(const mips64_family_exec_t *exec);

 bool mips64_family_exec_identity_matches(int control_fd, int dir_fd,
                                   const mips64_family_identity_t *identity);

 int exec_prepare(mips64_family_guard_t *guard, mips64_family_exec_t **out,
                         bool with_sources);

int mips64_family_exec_prepare(mips64_family_guard_t *guard, mips64_family_exec_t **out);

int mips64_family_exec_prepare_sources(mips64_family_guard_t *guard, mips64_family_exec_t **out);

const mips64_family_exec_state_t *mips64_family_exec_state(const mips64_family_exec_t *exec);

int mips64_family_exec_capabilities(const mips64_family_exec_t *exec, int output[4]);

int mips64_family_exec_source_capabilities(const mips64_family_exec_t *exec, int output[6]);

 int exec_restore_flags(mips64_family_exec_t *exec);

int mips64_family_exec_activate(mips64_family_exec_t *exec);

int mips64_family_exec_deactivate(mips64_family_exec_t *exec);

int mips64_family_exec_destroy(mips64_family_exec_t **owned);

 int exec_receive(mips64_family_t **out, mips64_family_guard_t *guard,
                         int owned_control_fd, int owned_dir_fd,
                         mips64_inode_pins_t owned_pins, mips64_file_caps_client_t sources,
                         const mips64_family_exec_state_t *state, bool terminal_sources);

int mips64_family_exec_receive(mips64_family_t **out, mips64_family_guard_t *guard,
                            int owned_control_fd, int owned_dir_fd,
                            mips64_inode_pins_t owned_pins,
                            const mips64_family_exec_state_t *state);

int mips64_family_exec_receive_sources(mips64_family_t **out, mips64_family_guard_t *guard,
                                    int owned_control_fd, int owned_dir_fd,
                                    mips64_inode_pins_t owned_pins,
                                    mips64_file_caps_client_t owned_sources,
                                    const mips64_family_exec_state_t *state);

int mips64_family_exec_receive_sources_terminal(mips64_family_t **out,
                                    mips64_family_guard_t *guard,
                                    int owned_control_fd, int owned_dir_fd,
                                    mips64_inode_pins_t owned_pins,
                                    mips64_file_caps_client_t owned_sources,
                                    const mips64_family_exec_state_t *state);

int mips64_family_fork_child_transfer(mips64_family_t **inherited,
                                   mips64_family_t **attached);

int mips64_family_create_with_authority(mips64_family_t **out,
                                     mips64_family_storage_authority_t authority);

int mips64_family_create(mips64_family_t **out);

/* Only for a new, never-published family: the service predates its creation,
 * and there are no workers, views or borrowed native capabilities. Discarding
 * unreachable staging does not need replay. Cancellation is restored only
 * when this guard is still held, and only after the local FDs are destroyed.
 * A guard that leave already released is not changed here. */
 void discard_unpublished_family(mips64_family_t *family, mips64_family_guard_t *guard);

int mips64_family_create_with_sources_authority(mips64_family_t **out,
    mips64_file_caps_client_t *owned, mips64_family_storage_authority_t authority);

int mips64_family_create_with_sources(mips64_family_t **out, mips64_file_caps_client_t *owned);

 int mips64_family_family_enter_internal(mips64_family_t *family, mips64_family_guard_t *guard,
                                 bool allow_retired);

int mips64_family_enter(mips64_family_t *family, mips64_family_guard_t *guard);

int mips64_family_leave(mips64_family_guard_t *guard);

int mips64_family_leave_with_cleanup(mips64_family_guard_t *guard,
                                  void (*after_unlock)(void *context),
                                  void *context);

uint64_t mips64_family_incarnation(const mips64_family_t *family);

bool mips64_family_zero_backing(const mips64_family_t *family);

int mips64_family_owner_alive(const mips64_family_guard_t *guard, uint64_t incarnation,
                           bool *alive);

int mips64_family_identity(const mips64_family_guard_t *guard,
                        mips64_family_identity_t *out);

int mips64_family_pin_file(mips64_family_guard_t *guard, int source_fd);

const mips64_file_caps_client_t *mips64_family_sources(const mips64_family_guard_t *guard);

uint64_t mips64_family_file_index_object(const mips64_family_guard_t *guard);

 int reject_source_inode(void *context, const struct stat *candidate);

int mips64_family_file_target_check(mips64_family_guard_t *guard, int source_fd);

int mips64_family_source_register(mips64_family_guard_t *guard,
                                int source_fd, uint64_t *source_id);

/* The sole control FD also owns this reserved extent. Never reopen/duplicate
 * it: closing any second descriptor would release the process's token lock. */
 int mips64_family_read_file_catalog(mips64_family_t *family, size_t count,
                              mips64_file_catalog_record_t **out);

 int find_file_record(const mips64_file_catalog_record_t *records, size_t count,
                             uint64_t next_id, const mips64_file_identity_t *identity,
                             uint64_t *id);

 int apply_file_record(mips64_family_t *family);

 int replay_file_record(mips64_family_t *family);

int mips64_family_file_intern(mips64_family_guard_t *guard,
                           const mips64_file_identity_t *identity, int source_fd,
                           uint64_t *file_id);

 int catalog_wait_keys(mips64_family_t *family,
                               const mips64_family_wait_row_t *rows, size_t count);

uint64_t mips64_family_recovery_epoch(const mips64_family_guard_t *guard);

const char *mips64_family_private_directory(const mips64_family_t *family);

int mips64_family_observe_inodes(mips64_family_guard_t *guard,
                             mips64_family_inode_observer_t observer, void *context);

int mips64_family_unobserve_inodes(mips64_family_guard_t *guard);

int mips64_family_page_create(mips64_family_guard_t *guard, mips64_family_page_t **out);

int mips64_family_page_open(mips64_family_guard_t *guard, mips64_family_page_key_t key,
                        mips64_family_page_t **out);

void mips64_family_page_close(mips64_family_page_t *page);

mips64_family_page_key_t mips64_family_page_key(const mips64_family_page_t *page);

const mips64_family_page_state_t *mips64_family_page_readonly(const mips64_family_guard_t *guard,
                                                       const mips64_family_page_t *page);

 int validate_target_mode(const mips64_family_page_state_t *current,
                                const mips64_family_page_state_t *target,
                                bool file_refresh);

 int validate_target(const mips64_family_page_state_t *current,
                           const mips64_family_page_state_t *target);

 int mips64_family_commit_states(mips64_family_guard_t *guard, uint32_t kind, size_t count,
                         const mips64_family_page_key_t keys[2],
                         mips64_family_page_state_t *const destinations[2],
                         const mips64_family_page_state_t *const targets[2],
                         bool file_refresh);

 int validate_wait_root(mips64_family_t *family,
                              mips64_family_wait_row_t **rows_out);

int mips64_family_wait_backend_read(mips64_family_guard_t *guard,
                                mips64_family_wait_table_t *table);

 bool mips64_family_catalog_reserved_end(uint64_t *end);

 bool wait_aligned_control_end(uint64_t *end);

 bool mips64_family_wait_control_max_size(off_t *size_out);

 void truncate_growth_tail(mips64_family_t *family, uint64_t old_end);

int mips64_family_wait_backend_commit(mips64_family_guard_t *guard,
                                  mips64_family_wait_table_t *table,
                                  const mips64_family_object_update_t *updates,
                                  size_t update_count);

int mips64_family_wait_backend_id(mips64_family_guard_t *guard, bool mm_id,
                              uint64_t *out);

int mips64_family_page_commit(mips64_family_guard_t *guard, mips64_family_page_t *page,
                          const mips64_family_page_state_t *target);

int mips64_family_object_create(mips64_family_guard_t *guard, uint32_t slot_count,
                            mips64_family_object_t **out);

int mips64_family_object_open(mips64_family_guard_t *guard, uint64_t object_id,
                          mips64_family_object_t **out);

void mips64_family_object_close(mips64_family_object_t *object);

uint64_t mips64_family_object_id(const mips64_family_object_t *object);

uint32_t mips64_family_object_count(const mips64_family_object_t *object);

int mips64_family_object_snapshot_observed(const mips64_family_guard_t *guard,
                                       const mips64_family_object_t *object,
                                       uint32_t page_index, mips64_family_page_state_t *out,
                                       mips64_measure_observer_t *measure);

int mips64_family_object_snapshot(const mips64_family_guard_t *guard,
                              const mips64_family_object_t *object,
                              uint32_t page_index, mips64_family_page_state_t *out);

int mips64_family_object_commitv(mips64_family_guard_t *guard,
                             const mips64_family_object_update_t *updates,
                             size_t count);

int mips64_family_object_commit(mips64_family_guard_t *guard, mips64_family_object_t *object,
                            uint32_t page_index,
                            const mips64_family_page_state_t *target);

int mips64_family_object_commit_file_refresh(mips64_family_guard_t *guard,
                                         mips64_family_object_t *object,
                                         uint32_t page_index,
                                         const mips64_family_page_state_t *target);

 int cleanup_held(mips64_family_guard_t *guard, bool fresh_scan);

int mips64_family_cleanup(mips64_family_t *family);

int mips64_family_cleanup_held_terminal(mips64_family_guard_t *guard,
                                    bool sole_family_owner);

int mips64_family_register_service_cleanup(mips64_family_guard_t *guard,
                                       bool *may_have_delegated);

void mips64_family_cleanup_service_release(void *retained);

int mips64_family_cleanup_service_prepare_authority(int borrowed_control_fd,
    int borrowed_directory_fd, const char *directory, void **out,
    mips64_family_storage_authority_t authority);

int mips64_family_cleanup_service_prepare(int borrowed_control_fd,
                                      int borrowed_directory_fd,
                                      const char *directory, void **out);

int mips64_family_cleanup_service_prepare_context(int borrowed_control_fd,
    int borrowed_directory_fd, const char *directory, void **out,
    void *context);

 int cleanup_service(int borrowed_control_fd,
                           int borrowed_directory_fd,
                           const char *directory, void *retained);

int mips64_family_cleanup_service(int borrowed_control_fd,
                              int borrowed_directory_fd,
                              const char *directory);

int mips64_family_cleanup_service_retained(int borrowed_control_fd,
                                       int borrowed_directory_fd,
                                       const char *directory, void *retained);

int mips64_family_destroy(mips64_family_t *family);

#ifdef MIPS64_FAMILY_TESTING
void mips64_family_test_set_hook(mips64_family_t *family, mips64_family_test_hook_t hook,
                             void *context);
/* Cross-part externs (Phase 0 mechanical split). */
extern  bool mips64_family_wait_control_max_size(off_t *size_out);
extern  int validate_target(const mips64_family_page_state_t *current,
                           const mips64_family_page_state_t *target);
extern  bool mips64_family_catalog_reserved_end(uint64_t *end);
extern  int replay_file_record(mips64_family_t *family);
extern  int catalog_wait_keys(mips64_family_t *family,
                               const mips64_family_wait_row_t *rows, size_t count);
#endif /* MIPS64RT_FAMILY_PARTS_H */
