/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef MIPS64RT_GUEST_MEMORY_PARTS_H
#define MIPS64RT_GUEST_MEMORY_PARTS_H

#include "runtime/guest_memory.h"
#include "runtime/family_file_index_internal.h"

#include "memory/family_backing.h"
#include "runtime/exec_tid.h"
#include "runtime/family.h"
#include "runtime/family_wait.h"
#include "runtime/mm_view.h"

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef enum {
    MIPS64_GUEST_MEMORY_STARTING,
    MIPS64_GUEST_MEMORY_READY,
    MIPS64_GUEST_MEMORY_STOPPING,
    MIPS64_GUEST_MEMORY_STOPPED,
    MIPS64_GUEST_MEMORY_FATAL
} guest_memory_phase_t;

typedef enum {
    MIPS64_WORKER_IDLE,
    MIPS64_WORKER_WAITING,
    MIPS64_WORKER_HELD
} worker_phase_t;

struct mips64_guest_memory_worker {
    mips64_guest_memory_t *session;
    mips64_family_guard_t guard;
    pthread_t owner;
    struct mips64_guest_memory_worker *next;
    worker_phase_t phase;
    int previous_cancel_state;
    bool initial;
    bool admitted, retiring, retired, cleanup_only;
    uint64_t task_id;
};

struct mips64_guest_memory {
    mips64_family_t *family;
    mips64_family_backing_t *backing;
    mips64_process_memory_t *owned_image; /* Child owns backing through image. */
    mips64_path_resolver_t *resolver; /* Borrowed through finish. */
    pid_t owner_pid;
    uint64_t mm_id;
    mips64_mm_view_t *mm_view;
    mips64_space_t *canonical_space; /* Owns contents, borrows stable storage. */
    mips64_linux_memory_t *canonical_memory;
    pthread_mutex_t lock;
    pthread_cond_t changed;
    mips64_guest_memory_worker_t initial;
    mips64_guest_memory_worker_t *workers;
    mips64_guest_memory_worker_t *held_worker;
    size_t extra_workers;
    uint64_t last_task_id;
    mips64_guest_memory_retirement_t *retirement;
    guest_memory_phase_t phase;
    bool observing;
    bool bound;
    bool transitioning;
    bool owns_family_cleanup;
    bool cleanup_registration_attempted;
    bool cleanup_delegated; /* Accepted locally or inherited by fork/exec. */
    bool family_creator; /* Immutable family origin, including terminal exec. */
    bool fork_frozen;
    /* Ordinary attach and legacy fork remain gated for source sessions;
     * canonical sessions use explicit worker admission and fork images. */
    bool source_restricted;
    bool terminal_only; /* Clean replay returned after source-peer death. */
    bool terminal_replay_complete;
#ifdef MIPS64_GUEST_MEMORY_TEST_TRANSITION
    void (*test_transition_hook)(void *);
    void *test_transition_context;
#endif
};

struct mips64_guest_memory_fork_freeze {
    mips64_guest_memory_t *session;
    mips64_guest_memory_worker_t *caller;
    pid_t parent_pid;
    int previous_cancel_state;
    mips64_family_exec_t *exec;
    bool exec_only;
    bool canonical_checked;
    mips64_family_mm_t canonical_mm;
    uint64_t canonical_caller_task;
    uint64_t *canonical_tasks; /* Owned here; callers borrow while sealed. */
    size_t canonical_task_count;
    mips64_mm_fork_image_t *canonical_child;
    mips64_mm_join_image_t *canonical_join;
    bool canonical_shared_owners;
};

struct mips64_guest_memory_retirement {
    mips64_guest_memory_t *session;
    mips64_guest_memory_worker_t *caller, *target;
    mips64_family_mm_t mm;
    mips64_family_mm_state_t state;
};
/* Cross-part prototypes (Phase 0 mechanical split). */

 bool mips64_guest_memory_local_session(const mips64_guest_memory_t *session);

/* A pthread synchronization failure makes ownership uncertain. The family
 * control descriptor must not be closed through ordinary cleanup in that case. */
 void mips64_guest_memory_lifecycle_lock(mips64_guest_memory_t *session);

 void mips64_guest_memory_lifecycle_unlock(mips64_guest_memory_t *session);

#ifdef MIPS64_GUEST_MEMORY_TEST_TRANSITION
void mips64_guest_memory_test_set_transition_hook(mips64_guest_memory_t *session,
                                              void (*hook)(void *), void *context);

 void mips64_guest_memory_lifecycle_signal(mips64_guest_memory_t *session);

 bool mips64_guest_memory_owned_by_current(const mips64_guest_memory_worker_t *worker);

 void mips64_guest_memory_restore_cancellation(int previous_state);

 int mips64_guest_memory_observe_inode(void *context, const struct stat *status);

 void mips64_guest_memory_poison(mips64_guest_memory_t *session);

 int allocate_session(mips64_guest_memory_t **out, mips64_path_resolver_t *resolver);

 int adopt_space(mips64_guest_memory_t *session, mips64_space_t *space,
                        uint32_t slots_per_object);

 bool valid_start(mips64_guest_memory_t **out, mips64_space_t *space,
                         mips64_path_resolver_t *resolver, uint32_t slots_per_object);

 int start_session(mips64_guest_memory_t **out, mips64_space_t *space,
                           mips64_path_resolver_t *resolver, uint32_t slots_per_object,
                           mips64_linux_memory_t *canonical_memory, uint64_t task_id,
                           mips64_file_caps_client_t *sources,
                           mips64_file_identity_policy_t identity_policy,
                           mips64_family_storage_authority_t authority);

int mips64_guest_memory_start(mips64_guest_memory_t **out, mips64_space_t *space,
                          mips64_path_resolver_t *resolver, uint32_t slots_per_object);

int mips64_guest_memory_start_authority(mips64_guest_memory_t **out, mips64_space_t *space,
                          mips64_path_resolver_t *resolver, uint32_t slots_per_object,
                          mips64_family_storage_authority_t authority);

int mips64_guest_memory_start_canonical(mips64_guest_memory_t **out, mips64_space_t *space,
                                    mips64_path_resolver_t *resolver, uint32_t slots_per_object,
                                    mips64_linux_memory_t *memory, uint64_t initial_task_id);

 int start_owned_sources(mips64_guest_memory_t **out,
                               mips64_space_t *space, mips64_path_resolver_t *resolver,
                               uint32_t slots_per_object,
                               mips64_linux_memory_t *memory, uint64_t initial_task_id,
                               mips64_file_caps_client_t *owned_sources,
                               mips64_file_identity_policy_t identity_policy,
                               mips64_family_storage_authority_t authority);

int mips64_guest_memory_start_canonical_sources(mips64_guest_memory_t **out,
                                    mips64_space_t *space, mips64_path_resolver_t *resolver,
                                    uint32_t slots_per_object,
                                    mips64_linux_memory_t *memory, uint64_t initial_task_id,
                                    mips64_file_caps_client_t *owned_sources,
                                    mips64_file_identity_policy_t identity_policy);

int mips64_guest_memory_start_canonical_sources_authority(mips64_guest_memory_t **out,
                                    mips64_space_t *space, mips64_path_resolver_t *resolver,
                                    uint32_t slots_per_object,
                                    mips64_linux_memory_t *memory, uint64_t initial_task_id,
                                    mips64_file_caps_client_t *owned_sources,
                                    mips64_file_identity_policy_t identity_policy,
                                    mips64_family_storage_authority_t authority);

int mips64_guest_memory_start_borrowed_sources(mips64_guest_memory_t **out,
                                    mips64_space_t *space, mips64_path_resolver_t *resolver,
                                    uint32_t slots_per_object,
                                    mips64_file_caps_client_t *owned_sources);

 int replay_exec_exit(mips64_family_guard_t *guard,
                            const mips64_family_exec_state_t *state,
                            mips64_family_mm_t old_mm,
                            const mips64_exec_tid_clear_t *intents, size_t count);

 int exec_receive_clear_mm(mips64_guest_memory_t **out,
                               int owned_control_fd, int owned_directory_fd,
                               mips64_inode_pins_t owned_pins,
                               mips64_file_caps_client_t sources,
                               const mips64_family_exec_state_t *state,
                               mips64_family_mm_t old_mm,
                               const mips64_exec_tid_clear_t *intents, size_t count);

int mips64_guest_memory_exec_receive_clear_mm(mips64_guest_memory_t **out,
                               int owned_control_fd, int owned_directory_fd,
                               mips64_inode_pins_t owned_pins,
                               const mips64_family_exec_state_t *state,
                               uint64_t old_mm_id,
                               const mips64_exec_tid_clear_t *intents, size_t count);

int mips64_guest_memory_exec_outside_guard(mips64_guest_memory_t *session,
                                      int (*operation)(void *), void *opaque);

int mips64_guest_memory_exec_receive_sources_mm(mips64_guest_memory_t **out,
                               int owned_control_fd, int owned_directory_fd,
                               mips64_inode_pins_t owned_pins,
                               mips64_file_caps_client_t owned_sources,
                               const mips64_family_exec_state_t *state,
                               uint64_t old_mm_id,
                               const mips64_exec_tid_clear_t *intents, size_t count);

 int retire_old_canonical_mm(mips64_family_guard_t *guard,
                                   const mips64_family_exec_state_t *state,
                                   mips64_family_mm_t old_mm, uint64_t old_task_id);

int mips64_guest_memory_exec_receive_sources_canonical_mm(mips64_guest_memory_t **out,
                               int owned_control_fd, int owned_directory_fd,
                               mips64_inode_pins_t owned_pins,
                               mips64_file_caps_client_t owned_sources,
                               const mips64_family_exec_state_t *state,
                               mips64_family_mm_t old_mm, uint64_t old_task_id,
                               const mips64_exec_tid_clear_t *intents, size_t count);

 int require_idle_file_cursor(mips64_family_guard_t *guard);

 int receive_clean_source_exec(
                               mips64_guest_memory_t **out,
                               int owned_control_fd, int owned_directory_fd,
                               mips64_inode_pins_t owned_pins,
                               mips64_file_caps_client_t owned_sources,
                               const mips64_family_exec_state_t *state,
                               mips64_family_mm_t old_mm, uint64_t old_task_id,
                               const mips64_exec_tid_clear_t *intents, size_t count);

 int exec_receive_sources_canonical_mm_classified(
                               mips64_guest_memory_t **out,
                               int owned_control_fd, int owned_directory_fd,
                               mips64_inode_pins_t owned_pins,
                               mips64_file_caps_client_t owned_sources,
                               const mips64_family_exec_state_t *state,
                               mips64_family_mm_t old_mm, uint64_t old_task_id,
                               const mips64_exec_tid_clear_t *intents, size_t count,
                               bool cleanup_delegated);

int mips64_guest_memory_exec_receive_sources_canonical_mm_classified(
                               mips64_guest_memory_t **out,
                               int owned_control_fd, int owned_directory_fd,
                               mips64_inode_pins_t owned_pins,
                               mips64_file_caps_client_t owned_sources,
                               const mips64_family_exec_state_t *state,
                               mips64_family_mm_t old_mm, uint64_t old_task_id,
                               const mips64_exec_tid_clear_t *intents, size_t count);

#ifdef MIPS64_RUNTIME_TEST_ATTRIBUTED_FILE
int mips64_guest_memory_exec_receive_sources_canonical_mm_classified_delegated(
                               mips64_guest_memory_t **out,
                               int owned_control_fd, int owned_directory_fd,
                               mips64_inode_pins_t owned_pins,
                               mips64_file_caps_client_t owned_sources,
                               const mips64_family_exec_state_t *state,
                               mips64_family_mm_t old_mm, uint64_t old_task_id,
                               const mips64_exec_tid_clear_t *intents, size_t count);

int mips64_guest_memory_exec_replay_dead_sources(
                               mips64_guest_memory_t **out,
                               int owned_control_fd, int owned_directory_fd,
                               mips64_inode_pins_t owned_pins,
                               mips64_file_caps_client_t owned_sources,
                               const mips64_family_exec_state_t *state,
                               mips64_family_mm_t old_mm, uint64_t old_task_id,
                               const mips64_exec_tid_clear_t *intents, size_t count);

int mips64_guest_memory_terminal_cleanup(mips64_guest_memory_t *session,
                                     bool proven_sole_family_owner);

int mips64_guest_memory_exec_receive_clear(mips64_guest_memory_t **out,
                               int owned_control_fd, int owned_directory_fd,
                               mips64_inode_pins_t owned_pins,
                               const mips64_family_exec_state_t *state,
                               const mips64_exec_tid_clear_t *intents, size_t count);

int mips64_guest_memory_exec_adopt(mips64_guest_memory_t *session,
                               mips64_space_t *space, mips64_path_resolver_t *resolver,
                               uint32_t slots_per_object);

int mips64_guest_memory_exec_adopt_canonical(mips64_guest_memory_t *session,
                               mips64_space_t *space, mips64_linux_memory_t *memory,
                               mips64_path_resolver_t *resolver,
                               uint32_t slots_per_object, uint64_t initial_task_id,
                               mips64_file_identity_policy_t identity_policy);

bool mips64_guest_memory_owns_image(const mips64_guest_memory_t *session,
                                const mips64_space_t *space,
                                const mips64_linux_memory_t *memory);

bool mips64_guest_memory_family_creator(const mips64_guest_memory_t *session);

bool mips64_guest_memory_zero_backing(const mips64_guest_memory_t *session);

int mips64_guest_memory_exec_start_with_clear(mips64_guest_memory_t **out,
                               mips64_space_t *space, mips64_path_resolver_t *resolver,
                               uint32_t slots_per_object,
                               int owned_control_fd, int owned_directory_fd,
                               mips64_inode_pins_t owned_pins,
                               const mips64_family_exec_state_t *state,
                               const mips64_exec_tid_clear_t *intents, size_t count);

int mips64_guest_memory_exec_start(mips64_guest_memory_t **out, mips64_space_t *space,
                               mips64_path_resolver_t *resolver,
                               uint32_t slots_per_object,
                               int owned_control_fd, int owned_directory_fd,
                               mips64_inode_pins_t owned_pins,
                               const mips64_family_exec_state_t *state);

int mips64_guest_memory_prepare_child(mips64_guest_memory_t *parent,
                                  const mips64_linux_memory_t *vmas,
                                  mips64_process_memory_t **out);

 int freeze_begin(mips64_guest_memory_worker_t *caller,
                        mips64_guest_memory_fork_freeze_t **out, bool exec_only);

int mips64_guest_memory_fork_freeze_begin(mips64_guest_memory_worker_t *caller,
                                      mips64_guest_memory_fork_freeze_t **out);

int mips64_guest_memory_exec_freeze_begin(mips64_guest_memory_worker_t *caller,
                                      mips64_guest_memory_fork_freeze_t **out);

int mips64_guest_memory_fork_freeze_end(mips64_guest_memory_fork_freeze_t **owned);

int mips64_guest_memory_exec_prepare(mips64_guest_memory_fork_freeze_t *freeze,
                                 mips64_family_exec_t **out);

 int compare_task_id(const void *left, const void *right);

int mips64_guest_memory_exec_canonical_identity(mips64_guest_memory_fork_freeze_t *freeze,
                                 mips64_family_mm_t *out_mm, uint64_t *out_task_id);

int mips64_guest_memory_exec_canonical_members(mips64_guest_memory_fork_freeze_t *freeze,
                                 const uint64_t **out_tasks, size_t *out_count);

int mips64_guest_memory_exec_shared_owners(mips64_guest_memory_fork_freeze_t *freeze,
                                      bool *out);

int mips64_guest_memory_exec_capture_clear_tids(mips64_guest_memory_fork_freeze_t *freeze,
                                  const mips64_linux_memory_t *memory,
                                  const uint64_t *addresses, size_t count,
                                  mips64_exec_tid_clear_t **out, size_t *out_count);

int mips64_guest_memory_exec_capture_clear_tids_tagged(
                                  mips64_guest_memory_fork_freeze_t *freeze,
                                  const mips64_linux_memory_t *memory,
                                  const mips64_exec_tid_request_t *requests,
                                  size_t count,
                                  mips64_exec_tid_clear_t **out, size_t *out_count);

int mips64_guest_memory_prepare_child_frozen(mips64_guest_memory_fork_freeze_t *freeze,
                                         const mips64_linux_memory_t *vmas,
                                         mips64_process_memory_t **out);

 int prepare_child_canonical_frozen(
    mips64_guest_memory_fork_freeze_t *freeze, bool shared);

int mips64_guest_memory_prepare_child_canonical_frozen(
    mips64_guest_memory_fork_freeze_t *freeze);

int mips64_guest_memory_prepare_child_shared_frozen(
    mips64_guest_memory_fork_freeze_t *freeze);

 int fork_child_start(mips64_guest_memory_fork_freeze_t **frozen,
                            mips64_guest_memory_t **copied_parent,
                            mips64_linux_memory_t *copied_vmas,
                            mips64_space_t *copied_space,
                            mips64_file_registry_t *copied_files,
                            mips64_process_memory_t **prepared,
                            mips64_path_resolver_t *resolver,
                            uint32_t slots_per_object,
                            mips64_guest_memory_t **out);

int mips64_guest_memory_fork_child_start(mips64_guest_memory_t **copied_parent,
                                     mips64_linux_memory_t *copied_vmas,
                                     mips64_space_t *copied_space,
                                     mips64_file_registry_t *copied_files,
                                     mips64_process_memory_t **prepared,
                                     mips64_path_resolver_t *resolver,
                                     uint32_t slots_per_object,
                                     mips64_guest_memory_t **out);

int mips64_guest_memory_fork_child_start_frozen(
    mips64_guest_memory_fork_freeze_t **freeze,
    mips64_guest_memory_t **copied_parent, mips64_linux_memory_t *copied_vmas,
    mips64_space_t *copied_space, mips64_file_registry_t *copied_files,
    mips64_process_memory_t **prepared, mips64_path_resolver_t *resolver,
    uint32_t slots_per_object, mips64_guest_memory_t **out);

 int fork_child_start_canonical_frozen(
    mips64_guest_memory_fork_freeze_t **frozen,
    mips64_guest_memory_t **copied_parent, mips64_linux_memory_t *copied_vmas,
    mips64_space_t *copied_space, mips64_file_registry_t *copied_files,
    mips64_path_resolver_t *resolver, uint32_t slots_per_object,
    uint64_t child_task_id, mips64_guest_memory_t **out, bool shared);

int mips64_guest_memory_fork_child_start_canonical_frozen(
    mips64_guest_memory_fork_freeze_t **frozen,
    mips64_guest_memory_t **copied_parent, mips64_linux_memory_t *copied_vmas,
    mips64_space_t *copied_space, mips64_file_registry_t *copied_files,
    mips64_path_resolver_t *resolver, uint32_t slots_per_object,
    uint64_t child_task_id, mips64_guest_memory_t **out);

int mips64_guest_memory_fork_child_start_shared_frozen(
    mips64_guest_memory_fork_freeze_t **frozen,
    mips64_guest_memory_t **copied_parent, mips64_linux_memory_t *copied_vmas,
    mips64_space_t *copied_space, mips64_file_registry_t *copied_files,
    mips64_path_resolver_t *resolver, uint32_t slots_per_object,
    uint64_t child_task_id, mips64_guest_memory_t **out);

mips64_space_t *mips64_guest_memory_child_space(mips64_guest_memory_t *session);

mips64_linux_memory_t *mips64_guest_memory_child_vmas(mips64_guest_memory_t *session);

mips64_file_registry_t *mips64_guest_memory_child_files(mips64_guest_memory_t *session);

mips64_guest_memory_worker_t *mips64_guest_memory_initial_worker(mips64_guest_memory_t *session);

bool mips64_guest_memory_worker_active(const mips64_guest_memory_worker_t *worker);

bool mips64_guest_memory_active(const mips64_guest_memory_t *session);

bool mips64_guest_memory_worker_resources(mips64_guest_memory_worker_t *worker,
    mips64_family_guard_t **guard, mips64_family_backing_t **backing, uint64_t *mm_id);

mips64_mm_view_t *mips64_guest_memory_worker_mm(mips64_guest_memory_worker_t *worker);

 int worker_attach(mips64_guest_memory_t *session, uint64_t task_id,
                         bool canonical, mips64_guest_memory_worker_t **out);

int mips64_guest_memory_worker_attach(mips64_guest_memory_t *session,
                                   mips64_guest_memory_worker_t **out);

int mips64_guest_memory_worker_attach_task(mips64_guest_memory_t *session,
                                       uint64_t task_id,
                                       mips64_guest_memory_worker_t **out);

 bool held_canonical_caller(const mips64_guest_memory_worker_t *caller);

 int member_order(mips64_family_mm_member_t left,
                        mips64_family_mm_member_t right);

 bool session_has_worker(const mips64_guest_memory_t *session,
                               const mips64_guest_memory_worker_t *target);

 bool state_has_member(const mips64_family_mm_state_t *state,
                             mips64_family_mm_member_t member);

int mips64_guest_memory_worker_admit(mips64_guest_memory_worker_t *caller,
                                  mips64_guest_memory_worker_t *child);

int mips64_guest_memory_worker_retire_prepare(mips64_guest_memory_worker_t *caller,
                                          mips64_guest_memory_worker_t *target,
                                          mips64_guest_memory_retirement_t **out);

int mips64_guest_memory_worker_retire_commit(mips64_guest_memory_retirement_t **owned);

 int worker_enter(mips64_guest_memory_worker_t *worker, bool cleanup);

int mips64_guest_memory_worker_enter(mips64_guest_memory_worker_t *worker);

int mips64_guest_memory_worker_enter_cleanup(mips64_guest_memory_worker_t *initial);

bool mips64_guest_memory_worker_cleanup_guard(mips64_guest_memory_worker_t *initial,
                                           mips64_family_guard_t **guard);

int mips64_guest_memory_worker_leave(mips64_guest_memory_worker_t *worker);

int mips64_guest_memory_worker_detach(mips64_guest_memory_worker_t **owned);

int mips64_guest_memory_round_trip(mips64_guest_memory_t *session);

int mips64_guest_memory_stop(mips64_guest_memory_t *session);

 int guest_memory_finish(mips64_guest_memory_t **owned, bool restore_prior,
                               int *prior_state);

int mips64_guest_memory_finish(mips64_guest_memory_t **owned);

int mips64_guest_memory_finish_keep_cancellation_disabled(mips64_guest_memory_t **owned,
                                                       int *prior_state);

int mips64_guest_memory_register_service_cleanup(mips64_guest_memory_t *session);

bool mips64_guest_memory_service_cleanup_delegated(const mips64_guest_memory_t *session);

int mips64_guest_memory_departure_begin(mips64_guest_memory_t *session,
                                   mips64_file_caps_departure_t *out);

const char *mips64_guest_memory_private_directory(const mips64_guest_memory_t *session);
/* Cross-part externs (Phase 0 mechanical split). */
extern /* Only the sealing thread observes this pointer. It prevents accidental
 * recursive entry into its held lifecycle mutex, including after native fork. */
 _Thread_local mips64_guest_memory_t *mips64_guest_memory_local_frozen_session;
#endif /* MIPS64RT_GUEST_MEMORY_PARTS_H */
