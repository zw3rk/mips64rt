/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef MIPS64RT_RT64_RUNTIME_FAMILY_H
#define MIPS64RT_RT64_RUNTIME_FAMILY_H

#include "runtime/private_inodes.h"
#include "runtime/inode_pins.h"
#include "runtime/file_caps.h"
#include "runtime/family_authority.h"
#include "runtime/measure.h"
#include "memory/file_identity.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/types.h>

#define MIPS64_FAMILY_PAGE_SIZE 4096u
#define MIPS64_FAMILY_EPOCHS 256u
#define MIPS64_FAMILY_OBJECT_MAX_SLOTS 4096u

typedef struct mips64_family mips64_family_t;
typedef struct mips64_family_page mips64_family_page_t;
typedef struct mips64_family_object mips64_family_object_t;

/* Internal Linux hard-zero first phase. This immutable construction choice
 * permits no native fork/exec or additional guest workers. */
bool mips64_family_zero_backing(const mips64_family_t *family);
typedef struct mips64_family_exec mips64_family_exec_t;


typedef struct {
    uint64_t object_id;
    uint64_t page_index;
} mips64_family_page_key_t;

typedef struct {
    unsigned char bytes[MIPS64_FAMILY_PAGE_SIZE];
    uint64_t epochs[MIPS64_FAMILY_EPOCHS];
    uint64_t notified[4];
    /* Bytes or COW/notification metadata changes require a newer generation.
     * Notification bookkeeping alone need not consume reservation epochs.
     * Actual COW still must advance the appropriate reservation epochs. */
    uint64_t content_generation;
    uint32_t private_cow; /* Canonical 0/1; file-view admission is separate. */
    uint32_t reserved;
} mips64_family_page_state_t;

typedef struct {
    mips64_family_t *family;
    uint64_t incarnation;
    pthread_t owner_thread;
    int previous_cancel_state;
    bool held;
} mips64_family_guard_t;

/* Retained inode identity of one live family attachment. A child attachment
 * may have a different mips64_family_t address but must name both same inodes. */
typedef struct {
    dev_t control_device, directory_device;
    ino_t control_inode, directory_inode;
} mips64_family_identity_t;

/* Local capability metadata, not an on-disk/wire representation. A versioned
 * exec transport must encode each field explicitly, never memcpy this struct. */
typedef struct {
    uint64_t owner_pid, incarnation, recovery_epoch, next_incarnation;
    mips64_family_identity_t identity;
    bool creator;
    char directory[64];
} mips64_family_exec_state_t;

/* Create a private 0700 family directory below /tmp, its sole 0600 control
 * inode descriptor, and a private kernel file-pin queue. The creator owns
 * directory cleanup; the last attached queue owner releases retained files. */
int mips64_family_create(mips64_family_t **out);
int mips64_family_create_with_authority(mips64_family_t **out,
                                    mips64_family_storage_authority_t authority);
/* Consume/clear an already running service's client before publishing this
 * new family. Start that service before family/guest workers: it must never
 * inherit control. The family owns the one immutable namespace until detach;
 * its destruction closes local client caps, never waits/kills the service
 * while relatives may still retain lifetime caps. Initialize *out=NULL. */
int mips64_family_create_with_sources(mips64_family_t **out, mips64_file_caps_client_t *owned);
int mips64_family_create_with_sources_authority(mips64_family_t **out,
    mips64_file_caps_client_t *owned, mips64_family_storage_authority_t authority);
/* Six trusted distinct >=3 capabilities. Consumes every supplied descriptor,
 * restoring private CLOEXEC ownership before first guard entry. Source-enabled
 * families reject legacy four-cap attachment instead of losing recovery caps. */
int mips64_family_attach_with_sources(mips64_family_t **out, int owned_control_fd,
                                    int owned_dir_fd, mips64_inode_pins_t owned_pins,
                                    mips64_file_caps_client_t owned_sources);
/* Consume all four descriptors on every outcome. They must designate the family's
 * directory and its existing control inode. Each process must own exactly one
 * descriptor for that inode; do not dup or reopen it. */
/* The private queue endpoints belong to this exact family and are transferred
 * by trusted fork/exec transport. Shape validation does not authenticate an
 * unrelated pair. Both endpoints are consumed on every outcome. */
int mips64_family_attach(mips64_family_t **out, int owned_control_fd, int owned_dir_fd,
                       mips64_inode_pins_t owned_pins);
/* Consume a rejected capability set, closing each numeric FD at most once. */
void mips64_family_close_capabilities(int owned_control_fd, int owned_dir_fd,
                                   mips64_inode_pins_t owned_pins);
void mips64_family_close_source_capabilities(int owned_control_fd, int owned_dir_fd,
                                          mips64_inode_pins_t owned_pins,
                                          mips64_file_caps_client_t owned_sources);
/* Child process only, after native fork with all other workers quiescent and
 * child-local disposal of every inherited page/object view. The parent
 * family remains alive. Caller enters with cancellation disabled and keeps it
 * disabled through child setup; transfer does not change cancellation state.
 * Never touch the copied guard or pthread mutex: the parent may still own
 * both. On precondition failure *inherited stays owned. Once the copied
 * control mapping is released, *inherited becomes NULL and the exact inherited
 * descriptors are consumed by mips64_family_attach even if fresh attachment
 * fails. No descriptor is duplicated or reopened. This primitive does not
 * qualify arbitrary multithreaded post-fork libc use or a guest process fork. */
int mips64_family_fork_child_transfer(mips64_family_t **inherited,
                                   mips64_family_t **attached);
/* Same-PID native exec, under complete worker/native-I/O quiescence with the
 * caller's guard held. Preparation only borrows the EXACT sole control and
 * directory FDs: never dup/reopen control, stop the family, or destroy views
 * before exec. All capabilities start CLOEXEC. State/capabilities are borrowed until
 * destroy; carry them explicitly through a separately validated transport.
 * Initialize *out=NULL; a failed prepare leaves it unchanged. Leave is EBUSY
 * until the prepared owner is destroyed, including after exec rollback. */
/* Four-cap preparation is only for anonymous families. Both APIs reject the
 * other mode with EOPNOTSUPP before publishing a prepared owner. */
int mips64_family_exec_prepare(mips64_family_guard_t *guard, mips64_family_exec_t **out);
int mips64_family_exec_prepare_sources(mips64_family_guard_t *guard, mips64_family_exec_t **out);
const mips64_family_exec_state_t *mips64_family_exec_state(const mips64_family_exec_t *exec);
/* Order: sole control FD, directory FD, pin sender, pin receiver. */
int mips64_family_exec_capabilities(const mips64_family_exec_t *exec, int output[4]);
/* Source mode appends request then lifetime to the four roles above. Getters
 * reject the other mode with EOPNOTSUPP, leaving output unchanged. */
int mips64_family_exec_source_capabilities(const mips64_family_exec_t *exec, int output[6]);
/* Activate immediately before native exec. Only the captured four/six FDs become
 * inheritable; all ordinary guard operations then fail. A returning exec must
 * deactivate before any old guest state resumes. Restoration failure poisons
 * the family and requires process exit; never continue guest execution. */
int mips64_family_exec_activate(mips64_family_exec_t *exec);
int mips64_family_exec_deactivate(mips64_family_exec_t *exec);
int mips64_family_exec_destroy(mips64_family_exec_t **owned);
/* Fresh startup after successful native exec only. Consumes distinct supplied
 * FDs on every outcome, restores CLOEXEC and fresh local synchronization,
 * retains the same PID/incarnation and creator cleanup responsibility, and
 * returns a held guard without dropping the inherited POSIX record lock.
 * Do not pass copied post-fork state or substitute/reopen descriptors. Native
 * callers/transport are trusted to obey this capability provenance contract.
 * Initialize *out=NULL. Failure leaves it unchanged and consumes supplied FDs.
 * Failure after native exec is fatal; no old image can be resumed. */
int mips64_family_exec_receive(mips64_family_t **out, mips64_family_guard_t *guard,
                            int owned_control_fd, int owned_dir_fd,
                            mips64_inode_pins_t owned_pins,
                            const mips64_family_exec_state_t *state);
int mips64_family_exec_receive_sources(mips64_family_t **out, mips64_family_guard_t *guard,
                                    int owned_control_fd, int owned_dir_fd,
                                    mips64_inode_pins_t owned_pins,
                                    mips64_file_caps_client_t owned_sources,
                                    const mips64_family_exec_state_t *state);
/* Clean same-PID source-exec replay phase. Consume exact inherited source
 * roles even if their peer has died, validate the same family identity and
 * uninterrupted owner lease, and return a held guard without source-journal
 * recovery. The caller must prove an IDLE cursor before exit effects. A
 * resumable session also requires a live client check after those effects;
 * no guest may use a family merely because this receive succeeded. */
int mips64_family_exec_receive_sources_terminal(mips64_family_t **out,
                                    mips64_family_guard_t *guard,
                                    int owned_control_fd, int owned_dir_fd,
                                    mips64_inode_pins_t owned_pins,
                                    mips64_file_caps_client_t owned_sources,
                                    const mips64_family_exec_state_t *state);
/* Explicit creator cleanup. The caller must confirm global quiescence: no
 * other process is attached and no page or object view is held anywhere. Retires the
 * family before unlinking managed files. */
int mips64_family_cleanup(mips64_family_t *family);
/* Terminal source-exec cleanup while the inherited lease is still held.
 * Only a trusted caller that has independently proved sole family ownership
 * may grant this; creator status alone is insufficient. No source recovery
 * or guard leave occurs inside this call. */
int mips64_family_cleanup_held_terminal(mips64_family_guard_t *guard,
                                    bool sole_family_owner);
/* Private file-service terminal callback. The server borrows retained exact
 * control/directory SCM rights, holds no source-client lifetime alias, and
 * calls only after final lifetime EOF plus request-queue drain. It validates
 * the pair/path again, takes a nonblocking byte-zero lock, requires an empty
 * journal and IDLE file cursor, then applies the normal guarded unlink policy.
 * Failure leaves remaining family evidence in place; no ordinary recovery or
 * service RPC is attempted from this single-threaded server. */
int mips64_family_cleanup_service(int borrowed_control_fd,
                              int borrowed_directory_fd,
                              const char *directory);
/* The source service retains marked SysV control and fixed file-index root
 * attachments before ACKing terminal-cleanup registration. The registering
 * creator still holds its family guard; prepare must not acquire its lock.
 * A positive-length family returns a NULL retained owner. */
int mips64_family_cleanup_service_prepare(int borrowed_control_fd,
                                      int borrowed_directory_fd,
                                      const char *directory, void **out);
int mips64_family_cleanup_service_prepare_authority(int borrowed_control_fd,
    int borrowed_directory_fd, const char *directory, void **out,
    mips64_family_storage_authority_t authority);
int mips64_family_cleanup_service_prepare_context(int borrowed_control_fd,
    int borrowed_directory_fd, const char *directory, void **out,
    void *context);
int mips64_family_cleanup_service_retained(int borrowed_control_fd,
                                       int borrowed_directory_fd,
                                       const char *directory, void *retained);
void mips64_family_cleanup_service_release(void *retained);
/* Creator's first held guard, before guest admission. The output becomes
 * true before a complete directory-leg send enters the kernel, even if its
 * ACK is lost. The caller must then surrender local unlink authority on
 * every outcome. A false output means no complete delegation was submitted. */
int mips64_family_register_service_cleanup(mips64_family_guard_t *guard,
                                       bool *may_have_delegated);
/* Local detach only. Caller guarantees no concurrent family calls or mutex
 * waiters. Returns EBUSY while a guard or local view exists. */
int mips64_family_destroy(mips64_family_t *family);

/* Acquires the process-local mutex and POSIX byte lock, recovers a committed
 * page or packed-slot operation, then drains a source-family resize intent
 * before exposing the active guard. Start with a zeroed
 * guard. Cancellation stays disabled until leave. Guards are nonrecursive,
 * noncopyable, and thread-bound. */
int mips64_family_enter(mips64_family_t *family, mips64_family_guard_t *guard);
int mips64_family_leave(mips64_family_guard_t *guard);
/* Release the family file lock, invalidate guard, then run a nonblocking
 * local cleanup while the process mutex still excludes another entrant.
 * Cleanup may close deferred owned FDs, but must not reenter this family.
 * It is skipped if file unlock fails; that failure poisons this family. */
int mips64_family_leave_with_cleanup(mips64_family_guard_t *guard,
                                  void (*after_unlock)(void *context),
                                  void *context);
/* Verify the currently active, thread-bound guard without exposing the
 * private ownership check to managed backing adapters. */
bool mips64_family_guard_matches(const mips64_family_guard_t *guard,
                             const mips64_family_t *family);
/* Diagnostic-only observer for the same exact guard predicate. */
bool mips64_family_guard_matches_observed(const mips64_family_guard_t *guard,
                                      const mips64_family_t *family,
                                      mips64_measure_observer_t *measure);
int mips64_family_identity(const mips64_family_guard_t *guard,
                        mips64_family_identity_t *out);
uint64_t mips64_family_incarnation(const mips64_family_t *family);
/* Query an allocated attachment incarnation while holding this family's
 * guard. Each incarnation owns a lifetime POSIX byte lock on the EXACT sole
 * control descriptor; ordinary guard leave releases only the execution token.
 * A foreign lock, rather than a numeric PID, proves the attachment is alive.
 * Our own incarnation uses local ownership because F_GETLK ignores our locks.
 * Native fork acquires a fresh lease; same-PID exec preserves the old lease.
 * Incarnations are never reused, including after an attachment dies. The
 * existing one-attachment/sole-control-FD-per-process contract is mandatory:
 * opening/closing another descriptor for control would drop all our leases. */
int mips64_family_owner_alive(const mips64_family_guard_t *guard, uint64_t incarnation,
                           bool *alive);
/* Read while holding this family's guard. */
uint64_t mips64_family_recovery_epoch(const mips64_family_guard_t *guard);
/* Retain an exact regular-file reference until the family's last queue owner
 * exits. The uninterrupted guard protects a shared, persistent, nonrefundable
 * attempt budget. This supplies lifetime, never an inode-equivalence test.
 * No production consumer may drain or shut down the queue. */
int mips64_family_pin_file(mips64_family_guard_t *guard, int source_fd);
/* Intern a proven mapped-inode identity from the exact retained source_fd.
 * Caller retains that descriptor and the uninterrupted guard. New identities
 * acquire a kernel pin BEFORE redo publication. IDs/records are never reused
 * or removed while the family survives, including after the producer exits.
 * Unknown/noneligible identity returns EOPNOTSUPP; capacity/native pin errors
 * remain errors, never fall back to stat dev/ino or unpinned IDs. */
int mips64_family_file_intern(mips64_family_guard_t *guard,
                           const mips64_file_identity_t *identity, int source_fd,
                           uint64_t *file_id);
/* Admit an exact readable source into this family's ONE immutable file-cap
 * service namespace. The client is family-owned and cannot be replaced by a
 * new service or shared with another family's counters. Hold
 * the uninterrupted exact guard; no prepared exec or unresolved redo allowed.
 * Source IDs and shared attempt charges are monotonic/nonrefundable, including
 * producer death and lost ACK. Only ACK changes *source_id; failure may consume
 * an unreachable ID/retained source. An uncertain EIO must fail closed for this
 * caller (no metadata or blind retry); peers may recover and use fresh IDs.
 * Borrow source_fd: reject every private family inode without dup/close. This
 * component does not start a service or publish file-MM records. */
int mips64_family_source_register(mips64_family_guard_t *guard,
                                int source_fd, uint64_t *source_id);
/* Borrow an ordinary regular target under the current source-family guard.
 * Reject every alias of control/data/metadata inventory by nofollow stat,
 * without opening/duplicating/closing a private inode or charging a source ID.
 * Access mode is operation-specific; writable-only mutation targets are valid. */
int mips64_family_file_target_check(mips64_family_guard_t *guard, int borrowed_fd);
/* Borrow under the exact guard only; never close or modify these owned FDs.
 * Anonymous families return NULL/EOPNOTSUPP. No guest descriptor exposure. */
const mips64_file_caps_client_t *mips64_family_sources(const mips64_family_guard_t *guard);
/* Immutable family-global index anchor, privately bootstrapped before mode1
 * publication. Zero/error for invalid guards or anonymous families. */
uint64_t mips64_family_file_index_object(const mips64_family_guard_t *guard);
/* Private host path for controlled attach/cleanup; never a guest-visible path. */
const char *mips64_family_private_directory(const mips64_family_t *family);
/* Install while holding the family guard before any guest path or managed
 * backing exposure. The observer and context are borrowed until quiescent
 * unobserve. Callbacks run under the process mutex and family record lock;
 * they must not reenter this family or open, duplicate, or close control.
 * They record inode identities from nofollow stat facts. Every later guard
 * entry rescans objects created by other attached processes. A failed scan
 * never installs the observer and must abort guest startup. */
int mips64_family_observe_inodes(mips64_family_guard_t *guard,
                             mips64_family_inode_observer_t observer, void *context);
/* Quiescent teardown only: stop guest work, unobserve under the guard, leave,
 * destroy the resolver, then cleanup/unlink and destroy the family. */
int mips64_family_unobserve_inodes(mips64_family_guard_t *guard);

/* Managed one-page files are retained until creator cleanup. Views are local
 * mmap wrappers; shared records contain no pointers, fds, or mutex bytes. */
int mips64_family_page_create(mips64_family_guard_t *guard, mips64_family_page_t **out);
int mips64_family_page_open(mips64_family_guard_t *guard, mips64_family_page_key_t key,
                        mips64_family_page_t **out);
void mips64_family_page_close(mips64_family_page_t *page);
mips64_family_page_key_t mips64_family_page_key(const mips64_family_page_t *page);
/* The returned view is valid only while the caller holds this family's guard. */
const mips64_family_page_state_t *mips64_family_page_readonly(const mips64_family_guard_t *guard,
                                                      const mips64_family_page_t *page);
/* Commit an absolute full-page state. Generations and epochs may not decrease;
 * every changed 16-byte granule must advance its epoch. The release-published
 * record is the operation's commit point and remains until fully applied. */
int mips64_family_page_commit(mips64_family_guard_t *guard, mips64_family_page_t *page,
                          const mips64_family_page_state_t *target);

/* A packed object retains one file descriptor and one host mapping for all
 * its fixed-size page slots. The file starts with a 16 KiB header; each 8 KiB
 * slot begins with 4 KiB of guest bytes at a page-aligned file offset. The
 * slot count never grows after creation. No mutable shared pointer escapes:
 * snapshot copies under the guard, and every update uses the same
 * absolute-state redo protocol as a one-page file. */
int mips64_family_object_create(mips64_family_guard_t *guard, uint32_t slot_count,
                            mips64_family_object_t **out);
int mips64_family_object_open(mips64_family_guard_t *guard, uint64_t object_id,
                          mips64_family_object_t **out);
void mips64_family_object_close(mips64_family_object_t *object);
uint64_t mips64_family_object_id(const mips64_family_object_t *object);
uint32_t mips64_family_object_count(const mips64_family_object_t *object);
int mips64_family_object_snapshot(const mips64_family_guard_t *guard,
                              const mips64_family_object_t *object,
                              uint32_t page_index, mips64_family_page_state_t *out);
int mips64_family_object_snapshot_observed(const mips64_family_guard_t *guard,
                                       const mips64_family_object_t *object,
                                       uint32_t page_index, mips64_family_page_state_t *out,
                                       mips64_measure_observer_t *measure);
typedef struct {
    mips64_family_object_t *object;
    uint32_t page_index;
    const mips64_family_page_state_t *target;
} mips64_family_object_update_t;
/* Commit one or two distinct slots as one crash-recoverable operation. All
 * targets are validated before the single release-published commit marker;
 * recovery replays both absolute targets until completion. */
int mips64_family_object_commitv(mips64_family_guard_t *guard,
                             const mips64_family_object_update_t *updates,
                             size_t count);
int mips64_family_object_commit(mips64_family_guard_t *guard, mips64_family_object_t *object,
                            uint32_t page_index,
                            const mips64_family_page_state_t *target);
/* Trusted clean-file refresh only. The producer has finished native mutation
 * under this guard and prepaid each notified granule's reservation epoch.
 * Commit clean-to-clean state, clear every notification bit, and advance CG by
 * exactly one. A changed granule may retain its epoch only when consuming its
 * current notification bit with a positive epoch. All other byte changes must
 * advance epochs. Generic commit/commitv/wait remain strict. This API uses the
 * same single-slot absolute redo; it does not authenticate FILE provenance or
 * supply native-mutation recovery. */
int mips64_family_object_commit_file_refresh(mips64_family_guard_t *guard,
                                         mips64_family_object_t *object,
                                         uint32_t page_index,
                                         const mips64_family_page_state_t *target);

#ifdef MIPS64_FAMILY_TESTING
typedef enum {
    MIPS64_FAMILY_TEST_SOURCE_ALLOCATED,
    MIPS64_FAMILY_TEST_PREPARED,
    MIPS64_FAMILY_TEST_COMMITTED,
    MIPS64_FAMILY_TEST_EPOCHS_APPLIED,
    MIPS64_FAMILY_TEST_BYTES_APPLIED,
    MIPS64_FAMILY_TEST_RECOVERY_COMMITTED,
    MIPS64_FAMILY_TEST_RECOVERY_EPOCHS_APPLIED,
    MIPS64_FAMILY_TEST_WAIT_BEFORE_BANK_WRITE,
    MIPS64_FAMILY_TEST_WAIT_BANK_WRITTEN,
    MIPS64_FAMILY_TEST_WAIT_RECOVERY_ROOT_APPLIED,
    MIPS64_FAMILY_TEST_WAIT_RECOVERY_FIRST_OBJECT_APPLIED,
    MIPS64_FAMILY_TEST_FILE_ID_ALLOCATED,
    MIPS64_FAMILY_TEST_FILE_PINNED,
    MIPS64_FAMILY_TEST_FILE_RECORD_APPLIED,
    MIPS64_FAMILY_TEST_FILE_COUNT_APPLIED,
    MIPS64_FAMILY_TEST_RESIZE_INTENT_PUBLISHED,
    MIPS64_FAMILY_TEST_RESIZE_NATIVE_RESULT,
    MIPS64_FAMILY_TEST_RESIZE_OBSERVATION_PUBLISHED,
    MIPS64_FAMILY_TEST_RESIZE_CURSOR_COMMITTED
} mips64_family_test_point_t;
typedef void (*mips64_family_test_hook_t)(mips64_family_test_point_t point, void *context);
void mips64_family_test_set_hook(mips64_family_t *family, mips64_family_test_hook_t hook,
                             void *context);
/* Internal semantic crash cuts; callbacks must not reenter family code. */
void mips64_family_test_point(mips64_family_guard_t *guard, mips64_family_test_point_t point);
/* Fault-inject one unlock attempt for fail-closed record-lock tests. */
void mips64_family_test_fail_next_unlock(mips64_family_t *family);
/* Force the fresh child attachment to reject after inherited ownership has
 * transferred, so failure cleanup can be tested without mutating parent. */
void mips64_family_test_fail_child_transfer_attach(mips64_family_t *family);
void mips64_family_test_fail_exec_activation(mips64_family_t *family);
/* Fail after this captured capability's CLOEXEC was cleared (0..5). */
void mips64_family_test_fail_exec_activation_at(mips64_family_t *family, size_t index);
/* Make the next committed waiter-table replay fail before applying state. */
void mips64_family_test_fail_next_wait_replay(mips64_family_t *family);
/* Simulate a transient source-intent drain allocation/read failure before
 * recovery; the durable intent and its service outcome remain untouched. */
void mips64_family_test_fail_next_file_recovery(mips64_family_t *family);
void mips64_family_test_descriptors(const mips64_family_t *family,
                                 int *control_fd, int *dir_fd);
/* Borrowed endpoints, for trusted test fork/exec handoff only. */
void mips64_family_test_pin_state(const mips64_family_t *family,
                               mips64_inode_pins_t *pins, uint64_t *attempts);
#endif

#endif

/* Family broker rendezvous below /tmp, parameterized on the MIPS64 family
 * name: .mips64rt-family-<pid>-<seq>. */
#define MIPS64_FAMILY_DIR_TEMPLATE "/tmp/.mips64rt-family-XXXXXX"
