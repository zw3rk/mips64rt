/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef MIPS64RT_RT64_RUNTIME_SCHEDULER_H
#define MIPS64RT_RT64_RUNTIME_SCHEDULER_H

#include <stdbool.h>
#include <stdint.h>

typedef struct mips64_scheduler mips64_scheduler_t;
typedef struct mips64_sched_ticket mips64_sched_ticket_t;
typedef bool (*mips64_sched_native_hook_fn)(void *context, unsigned int phase);

typedef enum {
    MIPS64_SCHED_CONTINUE,
    MIPS64_SCHED_YIELD,
    MIPS64_SCHED_TERMINAL
} mips64_sched_decision_t;

typedef enum {
    MIPS64_SCHED_SEQ_NONE,        /* Ordinary instruction or a broken sequence. */
    MIPS64_SCHED_SEQ_LR_START,    /* The LR is instruction one of a new sequence. */
    MIPS64_SCHED_SEQ_CONSTRAINED, /* Caller verified this intervening instruction. */
    MIPS64_SCHED_SEQ_SC_END,      /* SC terminates the constrained sequence. */
    MIPS64_SCHED_SEQ_BREAK        /* Trap, forbidden instruction or sequence exit. */
} mips64_sched_sequence_t;

/* One process scheduler. The first ticket belongs to its creator. Tickets
 * have stable heap addresses until explicitly destroyed after their native
 * owners have stopped using them. The scheduler does not enter/leave the
 * family token; the runtime does that around each admitted turn. */
int mips64_scheduler_create(mips64_scheduler_t **out, mips64_sched_ticket_t **initial,
                        uint32_t quantum);
/* Called by an admitted owner under the family token. The new ticket is
 * runnable but has no native owner until attach on its native pthread. */
int mips64_scheduler_add(mips64_sched_ticket_t *current, mips64_sched_ticket_t **child);
int mips64_scheduler_attach(mips64_sched_ticket_t *ticket);
/* Wait only after releasing the family token. 1 = admitted, 0 = group
 * terminal, -1 = invalid ownership/state. An admitted worker may block while
 * acquiring the family token formerly held by the previous worker; no
 * scheduler mutex is held during that acquisition. Native cancellation must
 * remain disabled across this cond-wait, as guest-memory worker attach does. */
int mips64_scheduler_wait_turn(mips64_sched_ticket_t *ticket);
/* Query the maximum next JIT retirement budget. When interpreter_only is
 * true, execute/classify one instruction at a time. A zero budget means the
 * owner must yield or observe terminal before executing another instruction. */
int mips64_scheduler_budget(mips64_sched_ticket_t *ticket, uint32_t *budget,
                        bool *interpreter_only);
/* Account exact retired instructions. Multi-instruction JIT blocks are valid
 * only with SEQ_NONE and outside an active LR/SC sequence. A constrained
 * sequence including LR may use at most 16 instructions; SC, trap, forbidden
 * instruction or the sixteenth instruction ends the extension. The caller
 * classifies each sequence instruction, never infers it from reservation_valid.
 * A zero-retirement SEQ_BREAK reports a faulting instruction without charging
 * quantum, while still ending any extension. Returns 0 and a decision; -1
 * on invalid retirement/owner/state. */
int mips64_scheduler_account(mips64_sched_ticket_t *ticket, uint32_t retired,
                         mips64_sched_sequence_t sequence,
                         mips64_sched_decision_t *decision);
/* Yield and park choose the FIFO successor BEFORE the caller releases its
 * family guard. They never wait for the successor. After release, call
 * wait_turn; wake-before-wait is retained by ticket state. */
int mips64_scheduler_yield(mips64_sched_ticket_t *ticket);
int mips64_scheduler_park(mips64_sched_ticket_t *ticket);
/* Transition a blocked ticket. A quiesce owner and no I/O flight stores
 * SUSPENDED. Otherwise the ticket is stored RUNNABLE. The caller holds the
 * family token or an equivalent serialized external-event boundary.
 * Returns 1 after that store, 0 if the ticket was not blocked, -1 on
 * invalid state. */
int mips64_scheduler_wake(mips64_scheduler_t *scheduler, mips64_sched_ticket_t *ticket);

/* Reversible process quiescence. The caller owns the running ticket and family
 * guard. Begin freezes queued dispatcher-boundary workers in FIFO order and
 * rejects new add; semantic blocked waiters remain blocked. A logical native
 * I/O flight begins before its first token-free release and ends only after
 * copyout, result, PC and restart state have been materialized under the
 * guard. Native wake is merely a prompt; it never proves no bytes were used.
 * If flights remain, wait publishes the owner as waiting. The caller releases
 * its family guard, waits for scheduler admission, and reacquires the guard.
 * Checkpoint suspends a sibling at a dispatcher boundary under the guard,
 * before another guest instruction. Abort restores the suspended FIFO without
 * changing any worker's CPU or completed I/O state. Native cancellation stays
 * disabled across waits. Terminate remains the irreversible exec-success path. */
int mips64_scheduler_io_begin(mips64_sched_ticket_t *ticket);
int mips64_scheduler_io_end(mips64_sched_ticket_t *ticket);
/* On an explained native EINTR with no guest signal, suspend INSIDE the
 * callback's owned descriptor lease and staging frame. 1 = suspended, 0 = no
 * active barrier, -1 = invalid state. The caller releases the guard and waits
 * for abort/termination; after reentry it calls io_resume and retries the
 * same native operation. No guest EINTR or descriptor reopen is published. */
int mips64_scheduler_io_suspend(mips64_sched_ticket_t *ticket);
int mips64_scheduler_io_resume(mips64_sched_ticket_t *ticket);
int mips64_scheduler_quiesce_begin(mips64_sched_ticket_t *owner);
/* Cheap dispatcher-boundary check. The caller holds the family guard, so a
 * coordinator cannot publish a new barrier between this check and the next
 * guest instruction without first taking that guard. */
bool mips64_scheduler_quiesce_pending(const mips64_sched_ticket_t *ticket);
int mips64_scheduler_quiesce_ready(mips64_sched_ticket_t *owner);
int mips64_scheduler_quiesce_wait(mips64_sched_ticket_t *owner);
int mips64_scheduler_quiesce_checkpoint(mips64_sched_ticket_t *ticket);
int mips64_scheduler_quiesce_abort(mips64_sched_ticket_t *owner);
/* A quiesced worker runs this hook on its own native thread, outside the
 * scheduler mutex and family guard. It may only change native thread state;
 * the coordinator holds the family guard while guest state is frozen. Bind
 * before an attached ticket is published ready. A failed hook is fatal. */
int mips64_scheduler_native_hook_bind(mips64_sched_ticket_t *ticket,
                                  mips64_sched_native_hook_fn hook, void *context);
/* A semantic blocked waiter may be outside wait_turn (for example, waiting
 * for a private vfork completion). Service a pending native-only hook on its
 * owning thread without selecting a guest turn or changing its blocked state.
 * The caller holds no family guard or scheduler lock. Returns 1 on terminal,
 * 0 otherwise, or -1 on invalid ownership. */
int mips64_scheduler_parked_native_hook(mips64_sched_ticket_t *ticket);
/* Start a native-only rendezvous after quiesce_wait reports no active I/O
 * flights. The owner separately applies the same phase on its own thread.
 * wait returns 1 when every attached nonowner has acknowledged, 0 when the
 * owner must release its guard and wait_turn, or -1 on invalid ownership. */
int mips64_scheduler_quiesce_hook_begin(mips64_sched_ticket_t *owner,
                                     unsigned int phase);
int mips64_scheduler_quiesce_hook_wait(mips64_sched_ticket_t *owner);
#ifdef MIPS64_RUNTIME_TEST_EXEC_SUSPENDED_IO
/* Compile-only observation after all exec native hooks acknowledge. Counts
 * actual callbacks suspended inside their existing native I/O frames. */
int mips64_scheduler_test_suspended_io(mips64_sched_ticket_t *owner, uint32_t *count);
#endif
/* Current owner retires under the token. Discard removes a nonrunning ticket
 * after its native worker has joined, including an attached worker that
 * failed setup; an unstarted ticket needs no join. It may remove a selected
 * ticket only when that owner is proven quiescent. */
int mips64_scheduler_retire(mips64_sched_ticket_t *ticket);
int mips64_scheduler_discard(mips64_scheduler_t *scheduler, mips64_sched_ticket_t *ticket);
/* Group-terminal publication wakes every waiter, including blocked workers.
 * Caller then joins native workers before destroying tickets and scheduler. */
int mips64_scheduler_terminate(mips64_scheduler_t *scheduler);
int mips64_scheduler_ticket_destroy(mips64_sched_ticket_t **ticket);
int mips64_scheduler_destroy(mips64_scheduler_t **scheduler);
/* Child-only after a sealed native fork, with copied futex/I/O capabilities
 * already abandoned. Accepts the running quiesce owner and sealed suspended,
 * blocked or dead peers. Disposes every copied ticket without touching a
 * copied pthread mutex/condition. The parent retains its original tickets. */
int mips64_scheduler_fork_child_abandon(mips64_scheduler_t **scheduler);

#endif
