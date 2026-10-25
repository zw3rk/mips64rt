/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef MIPS64RT_FILE_CAPS_PARTS_H
#define MIPS64RT_FILE_CAPS_PARTS_H

#define _GNU_SOURCE 1
#define _DARWIN_C_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#include "runtime/file_caps.h"
#include "runtime/file_caps_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

enum { FRAME_SIZE = 24, MAX_RIGHTS = 4, REPLY_WAIT_MS = 5000,
       OP_REGISTER = 1, OP_FETCH = 2, OP_TRUNCATE_STAGE = 3,
       OP_TRUNCATE_EXECUTE = 4, CLEANUP_FRAME_SIZE = 96,
       CLEANUP_VERSION = 4, OP_CLEANUP_CONTROL = 1,
       OP_CLEANUP_DIRECTORY = 2, DEPARTURE_VERSION = 5,
       OP_DEPARTURE_PREPARE = 1, MAX_DEPARTURES = 4096 };

typedef struct {
    uint64_t id;
    int fd;
} source_t;

typedef struct {
    int control_fd, directory_fd;
    char directory[64];
    void *retained;
    bool ready;
} cleanup_registration_t;

typedef struct {
    int reply_fd, lifetime_fd, sender_fd;
    bool release_seen, released;
} departure_slot_t;

_Static_assert(sizeof(off_t) == 8, "file service requires 64-bit truncate offsets");
/* Cross-part prototypes (Phase 0 mechanical split). */

#ifdef MIPS64_FILE_CAPS_TESTING
/* Installed only by single-threaded tests before fork. */
 mips64_file_caps_test_hook_t test_hook;
static void *test_context;
void mips64_file_caps_test_set_hook(mips64_file_caps_test_hook_t hook, void *context);

 void mips64_file_caps_close_two(int first, int second);

 void mips64_file_caps_close_rights(int rights[MAX_RIGHTS], size_t count);

 int mips64_file_caps_private_fd(int *fd);

 int duplicate_private(int fd);

 bool mips64_file_caps_connected_socket(int fd, int expected_type);

 bool mips64_file_caps_unix_socket_kind(int fd, int expected_type);

 bool live_lifetime(int fd);

bool mips64_file_caps_client_live(const mips64_file_caps_client_t *client);

 int mips64_file_caps_no_sigpipe(int fd);

 bool empty_client(const mips64_file_caps_client_t *client);

 bool empty_server(const mips64_file_caps_server_t *server);

 int native_lifetime_socket_type(void);

 int client_adopt(mips64_file_caps_client_t *out,
                        int request_fd, int lifetime_fd, bool terminal);

int mips64_file_caps_client_adopt(mips64_file_caps_client_t *out,
                              int request_fd, int lifetime_fd);

int mips64_file_caps_client_adopt_terminal(mips64_file_caps_client_t *out,
                                       int request_fd, int lifetime_fd);

int mips64_file_caps_pair_create(mips64_file_caps_client_t *client,
                             mips64_file_caps_server_t *server);

int mips64_file_caps_client_duplicate(const mips64_file_caps_client_t *source,
                                  mips64_file_caps_client_t *out);

void mips64_file_caps_client_close(mips64_file_caps_client_t *client);

void mips64_file_caps_server_close(mips64_file_caps_server_t *server);

 void mips64_file_caps_put_u32(unsigned char *at, uint32_t value);

 uint32_t mips64_file_caps_get_u32(const unsigned char *at);

 void mips64_file_caps_put_u64(unsigned char *at, uint64_t value);

 uint64_t mips64_file_caps_get_u64(const unsigned char *at);

 void mips64_file_caps_frame_base(unsigned char frame[FRAME_SIZE], unsigned char op);

 bool mips64_file_caps_frame_valid(const unsigned char frame[FRAME_SIZE],
                        unsigned char op);



/* Every ancillary FD is receiver-owned, including descriptors 0..2 when
 * native stdio was closed. Walk the whole chain before interpreting a frame. */
 int mips64_file_caps_collect_rights(struct msghdr *message, int rights[MAX_RIGHTS],
                          size_t *count);

 ssize_t send_packet(int socket_fd, const unsigned char *frame,
                           size_t frame_size, const int *rights, size_t count);

 ssize_t mips64_file_caps_send_frame(int socket_fd, const unsigned char frame[FRAME_SIZE],
                          const int *rights, size_t count);


 int64_t monotonic_ms(void);

 int mips64_file_caps_await_reply(int reply_fd, int life_fd, unsigned char *frame,
                       size_t frame_size,
                       int rights[MAX_RIGHTS], size_t *right_count);

 int mips64_file_caps_request(const mips64_file_caps_client_t *client, unsigned char op,
                   uint64_t id, uint64_t attempt, int source_fd, int *out_fd,
                   int *out_native_errno);


int mips64_file_caps_register(const mips64_file_caps_client_t *client,
                          int source_fd, uint64_t source_id,
                          uint64_t *attempts);

 int register_cleanup_part(const mips64_file_caps_client_t *client,
                                 unsigned char op, int borrowed_fd,
                                 const char *directory, size_t path_length,
                                 bool *submitted);

int mips64_file_caps_register_terminal_cleanup(const mips64_file_caps_client_t *client,
                                            int borrowed_control_fd,
                                            int borrowed_directory_fd,
                                            const char *directory,
                                            bool *may_have_delegated);

 int departure_reply_byte(int reply_fd, int lifetime_fd, char *answer);

int mips64_file_caps_departure_begin(const mips64_file_caps_client_t *client,
                                 mips64_file_caps_departure_t *out);

int mips64_file_caps_departure_finish(mips64_file_caps_departure_t *handle,
                                  bool *last);

int mips64_file_caps_departure_end(mips64_file_caps_departure_t *handle);

int mips64_file_caps_fetch(const mips64_file_caps_client_t *client,
                       uint64_t source_id, int *out_fd);

 int writable_regular(int fd);


/* The independent service has one thread. Preserve any preexisting pending
 * SIGXFSZ, but consume the new signal generated by our failed native operation
 * before restoring its mask. Otherwise RLIMIT_FSIZE can kill the service
 * before it retains EFBIG. This does not implement guest signal/limit policy. */
 int native_truncate(int fd, uint64_t length, int *native_error);


int mips64_file_caps_truncate_stage(const mips64_file_caps_client_t *client,
                                 uint64_t operation_id, int borrowed_fd,
                                 uint64_t length);

int mips64_file_caps_truncate_execute(const mips64_file_caps_client_t *client,
                                   uint64_t operation_id, int *out_native_errno);



 int send_response(int reply_fd, unsigned char op, uint64_t id,
                         int status, int source_fd, int native_error);

 bool cleanup_packet_valid(const unsigned char *packet,
                                 ssize_t received, unsigned char *op,
                                 size_t *path_length);

 int process_cleanup_request(const unsigned char *packet,
                                   ssize_t received, bool truncated,
                                   int rights[MAX_RIGHTS], size_t right_count,
                                   bool rights_valid,
                                   cleanup_registration_t *cleanup,
                                   bool allowed,
                                   const mips64_file_caps_retained_cleanup_t *retained_ops);

 void departure_slot_close(departure_slot_t *slot);

 bool departure_frame_valid(const unsigned char *frame, ssize_t count);

 int process_departure_prepare(const unsigned char *frame,
                                     ssize_t count, bool truncated,
                                     int rights[MAX_RIGHTS], size_t right_count,
                                     bool rights_valid,
                                     departure_slot_t *departures,
                                     bool allowed);



/* A closed datagram control can remain readable on Darwin. Stop polling it;
 * the independent stream lifetime still decides when retained sources retire. */
 int process_request(int control_fd, source_t *sources, size_t *count,
                           uint64_t *last_id, uint64_t *last_attempt,
                           mips64_file_caps_mutation_t *mutation,
                           cleanup_registration_t *cleanup,
                           departure_slot_t *departures, bool allow_cleanup,
                           const mips64_file_caps_retained_cleanup_t *retained_ops);

/* The client shuts down its write half after one R. Until EOF is observed,
 * another byte may still be queued and the handle cannot elect LAST. */
 int departure_receive_release(departure_slot_t *slot);

 int departure_answer(departure_slot_t *slot, char answer);

 int lifetime_probe(int fd);

 int serve_with_cleanup(mips64_file_caps_server_t *server,
                              mips64_file_caps_terminal_cleanup_fn terminal,
                              const mips64_file_caps_retained_cleanup_t *retained_ops);

int mips64_file_caps_serve_with_cleanup(mips64_file_caps_server_t *server,
                                    mips64_file_caps_terminal_cleanup_fn terminal);

int mips64_file_caps_serve_with_retained_cleanup(
    mips64_file_caps_server_t *server,
    const mips64_file_caps_retained_cleanup_t *cleanup);

int mips64_file_caps_serve(mips64_file_caps_server_t *server);

void mips64_file_caps_internal_close_two(int first, int second);
void mips64_file_caps_internal_close_rights(int rights[4], size_t count);
int mips64_file_caps_internal_private_fd(int *fd);
bool mips64_file_caps_internal_connected_socket(int fd, int type);
bool mips64_file_caps_internal_unix_socket_kind(int fd, int type);
void mips64_file_caps_internal_put_u32(unsigned char *at, uint32_t v);
uint32_t mips64_file_caps_internal_get_u32(const unsigned char *at);
void mips64_file_caps_internal_put_u64(unsigned char *at, uint64_t v);
uint64_t mips64_file_caps_internal_get_u64(const unsigned char *at);
int mips64_file_caps_internal_collect_rights(struct msghdr *m, int r[4], size_t *n);
int mips64_file_caps_internal_await_reply(int fd, int life, unsigned char *frame,
                                      size_t size, int rights[4], size_t *count);
int mips64_file_caps_internal_writable_regular(int fd);
int mips64_file_caps_internal_no_sigpipe(int fd);
void mips64_file_caps_internal_test_point(int point);
/* Cross-part externs (Phase 0 mechanical split). */
extern /* An admitted handle may not be copied or nested on one native thread. */
 _Thread_local mips64_file_caps_departure_t *active_departure;
#endif /* MIPS64RT_FILE_CAPS_PARTS_H */
