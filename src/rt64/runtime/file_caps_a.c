/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "file_caps_parts.h"

/* An admitted handle may not be copied or nested on one native thread. */
static _Thread_local mips64_file_caps_departure_t *active_departure;

#ifdef MIPS64_FILE_CAPS_TESTING
/* Installed only by single-threaded tests before fork. */
static mips64_file_caps_test_hook_t test_hook;
static void *test_context;
void mips64_file_caps_test_set_hook(mips64_file_caps_test_hook_t hook, void *context)
{
    test_hook = hook;
    test_context = context;
}
#define TEST_POINT(point) do { if (test_hook != NULL) \
    test_hook((point), test_context); } while (0)
#else
#define TEST_POINT(point) ((void)0)
#endif

 void mips64_file_caps_close_two(int first, int second)
{
    if (first >= 0)
        (void)close(first);
    if (second >= 0 && second != first)
        (void)close(second);
}

 void mips64_file_caps_close_rights(int rights[MAX_RIGHTS], size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        if (rights[i] >= 0)
            (void)close(rights[i]);
        rights[i] = -1;
    }
}

 int mips64_file_caps_private_fd(int *fd)
{
    if (*fd < 0) {
        errno = EBADF;
        return -1;
    }
    if (*fd < 3) {
        int raised = fcntl(*fd, F_DUPFD_CLOEXEC, 3);
        if (raised < 0)
            return -1;
        (void)close(*fd);
        *fd = raised;
        return 0;
    }
    int flags = fcntl(*fd, F_GETFD);
    return flags < 0 ? -1 : fcntl(*fd, F_SETFD, flags | FD_CLOEXEC);
}

static int duplicate_private(int fd)
{
    return fcntl(fd, F_DUPFD_CLOEXEC, 3);
}

 bool mips64_file_caps_connected_socket(int fd, int expected_type)
{
    int type = 0;
    socklen_t length = sizeof(type);
    struct sockaddr_storage address;
    socklen_t address_length = sizeof(address);
    return getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &length) == 0 &&
           length == sizeof(type) && type == expected_type &&
           getpeername(fd, (struct sockaddr *)&address, &address_length) == 0 &&
           address.ss_family == AF_UNIX;
}

 bool mips64_file_caps_unix_socket_kind(int fd, int expected_type)
{
    int type = 0;
    socklen_t length = sizeof(type);
    struct sockaddr_storage address;
    socklen_t address_length = sizeof(address);
    return getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &length) == 0 &&
           length == sizeof(type) && type == expected_type &&
           getsockname(fd, (struct sockaddr *)&address, &address_length) == 0 &&
           address.ss_family == AF_UNIX;
}

static bool live_lifetime(int fd)
{
    /* The service never writes on its lifetime stream. A non-consuming
     * probe distinguishes a live peer from Linux's retained getpeername()
     * address after that peer has closed. */
    unsigned char byte;
    ssize_t received;
    do {
        received = recv(fd, &byte, sizeof(byte), MSG_PEEK | MSG_DONTWAIT);
    } while (received < 0 && errno == EINTR);
    return received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK);
}

bool mips64_file_caps_client_live(const mips64_file_caps_client_t *client)
{
    return client != NULL && client->request_fd >= 3 &&
           client->lifetime_fd >= 3 &&
           mips64_file_caps_connected_socket(client->request_fd, SOCK_DGRAM) &&
           mips64_file_caps_connected_socket(client->lifetime_fd, SOCK_STREAM) &&
           live_lifetime(client->lifetime_fd);
}

 int mips64_file_caps_no_sigpipe(int fd)
{
#ifdef SO_NOSIGPIPE
    int enabled = 1;
    return setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled));
#else
    (void)fd;
    return 0;
#endif
}

static bool empty_client(const mips64_file_caps_client_t *client)
{
    return client != NULL && client->request_fd == -1 &&
           client->lifetime_fd == -1;
}

static bool empty_server(const mips64_file_caps_server_t *server)
{
    return server != NULL && server->request_fd == -1 &&
           server->lifetime_fd == -1;
}

static int native_lifetime_socket_type(void)
{
    int type = SOCK_STREAM;
#if defined(SOCK_CLOEXEC) && defined(SOCK_NONBLOCK)
    /* The MIPS64RT host selects its native lifetime-capability path from the
     * creation flags, before mips64_file_caps_private_fd normalizes the descriptors. */
    type |= SOCK_CLOEXEC | SOCK_NONBLOCK;
#endif
    return type;
}

static int client_adopt(mips64_file_caps_client_t *out,
                        int request_fd, int lifetime_fd, bool terminal)
{
    int saved = EINVAL;
    if (!empty_client(out) || request_fd < 0 || lifetime_fd < 0 ||
        request_fd == lifetime_fd)
        goto failed;
    if (!(terminal ? mips64_file_caps_unix_socket_kind(request_fd, SOCK_DGRAM) &&
                      mips64_file_caps_unix_socket_kind(lifetime_fd, SOCK_STREAM) :
                      mips64_file_caps_connected_socket(request_fd, SOCK_DGRAM) &&
                      mips64_file_caps_connected_socket(lifetime_fd, SOCK_STREAM) &&
                      live_lifetime(lifetime_fd))) {
        saved = EPROTOTYPE;
        goto failed;
    }
    if (mips64_file_caps_private_fd(&request_fd) != 0 || mips64_file_caps_private_fd(&lifetime_fd) != 0 ||
        mips64_file_caps_no_sigpipe(request_fd) != 0) {
        saved = errno;
        goto failed;
    }
    *out = (mips64_file_caps_client_t){request_fd, lifetime_fd};
    return 0;
failed:
    mips64_file_caps_close_two(request_fd, lifetime_fd);
    errno = saved;
    return -1;
}

int mips64_file_caps_client_adopt(mips64_file_caps_client_t *out,
                              int request_fd, int lifetime_fd)
{
    return client_adopt(out, request_fd, lifetime_fd, false);
}

int mips64_file_caps_client_adopt_terminal(mips64_file_caps_client_t *out,
                                       int request_fd, int lifetime_fd)
{
    return client_adopt(out, request_fd, lifetime_fd, true);
}

int mips64_file_caps_pair_create(mips64_file_caps_client_t *client,
                             mips64_file_caps_server_t *server)
{
    if (!empty_client(client) || !empty_server(server)) {
        errno = EINVAL;
        return -1;
    }
    int mips64_file_caps_request[2] = {-1, -1};
    int lifetime[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, mips64_file_caps_request) != 0)
        return -1;
    if (socketpair(AF_UNIX, native_lifetime_socket_type(), 0, lifetime) != 0)
        goto failed;
    if (mips64_file_caps_private_fd(&mips64_file_caps_request[0]) != 0 || mips64_file_caps_private_fd(&mips64_file_caps_request[1]) != 0 ||
        mips64_file_caps_private_fd(&lifetime[0]) != 0 || mips64_file_caps_private_fd(&lifetime[1]) != 0 ||
        mips64_file_caps_no_sigpipe(mips64_file_caps_request[0]) != 0 || mips64_file_caps_no_sigpipe(mips64_file_caps_request[1]) != 0)
        goto failed;
    *client = (mips64_file_caps_client_t){mips64_file_caps_request[0], lifetime[0]};
    *server = (mips64_file_caps_server_t){mips64_file_caps_request[1], lifetime[1]};
    return 0;
failed: {
    int saved = errno;
    mips64_file_caps_close_two(mips64_file_caps_request[0], mips64_file_caps_request[1]);
    mips64_file_caps_close_two(lifetime[0], lifetime[1]);
    errno = saved;
    return -1;
}
}

int mips64_file_caps_client_duplicate(const mips64_file_caps_client_t *source,
                                  mips64_file_caps_client_t *out)
{
    if (source == NULL || source->request_fd < 3 ||
        source->lifetime_fd < 3 || !empty_client(out)) {
        errno = EINVAL;
        return -1;
    }
    int mips64_file_caps_request = duplicate_private(source->request_fd);
    if (mips64_file_caps_request < 0)
        return -1;
    int lifetime = duplicate_private(source->lifetime_fd);
    if (lifetime < 0) {
        int saved = errno;
        (void)close(mips64_file_caps_request);
        errno = saved;
        return -1;
    }
    *out = (mips64_file_caps_client_t){mips64_file_caps_request, lifetime};
    return 0;
}

void mips64_file_caps_client_close(mips64_file_caps_client_t *client)
{
    if (client == NULL)
        return;
    int saved = errno;
    mips64_file_caps_close_two(client->request_fd, client->lifetime_fd);
    *client = (mips64_file_caps_client_t)MIPS64_FILE_CAPS_CLIENT_INITIALIZER;
    errno = saved;
}

void mips64_file_caps_server_close(mips64_file_caps_server_t *server)
{
    if (server == NULL)
        return;
    int saved = errno;
    mips64_file_caps_close_two(server->request_fd, server->lifetime_fd);
    *server = (mips64_file_caps_server_t)MIPS64_FILE_CAPS_SERVER_INITIALIZER;
    errno = saved;
}

 void mips64_file_caps_put_u32(unsigned char *at, uint32_t value)
{
    for (unsigned int i = 0; i < 4; ++i)
        at[i] = (unsigned char)(value >> (8u * i));
}

 uint32_t mips64_file_caps_get_u32(const unsigned char *at)
{
    uint32_t value = 0;
    for (unsigned int i = 0; i < 4; ++i)
        value |= (uint32_t)at[i] << (8u * i);
    return value;
}

 void mips64_file_caps_put_u64(unsigned char *at, uint64_t value)
{
    for (unsigned int i = 0; i < 8; ++i)
        at[i] = (unsigned char)(value >> (8u * i));
}

 uint64_t mips64_file_caps_get_u64(const unsigned char *at)
{
    uint64_t value = 0;
    for (unsigned int i = 0; i < 8; ++i)
        value |= (uint64_t)at[i] << (8u * i);
    return value;
}

 void mips64_file_caps_frame_base(unsigned char frame[FRAME_SIZE], unsigned char op)
{
    memset(frame, 0, FRAME_SIZE);
    memcpy(frame, "RVFC", 4);
    frame[4] = 1;
    frame[5] = op;
}

 bool mips64_file_caps_frame_valid(const unsigned char frame[FRAME_SIZE],
                        unsigned char op)
{
    return memcmp(frame, "RVFC", 4) == 0 && frame[4] == 1 &&
           frame[5] == op && frame[6] == 0 && frame[7] == 0;
}



/* Every ancillary FD is receiver-owned, including descriptors 0..2 when
 * native stdio was closed. Walk the whole chain before interpreting a frame. */
 int mips64_file_caps_collect_rights(struct msghdr *message, int rights[MAX_RIGHTS],
                          size_t *count)
{
    *count = 0;
    bool valid = true;
    const unsigned char *begin = message->msg_control;
    for (struct cmsghdr *header = CMSG_FIRSTHDR(message); header != NULL;
         header = CMSG_NXTHDR(message, header)) {
        size_t offset = (const unsigned char *)header - begin;
        if (offset > message->msg_controllen ||
            message->msg_controllen - offset < CMSG_LEN(0)) {
            valid = false;
            break;
        }
        size_t remaining = message->msg_controllen - offset;
        if (header->cmsg_level != SOL_SOCKET ||
            header->cmsg_type != SCM_RIGHTS) {
            valid = false;
            if (header->cmsg_len < CMSG_LEN(0) ||
                header->cmsg_len > remaining)
                break;
            continue;
        }
        size_t payload = header->cmsg_len >= CMSG_LEN(0) ?
            header->cmsg_len - CMSG_LEN(0) : 0;
        if (header->cmsg_len > remaining) {
            payload = remaining - CMSG_LEN(0);
            valid = false;
        }
        if (payload % sizeof(int) != 0) {
            valid = false;
            payload -= payload % sizeof(int);
        }
        size_t present = payload / sizeof(int);
        for (size_t i = 0; i < present; ++i) {
            int fd = -1;
            memcpy(&fd, CMSG_DATA(header) + i * sizeof(int), sizeof(fd));
            if (*count < MAX_RIGHTS)
                rights[(*count)++] = fd;
            else {
                if (fd >= 0)
                    (void)close(fd);
                valid = false;
            }
        }
        if (header->cmsg_len < CMSG_LEN(0) ||
            header->cmsg_len > remaining) {
            valid = false;
            break;
        }
    }
    if ((message->msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0)
        valid = false;
    return valid ? 0 : -1;
}

static ssize_t send_packet(int socket_fd, const unsigned char *frame,
                           size_t frame_size, const int *rights, size_t count)
{
    if (count > 4) {
        errno = EINVAL;
        return -1;
    }
    struct iovec vector = {.iov_base = (void *)frame, .iov_len = frame_size};
    union {
        struct cmsghdr alignment;
        unsigned char bytes[CMSG_SPACE(4 * sizeof(int))];
    } ancillary;
    memset(&ancillary, 0, sizeof(ancillary));
    struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1};
    if (count != 0) {
        message.msg_control = ancillary.bytes;
        message.msg_controllen = CMSG_SPACE(count * sizeof(int));
        struct cmsghdr *header = CMSG_FIRSTHDR(&message);
        if (header == NULL) {
            errno = EIO;
            return -1;
        }
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(count * sizeof(int));
        memcpy(CMSG_DATA(header), rights, count * sizeof(int));
    }
    return sendmsg(socket_fd, &message, MSG_DONTWAIT | MSG_NOSIGNAL);
}

 ssize_t mips64_file_caps_send_frame(int socket_fd, const unsigned char frame[FRAME_SIZE],
                          const int *rights, size_t count)
{
    return send_packet(socket_fd, frame, FRAME_SIZE, rights, count);
}


static int64_t monotonic_ms(void)
{
    struct timespec time;
    if (clock_gettime(CLOCK_MONOTONIC, &time) != 0)
        return -1;
    if (time.tv_sec < 0 || time.tv_nsec < 0 ||
        time.tv_nsec >= 1000000000 || time.tv_sec > INT64_MAX / 1000) {
        errno = EOVERFLOW;
        return -1;
    }
    int64_t whole = (int64_t)time.tv_sec * 1000;
    int64_t fraction = time.tv_nsec / 1000000;
    if (whole > INT64_MAX - REPLY_WAIT_MS - fraction) {
        errno = EOVERFLOW;
        return -1;
    }
    return whole + fraction;
}

 int mips64_file_caps_await_reply(int reply_fd, int life_fd, unsigned char *frame,
                       size_t frame_size,
                       int rights[MAX_RIGHTS], size_t *right_count)
{
    int64_t start = monotonic_ms();
    if (start < 0)
        return -1;
    int64_t deadline = start + REPLY_WAIT_MS;
    for (;;) {
        struct iovec vector = {.iov_base = frame, .iov_len = frame_size};
        union {
            struct cmsghdr alignment;
            unsigned char bytes[CMSG_SPACE(MAX_RIGHTS * sizeof(int))];
        } ancillary;
        memset(&ancillary, 0, sizeof(ancillary));
        struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1,
            .msg_control = ancillary.bytes, .msg_controllen = sizeof(ancillary.bytes)};
        ssize_t received = recvmsg(reply_fd, &message, MSG_DONTWAIT);
        if (received >= 0) {
            if (mips64_file_caps_collect_rights(&message, rights, right_count) != 0 ||
                received != (ssize_t)frame_size) {
                errno = EPROTO;
                return -1;
            }
            return 0;
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
            return -1;
        int64_t now = monotonic_ms();
        if (now < 0)
            return -1;
        if (now >= deadline) {
            errno = ETIMEDOUT;
            return -1;
        }
        struct pollfd waiters[2] = {
            {.fd = reply_fd, .events = POLLIN},
            {.fd = life_fd, .events = POLLIN | POLLHUP}
        };
        int wait_ms = (int)(deadline - now);
        int ready = poll(waiters, 2, wait_ms);
        if (ready < 0 && errno == EINTR)
            continue;
        if (ready < 0)
            return -1;
        if (ready == 0) {
            errno = ETIMEDOUT;
            return -1;
        }
        /* The reply wins when service shutdown and a complete response race. */
        if ((waiters[0].revents & (POLLIN | POLLERR)) != 0)
            continue;
        if ((waiters[1].revents & (POLLHUP | POLLERR | POLLNVAL)) != 0) {
            errno = EIO;
            return -1;
        }
    }
}

 int mips64_file_caps_request(const mips64_file_caps_client_t *client, unsigned char op,
                   uint64_t id, uint64_t attempt, int source_fd, int *out_fd,
                   int *out_native_errno)
{
    if (client == NULL || client->request_fd < 3 || client->lifetime_fd < 3 ||
        id == 0 || (op != OP_REGISTER && op != OP_FETCH &&
                    op != OP_TRUNCATE_STAGE && op != OP_TRUNCATE_EXECUTE)) {
        errno = EINVAL;
        return -1;
    }
    int reply[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, reply) != 0)
        return -1;
    if (mips64_file_caps_private_fd(&reply[0]) != 0 || mips64_file_caps_private_fd(&reply[1]) != 0 ||
        mips64_file_caps_no_sigpipe(reply[1]) != 0) {
        int saved = errno;
        mips64_file_caps_close_two(reply[0], reply[1]);
        errno = saved;
        return -1;
    }
    unsigned char frame[FRAME_SIZE];
    mips64_file_caps_frame_base(frame, op);
    mips64_file_caps_put_u64(frame + 8, id);
    mips64_file_caps_put_u64(frame + 16, attempt);
    /* The queued mips64_file_caps_request pins its own sending endpoint too. On Darwin a
     * final close can otherwise discard a still-queued datagram. */
    int rights[4] = {reply[1], client->lifetime_fd, client->request_fd,
                     source_fd};
    size_t sent_count = op == OP_REGISTER || op == OP_TRUNCATE_STAGE ? 4 : 3;
    ssize_t sent = mips64_file_caps_send_frame(client->request_fd, frame, rights, sent_count);
    int send_error = errno;
    (void)close(reply[1]);
    reply[1] = -1;
    if (sent != FRAME_SIZE) {
        (void)close(reply[0]);
        errno = sent >= 0 ? EIO : send_error;
        return -1;
    }
    TEST_POINT(op == OP_REGISTER ? MIPS64_FILE_CAPS_TEST_REGISTER_SENT :
               op == OP_FETCH ? MIPS64_FILE_CAPS_TEST_FETCH_SENT :
               op == OP_TRUNCATE_STAGE ? MIPS64_FILE_CAPS_TEST_TRUNCATE_STAGE_SENT :
               MIPS64_FILE_CAPS_TEST_TRUNCATE_EXECUTE_SENT);
    int received_rights[MAX_RIGHTS] = {-1, -1, -1, -1};
    size_t received_count = 0;
    int result = mips64_file_caps_await_reply(reply[0], client->lifetime_fd, frame, FRAME_SIZE,
                             received_rights, &received_count);
    (void)close(reply[0]);
    if (result != 0) {
        mips64_file_caps_close_rights(received_rights, received_count);
        errno = EIO; /* Submitted mutation or fetch outcome is uncertain. */
        return -1;
    }
    uint32_t status = mips64_file_caps_get_u32(frame + 8);
    uint32_t native_error = mips64_file_caps_get_u32(frame + 20);
    bool valid = mips64_file_caps_frame_valid(frame, op) && mips64_file_caps_get_u64(frame + 12) == id &&
                 native_error < 4096 && status < 4096 &&
                 ((op == OP_TRUNCATE_EXECUTE && status == 0) || native_error == 0) &&
                 (status != 0 ? received_count == 0 :
                  received_count == (op == OP_FETCH ? 1u : 0u));
    if (!valid) {
        mips64_file_caps_close_rights(received_rights, received_count);
        errno = EIO;
        return -1;
    }
    if (status != 0) {
        errno = (int)status;
        return -1;
    }
    if (op == OP_FETCH) {
        if (mips64_file_caps_private_fd(&received_rights[0]) != 0) {
            int saved = errno;
            mips64_file_caps_close_rights(received_rights, received_count);
            errno = saved;
            return -1;
        }
        *out_fd = received_rights[0];
        received_rights[0] = -1;
    }
    if (op == OP_TRUNCATE_EXECUTE)
        *out_native_errno = (int)native_error;
    return 0;
}


int mips64_file_caps_register(const mips64_file_caps_client_t *client,
                          int source_fd, uint64_t source_id,
                          uint64_t *attempts)
{
    if (attempts == NULL || source_fd < 0 || source_id == 0) {
        errno = EINVAL;
        return -1;
    }
    struct stat status;
    if (fstat(source_fd, &status) != 0)
        return -1;
    int flags = fcntl(source_fd, F_GETFL);
    if (flags < 0)
        return -1;
    if (!S_ISREG(status.st_mode) || (flags & O_ACCMODE) == O_WRONLY
#ifdef O_PATH
        || (flags & O_PATH) != 0
#endif
        ) {
        errno = EINVAL;
        return -1;
    }
    if (*attempts >= MIPS64_FILE_CAPS_MAX_ATTEMPTS) {
        errno = ENOSPC;
        return -1;
    }
    ++*attempts;
    atomic_thread_fence(memory_order_release);
    return mips64_file_caps_request(client, OP_REGISTER, source_id, *attempts, source_fd, NULL, NULL);
}

static int register_cleanup_part(const mips64_file_caps_client_t *client,
                                 unsigned char op, int borrowed_fd,
                                 const char *directory, size_t path_length,
                                 bool *submitted)
{
    int reply[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, reply) != 0)
        return -1;
    if (mips64_file_caps_private_fd(&reply[0]) != 0 || mips64_file_caps_private_fd(&reply[1]) != 0 ||
        mips64_file_caps_no_sigpipe(reply[1]) != 0) {
        int saved = errno;
        mips64_file_caps_close_two(reply[0], reply[1]);
        errno = saved;
        return -1;
    }
    unsigned char packet[CLEANUP_FRAME_SIZE] = {0};
    memcpy(packet, "RVFC", 4);
    packet[4] = CLEANUP_VERSION;
    packet[5] = op;
    mips64_file_caps_put_u64(packet + 8, op);
    if (op == OP_CLEANUP_DIRECTORY) {
        mips64_file_caps_put_u32(packet + 16, (uint32_t)path_length);
        memcpy(packet + 32, directory, path_length);
    }
    /* Both queued sender and lifetime rights survive a producer close. The
     * fourth right is the one exact borrowed family descriptor for this leg. */
    const int rights[4] = {reply[1], client->lifetime_fd,
                           client->request_fd, borrowed_fd};
    /* A failed native send may have submitted a complete datagram. Mark
     * possible delegation before entering the kernel, not after its reply. */
    if (submitted != NULL)
        *submitted = true;
    ssize_t sent = send_packet(client->request_fd, packet, sizeof(packet),
                               rights, 4);
    int send_error = errno;
    (void)close(reply[1]);
    reply[1] = -1;
    if (sent != (ssize_t)sizeof(packet)) {
        (void)close(reply[0]);
        errno = sent >= 0 ? EIO : send_error;
        return -1;
    }
    if (op == OP_CLEANUP_DIRECTORY)
        TEST_POINT(MIPS64_FILE_CAPS_TEST_CLEANUP_DIRECTORY_SENT);
    unsigned char answer[FRAME_SIZE];
    int received_rights[MAX_RIGHTS] = {-1, -1, -1, -1};
    size_t received_count = 0;
    int result = mips64_file_caps_await_reply(reply[0], client->lifetime_fd, answer,
                             sizeof(answer), received_rights, &received_count);
    (void)close(reply[0]);
    if (result != 0 || received_count != 0 ||
        !mips64_file_caps_frame_valid(answer, op) || mips64_file_caps_get_u64(answer + 12) != op ||
        mips64_file_caps_get_u32(answer + 20) != 0) {
        mips64_file_caps_close_rights(received_rights, received_count);
        errno = EIO;
        return -1;
    }
    uint32_t native_error = mips64_file_caps_get_u32(answer + 8);
    if (native_error != 0) {
        errno = native_error <= INT_MAX ? (int)native_error : EPROTO;
        return -1;
    }
    return 0;
}

int mips64_file_caps_register_terminal_cleanup(const mips64_file_caps_client_t *client,
                                            int borrowed_control_fd,
                                            int borrowed_directory_fd,
                                            const char *directory,
                                            bool *may_have_delegated)
{
    if (may_have_delegated != NULL)
        *may_have_delegated = false;
    if (client == NULL || client->request_fd < 3 || client->lifetime_fd < 3 ||
        borrowed_control_fd < 3 || borrowed_directory_fd < 3 ||
        borrowed_control_fd == borrowed_directory_fd || directory == NULL ||
        may_have_delegated == NULL) {
        errno = EINVAL;
        return -1;
    }
    size_t length = strnlen(directory, 64);
    if (length == 0 || length >= 64 || directory[0] != '/') {
        errno = EINVAL;
        return -1;
    }
    if (register_cleanup_part(client, OP_CLEANUP_CONTROL,
                              borrowed_control_fd, NULL, 0, NULL) != 0)
        return -1;
    return register_cleanup_part(client, OP_CLEANUP_DIRECTORY,
                                 borrowed_directory_fd, directory, length,
                                 may_have_delegated);
}

static int departure_reply_byte(int reply_fd, int lifetime_fd, char *answer)
{
    int64_t start = monotonic_ms();
    if (start < 0)
        return -1;
    int64_t deadline = start + REPLY_WAIT_MS;
    for (;;) {
        ssize_t count = recv(reply_fd, answer, 1, MSG_DONTWAIT);
        if (count == 1)
            return 0;
        if (count == 0) {
            errno = EIO;
            return -1;
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
            return -1;
        int64_t now = monotonic_ms();
        if (now < 0)
            return -1;
        if (now >= deadline) {
            errno = ETIMEDOUT;
            return -1;
        }
        struct pollfd waiters[2] = {
            {.fd = reply_fd, .events = POLLIN | POLLHUP},
            {.fd = lifetime_fd, .events = POLLIN | POLLHUP}
        };
        int ready = poll(waiters, 2, (int)(deadline - now));
        if (ready < 0 && errno == EINTR)
            continue;
        if (ready < 0)
            return -1;
        if (ready == 0) {
            errno = ETIMEDOUT;
            return -1;
        }
        if ((waiters[0].revents & (POLLIN | POLLHUP)) != 0)
            continue;
        if (lifetime_fd >= 0 &&
            (waiters[1].revents & (POLLHUP | POLLERR | POLLNVAL)) != 0) {
            errno = EIO;
            return -1;
        }
    }
}

int mips64_file_caps_departure_begin(const mips64_file_caps_client_t *client,
                                 mips64_file_caps_departure_t *out)
{
    if (client == NULL || client->request_fd < 3 || client->lifetime_fd < 3 ||
        out == NULL || out->reply_fd != -1 || out->active ||
        active_departure != NULL) {
        errno = EINVAL;
        return -1;
    }
    int prior;
    int cancel_error = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior);
    if (cancel_error != 0) {
        errno = cancel_error;
        return -1;
    }
    int pair[2] = {-1, -1};
    int saved = 0;
    bool submitted = false;
    if (socketpair(AF_UNIX, native_lifetime_socket_type(), 0, pair) != 0 ||
        mips64_file_caps_private_fd(&pair[0]) != 0 || mips64_file_caps_private_fd(&pair[1]) != 0 ||
        mips64_file_caps_no_sigpipe(pair[0]) != 0 || mips64_file_caps_no_sigpipe(pair[1]) != 0) {
        saved = errno;
        goto failed;
    }
    unsigned char frame[FRAME_SIZE] = {0};
    memcpy(frame, "RVFD", 4);
    frame[4] = DEPARTURE_VERSION;
    frame[5] = OP_DEPARTURE_PREPARE;
    mips64_file_caps_put_u64(frame + 8, 1);
    int rights[3] = {pair[1], client->lifetime_fd, client->request_fd};
    submitted = true;
    ssize_t sent = send_packet(client->request_fd, frame, sizeof(frame), rights, 3);
    saved = sent < 0 ? errno : EIO;
    if (sent != (ssize_t)sizeof(frame))
        goto failed;
    TEST_POINT(MIPS64_FILE_CAPS_TEST_DEPARTURE_PREPARE_SENT);
    char answer = 0;
    if (departure_reply_byte(pair[0], client->lifetime_fd, &answer) != 0) {
        saved = errno;
        goto failed;
    }
    if (answer == 'E') {
        saved = EAGAIN; /* Admission refused before caller teardown. */
        submitted = false;
        goto failed;
    }
    if (answer != 'A') {
        saved = EPROTO;
        goto failed;
    }
    /* Darwin can discard a queued SCM endpoint when its producer dies.
     * Retain this local sender until ADMITTED proves server ownership. */
    (void)close(pair[1]);
    pair[1] = -1;
    *out = (mips64_file_caps_departure_t){.reply_fd = pair[0],
        .owner_thread = pthread_self(), .prior_cancel_state = prior,
        .active = true, .finished = false};
    active_departure = out;
    return 0;
failed:
    mips64_file_caps_close_two(pair[0], pair[1]);
    /* Once PREPARE may have entered the kernel, the caller must fail-stop;
     * restoring cancellation could abandon its family before that decision. */
    if (!submitted)
        (void)pthread_setcancelstate(prior, NULL);
    errno = saved;
    return submitted ? -2 : -1;
}

int mips64_file_caps_departure_finish(mips64_file_caps_departure_t *handle,
                                  bool *last)
{
    if (handle == NULL || last == NULL || !handle->active || handle->finished ||
        handle->reply_fd < 3 || active_departure != handle ||
        !pthread_equal(handle->owner_thread, pthread_self())) {
        errno = EINVAL;
        return -1;
    }
    char release = 'R';
    ssize_t sent = send(handle->reply_fd, &release, 1,
                        MSG_DONTWAIT | MSG_NOSIGNAL);
    if (sent != 1) {
        errno = sent < 0 ? errno : EIO;
        return -2;
    }
    if (shutdown(handle->reply_fd, SHUT_WR) != 0)
        return -2;
    char answer = 0;
    if (departure_reply_byte(handle->reply_fd, -1, &answer) != 0)
        return -2;
    if (answer != 'N' && answer != 'L') {
        errno = EPROTO;
        return -2;
    }
    *last = answer == 'L';
    handle->finished = true;
    (void)close(handle->reply_fd);
    handle->reply_fd = -1;
    return 0;
}

int mips64_file_caps_departure_end(mips64_file_caps_departure_t *handle)
{
    if (handle == NULL || !handle->active || !handle->finished ||
        active_departure != handle ||
        !pthread_equal(handle->owner_thread, pthread_self())) {
        errno = EINVAL;
        return -1;
    }
    int prior = handle->prior_cancel_state;
    active_departure = NULL;
    *handle = (mips64_file_caps_departure_t)MIPS64_FILE_CAPS_DEPARTURE_INITIALIZER;
    int result = pthread_setcancelstate(prior, NULL);
    if (result != 0) {
        errno = result;
        return -1;
    }
    return 0;
}
