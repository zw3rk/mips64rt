/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "exec_state_parts.h"

static void put32(unsigned char *p, uint32_t value)
{
    for (unsigned int i = 0; i < 4; ++i)
        p[i] = (unsigned char)(value >> (8u * i));
}

static void put64(unsigned char *p, uint64_t value)
{
    for (unsigned int i = 0; i < 8; ++i)
        p[i] = (unsigned char)(value >> (8u * i));
}

static uint32_t get32(const unsigned char *p)
{
    uint32_t value = 0;
    for (unsigned int i = 0; i < 4; ++i)
        value |= (uint32_t)p[i] << (8u * i);
    return value;
}

static uint64_t get64(const unsigned char *p)
{
    uint64_t value = 0;
    for (unsigned int i = 0; i < 8; ++i)
        value |= (uint64_t)p[i] << (8u * i);
    return value;
}

static bool write_bytes(writer_t *writer, const void *bytes, size_t length)
{
    if (length > writer->limit - writer->pos) {
        errno = E2BIG;
        return false;
    }
    memcpy(writer->bytes + writer->pos, bytes, length);
    writer->pos += length;
    return true;
}

static bool write32(writer_t *writer, uint32_t value)
{
    unsigned char bytes[4];
    put32(bytes, value);
    return write_bytes(writer, bytes, sizeof(bytes));
}

static bool write64(writer_t *writer, uint64_t value)
{
    unsigned char bytes[8];
    put64(bytes, value);
    return write_bytes(writer, bytes, sizeof(bytes));
}

static bool read_bytes(reader_t *reader, void *bytes, size_t length)
{
    if (length > reader->limit - reader->pos) {
        errno = EINVAL;
        return false;
    }
    memcpy(bytes, reader->bytes + reader->pos, length);
    reader->pos += length;
    return true;
}

static bool read32(reader_t *reader, uint32_t *value)
{
    unsigned char bytes[4];
    if (!read_bytes(reader, bytes, sizeof(bytes)))
        return false;
    *value = get32(bytes);
    return true;
}

static bool read64(reader_t *reader, uint64_t *value)
{
    unsigned char bytes[8];
    if (!read_bytes(reader, bytes, sizeof(bytes)))
        return false;
    *value = get64(bytes);
    return true;
}

static bool string_length(const char *string, size_t maximum, size_t *length)
{
    if (string == NULL) {
        errno = EINVAL;
        return false;
    }
    size_t size = strnlen(string, maximum);
    if (size == maximum) {
        errno = E2BIG;
        return false;
    }
    *length = size + 1;
    return true;
}

static bool write_string(writer_t *writer, const char *string,
                         size_t maximum)
{
    size_t length;
    return string_length(string, maximum, &length) &&
           write32(writer, (uint32_t)length) &&
           write_bytes(writer, string, length);
}

static bool read_string(reader_t *reader, size_t maximum, char **out)
{
    uint32_t length;
    if (!read32(reader, &length))
        return false;
    if (length == 0 || length > maximum || length > reader->limit - reader->pos) {
        errno = EINVAL;
        return false;
    }
    char *copy = malloc(length);
    if (copy == NULL)
        return false;
    if (!read_bytes(reader, copy, length)) {
        free(copy);
        return false;
    }
    if (copy[length - 1] != '\0' || strnlen(copy, length) != length - 1) {
        free(copy);
        errno = EINVAL;
        return false;
    }
    *out = copy;
    return true;
}

static bool family_valid(const mips64_family_exec_state_t *family)
{
    if (family->owner_pid != (uint64_t)getpid() ||
        family->incarnation == 0 ||
        family->incarnation >= family->next_incarnation ||
        family->identity.control_inode == 0 ||
        family->identity.directory_inode == 0)
        return false;
    size_t directory = strnlen(family->directory, sizeof(family->directory));
    return directory < sizeof(family->directory) &&
           (family->creator ? (directory != 0 && family->directory[0] == '/') :
                              directory == 0);
}

static bool config_valid(const mips64_exec_config_t *config)
{
    if (config->xlen != 64 || config->quantum == 0 ||
        (config->flags & ~MIPS64_EXEC_FLAG_ALL) != 0 ||
        config->stats_period > UINT32_MAX ||
        config->progress_period > UINT32_MAX ||
        (config->max_steps != 0 && config->steps > config->max_steps) ||
        config->jit_steps > config->steps ||
        config->fallback_steps > config->steps ||
        config->jit_steps > UINT64_MAX - config->fallback_steps ||
        config->jit_steps + config->fallback_steps > config->steps ||
        config->cache_authority > MIPS64_AOT_AUTHORITY_HYPER_LINUX_APFS_ACL_V1 ||
        (config->cache_blocks != 1 && config->cache_blocks != 2))
        return false;
#ifdef MIPS64_RUNTIME_TEST_ATTRIBUTED_FILE
    if (config->fsize_soft > config->fsize_hard)
        return false;
#endif
    return true;
}

static bool clear_tid_valid(const mips64_exec_tid_clear_t *clear)
{
    if (clear->segment_count == 0 || clear->segment_count > 2)
        return false;
    if (clear->role > MIPS64_EXEC_TID_CALLER_IF_LIVE_PEER)
        return false;
#ifndef MIPS64_RUNTIME_TEST_ATTRIBUTED_FILE
    if (clear->mm_shared_wake_address != 0 || clear->role != MIPS64_EXEC_TID_SIBLING)
        return false;
#endif
    if (clear->mm_shared_wake_address != 0 &&
        (clear->segment_count != 1 || clear->lengths[0] != 4 ||
         (clear->mm_shared_wake_address & 3u) != 0 ||
         (clear->mm_shared_wake_address & (MIPS64_FAMILY_PAGE_SIZE - 1u)) !=
             clear->offsets[0]))
        return false;
    uint32_t total = 0;
    for (uint32_t i = 0; i < 2; ++i) {
        bool used = i < clear->segment_count;
        if (!used) {
            if (clear->keys[i].object_id != 0 ||
                clear->keys[i].page_index != 0 ||
                clear->offsets[i] != 0 || clear->lengths[i] != 0)
                return false;
            continue;
        }
        if (clear->keys[i].object_id == 0 ||
            clear->keys[i].page_index > UINT32_MAX ||
            clear->lengths[i] == 0 || clear->lengths[i] > 4 ||
            clear->offsets[i] > MIPS64_FAMILY_PAGE_SIZE - clear->lengths[i])
            return false;
        total += clear->lengths[i];
    }
    if (total > 4)
        return false;
    if (clear->segment_count == 2 &&
        clear->keys[0].object_id == clear->keys[1].object_id &&
        clear->keys[0].page_index == clear->keys[1].page_index) {
        uint32_t a = clear->offsets[0], b = clear->offsets[1];
        if (a < b + clear->lengths[1] && b < a + clear->lengths[0])
            return false;
    }
    return true;
}

static bool state_valid(const mips64_exec_state_t *state)
{
    if (state == NULL || state->args.argc == 0) {
        errno = EINVAL;
        return false;
    }
    if (state->args.argc > MIPS64_LINUX_EXEC_VECTOR_MAX ||
        state->args.envc > MIPS64_LINUX_EXEC_VECTOR_MAX ||
        state->child_count > EXEC_INVENTORY_MAX ||
        state->fifo_count > EXEC_INVENTORY_MAX ||
        state->clear_tid_count > EXEC_INVENTORY_MAX) {
        errno = E2BIG;
        return false;
    }
    if (state->args.argv == NULL || state->args.envp == NULL ||
        state->args.argv[state->args.argc] != NULL ||
        state->args.envp[state->args.envc] != NULL ||
        (state->child_count != 0 && state->children == NULL) ||
        (state->fifo_count != 0 && state->fifos == NULL) ||
        (state->clear_tid_count != 0 && state->clear_tids == NULL) ||
        !mips64_linux_signal_exec_state_valid(&state->signals) ||
        !family_valid(&state->family) || state->old_mm_id == 0 ||
#ifdef MIPS64_RUNTIME_TEST_ATTRIBUTED_FILE
        (state->old_mm_root_object == 0) != (state->old_mm_task_id == 0) ||
#endif
        !config_valid(&state->config)) {
        errno = EINVAL;
        return false;
    }
    size_t length, total = 0;
    if (!string_length(state->args.path, MIPS64_LINUX_EXEC_PATH_MAX, &length))
        return false;
    total += length;
    for (size_t i = 0; i < state->args.argc + state->args.envc; ++i) {
        const char *string = i < state->args.argc ? state->args.argv[i] :
                             state->args.envp[i - state->args.argc];
        if (!string_length(string, MIPS64_LINUX_EXEC_BYTES_MAX, &length))
            return false;
        if (length > MIPS64_LINUX_EXEC_BYTES_MAX - total) {
            errno = E2BIG;
            return false;
        }
        total += length;
    }
    if (state->sysroot != NULL) {
        if (!string_length(state->sysroot, EXEC_SYSROOT_MAX, &length))
            return false;
        if (state->sysroot[0] != '/') {
            errno = EINVAL;
            return false;
        }
    }
    if (state->cache_directory != NULL) {
        if (!string_length(state->cache_directory,
                           EXEC_CACHE_DIRECTORY_MAX, &length))
            return false;
        if (length == 1 || state->cache_directory[0] != '/') {
            errno = EINVAL;
            return false;
        }
    } else if (state->config.cache_authority != MIPS64_AOT_AUTHORITY_AUTO ||
               state->config.cache_blocks != 1) {
        errno = EINVAL;
        return false;
    }
    for (size_t i = 0; i < state->child_count; ++i) {
        if (state->children[i].pid <= 0 ||
            state->children[i].pid == getpid() ||
            state->children[i].cap_fd < 3) {
            errno = EINVAL;
            return false;
        }
        for (size_t j = 0; j < i; ++j)
            if (state->children[j].pid == state->children[i].pid ||
                state->children[j].cap_fd == state->children[i].cap_fd) {
                errno = EINVAL;
                return false;
            }
    }
    for (size_t i = 0; i < state->fifo_count; ++i)
        if (state->fifos[i].inode == 0 ||
            state->fifos[i].birth_nanoseconds >= 1000000000u) {
            errno = EINVAL;
            return false;
        }
    bool caller_root_valid = true;
#ifdef MIPS64_RUNTIME_TEST_ATTRIBUTED_FILE
    caller_root_valid = state->old_mm_root_object != 0;
#endif
    size_t conditional_callers = 0;
    for (size_t i = 0; i < state->clear_tid_count; ++i)
        if (!clear_tid_valid(&state->clear_tids[i]) ||
            (state->clear_tids[i].role == MIPS64_EXEC_TID_CALLER_IF_LIVE_PEER &&
             (++conditional_callers > 1 || !caller_root_valid))) {
            errno = EINVAL;
            return false;
        }
    return true;
}

void mips64_exec_state_destroy(mips64_exec_state_t *state)
{
    if (state == NULL)
        return;
    int saved = errno;
    mips64_linux_exec_args_destroy(&state->args);
    free(state->sysroot);
    free(state->cache_directory);
    free(state->children);
    free(state->fifos);
    free(state->clear_tids);
    memset(state, 0, sizeof(*state));
    errno = saved;
}

static bool encode(const mips64_exec_state_t *state, unsigned char **out,
                   size_t *length)
{
    if (!state_valid(state))
        return false;
    unsigned char *bytes = calloc(1, EXEC_RECORD_MAX);
    if (bytes == NULL)
        return false;
    writer_t writer = {.bytes = bytes, .limit = EXEC_RECORD_MAX};
    const mips64_family_exec_state_t *family = &state->family;
    const mips64_exec_config_t *config = &state->config;
    bool valid = write_bytes(&writer, EXEC_RECORD_MAGIC, 8) &&
        write32(&writer, EXEC_RECORD_VERSION) && write32(&writer, EXEC_RECORD_HEADER) &&
        write64(&writer, 0) &&
        write32(&writer, (uint32_t)state->args.argc) &&
        write32(&writer, (uint32_t)state->args.envc) &&
        write32(&writer, (uint32_t)state->child_count) &&
        write32(&writer, (uint32_t)state->fifo_count) &&
        write64(&writer, config->max_steps) &&
        write64(&writer, config->steps) &&
        write64(&writer, config->jit_steps) &&
        write64(&writer, config->fallback_steps) &&
        write64(&writer, config->progress_period) &&
        write64(&writer, config->stats_period) &&
        write64(&writer, config->worker_attempts) &&
#ifdef MIPS64_RUNTIME_TEST_ATTRIBUTED_FILE
        write64(&writer, config->fsize_soft) &&
        write64(&writer, config->fsize_hard) &&
#endif
        write32(&writer, config->quantum) &&
        write32(&writer, config->flags) &&
        write32(&writer, config->xlen) &&
        write64(&writer, family->owner_pid) &&
        write64(&writer, family->incarnation) &&
        write64(&writer, family->recovery_epoch) &&
        write64(&writer, family->next_incarnation) &&
        write64(&writer, state->old_mm_id) &&
#ifdef MIPS64_RUNTIME_TEST_ATTRIBUTED_FILE
        write64(&writer, state->old_mm_root_object) &&
        write64(&writer, state->old_mm_task_id) &&
#endif
        write64(&writer, (uint64_t)family->identity.control_device) &&
        write64(&writer, (uint64_t)family->identity.control_inode) &&
        write64(&writer, (uint64_t)family->identity.directory_device) &&
        write64(&writer, (uint64_t)family->identity.directory_inode) &&
        write32(&writer, family->creator ? 1u : 0u) &&
        write_string(&writer, family->directory, sizeof(family->directory)) &&
        write64(&writer, state->signals.ignored) &&
        write64(&writer, state->signals.blocked) &&
        write64(&writer, state->signals.process_pending) &&
        write64(&writer, state->signals.thread_pending) &&
        write_bytes(&writer, state->signals.process_information,
                    sizeof(state->signals.process_information)) &&
        write_bytes(&writer, state->signals.thread_information,
                    sizeof(state->signals.thread_information)) &&
        write_string(&writer, state->args.path, MIPS64_LINUX_EXEC_PATH_MAX);
    for (size_t i = 0; valid && i < state->args.argc; ++i)
        valid = write_string(&writer, state->args.argv[i],
                             MIPS64_LINUX_EXEC_BYTES_MAX);
    for (size_t i = 0; valid && i < state->args.envc; ++i)
        valid = write_string(&writer, state->args.envp[i],
                             MIPS64_LINUX_EXEC_BYTES_MAX);
    if (valid)
        valid = state->sysroot == NULL ? write32(&writer, 0) :
                write_string(&writer, state->sysroot, EXEC_SYSROOT_MAX);
    for (size_t i = 0; valid && i < state->child_count; ++i)
        valid = write64(&writer, (uint64_t)state->children[i].pid) &&
                write64(&writer, (uint64_t)state->children[i].cap_fd);
    for (size_t i = 0; valid && i < state->fifo_count; ++i) {
        const mips64_linux_fifo_identity_t *fifo = &state->fifos[i];
        valid = write32(&writer, fifo->device_major) &&
                write32(&writer, fifo->device_minor) &&
                write64(&writer, fifo->inode) &&
                write64(&writer, (uint64_t)fifo->birth_seconds) &&
                write32(&writer, fifo->birth_nanoseconds) &&
                write32(&writer, 0);
    }
    if (valid)
        valid = write32(&writer, (uint32_t)state->clear_tid_count);
    for (size_t i = 0; valid && i < state->clear_tid_count; ++i) {
        const mips64_exec_tid_clear_t *clear = &state->clear_tids[i];
        valid = write32(&writer, clear->segment_count);
        for (size_t segment = 0; valid && segment < 2; ++segment)
            valid = write64(&writer, clear->keys[segment].object_id) &&
                    write64(&writer, clear->keys[segment].page_index) &&
                    write32(&writer, clear->offsets[segment]) &&
                    write32(&writer, clear->lengths[segment]);
#ifdef MIPS64_RUNTIME_TEST_ATTRIBUTED_FILE
        if (valid)
            valid = write64(&writer, clear->mm_shared_wake_address) &&
                    write64(&writer, clear->role);
#endif
    }
    if (valid)
        valid = write32(&writer, config->cache_authority) &&
                write32(&writer, config->cache_blocks) &&
                (state->cache_directory == NULL ? write32(&writer, 0) :
                 write_string(&writer, state->cache_directory,
                              EXEC_CACHE_DIRECTORY_MAX));
    if (!valid) {
        free(bytes);
        return false;
    }
    put64(bytes + 16, writer.pos);
    *out = bytes;
    *length = writer.pos;
    return true;
}

static int64_t decode_i64(uint64_t word)
{
    if (word <= INT64_MAX)
        return (int64_t)word;
    return -(int64_t)(~word) - 1;
}

 bool mips64_exec_state_decode(const unsigned char *bytes, size_t length,
                   mips64_exec_state_t *out)
{
    if (length < EXEC_RECORD_HEADER || memcmp(bytes, EXEC_RECORD_MAGIC, 8) != 0 ||
        get32(bytes + 8) != EXEC_RECORD_VERSION ||
        get32(bytes + 12) != EXEC_RECORD_HEADER ||
        get64(bytes + 16) != length) {
        errno = EINVAL;
        return false;
    }
    reader_t reader = {.bytes = bytes, .pos = EXEC_RECORD_HEADER,
                       .limit = length};
    mips64_exec_state_t staged = {0};
    mips64_family_exec_state_t *family = &staged.family;
    mips64_exec_config_t *config = &staged.config;
    uint32_t argc, envc, children, fifos, creator;
    uint64_t control_device, control_inode, directory_device, directory_inode;
    bool valid = read32(&reader, &argc) && read32(&reader, &envc) &&
        read32(&reader, &children) && read32(&reader, &fifos) &&
        read64(&reader, &config->max_steps) &&
        read64(&reader, &config->steps) &&
        read64(&reader, &config->jit_steps) &&
        read64(&reader, &config->fallback_steps) &&
        read64(&reader, &config->progress_period) &&
        read64(&reader, &config->stats_period) &&
        read64(&reader, &config->worker_attempts) &&
#ifdef MIPS64_RUNTIME_TEST_ATTRIBUTED_FILE
        read64(&reader, &config->fsize_soft) &&
        read64(&reader, &config->fsize_hard) &&
#endif
        read32(&reader, &config->quantum) &&
        read32(&reader, &config->flags) &&
        read32(&reader, &config->xlen) &&
        read64(&reader, &family->owner_pid) &&
        read64(&reader, &family->incarnation) &&
        read64(&reader, &family->recovery_epoch) &&
        read64(&reader, &family->next_incarnation) &&
        read64(&reader, &staged.old_mm_id) &&
#ifdef MIPS64_RUNTIME_TEST_ATTRIBUTED_FILE
        read64(&reader, &staged.old_mm_root_object) &&
        read64(&reader, &staged.old_mm_task_id) &&
#endif
        read64(&reader, &control_device) &&
        read64(&reader, &control_inode) &&
        read64(&reader, &directory_device) &&
        read64(&reader, &directory_inode) &&
        read32(&reader, &creator);
    if (!valid)
        goto fail;
    if (argc == 0 || argc > MIPS64_LINUX_EXEC_VECTOR_MAX ||
        envc > MIPS64_LINUX_EXEC_VECTOR_MAX ||
        children > EXEC_INVENTORY_MAX || fifos > EXEC_INVENTORY_MAX ||
        creator > 1 || (uint64_t)(dev_t)control_device != control_device ||
        (uint64_t)(ino_t)control_inode != control_inode ||
        (uint64_t)(dev_t)directory_device != directory_device ||
        (uint64_t)(ino_t)directory_inode != directory_inode) {
        errno = EINVAL;
        goto fail;
    }
    family->identity = (mips64_family_identity_t){
        .control_device = (dev_t)control_device,
        .control_inode = (ino_t)control_inode,
        .directory_device = (dev_t)directory_device,
        .directory_inode = (ino_t)directory_inode
    };
    family->creator = creator != 0;
    char *directory = NULL;
    if (!read_string(&reader, sizeof(family->directory), &directory))
        goto fail;
    size_t directory_length = strlen(directory) + 1;
    memcpy(family->directory, directory, directory_length);
    free(directory);
    if (!read64(&reader, &staged.signals.ignored) ||
        !read64(&reader, &staged.signals.blocked) ||
        !read64(&reader, &staged.signals.process_pending) ||
        !read64(&reader, &staged.signals.thread_pending) ||
        !read_bytes(&reader, staged.signals.process_information,
                    sizeof(staged.signals.process_information)) ||
        !read_bytes(&reader, staged.signals.thread_information,
                    sizeof(staged.signals.thread_information)) ||
        !read_string(&reader, MIPS64_LINUX_EXEC_PATH_MAX, &staged.args.path))
        goto fail;
    staged.args.argc = argc;
    staged.args.envc = envc;
    staged.args.argv = calloc((size_t)argc + 1, sizeof(char *));
    staged.args.envp = calloc((size_t)envc + 1, sizeof(char *));
    if (staged.args.argv == NULL || staged.args.envp == NULL)
        goto fail;
    for (size_t i = 0; i < argc; ++i)
        if (!read_string(&reader, MIPS64_LINUX_EXEC_BYTES_MAX,
                         &staged.args.argv[i]))
            goto fail;
    for (size_t i = 0; i < envc; ++i)
        if (!read_string(&reader, MIPS64_LINUX_EXEC_BYTES_MAX,
                         &staged.args.envp[i]))
            goto fail;
    uint32_t sysroot_length;
    if (!read32(&reader, &sysroot_length))
        goto fail;
    if (sysroot_length != 0) {
        reader.pos -= 4;
        if (!read_string(&reader, EXEC_SYSROOT_MAX, &staged.sysroot))
            goto fail;
    }
    staged.child_count = children;
    staged.fifo_count = fifos;
    if (children != 0) {
        staged.children = calloc(children, sizeof(*staged.children));
        if (staged.children == NULL)
            goto fail;
    }
    for (size_t i = 0; i < children; ++i) {
        uint64_t pid, cap_fd;
        if (!read64(&reader, &pid) || !read64(&reader, &cap_fd))
            goto fail;
        if (pid == 0 || pid > INT_MAX || cap_fd < 3 || cap_fd > INT_MAX) {
            errno = EINVAL;
            goto fail;
        }
        staged.children[i] = (mips64_process_child_cap_t){
            .pid = (pid_t)pid, .cap_fd = (int)cap_fd};
    }
    if (fifos != 0) {
        staged.fifos = calloc(fifos, sizeof(*staged.fifos));
        if (staged.fifos == NULL)
            goto fail;
    }
    for (size_t i = 0; i < fifos; ++i) {
        mips64_linux_fifo_identity_t *fifo = &staged.fifos[i];
        uint64_t seconds;
        uint32_t reserved;
        if (!read32(&reader, &fifo->device_major) ||
            !read32(&reader, &fifo->device_minor) ||
            !read64(&reader, &fifo->inode) ||
            !read64(&reader, &seconds) ||
            !read32(&reader, &fifo->birth_nanoseconds) ||
            !read32(&reader, &reserved))
            goto fail;
        if (reserved != 0) {
            errno = EINVAL;
            goto fail;
        }
        fifo->birth_seconds = decode_i64(seconds);
    }
    uint32_t clear_count;
    if (!read32(&reader, &clear_count))
        goto fail;
    if (clear_count > EXEC_INVENTORY_MAX ||
#ifdef MIPS64_RUNTIME_TEST_ATTRIBUTED_FILE
        clear_count > (reader.limit - reader.pos) / 68u) {
#else
        clear_count > (reader.limit - reader.pos) / 52u) {
#endif
        errno = EINVAL;
        goto fail;
    }
    staged.clear_tid_count = clear_count;
    if (clear_count != 0) {
        staged.clear_tids = calloc(clear_count, sizeof(*staged.clear_tids));
        if (staged.clear_tids == NULL)
            goto fail;
    }
    for (size_t i = 0; i < clear_count; ++i) {
        mips64_exec_tid_clear_t *clear = &staged.clear_tids[i];
        if (!read32(&reader, &clear->segment_count))
            goto fail;
        for (size_t segment = 0; segment < 2; ++segment)
            if (!read64(&reader, &clear->keys[segment].object_id) ||
                !read64(&reader, &clear->keys[segment].page_index) ||
                !read32(&reader, &clear->offsets[segment]) ||
                !read32(&reader, &clear->lengths[segment]))
                goto fail;
#ifdef MIPS64_RUNTIME_TEST_ATTRIBUTED_FILE
        uint64_t role = 0;
        if (!read64(&reader, &clear->mm_shared_wake_address) ||
            !read64(&reader, &role) || role > MIPS64_EXEC_TID_CALLER_IF_LIVE_PEER)
            goto fail;
        clear->role = (mips64_exec_tid_role_t)role;
#endif
    }
    uint32_t cache_directory_length;
    if (!read32(&reader, &config->cache_authority) ||
        !read32(&reader, &config->cache_blocks) ||
        !read32(&reader, &cache_directory_length))
        goto fail;
    if (cache_directory_length != 0) {
        reader.pos -= 4;
        if (!read_string(&reader, EXEC_CACHE_DIRECTORY_MAX,
                         &staged.cache_directory))
            goto fail;
    }
    if (reader.pos != reader.limit || !state_valid(&staged)) {
        if (reader.pos != reader.limit)
            errno = EINVAL;
        goto fail;
    }
    *out = staged;
    return true;
fail: {
        int saved = errno;
        mips64_exec_state_destroy(&staged);
        errno = saved;
        return false;
    }
}

 bool mips64_exec_state_private_metadata(int fd, struct stat *status)
{
    return fd >= 3 && fstat(fd, status) == 0 && S_ISREG(status->st_mode) &&
           status->st_uid == geteuid() && status->st_nlink == 0 &&
           (status->st_mode & 07777) == 0600;
}

 bool mips64_exec_state_same_record_stat(const struct stat *before, const struct stat *after)
{
#ifdef __APPLE__
    struct timespec before_mtime = {before->st_mtime, before->st_mtimensec};
    struct timespec after_mtime = {after->st_mtime, after->st_mtimensec};
    struct timespec before_ctime = {before->st_ctime, before->st_ctimensec};
    struct timespec after_ctime = {after->st_ctime, after->st_ctimensec};
#else
    struct timespec before_mtime = before->st_mtim, after_mtime = after->st_mtim;
    struct timespec before_ctime = before->st_ctim, after_ctime = after->st_ctim;
#endif
    return before->st_dev == after->st_dev && before->st_ino == after->st_ino &&
           before->st_size == after->st_size &&
           before_mtime.tv_sec == after_mtime.tv_sec &&
           before_mtime.tv_nsec == after_mtime.tv_nsec &&
           before_ctime.tv_sec == after_ctime.tv_sec &&
           before_ctime.tv_nsec == after_ctime.tv_nsec;
}

static int write_all(int fd, const unsigned char *bytes, size_t length)
{
    size_t done = 0;
    while (done < length) {
        ssize_t count = pwrite(fd, bytes + done, length - done, (off_t)done);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0) {
            if (count == 0)
                errno = EIO;
            return -1;
        }
        done += (size_t)count;
    }
    return 0;
}

 int mips64_exec_state_read_all(int fd, unsigned char *bytes, size_t length)
{
    size_t done = 0;
    while (done < length) {
        ssize_t count = pread(fd, bytes + done, length - done, (off_t)done);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0) {
            if (count == 0)
                errno = EINVAL;
            return -1;
        }
        done += (size_t)count;
    }
    return 0;
}

void mips64_exec_state_export_destroy(mips64_exec_state_export_t **handle)
{
    if (handle == NULL || *handle == NULL)
        return;
    int saved = errno;
    mips64_exec_state_export_t *owner = *handle;
    mips64_path_retire_temporary(&owner->registration);
    if (owner->metadata >= 3)
        (void)close(owner->metadata);
    free(owner->child_caps);
    free(owner->child_flags);
    free(owner);
    *handle = NULL;
    errno = saved;
}

int mips64_exec_state_export_create(const mips64_exec_state_t *state,
                                mips64_path_resolver_t *resolver,
                                mips64_exec_state_export_t **out)
{
    if (out == NULL) {
        errno = EINVAL;
        return -1;
    }
    *out = NULL;
    if (resolver == NULL || !resolver->initialized) {
        errno = EINVAL;
        return -1;
    }
    unsigned char *data = NULL;
    size_t length = 0;
    if (!encode(state, &data, &length))
        return -1;
    mips64_exec_state_export_t *owner = calloc(1, sizeof(*owner));
    if (owner == NULL) {
        free(data);
        return -1;
    }
    owner->metadata = -1;
    owner->child_count = state->child_count;
    if (owner->child_count != 0) {
        owner->child_caps = calloc(owner->child_count,
                                   sizeof(*owner->child_caps));
        owner->child_flags = calloc(owner->child_count,
                                    sizeof(*owner->child_flags));
        if (owner->child_caps == NULL || owner->child_flags == NULL)
            goto fail;
        for (size_t i = 0; i < owner->child_count; ++i) {
            int cap = state->children[i].cap_fd;
            int flags = fcntl(cap, F_GETFD);
            if (flags < 0 || (flags & FD_CLOEXEC) == 0) {
                if (flags >= 0)
                    errno = EINVAL;
                goto fail;
            }
            owner->child_caps[i] = cap;
            owner->child_flags[i] = flags;
        }
    }
    char path[] = "/tmp/mips64rt-exec-state-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0)
        goto fail;
    if (unlink(path) != 0) {
        int saved = errno;
        (void)close(fd);
        errno = saved;
        goto fail;
    }
    owner->metadata = fcntl(fd, F_DUPFD_CLOEXEC, 3);
    int saved = errno;
    (void)close(fd);
    errno = saved;
    if (owner->metadata < 0 || fchmod(owner->metadata, 0600) != 0)
        goto fail;
    struct stat before, after;
    if (!mips64_exec_state_private_metadata(owner->metadata, &before)) {
        errno = EINVAL;
        goto fail;
    }
    if (mips64_path_protect_temporary(resolver, before.st_dev, before.st_ino,
                                  &owner->registration) != 0)
        goto fail;
    if (write_all(owner->metadata, data, length) != 0)
        goto fail;
    if (!mips64_exec_state_private_metadata(owner->metadata, &after) ||
        after.st_dev != before.st_dev || after.st_ino != before.st_ino ||
        after.st_size < 0 || (uint64_t)after.st_size != length) {
        errno = EINVAL;
        goto fail;
    }
    free(data);
    *out = owner;
    return 0;
fail: {
        int failure = errno;
        free(data);
        mips64_exec_state_export_destroy(&owner);
        errno = failure;
        return -1;
    }
}

int mips64_exec_state_export_fd(const mips64_exec_state_export_t *owner)
{
    if (owner == NULL) {
        errno = EINVAL;
        return -1;
    }
    return owner->metadata;
}
