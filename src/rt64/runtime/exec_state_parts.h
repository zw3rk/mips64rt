/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef MIPS64RT_EXEC_STATE_PARTS_H
#define MIPS64RT_EXEC_STATE_PARTS_H

#define _POSIX_C_SOURCE 200809L
#include "runtime/exec_state.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define EXEC_RECORD_MAX ((size_t)1024 * 1024)
#define EXEC_RECORD_HEADER 24u
#define EXEC_INVENTORY_MAX ((size_t)4096)
#define EXEC_SYSROOT_MAX ((size_t)8192)
#define EXEC_CACHE_DIRECTORY_MAX MIPS64_EXEC_CACHE_DIRECTORY_MAX
#ifdef MIPS64_RUNTIME_TEST_ATTRIBUTED_FILE
#define EXEC_RECORD_MAGIC "LAEXST11"
#define EXEC_RECORD_VERSION 11u
#else
#define EXEC_RECORD_MAGIC "LAEXST05"
#define EXEC_RECORD_VERSION 5u
#endif

struct mips64_exec_state_export {
    mips64_path_registration_t *registration;
    int metadata;
    int old_flags;
    int *child_caps;
    int *child_flags;
    size_t child_count;
    bool active, poisoned;
};

typedef struct {
    unsigned char *bytes;
    size_t pos, limit;
} writer_t;

typedef struct {
    const unsigned char *bytes;
    size_t pos, limit;
} reader_t;
/* Cross-part prototypes (Phase 0 mechanical split). */

 void put32(unsigned char *p, uint32_t value);

 void put64(unsigned char *p, uint64_t value);

 uint32_t get32(const unsigned char *p);

 uint64_t get64(const unsigned char *p);

 bool write_bytes(writer_t *writer, const void *bytes, size_t length);

 bool write32(writer_t *writer, uint32_t value);

 bool write64(writer_t *writer, uint64_t value);

 bool read_bytes(reader_t *reader, void *bytes, size_t length);

 bool read32(reader_t *reader, uint32_t *value);

 bool read64(reader_t *reader, uint64_t *value);

 bool string_length(const char *string, size_t maximum, size_t *length);

 bool write_string(writer_t *writer, const char *string,
                         size_t maximum);

 bool read_string(reader_t *reader, size_t maximum, char **out);

 bool family_valid(const mips64_family_exec_state_t *family);

 bool config_valid(const mips64_exec_config_t *config);

 bool clear_tid_valid(const mips64_exec_tid_clear_t *clear);

 bool state_valid(const mips64_exec_state_t *state);

void mips64_exec_state_destroy(mips64_exec_state_t *state);

 bool encode(const mips64_exec_state_t *state, unsigned char **out,
                   size_t *length);

 int64_t decode_i64(uint64_t word);

 bool mips64_exec_state_decode(const unsigned char *bytes, size_t length,
                   mips64_exec_state_t *out);

 bool mips64_exec_state_private_metadata(int fd, struct stat *status);

 bool mips64_exec_state_same_record_stat(const struct stat *before, const struct stat *after);

 int write_all(int fd, const unsigned char *bytes, size_t length);

 int mips64_exec_state_read_all(int fd, unsigned char *bytes, size_t length);

void mips64_exec_state_export_destroy(mips64_exec_state_export_t **handle);

int mips64_exec_state_export_create(const mips64_exec_state_t *state,
                                mips64_path_resolver_t *resolver,
                                mips64_exec_state_export_t **out);

int mips64_exec_state_export_fd(const mips64_exec_state_export_t *owner);

int mips64_exec_state_export_activate(mips64_exec_state_export_t *owner);

int mips64_exec_state_export_deactivate(mips64_exec_state_export_t *owner);

int mips64_exec_state_import(int owned_fd, mips64_exec_state_t *out);
#endif /* MIPS64RT_EXEC_STATE_PARTS_H */
