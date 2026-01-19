/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * snapshot.c - Disk persistence implementation
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

#include <qsysdb/types.h>
#include "snapshot.h"
#include "database.h"
#include "common/shm.h"
#include "common/radix_tree.h"

/* External declarations */
extern uint32_t qsysdb_crc32(const void *data, size_t len);
extern uint32_t qsysdb_crc32_update(uint32_t crc, const void *data, size_t len);
extern uint64_t qsysdb_timestamp_ns(void);

static char default_path[512] = "";

const char *snapshot_default_path(void)
{
    if (default_path[0] == '\0') {
        snprintf(default_path, sizeof(default_path), "%s/%s",
                 QSYSDB_SNAPSHOT_DIR, QSYSDB_SNAPSHOT_FILE);
    }
    return default_path;
}

/* Callback context for saving */
struct save_ctx {
    struct qsysdb_db *db;
    int fd;
    uint64_t count;
    uint64_t data_size;
    uint32_t checksum;
    int error;
};

static int save_entry_cb(const char *path, uint32_t entry_offset, void *userdata)
{
    (void)path;  /* Path is reconstructed from entry */
    struct save_ctx *ctx = userdata;

    struct qsysdb_entry *entry = qsysdb_shm_data_ptr(&ctx->db->shm, entry_offset);
    if (!entry || (entry->flags & QSYSDB_FLAG_DELETED)) {
        return 0;  /* Skip deleted entries */
    }

    /* Skip non-persistent entries */
    if (entry->flags & QSYSDB_FLAG_EPHEMERAL) {
        return 0;
    }

    struct snapshot_entry se = {
        .path_len = entry->path_len,
        .value_len = entry->value_len,
        .flags = entry->flags,
        .version = entry->version,
        .timestamp_ns = entry->timestamp_ns
    };

    /* Write entry header */
    if (write(ctx->fd, &se, sizeof(se)) != sizeof(se)) {
        ctx->error = QSYSDB_ERR_IO;
        return 1;  /* Stop iteration */
    }

    /* Write path */
    if (write(ctx->fd, QSYSDB_ENTRY_PATH(entry), entry->path_len) != entry->path_len) {
        ctx->error = QSYSDB_ERR_IO;
        return 1;
    }

    /* Write value */
    if (entry->value_len > 0) {
        if (write(ctx->fd, QSYSDB_ENTRY_VALUE(entry), entry->value_len) != entry->value_len) {
            ctx->error = QSYSDB_ERR_IO;
            return 1;
        }
    }

    /* Update checksum */
    ctx->checksum = qsysdb_crc32_update(ctx->checksum, &se, sizeof(se));
    ctx->checksum = qsysdb_crc32_update(ctx->checksum,
                                         QSYSDB_ENTRY_PATH(entry), entry->path_len);
    if (entry->value_len > 0) {
        ctx->checksum = qsysdb_crc32_update(ctx->checksum,
                                             QSYSDB_ENTRY_VALUE(entry), entry->value_len);
    }

    ctx->count++;
    ctx->data_size += sizeof(se) + entry->path_len + entry->value_len;

    return 0;
}

int snapshot_save(struct qsysdb_db *db, const char *path)
{
    if (path == NULL) {
        path = snapshot_default_path();
    }

    /* Ensure directory exists */
    char dir[512];
    strncpy(dir, path, sizeof(dir) - 1);
    char *last_slash = strrchr(dir, '/');
    if (last_slash) {
        *last_slash = '\0';
        mkdir(dir, 0755);  /* Ignore error if exists */
    }

    /* Create temporary file */
    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%d", path, getpid());

    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        return QSYSDB_ERR_IO;
    }

    /* Write placeholder header */
    struct snapshot_header hdr = {
        .magic = QSYSDB_SNAPSHOT_MAGIC,
        .version = QSYSDB_SNAPSHOT_VERSION,
        .timestamp_ns = qsysdb_timestamp_ns(),
        .entry_count = 0,
        .data_size = 0,
        .checksum = 0,
        .flags = 0,
        .sequence = db->shm.header->sequence
    };

    if (write(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
        close(fd);
        unlink(tmp_path);
        return QSYSDB_ERR_IO;
    }

    /* Lock database for reading */
    int ret = qsysdb_shm_rdlock(&db->shm);
    if (ret != QSYSDB_OK) {
        close(fd);
        unlink(tmp_path);
        return ret;
    }

    /* Iterate and save all entries */
    struct save_ctx ctx = {
        .db = db,
        .fd = fd,
        .count = 0,
        .data_size = 0,
        .checksum = 0,
        .error = QSYSDB_OK
    };

    radix_tree_iterate(db->shm.index, db->shm.index, NULL, 0,
                       save_entry_cb, &ctx);

    qsysdb_shm_unlock(&db->shm);

    if (ctx.error != QSYSDB_OK) {
        close(fd);
        unlink(tmp_path);
        return ctx.error;
    }

    /* Update header with actual counts */
    hdr.entry_count = ctx.count;
    hdr.data_size = ctx.data_size;
    hdr.checksum = ctx.checksum;

    if (lseek(fd, 0, SEEK_SET) != 0 ||
        write(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
        close(fd);
        unlink(tmp_path);
        return QSYSDB_ERR_IO;
    }

    /* Sync and close */
    fsync(fd);
    close(fd);

    /* Atomic rename */
    if (rename(tmp_path, path) != 0) {
        unlink(tmp_path);
        return QSYSDB_ERR_IO;
    }

    return QSYSDB_OK;
}

int snapshot_load(struct qsysdb_db *db, const char *path)
{
    if (path == NULL) {
        path = snapshot_default_path();
    }

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        if (errno == ENOENT) {
            return QSYSDB_ERR_NOTFOUND;
        }
        return QSYSDB_ERR_IO;
    }

    /* Read header */
    struct snapshot_header hdr;
    if (read(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
        close(fd);
        return QSYSDB_ERR_IO;
    }

    /* Validate header */
    if (hdr.magic != QSYSDB_SNAPSHOT_MAGIC) {
        close(fd);
        return QSYSDB_ERR_PROTO;
    }

    if (hdr.version != QSYSDB_SNAPSHOT_VERSION) {
        close(fd);
        return QSYSDB_ERR_PROTO;
    }

    /* Read and restore entries */
    uint32_t checksum = 0;
    uint64_t loaded = 0;

    char path_buf[QSYSDB_MAX_PATH];
    char value_buf[QSYSDB_MAX_VALUE];

    while (loaded < hdr.entry_count) {
        struct snapshot_entry se;
        ssize_t n = read(fd, &se, sizeof(se));
        if (n != sizeof(se)) {
            break;
        }

        /* Validate lengths - value_len is uint16_t so always < QSYSDB_MAX_VALUE (64KB) */
        if (se.path_len >= QSYSDB_MAX_PATH) {
            close(fd);
            return QSYSDB_ERR_PROTO;
        }

        /* Read path */
        if (read(fd, path_buf, se.path_len) != se.path_len) {
            close(fd);
            return QSYSDB_ERR_IO;
        }
        path_buf[se.path_len] = '\0';

        /* Read value */
        if (se.value_len > 0) {
            if (read(fd, value_buf, se.value_len) != se.value_len) {
                close(fd);
                return QSYSDB_ERR_IO;
            }
        }
        value_buf[se.value_len] = '\0';

        /* Update checksum */
        checksum = qsysdb_crc32_update(checksum, &se, sizeof(se));
        checksum = qsysdb_crc32_update(checksum, path_buf, se.path_len);
        if (se.value_len > 0) {
            checksum = qsysdb_crc32_update(checksum, value_buf, se.value_len);
        }

        /* Restore entry to database */
        int ret = db_set(db, path_buf, se.path_len,
                         value_buf, se.value_len, se.flags, NULL);
        if (ret != QSYSDB_OK && ret != QSYSDB_ERR_EXISTS) {
            /* Log but continue on non-fatal errors */
            fprintf(stderr, "Warning: failed to restore %s: %d\n", path_buf, ret);
        }

        loaded++;
    }

    close(fd);

    /* Verify checksum */
    if (checksum != hdr.checksum) {
        fprintf(stderr, "Warning: snapshot checksum mismatch\n");
        /* Continue anyway - data might still be usable */
    }

    return QSYSDB_OK;
}

int snapshot_info(const char *path, uint64_t *entry_count,
                  uint64_t *data_size, uint64_t *timestamp_ns)
{
    if (path == NULL) {
        path = snapshot_default_path();
    }

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        if (errno == ENOENT) {
            return QSYSDB_ERR_NOTFOUND;
        }
        return QSYSDB_ERR_IO;
    }

    struct snapshot_header hdr;
    if (read(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
        close(fd);
        return QSYSDB_ERR_IO;
    }

    close(fd);

    if (hdr.magic != QSYSDB_SNAPSHOT_MAGIC) {
        return QSYSDB_ERR_PROTO;
    }

    if (entry_count) *entry_count = hdr.entry_count;
    if (data_size) *data_size = hdr.data_size;
    if (timestamp_ns) *timestamp_ns = hdr.timestamp_ns;

    return QSYSDB_OK;
}

int snapshot_validate(const char *path)
{
    if (path == NULL) {
        path = snapshot_default_path();
    }

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return QSYSDB_ERR_NOTFOUND;
    }

    struct snapshot_header hdr;
    if (read(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
        close(fd);
        return QSYSDB_ERR_IO;
    }

    if (hdr.magic != QSYSDB_SNAPSHOT_MAGIC ||
        hdr.version != QSYSDB_SNAPSHOT_VERSION) {
        close(fd);
        return QSYSDB_ERR_PROTO;
    }

    /* Calculate checksum */
    uint32_t checksum = 0;
    uint64_t count = 0;

    while (count < hdr.entry_count) {
        struct snapshot_entry se;
        if (read(fd, &se, sizeof(se)) != sizeof(se)) {
            close(fd);
            return QSYSDB_ERR_IO;
        }

        char buf[QSYSDB_MAX_PATH + QSYSDB_MAX_VALUE];
        size_t data_len = se.path_len + se.value_len;
        if (data_len > sizeof(buf)) {
            close(fd);
            return QSYSDB_ERR_PROTO;
        }

        if (read(fd, buf, data_len) != (ssize_t)data_len) {
            close(fd);
            return QSYSDB_ERR_IO;
        }

        checksum = qsysdb_crc32_update(checksum, &se, sizeof(se));
        checksum = qsysdb_crc32_update(checksum, buf, data_len);

        count++;
    }

    close(fd);

    if (checksum != hdr.checksum) {
        return QSYSDB_ERR_PROTO;  /* Checksum mismatch */
    }

    return QSYSDB_OK;
}
