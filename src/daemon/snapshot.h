/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * snapshot.h - Disk persistence (save/restore)
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#ifndef QSYSDB_SNAPSHOT_H
#define QSYSDB_SNAPSHOT_H

#include <stdint.h>
#include <stddef.h>

#include <qsysdb/types.h>
#include "database.h"

/*
 * Snapshot file header
 */
struct snapshot_header {
    uint32_t magic;             /* QSYSDB_SNAPSHOT_MAGIC */
    uint32_t version;           /* QSYSDB_SNAPSHOT_VERSION */
    uint64_t timestamp_ns;      /* Creation timestamp */
    uint64_t entry_count;       /* Number of entries */
    uint64_t data_size;         /* Total data size */
    uint32_t checksum;          /* CRC32 of data */
    uint32_t flags;             /* Snapshot flags */
    uint64_t sequence;          /* Database sequence at snapshot */
    uint8_t reserved[32];       /* Reserved for future use */
};

/*
 * Snapshot entry header (precedes each entry in file)
 */
struct snapshot_entry {
    uint16_t path_len;
    uint16_t value_len;
    uint32_t flags;
    uint64_t version;
    uint64_t timestamp_ns;
    /* Followed by: path (path_len bytes) + value (value_len bytes) */
};

/*
 * Save database to snapshot file
 */
int snapshot_save(struct qsysdb_db *db, const char *path);

/*
 * Load database from snapshot file
 */
int snapshot_load(struct qsysdb_db *db, const char *path);

/*
 * Get snapshot info without loading
 */
int snapshot_info(const char *path, uint64_t *entry_count,
                  uint64_t *data_size, uint64_t *timestamp_ns);

/*
 * Validate snapshot file integrity
 */
int snapshot_validate(const char *path);

/*
 * Get default snapshot path
 */
const char *snapshot_default_path(void);

#endif /* QSYSDB_SNAPSHOT_H */
