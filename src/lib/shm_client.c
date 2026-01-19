/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * shm_client.c - Direct shared memory access for high-performance reads
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#include <string.h>

#include <qsysdb/types.h>
#include <qsysdb/qsysdb.h>
#include "client.h"
#include "common/shm.h"
#include "common/radix_tree.h"
#include "common/ringbuf.h"

/*
 * Fast path read using shared memory
 * This bypasses the socket for read-only operations
 */
int qsysdb_shm_read(qsysdb_t *db, const char *path,
                    char *buf, size_t buflen,
                    uint64_t *version)
{
    if (!db || !path || !db->shm.base) {
        return QSYSDB_ERR_INVALID;
    }

    size_t path_len = strlen(path);
    if (path_len >= QSYSDB_MAX_PATH) {
        return QSYSDB_ERR_BADPATH;
    }

    /* Use seqlock for consistent read */
    uint64_t seq;
    int result = QSYSDB_ERR_NOTFOUND;

    do {
        seq = qsysdb_shm_read_begin(db->shm.header);

        uint32_t entry_offset = radix_tree_lookup(db->shm.index,
                                                   db->shm.index,
                                                   path, path_len);

        if (entry_offset == 0) {
            result = QSYSDB_ERR_NOTFOUND;
            continue;
        }

        struct qsysdb_entry *entry = qsysdb_shm_data_ptr(&db->shm, entry_offset);

        if (!entry || (entry->flags & QSYSDB_FLAG_DELETED)) {
            result = QSYSDB_ERR_NOTFOUND;
            continue;
        }

        /* Copy value */
        if (buf && buflen > 0) {
            size_t copy_len = entry->value_len;
            if (copy_len >= buflen) {
                copy_len = buflen - 1;
            }
            memcpy(buf, QSYSDB_ENTRY_VALUE(entry), copy_len);
            buf[copy_len] = '\0';
        }

        if (version) {
            *version = entry->version;
        }

        result = QSYSDB_OK;

    } while (qsysdb_shm_read_retry(db->shm.header, seq));

    return result;
}

/*
 * Check if a path exists using shared memory
 */
int qsysdb_shm_exists(qsysdb_t *db, const char *path)
{
    if (!db || !path || !db->shm.base) {
        return QSYSDB_ERR_INVALID;
    }

    size_t path_len = strlen(path);
    if (path_len >= QSYSDB_MAX_PATH) {
        return 0;
    }

    uint64_t seq;
    int exists = 0;

    do {
        seq = qsysdb_shm_read_begin(db->shm.header);

        uint32_t entry_offset = radix_tree_lookup(db->shm.index,
                                                   db->shm.index,
                                                   path, path_len);

        if (entry_offset != 0) {
            struct qsysdb_entry *entry = qsysdb_shm_data_ptr(&db->shm,
                                                              entry_offset);
            exists = (entry && !(entry->flags & QSYSDB_FLAG_DELETED)) ? 1 : 0;
        } else {
            exists = 0;
        }

    } while (qsysdb_shm_read_retry(db->shm.header, seq));

    return exists;
}

/*
 * Get current sequence number
 */
uint64_t qsysdb_shm_sequence(qsysdb_t *db)
{
    if (!db || !db->shm.base) {
        return 0;
    }

    return qsysdb_shm_get_sequence(&db->shm);
}

/*
 * Poll for notifications from ring buffer
 * Returns the number of notifications processed
 */
int qsysdb_shm_poll_notifications(qsysdb_t *db,
                                   void (*callback)(const struct qsysdb_notification *notif,
                                                    void *userdata),
                                   void *userdata,
                                   int max_notifications)
{
    if (!db || !db->shm.base || !callback) {
        return 0;
    }

    int processed = 0;
    struct qsysdb_notification notif;

    while (processed < max_notifications) {
        int ret = ringbuf_consume(db->shm.ring, &db->ring_consumer, &notif);
        if (ret != QSYSDB_OK) {
            break;  /* No more notifications */
        }

        callback(&notif, userdata);
        processed++;
    }

    return processed;
}

/*
 * Check if there are pending notifications
 */
int qsysdb_shm_has_notifications(qsysdb_t *db)
{
    if (!db || !db->shm.base) {
        return 0;
    }

    return ringbuf_has_data(db->shm.ring, &db->ring_consumer) ? 1 : 0;
}

/*
 * Get number of pending notifications
 */
uint64_t qsysdb_shm_pending_notifications(qsysdb_t *db)
{
    if (!db || !db->shm.base) {
        return 0;
    }

    return ringbuf_pending_count(db->shm.ring, &db->ring_consumer);
}

/*
 * Reset notification consumer to current head
 * (skip all pending notifications)
 */
void qsysdb_shm_reset_notifications(qsysdb_t *db)
{
    if (!db || !db->shm.base) {
        return;
    }

    ringbuf_consumer_reset(db->shm.ring, &db->ring_consumer);
}

/*
 * Get database statistics directly from shared memory (client view)
 */
int qsysdb_stats_direct(qsysdb_t *db, uint64_t *entry_count,
                        uint64_t *data_used, uint64_t *sequence)
{
    if (!db || !db->shm.base) {
        return QSYSDB_ERR_INVALID;
    }

    if (entry_count) {
        *entry_count = db->shm.header->entry_count;
    }
    if (data_used) {
        *data_used = db->shm.header->data_used;
    }
    if (sequence) {
        *sequence = db->shm.header->sequence;
    }

    return QSYSDB_OK;
}
