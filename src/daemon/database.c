/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * database.c - Core database operations implementation
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <qsysdb/types.h>
#include <qsysdb/protocol.h>
#include "database.h"
#include "common/shm.h"
#include "common/radix_tree.h"
#include "common/ringbuf.h"

/* External declarations */
extern int qsysdb_json_validate(const char *json, size_t len);
extern uint32_t qsysdb_hash_path(const char *path, size_t len);
extern uint64_t qsysdb_timestamp_ns(void);

/* Transaction ID counter */
static int next_txn_id = 1;

int db_init(struct qsysdb_db *db, const char *shm_name, size_t shm_size)
{
    int ret;

    memset(db, 0, sizeof(*db));

    ret = qsysdb_shm_create(&db->shm, shm_name, shm_size);
    if (ret != QSYSDB_OK) {
        return ret;
    }

    db->initialized = true;
    return QSYSDB_OK;
}

void db_shutdown(struct qsysdb_db *db)
{
    if (!db->initialized) {
        return;
    }

    /* Abort any active transactions */
    for (int i = 0; i < db->txn_count; i++) {
        if (db->active_txns[i]) {
            db_txn_abort(db, db->active_txns[i]->id);
        }
    }

    qsysdb_shm_close(&db->shm);
    db->initialized = false;
}

int db_validate_path(const char *path, size_t len)
{
    if (path == NULL || len == 0) {
        return QSYSDB_ERR_INVALID;
    }

    if (len > QSYSDB_MAX_PATH - 1) {
        return QSYSDB_ERR_TOOBIG;
    }

    /* Path must start with '/' */
    if (path[0] != '/') {
        return QSYSDB_ERR_BADPATH;
    }

    /* Check each character */
    bool last_was_slash = false;
    for (size_t i = 0; i < len; i++) {
        char c = path[i];

        if (c == '/') {
            /* No double slashes */
            if (last_was_slash && i > 0) {
                return QSYSDB_ERR_BADPATH;
            }
            last_was_slash = true;
        } else {
            last_was_slash = false;
            if (!QSYSDB_PATH_CHAR_VALID(c)) {
                return QSYSDB_ERR_BADPATH;
            }
        }
    }

    /* Path should not end with '/' (unless it's just "/") */
    if (len > 1 && path[len - 1] == '/') {
        return QSYSDB_ERR_BADPATH;
    }

    return QSYSDB_OK;
}

int db_set(struct qsysdb_db *db, const char *path, size_t path_len,
           const char *value, size_t value_len, uint32_t flags,
           uint64_t *out_version)
{
    int ret;

    if (!db->initialized) {
        return QSYSDB_ERR_INTERNAL;
    }

    /* Validate path */
    ret = db_validate_path(path, path_len);
    if (ret != QSYSDB_OK) {
        return ret;
    }

    /* Validate value size */
    if (value_len > QSYSDB_MAX_VALUE) {
        return QSYSDB_ERR_TOOBIG;
    }

    /* Validate JSON */
    if (value && value_len > 0) {
        ret = qsysdb_json_validate(value, value_len);
        if (ret != QSYSDB_OK) {
            return ret;
        }
    }

    /* Lock for writing */
    ret = qsysdb_shm_wrlock(&db->shm);
    if (ret != QSYSDB_OK) {
        return ret;
    }

    /* Start seqlock write */
    qsysdb_shm_write_begin(db->shm.header);

    /* Check if entry already exists */
    uint32_t existing_offset = radix_tree_lookup(db->shm.index, db->shm.index,
                                                  path, path_len);

    struct qsysdb_entry *entry;
    uint32_t entry_offset;
    bool is_update = false;

    if (existing_offset != 0) {
        /* Update existing entry */
        entry = qsysdb_shm_data_ptr(&db->shm, existing_offset);
        is_update = true;

        /* Check if we need to reallocate (value size changed significantly) */
        size_t old_size = QSYSDB_ENTRY_SIZE(entry->path_len, entry->value_len);
        size_t new_size = QSYSDB_ENTRY_SIZE(path_len, value_len);

        if (new_size > old_size) {
            /* Need to allocate new space */
            entry_offset = qsysdb_shm_alloc(&db->shm, new_size);
            if (entry_offset == 0) {
                qsysdb_shm_write_end(db->shm.header);
                qsysdb_shm_unlock(&db->shm);
                return QSYSDB_ERR_FULL;
            }

            /* Update radix tree to point to new location */
            radix_tree_insert(db->shm.index, db->shm.index,
                              path, path_len, entry_offset);

            /* Mark old entry as deleted (for potential GC) */
            entry->flags |= QSYSDB_FLAG_DELETED;

            entry = qsysdb_shm_data_ptr(&db->shm, entry_offset);
        } else {
            entry_offset = existing_offset;
        }
    } else {
        /* Create new entry */
        size_t entry_size = QSYSDB_ENTRY_SIZE(path_len, value_len);
        entry_offset = qsysdb_shm_alloc(&db->shm, entry_size);
        if (entry_offset == 0) {
            qsysdb_shm_write_end(db->shm.header);
            qsysdb_shm_unlock(&db->shm);
            return QSYSDB_ERR_FULL;
        }

        entry = qsysdb_shm_data_ptr(&db->shm, entry_offset);

        /* Insert into radix tree */
        ret = radix_tree_insert(db->shm.index, db->shm.index,
                                path, path_len, entry_offset);
        if (ret == 0) {
            qsysdb_shm_write_end(db->shm.header);
            qsysdb_shm_unlock(&db->shm);
            return QSYSDB_ERR_FULL;
        }

        db->shm.header->entry_count++;
    }

    /* Fill in entry */
    entry->path_hash = qsysdb_hash_path(path, path_len);
    entry->path_len = (uint16_t)path_len;
    entry->value_len = (uint16_t)value_len;
    entry->version = is_update ? entry->version + 1 : 1;
    entry->timestamp_ns = qsysdb_timestamp_ns();
    entry->flags = flags & ~QSYSDB_FLAG_DELETED;
    entry->next_offset = 0;

    /* Copy path and value */
    memcpy(QSYSDB_ENTRY_PATH(entry), path, path_len);
    QSYSDB_ENTRY_PATH(entry)[path_len] = '\0';

    if (value && value_len > 0) {
        memcpy(QSYSDB_ENTRY_VALUE(entry), value, value_len);
    }
    QSYSDB_ENTRY_VALUE(entry)[value_len] = '\0';

    /* Update statistics */
    db->shm.header->total_sets++;

    uint64_t version = entry->version;

    /* End seqlock write */
    qsysdb_shm_write_end(db->shm.header);

    /* Unlock */
    qsysdb_shm_unlock(&db->shm);

    /* Send notification */
    db_notify(db, is_update ? QSYSDB_EVENT_UPDATE : QSYSDB_EVENT_CREATE,
              path, path_len, version);

    if (out_version) {
        *out_version = version;
    }

    return QSYSDB_OK;
}

int db_get(struct qsysdb_db *db, const char *path, size_t path_len,
           char *buf, size_t buflen, size_t *out_len,
           uint64_t *out_version, uint64_t *out_timestamp)
{
    int ret;

    if (!db->initialized) {
        return QSYSDB_ERR_INTERNAL;
    }

    ret = db_validate_path(path, path_len);
    if (ret != QSYSDB_OK) {
        return ret;
    }

    /* Use seqlock for consistent read */
    uint64_t seq;
    do {
        seq = qsysdb_shm_read_begin(db->shm.header);

        uint32_t entry_offset = radix_tree_lookup(db->shm.index, db->shm.index,
                                                   path, path_len);
        if (entry_offset == 0) {
            if (!qsysdb_shm_read_retry(db->shm.header, seq)) {
                db->shm.header->total_gets++;
                return QSYSDB_ERR_NOTFOUND;
            }
            continue;  /* Retry */
        }

        struct qsysdb_entry *entry = qsysdb_shm_data_ptr(&db->shm, entry_offset);

        if (entry->flags & QSYSDB_FLAG_DELETED) {
            if (!qsysdb_shm_read_retry(db->shm.header, seq)) {
                db->shm.header->total_gets++;
                return QSYSDB_ERR_NOTFOUND;
            }
            continue;
        }

        /* Copy value */
        size_t value_len = entry->value_len;
        if (buf && buflen > 0) {
            size_t copy_len = value_len < buflen - 1 ? value_len : buflen - 1;
            memcpy(buf, QSYSDB_ENTRY_VALUE(entry), copy_len);
            buf[copy_len] = '\0';
        }

        if (out_len) {
            *out_len = value_len;
        }
        if (out_version) {
            *out_version = entry->version;
        }
        if (out_timestamp) {
            *out_timestamp = entry->timestamp_ns;
        }

    } while (qsysdb_shm_read_retry(db->shm.header, seq));

    db->shm.header->total_gets++;
    return QSYSDB_OK;
}

int db_delete(struct qsysdb_db *db, const char *path, size_t path_len)
{
    int ret;

    if (!db->initialized) {
        return QSYSDB_ERR_INTERNAL;
    }

    ret = db_validate_path(path, path_len);
    if (ret != QSYSDB_OK) {
        return ret;
    }

    ret = qsysdb_shm_wrlock(&db->shm);
    if (ret != QSYSDB_OK) {
        return ret;
    }

    qsysdb_shm_write_begin(db->shm.header);

    /* Find and remove from radix tree */
    uint32_t entry_offset = radix_tree_delete(db->shm.index, db->shm.index,
                                               path, path_len);

    if (entry_offset == 0) {
        qsysdb_shm_write_end(db->shm.header);
        qsysdb_shm_unlock(&db->shm);
        return QSYSDB_ERR_NOTFOUND;
    }

    /* Mark entry as deleted */
    struct qsysdb_entry *entry = qsysdb_shm_data_ptr(&db->shm, entry_offset);
    uint64_t version = entry->version;
    entry->flags |= QSYSDB_FLAG_DELETED;

    db->shm.header->entry_count--;
    db->shm.header->total_deletes++;

    qsysdb_shm_write_end(db->shm.header);
    qsysdb_shm_unlock(&db->shm);

    /* Send notification */
    db_notify(db, QSYSDB_EVENT_DELETE, path, path_len, version);

    return QSYSDB_OK;
}

int db_exists(struct qsysdb_db *db, const char *path, size_t path_len,
              bool *exists)
{
    int ret;

    if (!db->initialized) {
        return QSYSDB_ERR_INTERNAL;
    }

    ret = db_validate_path(path, path_len);
    if (ret != QSYSDB_OK) {
        return ret;
    }

    uint64_t seq;
    do {
        seq = qsysdb_shm_read_begin(db->shm.header);

        uint32_t entry_offset = radix_tree_lookup(db->shm.index, db->shm.index,
                                                   path, path_len);

        if (entry_offset == 0) {
            *exists = false;
        } else {
            struct qsysdb_entry *entry = qsysdb_shm_data_ptr(&db->shm,
                                                              entry_offset);
            *exists = !(entry->flags & QSYSDB_FLAG_DELETED);
        }
    } while (qsysdb_shm_read_retry(db->shm.header, seq));

    return QSYSDB_OK;
}

/* Callback context for list operation */
struct list_ctx {
    struct qsysdb_shm *shm;
    char **paths;
    size_t count;
    size_t capacity;
    size_t max_results;
};

static int list_visitor(const char *path, uint32_t entry_offset, void *userdata)
{
    struct list_ctx *ctx = userdata;

    if (ctx->max_results > 0 && ctx->count >= ctx->max_results) {
        return 1;  /* Stop iteration */
    }

    struct qsysdb_entry *entry = qsysdb_shm_data_ptr(ctx->shm, entry_offset);
    if (entry->flags & QSYSDB_FLAG_DELETED) {
        return 0;  /* Skip deleted entries */
    }

    /* Grow array if needed */
    if (ctx->count >= ctx->capacity) {
        size_t new_cap = ctx->capacity * 2;
        if (new_cap == 0) new_cap = 64;

        char **new_paths = realloc(ctx->paths, new_cap * sizeof(char *));
        if (!new_paths) {
            return 1;  /* Stop on error */
        }
        ctx->paths = new_paths;
        ctx->capacity = new_cap;
    }

    ctx->paths[ctx->count] = strdup(path);
    if (!ctx->paths[ctx->count]) {
        return 1;
    }
    ctx->count++;

    return 0;
}

int db_list(struct qsysdb_db *db, const char *prefix, size_t prefix_len,
            char ***paths, size_t *count, size_t max_results)
{
    int ret;

    if (!db->initialized) {
        return QSYSDB_ERR_INTERNAL;
    }

    struct list_ctx ctx = {
        .shm = &db->shm,
        .paths = NULL,
        .count = 0,
        .capacity = 0,
        .max_results = max_results
    };

    ret = qsysdb_shm_rdlock(&db->shm);
    if (ret != QSYSDB_OK) {
        return ret;
    }

    radix_tree_iterate(db->shm.index, db->shm.index,
                       prefix, prefix_len, list_visitor, &ctx);

    qsysdb_shm_unlock(&db->shm);

    *paths = ctx.paths;
    *count = ctx.count;

    return QSYSDB_OK;
}

void db_list_free(char **paths, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        free(paths[i]);
    }
    free(paths);
}

int db_delete_tree(struct qsysdb_db *db, const char *prefix, size_t prefix_len,
                   size_t *deleted_count)
{
    if (!db->initialized) {
        return QSYSDB_ERR_INTERNAL;
    }

    /* First, collect all paths to delete */
    char **paths = NULL;
    size_t count = 0;

    int ret = db_list(db, prefix, prefix_len, &paths, &count, 0);
    if (ret != QSYSDB_OK) {
        return ret;
    }

    /* Delete each path */
    for (size_t i = 0; i < count; i++) {
        db_delete(db, paths[i], strlen(paths[i]));
    }

    if (deleted_count) {
        *deleted_count = count;
    }

    db_list_free(paths, count);

    /* Send tree deletion notification */
    db_notify(db, QSYSDB_EVENT_DELETE_TREE, prefix, prefix_len, 0);

    return QSYSDB_OK;
}

int db_txn_begin(struct qsysdb_db *db, int client_id, int *txn_id)
{
    if (db->txn_count >= 256) {
        return QSYSDB_ERR_FULL;
    }

    struct qsysdb_txn *txn = calloc(1, sizeof(*txn));
    if (!txn) {
        return QSYSDB_ERR_NOMEM;
    }

    txn->id = next_txn_id++;
    txn->client_id = client_id;
    txn->ops = NULL;
    txn->op_count = 0;
    txn->op_capacity = 0;
    txn->start_sequence = qsysdb_shm_get_sequence(&db->shm);
    txn->committed = false;
    txn->aborted = false;

    /* Find a slot */
    for (int i = 0; i < 256; i++) {
        if (db->active_txns[i] == NULL) {
            db->active_txns[i] = txn;
            db->txn_count++;
            *txn_id = txn->id;
            return QSYSDB_OK;
        }
    }

    free(txn);
    return QSYSDB_ERR_FULL;
}

static struct qsysdb_txn *find_txn(struct qsysdb_db *db, int txn_id)
{
    for (int i = 0; i < 256; i++) {
        if (db->active_txns[i] && db->active_txns[i]->id == txn_id) {
            return db->active_txns[i];
        }
    }
    return NULL;
}

static int txn_add_op(struct qsysdb_txn *txn, int op_type,
                      const char *path, size_t path_len,
                      const char *value, size_t value_len, uint32_t flags)
{
    (void)flags;  /* Reserved for future use */

    if (txn->op_count >= txn->op_capacity) {
        int new_cap = txn->op_capacity * 2;
        if (new_cap == 0) new_cap = 16;

        struct qsysdb_txn_op *new_ops = realloc(txn->ops,
                                                 new_cap * sizeof(*new_ops));
        if (!new_ops) {
            return QSYSDB_ERR_NOMEM;
        }
        txn->ops = new_ops;
        txn->op_capacity = new_cap;
    }

    struct qsysdb_txn_op *op = &txn->ops[txn->op_count];
    op->op_type = op_type;

    if (path_len >= QSYSDB_MAX_PATH) {
        return QSYSDB_ERR_TOOBIG;
    }
    memcpy(op->path, path, path_len);
    op->path[path_len] = '\0';

    if (value && value_len > 0) {
        op->value = strndup(value, value_len);
        if (!op->value) {
            return QSYSDB_ERR_NOMEM;
        }
        op->value_len = value_len;
    } else {
        op->value = NULL;
        op->value_len = 0;
    }

    txn->op_count++;
    return QSYSDB_OK;
}

int db_txn_set(struct qsysdb_db *db, int txn_id, const char *path,
               size_t path_len, const char *value, size_t value_len,
               uint32_t flags)
{
    struct qsysdb_txn *txn = find_txn(db, txn_id);
    if (!txn) {
        return QSYSDB_ERR_NOTFOUND;
    }

    if (txn->committed || txn->aborted) {
        return QSYSDB_ERR_TXN;
    }

    return txn_add_op(txn, QSYSDB_MSG_SET_REQ, path, path_len,
                      value, value_len, flags);
}

int db_txn_delete(struct qsysdb_db *db, int txn_id, const char *path,
                  size_t path_len)
{
    struct qsysdb_txn *txn = find_txn(db, txn_id);
    if (!txn) {
        return QSYSDB_ERR_NOTFOUND;
    }

    if (txn->committed || txn->aborted) {
        return QSYSDB_ERR_TXN;
    }

    return txn_add_op(txn, QSYSDB_MSG_DELETE_REQ, path, path_len, NULL, 0, 0);
}

int db_txn_commit(struct qsysdb_db *db, int txn_id, uint64_t *sequence,
                  int *op_count)
{
    struct qsysdb_txn *txn = find_txn(db, txn_id);
    if (!txn) {
        return QSYSDB_ERR_NOTFOUND;
    }

    if (txn->committed || txn->aborted) {
        return QSYSDB_ERR_TXN;
    }

    /* Apply all operations atomically */
    int ret = qsysdb_shm_wrlock(&db->shm);
    if (ret != QSYSDB_OK) {
        return ret;
    }

    for (int i = 0; i < txn->op_count; i++) {
        struct qsysdb_txn_op *op = &txn->ops[i];
        size_t path_len = strlen(op->path);

        if (op->op_type == QSYSDB_MSG_SET_REQ) {
            /* Temporarily unlock to call db_set (which does its own locking) */
            qsysdb_shm_unlock(&db->shm);
            db_set(db, op->path, path_len, op->value, op->value_len, 0, NULL);
            qsysdb_shm_wrlock(&db->shm);
        } else if (op->op_type == QSYSDB_MSG_DELETE_REQ) {
            qsysdb_shm_unlock(&db->shm);
            db_delete(db, op->path, path_len);
            qsysdb_shm_wrlock(&db->shm);
        }
    }

    qsysdb_shm_unlock(&db->shm);

    txn->committed = true;

    if (sequence) {
        *sequence = qsysdb_shm_get_sequence(&db->shm);
    }
    if (op_count) {
        *op_count = txn->op_count;
    }

    /* Clean up transaction */
    db_txn_abort(db, txn_id);

    return QSYSDB_OK;
}

int db_txn_abort(struct qsysdb_db *db, int txn_id)
{
    struct qsysdb_txn *txn = NULL;
    int slot = -1;

    for (int i = 0; i < 256; i++) {
        if (db->active_txns[i] && db->active_txns[i]->id == txn_id) {
            txn = db->active_txns[i];
            slot = i;
            break;
        }
    }

    if (!txn) {
        return QSYSDB_ERR_NOTFOUND;
    }

    /* Free operation values */
    for (int i = 0; i < txn->op_count; i++) {
        free(txn->ops[i].value);
    }
    free(txn->ops);
    free(txn);

    db->active_txns[slot] = NULL;
    db->txn_count--;

    return QSYSDB_OK;
}

void db_stats(struct qsysdb_db *db, uint64_t *entry_count,
              uint64_t *data_used, uint64_t *data_total,
              uint64_t *sequence, uint64_t *total_sets,
              uint64_t *total_gets, uint64_t *total_deletes)
{
    if (entry_count) *entry_count = db->shm.header->entry_count;
    if (data_used) *data_used = db->shm.header->data_used;
    if (data_total) *data_total = db->shm.header->data_size;
    if (sequence) *sequence = db->shm.header->sequence;
    if (total_sets) *total_sets = db->shm.header->total_sets;
    if (total_gets) *total_gets = db->shm.header->total_gets;
    if (total_deletes) *total_deletes = db->shm.header->total_deletes;
}

int db_notify(struct qsysdb_db *db, int event_type, const char *path,
              size_t path_len, uint64_t entry_version)
{
    struct qsysdb_notification notif = {0};

    notif.sequence = qsysdb_shm_next_sequence(&db->shm);
    notif.event_type = (uint32_t)event_type;
    notif.path_len = (uint32_t)path_len;
    notif.timestamp_ns = qsysdb_timestamp_ns();
    notif.entry_version = entry_version;

    if (path_len < sizeof(notif.path)) {
        memcpy(notif.path, path, path_len);
        notif.path[path_len] = '\0';
    }

    return qsysdb_shm_notify(&db->shm, &notif);
}
