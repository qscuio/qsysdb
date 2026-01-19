/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * database.h - Core database operations
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#ifndef QSYSDB_DATABASE_H
#define QSYSDB_DATABASE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <qsysdb/types.h>
#include "common/shm.h"

/*
 * Database context
 */
struct qsysdb_db {
    struct qsysdb_shm shm;          /* Shared memory context */
    bool initialized;
    /* Transaction support */
    struct qsysdb_txn *active_txns[256];
    int txn_count;
};

/*
 * Transaction context
 */
struct qsysdb_txn {
    int id;
    int client_id;
    struct qsysdb_txn_op *ops;
    int op_count;
    int op_capacity;
    uint64_t start_sequence;
    bool committed;
    bool aborted;
};

/*
 * Initialize the database
 */
int db_init(struct qsysdb_db *db, const char *shm_name, size_t shm_size);

/*
 * Shutdown the database
 */
void db_shutdown(struct qsysdb_db *db);

/*
 * Set a value in the database
 */
int db_set(struct qsysdb_db *db, const char *path, size_t path_len,
           const char *value, size_t value_len, uint32_t flags,
           uint64_t *out_version);

/*
 * Get a value from the database
 */
int db_get(struct qsysdb_db *db, const char *path, size_t path_len,
           char *buf, size_t buflen, size_t *out_len,
           uint64_t *out_version, uint64_t *out_timestamp);

/*
 * Delete a value from the database
 */
int db_delete(struct qsysdb_db *db, const char *path, size_t path_len);

/*
 * Check if a path exists
 */
int db_exists(struct qsysdb_db *db, const char *path, size_t path_len,
              bool *exists);

/*
 * List paths with a given prefix
 */
int db_list(struct qsysdb_db *db, const char *prefix, size_t prefix_len,
            char ***paths, size_t *count, size_t max_results);

/*
 * Free path list returned by db_list
 */
void db_list_free(char **paths, size_t count);

/*
 * Delete all paths with a given prefix
 */
int db_delete_tree(struct qsysdb_db *db, const char *prefix, size_t prefix_len,
                   size_t *deleted_count);

/*
 * Begin a transaction
 */
int db_txn_begin(struct qsysdb_db *db, int client_id, int *txn_id);

/*
 * Add a set operation to a transaction
 */
int db_txn_set(struct qsysdb_db *db, int txn_id, const char *path,
               size_t path_len, const char *value, size_t value_len,
               uint32_t flags);

/*
 * Add a delete operation to a transaction
 */
int db_txn_delete(struct qsysdb_db *db, int txn_id, const char *path,
                  size_t path_len);

/*
 * Commit a transaction
 */
int db_txn_commit(struct qsysdb_db *db, int txn_id, uint64_t *sequence,
                  int *op_count);

/*
 * Abort a transaction
 */
int db_txn_abort(struct qsysdb_db *db, int txn_id);

/*
 * Get database statistics
 */
void db_stats(struct qsysdb_db *db, uint64_t *entry_count,
              uint64_t *data_used, uint64_t *data_total,
              uint64_t *sequence, uint64_t *total_sets,
              uint64_t *total_gets, uint64_t *total_deletes);

/*
 * Validate a path
 */
int db_validate_path(const char *path, size_t len);

/*
 * Generate a notification for a database change
 */
int db_notify(struct qsysdb_db *db, int event_type, const char *path,
              size_t path_len, uint64_t entry_version);

#endif /* QSYSDB_DATABASE_H */
