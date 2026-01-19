/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * qsysdb.h - Public client library API
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#ifndef QSYSDB_H
#define QSYSDB_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <qsysdb/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Opaque handle types
 */
typedef struct qsysdb qsysdb_t;
typedef struct qsysdb_txn qsysdb_txn_t;

/*
 * Subscription callback function type
 */
typedef void (*qsysdb_callback_t)(const char *path, const char *value,
                                   int event_type, void *userdata);

/*
 * Connection Management
 */

/**
 * Connect to QSysDB daemon via Unix socket
 *
 * @param socket_path  Path to daemon socket (NULL for default)
 * @param flags        Connection flags (QSYSDB_CONN_*)
 * @return             Connection handle or NULL on error
 */
qsysdb_t *qsysdb_connect(const char *socket_path, int flags);

/**
 * Connect directly to shared memory (bypass socket)
 *
 * @param shm_name     Shared memory name (NULL for default)
 * @param flags        Connection flags
 * @return             Connection handle or NULL on error
 */
qsysdb_t *qsysdb_connect_shm(const char *shm_name, int flags);

/**
 * Connect to QSysDB daemon via TCP
 *
 * @param host         Hostname or IP address (NULL for localhost)
 * @param port         TCP port (0 for default: 5959)
 * @param flags        Connection flags (QSYSDB_CONN_*)
 * @return             Connection handle or NULL on error
 */
qsysdb_t *qsysdb_connect_tcp(const char *host, uint16_t port, int flags);

/**
 * Disconnect from QSysDB
 *
 * @param db           Connection handle
 */
void qsysdb_disconnect(qsysdb_t *db);

/**
 * Get last error code
 *
 * @param db           Connection handle
 * @return             Last error code (QSYSDB_ERR_*)
 */
int qsysdb_error(qsysdb_t *db);

/**
 * Get error message for error code
 *
 * @param error_code   Error code
 * @return             Human-readable error message
 */
const char *qsysdb_strerror(int error_code);

/**
 * Check if connection is alive
 *
 * @param db           Connection handle
 * @return             true if connected, false otherwise
 */
bool qsysdb_connected(qsysdb_t *db);

/*
 * Basic Operations
 */

/**
 * Set a value in the database
 *
 * @param db           Connection handle
 * @param path         Path (must start with '/')
 * @param json_value   JSON value string
 * @return             QSYSDB_OK on success, error code otherwise
 */
int qsysdb_set(qsysdb_t *db, const char *path, const char *json_value);

/**
 * Get a value from the database
 *
 * @param db           Connection handle
 * @param path         Path to retrieve
 * @param buf          Buffer to store value
 * @param buflen       Size of buffer
 * @return             QSYSDB_OK on success, error code otherwise
 */
int qsysdb_get(qsysdb_t *db, const char *path, char *buf, size_t buflen);

/**
 * Delete a value from the database
 *
 * @param db           Connection handle
 * @param path         Path to delete
 * @return             QSYSDB_OK on success, error code otherwise
 */
int qsysdb_delete(qsysdb_t *db, const char *path);

/**
 * Check if a path exists
 *
 * @param db           Connection handle
 * @param path         Path to check
 * @return             1 if exists, 0 if not, negative on error
 */
int qsysdb_exists(qsysdb_t *db, const char *path);

/*
 * Extended Operations
 */

/**
 * Set a value with additional metadata
 *
 * @param db           Connection handle
 * @param path         Path
 * @param json_value   JSON value string
 * @param flags        Entry flags (QSYSDB_FLAG_*)
 * @param out_version  Output: entry version (can be NULL)
 * @return             QSYSDB_OK on success
 */
int qsysdb_set_ex(qsysdb_t *db, const char *path, const char *json_value,
                  uint32_t flags, uint64_t *out_version);

/**
 * Get a value with metadata
 *
 * @param db           Connection handle
 * @param path         Path
 * @param buf          Buffer for value
 * @param buflen       Buffer size
 * @param out_len      Output: actual value length (can be NULL)
 * @param out_version  Output: entry version (can be NULL)
 * @param out_timestamp Output: modification timestamp (can be NULL)
 * @return             QSYSDB_OK on success
 */
int qsysdb_get_ex(qsysdb_t *db, const char *path, char *buf, size_t buflen,
                  size_t *out_len, uint64_t *out_version, uint64_t *out_timestamp);

/*
 * Hierarchical Operations
 */

/**
 * List all paths under a prefix
 *
 * @param db           Connection handle
 * @param prefix       Path prefix (or "/" for all)
 * @param paths        Output: array of path strings (must be freed with qsysdb_list_free)
 * @param count        Output: number of paths
 * @return             QSYSDB_OK on success
 */
int qsysdb_list(qsysdb_t *db, const char *prefix, char ***paths, size_t *count);

/**
 * Free path list returned by qsysdb_list
 *
 * @param paths        Path array
 * @param count        Number of paths
 */
void qsysdb_list_free(char **paths, size_t count);

/**
 * Delete all paths under a prefix
 *
 * @param db           Connection handle
 * @param prefix       Path prefix
 * @param deleted      Output: number of entries deleted (can be NULL)
 * @return             QSYSDB_OK on success
 */
int qsysdb_delete_tree(qsysdb_t *db, const char *prefix, size_t *deleted);

/*
 * Subscriptions
 */

/**
 * Subscribe to changes matching a pattern
 *
 * Pattern can be:
 * - Exact path: "/agents/foo/status"
 * - Prefix with wildcard: "/agents/foo/ *" (matches all children)
 *
 * @param db           Connection handle
 * @param pattern      Path pattern
 * @param callback     Callback function for notifications
 * @param userdata     User data passed to callback
 * @return             Subscription ID (>0) on success, negative on error
 */
int qsysdb_subscribe(qsysdb_t *db, const char *pattern,
                     qsysdb_callback_t callback, void *userdata);

/**
 * Unsubscribe from notifications
 *
 * @param db           Connection handle
 * @param subscription_id  ID returned by qsysdb_subscribe
 * @return             QSYSDB_OK on success
 */
int qsysdb_unsubscribe(qsysdb_t *db, int subscription_id);

/**
 * Poll for and process pending notifications
 *
 * @param db           Connection handle
 * @param timeout_ms   Timeout in milliseconds (-1 for infinite, 0 for non-blocking)
 * @return             Number of notifications processed, negative on error
 */
int qsysdb_poll(qsysdb_t *db, int timeout_ms);

/**
 * Get file descriptor for use with select/poll/epoll
 *
 * @param db           Connection handle
 * @return             File descriptor, or -1 if not available
 */
int qsysdb_fd(qsysdb_t *db);

/*
 * Transactions
 */

/**
 * Begin a transaction
 *
 * @param db           Connection handle
 * @return             Transaction handle or NULL on error
 */
qsysdb_txn_t *qsysdb_txn_begin(qsysdb_t *db);

/**
 * Add a set operation to transaction
 *
 * @param txn          Transaction handle
 * @param path         Path
 * @param json_value   JSON value
 * @return             QSYSDB_OK on success
 */
int qsysdb_txn_set(qsysdb_txn_t *txn, const char *path, const char *json_value);

/**
 * Add a delete operation to transaction
 *
 * @param txn          Transaction handle
 * @param path         Path
 * @return             QSYSDB_OK on success
 */
int qsysdb_txn_delete(qsysdb_txn_t *txn, const char *path);

/**
 * Commit transaction atomically
 *
 * @param txn          Transaction handle (freed on success)
 * @return             QSYSDB_OK on success
 */
int qsysdb_txn_commit(qsysdb_txn_t *txn);

/**
 * Abort transaction
 *
 * @param txn          Transaction handle (freed)
 */
void qsysdb_txn_abort(qsysdb_txn_t *txn);

/*
 * Statistics
 */

/**
 * Database statistics structure
 */
struct qsysdb_stats {
    uint64_t entry_count;
    uint64_t total_size;
    uint64_t used_size;
    uint64_t sequence;
    uint64_t total_sets;
    uint64_t total_gets;
    uint64_t total_deletes;
    uint32_t client_count;
    uint32_t subscription_count;
};

/**
 * Get database statistics
 *
 * @param db           Connection handle
 * @param stats        Output statistics structure
 * @return             QSYSDB_OK on success
 */
int qsysdb_stats(qsysdb_t *db, struct qsysdb_stats *stats);

/*
 * Utility Functions
 */

/**
 * Validate a path string
 *
 * @param path         Path to validate
 * @return             QSYSDB_OK if valid, error code otherwise
 */
int qsysdb_validate_path(const char *path);

/**
 * Validate a JSON string
 *
 * @param json         JSON string to validate
 * @return             QSYSDB_OK if valid, error code otherwise
 */
int qsysdb_validate_json(const char *json);

/**
 * Get library version
 *
 * @return             Version string
 */
const char *qsysdb_version(void);

#ifdef __cplusplus
}
#endif

#endif /* QSYSDB_H */
