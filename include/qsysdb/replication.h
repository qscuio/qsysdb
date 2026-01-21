/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * replication.h - Master-to-slave replication API
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#ifndef QSYSDB_REPLICATION_H
#define QSYSDB_REPLICATION_H

#include <qsysdb/cluster.h>
#include <pthread.h>

/*
 * Replication constants
 */
#define QSYSDB_REPL_MAX_ENTRIES         100     /* Max entries per AppendEntries */
#define QSYSDB_REPL_BATCH_SIZE          1000    /* Batch size for initial sync */
#define QSYSDB_REPL_LOG_CAPACITY        100000  /* Default log capacity */

/*
 * Replication operation types
 */
typedef enum qsysdb_repl_op {
    QSYSDB_REPL_OP_SET = 1,         /* Set a value */
    QSYSDB_REPL_OP_DELETE,          /* Delete a value */
    QSYSDB_REPL_OP_DELETE_TREE,     /* Delete a subtree */
    QSYSDB_REPL_OP_TXN_COMMIT       /* Transaction commit (batch of ops) */
} qsysdb_repl_op_t;

/*
 * Replication log entry
 * Each write operation creates a log entry for replication
 */
typedef struct qsysdb_repl_entry {
    uint64_t index;                 /* Log index (global sequence number) */
    uint64_t term;                  /* Term when entry was created */
    qsysdb_repl_op_t op_type;       /* Operation type */
    uint32_t flags;                 /* Entry flags */
    uint16_t path_len;              /* Length of path */
    uint16_t value_len;             /* Length of value (0 for DELETE) */
    char *path;                     /* Path (allocated) */
    char *value;                    /* JSON value (allocated, NULL for DELETE) */
} qsysdb_repl_entry_t;

/*
 * Follower replication state (tracked by leader)
 */
typedef struct qsysdb_follower_state {
    uint32_t node_id;               /* Follower node ID */
    uint64_t next_index;            /* Next log entry to send to this follower */
    uint64_t match_index;           /* Highest log entry replicated to follower */
    bool replication_active;        /* True if actively replicating */
    bool snapshot_in_progress;      /* True if sending snapshot */
    uint64_t last_contact;          /* Last successful communication (ms) */
    int consecutive_failures;       /* Consecutive replication failures */
} qsysdb_follower_state_t;

/*
 * Replication manager state
 */
struct qsysdb_replication {
    /* Log storage */
    qsysdb_repl_entry_t *log;       /* Circular log buffer */
    uint64_t log_capacity;          /* Maximum log entries */
    uint64_t log_start;             /* First valid log index */
    uint64_t log_end;               /* Next log index to use */
    pthread_rwlock_t log_lock;

    /* Commit tracking */
    uint64_t commit_index;          /* Highest committed log index */
    uint64_t last_applied;          /* Last applied to state machine */

    /* Leader state */
    qsysdb_follower_state_t *followers;
    int follower_count;
    pthread_mutex_t followers_lock;

    /* Replication thread */
    pthread_t replication_thread;
    bool running;
    pthread_cond_t replication_cond;
    pthread_mutex_t replication_lock;

    /* Callbacks */
    void (*on_apply)(qsysdb_repl_entry_t *entry, void *userdata);
    void *apply_userdata;
    void (*on_commit)(uint64_t commit_index, void *userdata);
    void *commit_userdata;

    /* Back-reference */
    qsysdb_cluster_t *cluster;

    /* Statistics */
    uint64_t entries_appended;
    uint64_t entries_committed;
    uint64_t entries_applied;
    uint64_t snapshots_sent;
    uint64_t snapshots_received;
};

/*
 * Replication lifecycle functions
 */

/**
 * Initialize replication manager
 * @param cluster Cluster handle
 * @return 0 on success, negative error code on failure
 */
int qsysdb_replication_init(qsysdb_cluster_t *cluster);

/**
 * Cleanup replication manager
 * @param cluster Cluster handle
 */
void qsysdb_replication_cleanup(qsysdb_cluster_t *cluster);

/**
 * Start replication threads
 * @param cluster Cluster handle
 * @return 0 on success, negative error code on failure
 */
int qsysdb_replication_start(qsysdb_cluster_t *cluster);

/**
 * Stop replication threads
 * @param cluster Cluster handle
 */
void qsysdb_replication_stop(qsysdb_cluster_t *cluster);

/*
 * Leader operations
 */

/**
 * Append a new entry to the replication log (leader only)
 * @param cluster Cluster handle
 * @param op_type Operation type
 * @param path Path being modified
 * @param value Value (NULL for DELETE operations)
 * @param value_len Value length
 * @param flags Entry flags
 * @return Log index on success, negative error code on failure
 */
int64_t qsysdb_replication_append(qsysdb_cluster_t *cluster,
                                  qsysdb_repl_op_t op_type,
                                  const char *path,
                                  const char *value,
                                  size_t value_len,
                                  uint32_t flags);

/**
 * Trigger replication to a specific follower
 * @param cluster Cluster handle
 * @param follower_id Follower node ID
 * @return 0 on success, negative error code on failure
 */
int qsysdb_replication_sync(qsysdb_cluster_t *cluster, uint32_t follower_id);

/**
 * Trigger replication to all followers
 * @param cluster Cluster handle
 * @return 0 on success, negative error code on failure
 */
int qsysdb_replication_sync_all(qsysdb_cluster_t *cluster);

/**
 * Update commit index based on follower acknowledgments
 * @param cluster Cluster handle
 */
void qsysdb_replication_update_commit(qsysdb_cluster_t *cluster);

/*
 * Follower operations
 */

/**
 * Handle AppendEntries from leader
 * @param cluster Cluster handle
 * @param leader_id Leader node ID
 * @param term Leader's term
 * @param prev_log_index Index of log entry before new ones
 * @param prev_log_term Term of prev_log_index entry
 * @param entries Array of entries to append
 * @param entry_count Number of entries
 * @param leader_commit Leader's commit index
 * @param success Output: whether append was successful
 * @param match_index Output: last matching index (for leader tracking)
 * @return 0 on success, negative error code on failure
 */
int qsysdb_replication_handle_append(qsysdb_cluster_t *cluster,
                                     uint32_t leader_id,
                                     uint64_t term,
                                     uint64_t prev_log_index,
                                     uint64_t prev_log_term,
                                     qsysdb_repl_entry_t *entries,
                                     int entry_count,
                                     uint64_t leader_commit,
                                     bool *success,
                                     uint64_t *match_index);

/**
 * Handle AppendEntries response from follower (leader only)
 * @param cluster Cluster handle
 * @param follower_id Follower node ID
 * @param term Follower's term
 * @param success Whether append was successful
 * @param match_index Follower's last matching index
 * @return 0 on success, negative error code on failure
 */
int qsysdb_replication_handle_append_response(qsysdb_cluster_t *cluster,
                                              uint32_t follower_id,
                                              uint64_t term,
                                              bool success,
                                              uint64_t match_index);

/*
 * Log query functions
 */

/**
 * Get log entry by index
 * @param cluster Cluster handle
 * @param index Log index
 * @return Pointer to entry, or NULL if not found
 */
qsysdb_repl_entry_t *qsysdb_replication_get_entry(qsysdb_cluster_t *cluster,
                                                  uint64_t index);

/**
 * Get last log index
 * @param cluster Cluster handle
 * @return Last log index, or 0 if log is empty
 */
uint64_t qsysdb_replication_last_index(qsysdb_cluster_t *cluster);

/**
 * Get last log term
 * @param cluster Cluster handle
 * @return Term of last log entry, or 0 if log is empty
 */
uint64_t qsysdb_replication_last_term(qsysdb_cluster_t *cluster);

/**
 * Get commit index
 * @param cluster Cluster handle
 * @return Current commit index
 */
uint64_t qsysdb_replication_commit_index(qsysdb_cluster_t *cluster);

/*
 * Callback registration
 */

/**
 * Register callback for entry application
 * Called when an entry is ready to be applied to the state machine
 * @param cluster Cluster handle
 * @param callback Function to call
 * @param userdata User data
 */
void qsysdb_replication_on_apply(qsysdb_cluster_t *cluster,
                                 void (*callback)(qsysdb_repl_entry_t *entry,
                                                  void *userdata),
                                 void *userdata);

/**
 * Register callback for commit advancement
 * @param cluster Cluster handle
 * @param callback Function to call
 * @param userdata User data
 */
void qsysdb_replication_on_commit(qsysdb_cluster_t *cluster,
                                  void (*callback)(uint64_t commit_index,
                                                   void *userdata),
                                  void *userdata);

/*
 * Entry management utilities
 */

/**
 * Create a replication entry
 * @param op_type Operation type
 * @param path Path
 * @param value Value (can be NULL)
 * @param value_len Value length
 * @return New entry (caller must free with qsysdb_repl_entry_free)
 */
qsysdb_repl_entry_t *qsysdb_repl_entry_create(qsysdb_repl_op_t op_type,
                                              const char *path,
                                              const char *value,
                                              size_t value_len);

/**
 * Free a replication entry
 * @param entry Entry to free
 */
void qsysdb_repl_entry_free(qsysdb_repl_entry_t *entry);

/**
 * Duplicate a replication entry
 * @param entry Entry to duplicate
 * @return New entry copy
 */
qsysdb_repl_entry_t *qsysdb_repl_entry_dup(const qsysdb_repl_entry_t *entry);

#endif /* QSYSDB_REPLICATION_H */
