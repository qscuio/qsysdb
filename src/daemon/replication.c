/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * replication.c - Master-to-slave replication implementation
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#include <qsysdb/replication.h>
#include <qsysdb/cluster_protocol.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*
 * Logging macros
 */
#define REPL_LOG(fmt, ...) \
    fprintf(stderr, "[REPLICATION] " fmt "\n", ##__VA_ARGS__)
#define REPL_DEBUG(fmt, ...) \
    fprintf(stderr, "[REPLICATION DEBUG] " fmt "\n", ##__VA_ARGS__)
#define REPL_ERROR(fmt, ...) \
    fprintf(stderr, "[REPLICATION ERROR] " fmt "\n", ##__VA_ARGS__)

/*
 * Forward declarations
 */
static void *replication_thread_main(void *arg);
static int replication_send_append_entries(qsysdb_cluster_t *cluster,
                                           uint32_t follower_id);

/*
 * Initialize replication manager
 */
int qsysdb_replication_init(qsysdb_cluster_t *cluster)
{
    if (!cluster)
        return QSYSDB_ERR_INVALID;

    qsysdb_replication_t *repl = calloc(1, sizeof(*repl));
    if (!repl)
        return QSYSDB_ERR_NOMEM;

    /* Allocate log buffer */
    repl->log_capacity = QSYSDB_REPL_LOG_CAPACITY;
    repl->log = calloc(repl->log_capacity, sizeof(qsysdb_repl_entry_t));
    if (!repl->log) {
        free(repl);
        return QSYSDB_ERR_NOMEM;
    }

    repl->log_start = 1;  /* Log indices start at 1 */
    repl->log_end = 1;
    repl->commit_index = 0;
    repl->last_applied = 0;

    pthread_rwlock_init(&repl->log_lock, NULL);
    pthread_mutex_init(&repl->followers_lock, NULL);
    pthread_mutex_init(&repl->replication_lock, NULL);
    pthread_cond_init(&repl->replication_cond, NULL);

    repl->running = false;
    repl->cluster = cluster;

    cluster->replication = repl;

    REPL_LOG("Replication manager initialized (capacity=%lu entries)",
             repl->log_capacity);

    return QSYSDB_OK;
}

/*
 * Cleanup replication manager
 */
void qsysdb_replication_cleanup(qsysdb_cluster_t *cluster)
{
    if (!cluster || !cluster->replication)
        return;

    qsysdb_replication_t *repl = cluster->replication;

    /* Stop replication thread */
    qsysdb_replication_stop(cluster);

    /* Free log entries */
    for (uint64_t i = repl->log_start; i < repl->log_end; i++) {
        uint64_t idx = i % repl->log_capacity;
        free(repl->log[idx].path);
        free(repl->log[idx].value);
    }
    free(repl->log);

    /* Free followers array */
    free(repl->followers);

    pthread_rwlock_destroy(&repl->log_lock);
    pthread_mutex_destroy(&repl->followers_lock);
    pthread_mutex_destroy(&repl->replication_lock);
    pthread_cond_destroy(&repl->replication_cond);

    free(repl);
    cluster->replication = NULL;

    REPL_LOG("Replication manager cleaned up");
}

/*
 * Start replication threads
 */
int qsysdb_replication_start(qsysdb_cluster_t *cluster)
{
    if (!cluster || !cluster->replication)
        return QSYSDB_ERR_INVALID;

    qsysdb_replication_t *repl = cluster->replication;

    if (repl->running)
        return QSYSDB_OK;

    repl->running = true;

    int ret = pthread_create(&repl->replication_thread, NULL,
                             replication_thread_main, cluster);
    if (ret != 0) {
        REPL_ERROR("Failed to create replication thread: %s", strerror(ret));
        repl->running = false;
        return QSYSDB_ERR_INTERNAL;
    }

    REPL_LOG("Replication started");
    return QSYSDB_OK;
}

/*
 * Stop replication threads
 */
void qsysdb_replication_stop(qsysdb_cluster_t *cluster)
{
    if (!cluster || !cluster->replication)
        return;

    qsysdb_replication_t *repl = cluster->replication;

    if (!repl->running)
        return;

    repl->running = false;
    pthread_cond_broadcast(&repl->replication_cond);
    pthread_join(repl->replication_thread, NULL);

    REPL_LOG("Replication stopped");
}

/*
 * Replication thread main function
 */
static void *replication_thread_main(void *arg)
{
    qsysdb_cluster_t *cluster = arg;
    qsysdb_replication_t *repl = cluster->replication;

    REPL_LOG("Replication thread started");

    while (repl->running) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += 50 * 1000000;  /* 50ms */
        if (ts.tv_nsec >= 1000000000) {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000;
        }

        pthread_mutex_lock(&repl->replication_lock);
        pthread_cond_timedwait(&repl->replication_cond,
                               &repl->replication_lock, &ts);
        pthread_mutex_unlock(&repl->replication_lock);

        if (!repl->running)
            break;

        /* Only leader replicates */
        if (cluster->state != QSYSDB_NODE_LEADER)
            continue;

        /* Send append entries to all followers */
        pthread_rwlock_rdlock(&cluster->nodes_lock);
        for (int i = 0; i < cluster->node_count; i++) {
            qsysdb_node_t *node = &cluster->nodes[i];
            if (!node->is_self && node->is_alive) {
                replication_send_append_entries(cluster, node->node_id);
            }
        }
        pthread_rwlock_unlock(&cluster->nodes_lock);

        /* Update commit index */
        qsysdb_replication_update_commit(cluster);

        /* Apply committed entries */
        while (repl->last_applied < repl->commit_index) {
            repl->last_applied++;
            qsysdb_repl_entry_t *entry = qsysdb_replication_get_entry(
                cluster, repl->last_applied);
            if (entry && repl->on_apply) {
                repl->on_apply(entry, repl->apply_userdata);
                repl->entries_applied++;
            }
        }
    }

    REPL_LOG("Replication thread exiting");
    return NULL;
}

/*
 * Send AppendEntries to a specific follower
 */
static int replication_send_append_entries(qsysdb_cluster_t *cluster,
                                           uint32_t follower_id)
{
    qsysdb_replication_t *repl = cluster->replication;

    /* Find follower's next_index */
    pthread_mutex_lock(&repl->followers_lock);

    qsysdb_follower_state_t *follower = NULL;
    for (int i = 0; i < repl->follower_count; i++) {
        if (repl->followers[i].node_id == follower_id) {
            follower = &repl->followers[i];
            break;
        }
    }

    /* Initialize follower state if needed */
    if (!follower) {
        repl->followers = realloc(repl->followers,
                                  (repl->follower_count + 1) *
                                  sizeof(qsysdb_follower_state_t));
        if (!repl->followers) {
            pthread_mutex_unlock(&repl->followers_lock);
            return QSYSDB_ERR_NOMEM;
        }

        follower = &repl->followers[repl->follower_count];
        memset(follower, 0, sizeof(*follower));
        follower->node_id = follower_id;
        follower->next_index = repl->log_end;  /* Start at end of log */
        follower->match_index = 0;
        follower->replication_active = true;
        repl->follower_count++;
    }

    uint64_t next_index = follower->next_index;
    pthread_mutex_unlock(&repl->followers_lock);

    /* Build AppendEntries message */
    pthread_rwlock_rdlock(&repl->log_lock);

    /* Calculate entries to send */
    int entry_count = 0;
    uint64_t max_entries = cluster->config.max_entries_per_append;
    if (next_index < repl->log_end) {
        entry_count = repl->log_end - next_index;
        if ((uint64_t)entry_count > max_entries)
            entry_count = max_entries;
    }

    /* Get previous log entry info */
    uint64_t prev_log_index = next_index - 1;
    uint64_t prev_log_term = 0;
    if (prev_log_index >= repl->log_start && prev_log_index < repl->log_end) {
        uint64_t idx = prev_log_index % repl->log_capacity;
        prev_log_term = repl->log[idx].term;
    }

    /* Calculate message size */
    size_t entries_size = 0;
    for (int i = 0; i < entry_count; i++) {
        uint64_t log_idx = (next_index + i) % repl->log_capacity;
        entries_size += sizeof(qsysdb_wire_entry_t);
        entries_size += repl->log[log_idx].path_len;
        entries_size += repl->log[log_idx].value_len;
    }

    size_t msg_size = sizeof(qsysdb_msg_append_entries_t) + entries_size;
    qsysdb_msg_append_entries_t *msg = malloc(msg_size);
    if (!msg) {
        pthread_rwlock_unlock(&repl->log_lock);
        return QSYSDB_ERR_NOMEM;
    }

    /* Fill header */
    qsysdb_cluster_msg_init(&msg->header, CLUSTER_MSG_APPEND_ENTRIES,
                            cluster->config.node_id,
                            cluster->current_term,
                            msg_size - sizeof(msg->header));
    msg->leader_id = cluster->config.node_id;
    msg->entry_count = entry_count;
    msg->prev_log_index = prev_log_index;
    msg->prev_log_term = prev_log_term;
    msg->leader_commit = repl->commit_index;
    msg->header.timestamp = qsysdb_cluster_time_ms();

    /* Serialize entries */
    char *entry_ptr = (char *)(msg + 1);
    for (int i = 0; i < entry_count; i++) {
        uint64_t log_idx = (next_index + i) % repl->log_capacity;
        qsysdb_repl_entry_t *entry = &repl->log[log_idx];

        qsysdb_wire_entry_t *we = (qsysdb_wire_entry_t *)entry_ptr;
        we->index = entry->index;
        we->term = entry->term;
        we->op_type = entry->op_type;
        we->flags = entry->flags;
        we->path_len = entry->path_len;
        we->value_len = entry->value_len;

        memcpy(we->data, entry->path, entry->path_len);
        if (entry->value_len > 0 && entry->value) {
            memcpy(we->data + entry->path_len, entry->value, entry->value_len);
        }

        entry_ptr += sizeof(qsysdb_wire_entry_t) + entry->path_len + entry->value_len;
    }

    pthread_rwlock_unlock(&repl->log_lock);

    /* Send message */
    int ret = qsysdb_cluster_send(cluster, follower_id, msg, msg_size);
    free(msg);

    if (ret == QSYSDB_OK && entry_count > 0) {
        REPL_DEBUG("Sent %d entries to follower %u (prev_idx=%lu)",
                   entry_count, follower_id, prev_log_index);
    }

    return ret;
}

/*
 * Append a new entry to the log (leader only)
 */
int64_t qsysdb_replication_append(qsysdb_cluster_t *cluster,
                                  qsysdb_repl_op_t op_type,
                                  const char *path,
                                  const char *value,
                                  size_t value_len,
                                  uint32_t flags)
{
    if (!cluster || !cluster->replication || !path)
        return QSYSDB_ERR_INVALID;

    if (cluster->state != QSYSDB_NODE_LEADER)
        return QSYSDB_ERR_PERM;

    qsysdb_replication_t *repl = cluster->replication;

    pthread_rwlock_wrlock(&repl->log_lock);

    /* Check if log is full */
    if (repl->log_end - repl->log_start >= repl->log_capacity) {
        /* Need to compact or grow log */
        pthread_rwlock_unlock(&repl->log_lock);
        REPL_ERROR("Log is full");
        return QSYSDB_ERR_FULL;
    }

    /* Allocate new entry */
    uint64_t idx = repl->log_end % repl->log_capacity;
    qsysdb_repl_entry_t *entry = &repl->log[idx];

    entry->index = repl->log_end;
    entry->term = cluster->current_term;
    entry->op_type = op_type;
    entry->flags = flags;
    entry->path_len = strlen(path);
    entry->value_len = value_len;

    entry->path = strdup(path);
    if (!entry->path) {
        pthread_rwlock_unlock(&repl->log_lock);
        return QSYSDB_ERR_NOMEM;
    }

    if (value && value_len > 0) {
        entry->value = malloc(value_len);
        if (!entry->value) {
            free(entry->path);
            entry->path = NULL;
            pthread_rwlock_unlock(&repl->log_lock);
            return QSYSDB_ERR_NOMEM;
        }
        memcpy(entry->value, value, value_len);
    } else {
        entry->value = NULL;
    }

    uint64_t new_index = repl->log_end;
    repl->log_end++;
    repl->entries_appended++;

    pthread_rwlock_unlock(&repl->log_lock);

    REPL_DEBUG("Appended entry %lu: op=%d path=%s",
               new_index, op_type, path);

    /* Wake up replication thread */
    pthread_cond_signal(&repl->replication_cond);

    return new_index;
}

/*
 * Handle AppendEntries from leader (follower)
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
                                     uint64_t *match_index)
{
    (void)leader_id;  /* Used for logging in production */

    if (!cluster || !cluster->replication || !success || !match_index)
        return QSYSDB_ERR_INVALID;

    qsysdb_replication_t *repl = cluster->replication;
    *success = false;
    *match_index = 0;

    /* Check term */
    if (term < cluster->current_term) {
        REPL_DEBUG("Rejecting append: term %lu < %lu", term, cluster->current_term);
        return QSYSDB_OK;
    }

    pthread_rwlock_wrlock(&repl->log_lock);

    /* Check if we have the previous entry */
    if (prev_log_index > 0) {
        if (prev_log_index < repl->log_start ||
            prev_log_index >= repl->log_end) {
            /* We don't have the previous entry */
            REPL_DEBUG("Missing previous entry: index=%lu (have %lu-%lu)",
                       prev_log_index, repl->log_start, repl->log_end - 1);
            pthread_rwlock_unlock(&repl->log_lock);
            return QSYSDB_OK;
        }

        uint64_t idx = prev_log_index % repl->log_capacity;
        if (repl->log[idx].term != prev_log_term) {
            /* Term mismatch - need to delete conflicting entries */
            REPL_DEBUG("Term mismatch at index %lu: %lu != %lu",
                       prev_log_index, repl->log[idx].term, prev_log_term);
            repl->log_end = prev_log_index;  /* Truncate log */
            pthread_rwlock_unlock(&repl->log_lock);
            return QSYSDB_OK;
        }
    }

    /* Append new entries */
    for (int i = 0; i < entry_count; i++) {
        qsysdb_repl_entry_t *new_entry = &entries[i];
        uint64_t entry_index = new_entry->index;

        /* Check for conflicts */
        if (entry_index >= repl->log_start && entry_index < repl->log_end) {
            uint64_t idx = entry_index % repl->log_capacity;
            if (repl->log[idx].term != new_entry->term) {
                /* Conflict - truncate from here */
                REPL_DEBUG("Conflict at index %lu, truncating", entry_index);
                repl->log_end = entry_index;
            } else {
                /* Already have this entry, skip */
                continue;
            }
        }

        /* Append entry */
        if (repl->log_end - repl->log_start >= repl->log_capacity) {
            REPL_ERROR("Log full, cannot append");
            break;
        }

        uint64_t idx = repl->log_end % repl->log_capacity;
        qsysdb_repl_entry_t *entry = &repl->log[idx];

        entry->index = repl->log_end;
        entry->term = new_entry->term;
        entry->op_type = new_entry->op_type;
        entry->flags = new_entry->flags;
        entry->path_len = new_entry->path_len;
        entry->value_len = new_entry->value_len;

        entry->path = new_entry->path ? strdup(new_entry->path) : NULL;
        entry->value = NULL;
        if (new_entry->value && new_entry->value_len > 0) {
            entry->value = malloc(new_entry->value_len);
            if (entry->value) {
                memcpy(entry->value, new_entry->value, new_entry->value_len);
            }
        }

        repl->log_end++;
        REPL_DEBUG("Appended entry %lu from leader", entry->index);
    }

    *match_index = repl->log_end - 1;
    *success = true;

    /* Update commit index */
    if (leader_commit > repl->commit_index) {
        uint64_t new_commit = leader_commit;
        if (new_commit > repl->log_end - 1) {
            new_commit = repl->log_end - 1;
        }
        if (new_commit > repl->commit_index) {
            repl->commit_index = new_commit;
            repl->entries_committed++;

            /* Apply committed entries */
            while (repl->last_applied < repl->commit_index) {
                repl->last_applied++;
                qsysdb_repl_entry_t *entry = qsysdb_replication_get_entry(
                    cluster, repl->last_applied);
                if (entry && repl->on_apply) {
                    repl->on_apply(entry, repl->apply_userdata);
                    repl->entries_applied++;
                }
            }
        }
    }

    pthread_rwlock_unlock(&repl->log_lock);

    REPL_DEBUG("Append success: match_index=%lu, commit=%lu",
               *match_index, repl->commit_index);

    return QSYSDB_OK;
}

/*
 * Handle AppendEntries response from follower (leader only)
 */
int qsysdb_replication_handle_append_response(qsysdb_cluster_t *cluster,
                                              uint32_t follower_id,
                                              uint64_t term,
                                              bool success,
                                              uint64_t match_index)
{
    if (!cluster || !cluster->replication)
        return QSYSDB_ERR_INVALID;

    if (cluster->state != QSYSDB_NODE_LEADER)
        return QSYSDB_OK;

    qsysdb_replication_t *repl = cluster->replication;

    /* Check term */
    if (term > cluster->current_term) {
        /* We're out of date, step down */
        return QSYSDB_OK;
    }

    pthread_mutex_lock(&repl->followers_lock);

    /* Find follower state */
    qsysdb_follower_state_t *follower = NULL;
    for (int i = 0; i < repl->follower_count; i++) {
        if (repl->followers[i].node_id == follower_id) {
            follower = &repl->followers[i];
            break;
        }
    }

    if (!follower) {
        pthread_mutex_unlock(&repl->followers_lock);
        return QSYSDB_OK;
    }

    if (success) {
        /* Update follower state */
        follower->match_index = match_index;
        follower->next_index = match_index + 1;
        follower->consecutive_failures = 0;
        follower->last_contact = qsysdb_cluster_time_ms();

        REPL_DEBUG("Follower %u: match_index=%lu, next_index=%lu",
                   follower_id, follower->match_index, follower->next_index);
    } else {
        /* Decrement next_index and retry */
        if (follower->next_index > 1) {
            follower->next_index--;
        }
        follower->consecutive_failures++;

        REPL_DEBUG("Follower %u append failed, backing up to %lu",
                   follower_id, follower->next_index);
    }

    pthread_mutex_unlock(&repl->followers_lock);

    /* Update commit index */
    qsysdb_replication_update_commit(cluster);

    return QSYSDB_OK;
}

/*
 * Update commit index based on follower acknowledgments
 */
void qsysdb_replication_update_commit(qsysdb_cluster_t *cluster)
{
    if (!cluster || !cluster->replication)
        return;

    if (cluster->state != QSYSDB_NODE_LEADER)
        return;

    qsysdb_replication_t *repl = cluster->replication;

    pthread_mutex_lock(&repl->followers_lock);
    pthread_rwlock_rdlock(&repl->log_lock);

    /* Find the highest index that a majority of nodes have */
    for (uint64_t n = repl->log_end - 1; n > repl->commit_index; n--) {
        /* Check if this entry is from the current term */
        uint64_t idx = n % repl->log_capacity;
        if (repl->log[idx].term != cluster->current_term) {
            continue;  /* Only commit entries from current term */
        }

        /* Count nodes that have this entry */
        int count = 1;  /* Count self */
        for (int i = 0; i < repl->follower_count; i++) {
            if (repl->followers[i].match_index >= n) {
                count++;
            }
        }

        /* Check for majority */
        pthread_rwlock_rdlock(&cluster->nodes_lock);
        int total_nodes = 0;
        for (int i = 0; i < cluster->node_count; i++) {
            if (cluster->nodes[i].is_alive)
                total_nodes++;
        }
        pthread_rwlock_unlock(&cluster->nodes_lock);

        if (count > total_nodes / 2) {
            repl->commit_index = n;
            repl->entries_committed++;
            REPL_DEBUG("Committed up to index %lu", n);
            break;
        }
    }

    pthread_rwlock_unlock(&repl->log_lock);
    pthread_mutex_unlock(&repl->followers_lock);

    /* Notify commit callback */
    if (repl->on_commit) {
        repl->on_commit(repl->commit_index, repl->commit_userdata);
    }
}

/*
 * Trigger replication to a specific follower
 */
int qsysdb_replication_sync(qsysdb_cluster_t *cluster, uint32_t follower_id)
{
    if (!cluster || !cluster->replication)
        return QSYSDB_ERR_INVALID;

    if (cluster->state != QSYSDB_NODE_LEADER)
        return QSYSDB_ERR_PERM;

    return replication_send_append_entries(cluster, follower_id);
}

/*
 * Trigger replication to all followers
 */
int qsysdb_replication_sync_all(qsysdb_cluster_t *cluster)
{
    if (!cluster || !cluster->replication)
        return QSYSDB_ERR_INVALID;

    if (cluster->state != QSYSDB_NODE_LEADER)
        return QSYSDB_ERR_PERM;

    pthread_rwlock_rdlock(&cluster->nodes_lock);
    for (int i = 0; i < cluster->node_count; i++) {
        qsysdb_node_t *node = &cluster->nodes[i];
        if (!node->is_self && node->is_alive) {
            replication_send_append_entries(cluster, node->node_id);
        }
    }
    pthread_rwlock_unlock(&cluster->nodes_lock);

    return QSYSDB_OK;
}

/*
 * Log query functions
 */

qsysdb_repl_entry_t *qsysdb_replication_get_entry(qsysdb_cluster_t *cluster,
                                                  uint64_t index)
{
    if (!cluster || !cluster->replication)
        return NULL;

    qsysdb_replication_t *repl = cluster->replication;

    pthread_rwlock_rdlock(&repl->log_lock);

    if (index < repl->log_start || index >= repl->log_end) {
        pthread_rwlock_unlock(&repl->log_lock);
        return NULL;
    }

    uint64_t idx = index % repl->log_capacity;
    qsysdb_repl_entry_t *entry = &repl->log[idx];

    pthread_rwlock_unlock(&repl->log_lock);

    return entry;
}

uint64_t qsysdb_replication_last_index(qsysdb_cluster_t *cluster)
{
    if (!cluster || !cluster->replication)
        return 0;

    qsysdb_replication_t *repl = cluster->replication;

    pthread_rwlock_rdlock(&repl->log_lock);
    uint64_t last = repl->log_end > repl->log_start ? repl->log_end - 1 : 0;
    pthread_rwlock_unlock(&repl->log_lock);

    return last;
}

uint64_t qsysdb_replication_last_term(qsysdb_cluster_t *cluster)
{
    if (!cluster || !cluster->replication)
        return 0;

    qsysdb_replication_t *repl = cluster->replication;

    pthread_rwlock_rdlock(&repl->log_lock);
    uint64_t term = 0;
    if (repl->log_end > repl->log_start) {
        uint64_t idx = (repl->log_end - 1) % repl->log_capacity;
        term = repl->log[idx].term;
    }
    pthread_rwlock_unlock(&repl->log_lock);

    return term;
}

uint64_t qsysdb_replication_commit_index(qsysdb_cluster_t *cluster)
{
    if (!cluster || !cluster->replication)
        return 0;

    return cluster->replication->commit_index;
}

/*
 * Callback registration
 */

void qsysdb_replication_on_apply(qsysdb_cluster_t *cluster,
                                 void (*callback)(qsysdb_repl_entry_t *entry,
                                                  void *userdata),
                                 void *userdata)
{
    if (!cluster || !cluster->replication)
        return;

    cluster->replication->on_apply = callback;
    cluster->replication->apply_userdata = userdata;
}

void qsysdb_replication_on_commit(qsysdb_cluster_t *cluster,
                                  void (*callback)(uint64_t commit_index,
                                                   void *userdata),
                                  void *userdata)
{
    if (!cluster || !cluster->replication)
        return;

    cluster->replication->on_commit = callback;
    cluster->replication->commit_userdata = userdata;
}

/*
 * Entry management utilities
 */

qsysdb_repl_entry_t *qsysdb_repl_entry_create(qsysdb_repl_op_t op_type,
                                              const char *path,
                                              const char *value,
                                              size_t value_len)
{
    qsysdb_repl_entry_t *entry = calloc(1, sizeof(*entry));
    if (!entry)
        return NULL;

    entry->op_type = op_type;
    entry->path_len = path ? strlen(path) : 0;
    entry->value_len = value_len;

    if (path) {
        entry->path = strdup(path);
        if (!entry->path) {
            free(entry);
            return NULL;
        }
    }

    if (value && value_len > 0) {
        entry->value = malloc(value_len);
        if (!entry->value) {
            free(entry->path);
            free(entry);
            return NULL;
        }
        memcpy(entry->value, value, value_len);
    }

    return entry;
}

void qsysdb_repl_entry_free(qsysdb_repl_entry_t *entry)
{
    if (!entry)
        return;

    free(entry->path);
    free(entry->value);
    free(entry);
}

qsysdb_repl_entry_t *qsysdb_repl_entry_dup(const qsysdb_repl_entry_t *entry)
{
    if (!entry)
        return NULL;

    qsysdb_repl_entry_t *dup = calloc(1, sizeof(*dup));
    if (!dup)
        return NULL;

    *dup = *entry;

    if (entry->path) {
        dup->path = strdup(entry->path);
        if (!dup->path) {
            free(dup);
            return NULL;
        }
    }

    if (entry->value && entry->value_len > 0) {
        dup->value = malloc(entry->value_len);
        if (!dup->value) {
            free(dup->path);
            free(dup);
            return NULL;
        }
        memcpy(dup->value, entry->value, entry->value_len);
    }

    return dup;
}
