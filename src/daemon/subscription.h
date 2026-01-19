/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * subscription.h - Subscription management
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#ifndef QSYSDB_SUBSCRIPTION_H
#define QSYSDB_SUBSCRIPTION_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <qsysdb/types.h>

/* Forward declaration */
struct client_conn;

/*
 * Subscription entry
 */
struct subscription {
    int id;                         /* Unique subscription ID */
    int client_id;                  /* Owning client */
    char pattern[QSYSDB_MAX_PATH];  /* Path pattern */
    size_t pattern_len;
    bool prefix_match;              /* True if pattern ends with '*' */
    uint64_t last_sequence;         /* Last delivered sequence */
    struct subscription *next;      /* Next in list */
};

/*
 * Subscription manager
 */
struct sub_manager {
    struct subscription *subscriptions;  /* Linked list of subscriptions */
    int next_id;                         /* Next subscription ID */
    int count;                           /* Total subscription count */
    pthread_mutex_t lock;                /* Protects the list */
};

/*
 * Initialize subscription manager
 */
int sub_manager_init(struct sub_manager *mgr);

/*
 * Shutdown subscription manager
 */
void sub_manager_shutdown(struct sub_manager *mgr);

/*
 * Add a subscription
 */
int sub_add(struct sub_manager *mgr, int client_id, const char *pattern,
            size_t pattern_len, int *sub_id);

/*
 * Remove a subscription by ID
 */
int sub_remove(struct sub_manager *mgr, int sub_id);

/*
 * Remove all subscriptions for a client
 */
int sub_remove_client(struct sub_manager *mgr, int client_id);

/*
 * Check if a path matches any subscription and return matching client IDs
 * Returns the number of matching subscriptions
 */
int sub_match(struct sub_manager *mgr, const char *path, size_t path_len,
              int *client_ids, int *sub_ids, int max_matches);

/*
 * Get subscription count for a client
 */
int sub_count_client(struct sub_manager *mgr, int client_id);

/*
 * Get total subscription count
 */
int sub_count_total(struct sub_manager *mgr);

/*
 * Check if a pattern matches a path
 */
bool pattern_matches(const char *pattern, size_t pattern_len,
                     const char *path, size_t path_len);

#endif /* QSYSDB_SUBSCRIPTION_H */
