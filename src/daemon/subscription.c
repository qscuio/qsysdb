/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * subscription.c - Subscription management implementation
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include <qsysdb/types.h>
#include "subscription.h"

int sub_manager_init(struct sub_manager *mgr)
{
    memset(mgr, 0, sizeof(*mgr));
    mgr->subscriptions = NULL;
    mgr->next_id = 1;
    mgr->count = 0;

    if (pthread_mutex_init(&mgr->lock, NULL) != 0) {
        return QSYSDB_ERR_INTERNAL;
    }

    return QSYSDB_OK;
}

void sub_manager_shutdown(struct sub_manager *mgr)
{
    pthread_mutex_lock(&mgr->lock);

    struct subscription *sub = mgr->subscriptions;
    while (sub) {
        struct subscription *next = sub->next;
        free(sub);
        sub = next;
    }
    mgr->subscriptions = NULL;
    mgr->count = 0;

    pthread_mutex_unlock(&mgr->lock);
    pthread_mutex_destroy(&mgr->lock);
}

int sub_add(struct sub_manager *mgr, int client_id, const char *pattern,
            size_t pattern_len, int *sub_id)
{
    if (pattern_len == 0 || pattern_len >= QSYSDB_MAX_PATH) {
        return QSYSDB_ERR_INVALID;
    }

    if (mgr->count >= QSYSDB_MAX_SUBSCRIPTIONS) {
        return QSYSDB_ERR_FULL;
    }

    struct subscription *sub = calloc(1, sizeof(*sub));
    if (!sub) {
        return QSYSDB_ERR_NOMEM;
    }

    pthread_mutex_lock(&mgr->lock);

    sub->id = mgr->next_id++;
    sub->client_id = client_id;
    memcpy(sub->pattern, pattern, pattern_len);
    sub->pattern[pattern_len] = '\0';
    sub->pattern_len = pattern_len;

    /* Check if pattern ends with '*' (prefix match) */
    if (pattern_len > 0 && pattern[pattern_len - 1] == '*') {
        sub->prefix_match = true;
        sub->pattern_len--;  /* Exclude the '*' from comparison */
        sub->pattern[sub->pattern_len] = '\0';
    } else {
        sub->prefix_match = false;
    }

    sub->last_sequence = 0;

    /* Add to head of list */
    sub->next = mgr->subscriptions;
    mgr->subscriptions = sub;
    mgr->count++;

    *sub_id = sub->id;

    pthread_mutex_unlock(&mgr->lock);

    return QSYSDB_OK;
}

int sub_remove(struct sub_manager *mgr, int sub_id)
{
    pthread_mutex_lock(&mgr->lock);

    struct subscription **pp = &mgr->subscriptions;
    while (*pp) {
        if ((*pp)->id == sub_id) {
            struct subscription *sub = *pp;
            *pp = sub->next;
            free(sub);
            mgr->count--;
            pthread_mutex_unlock(&mgr->lock);
            return QSYSDB_OK;
        }
        pp = &(*pp)->next;
    }

    pthread_mutex_unlock(&mgr->lock);
    return QSYSDB_ERR_NOTFOUND;
}

int sub_remove_client(struct sub_manager *mgr, int client_id)
{
    int removed = 0;

    pthread_mutex_lock(&mgr->lock);

    struct subscription **pp = &mgr->subscriptions;
    while (*pp) {
        if ((*pp)->client_id == client_id) {
            struct subscription *sub = *pp;
            *pp = sub->next;
            free(sub);
            mgr->count--;
            removed++;
        } else {
            pp = &(*pp)->next;
        }
    }

    pthread_mutex_unlock(&mgr->lock);
    return removed;
}

bool pattern_matches(const char *pattern, size_t pattern_len,
                     const char *path, size_t path_len)
{
    /* Check for prefix match (pattern ends with '*') */
    if (pattern_len > 0 && pattern[pattern_len - 1] == '*') {
        size_t prefix_len = pattern_len - 1;
        if (path_len >= prefix_len &&
            memcmp(pattern, path, prefix_len) == 0) {
            return true;
        }
        return false;
    }

    /* Exact match */
    if (pattern_len != path_len) {
        return false;
    }

    return memcmp(pattern, path, path_len) == 0;
}

int sub_match(struct sub_manager *mgr, const char *path, size_t path_len,
              int *client_ids, int *sub_ids, int max_matches)
{
    int matches = 0;

    pthread_mutex_lock(&mgr->lock);

    struct subscription *sub = mgr->subscriptions;
    while (sub && matches < max_matches) {
        bool match = false;

        if (sub->prefix_match) {
            /* Prefix match: path must start with pattern */
            if (path_len >= sub->pattern_len &&
                memcmp(sub->pattern, path, sub->pattern_len) == 0) {
                match = true;
            }
        } else {
            /* Exact match */
            if (path_len == sub->pattern_len &&
                memcmp(sub->pattern, path, path_len) == 0) {
                match = true;
            }
        }

        if (match) {
            if (client_ids) {
                client_ids[matches] = sub->client_id;
            }
            if (sub_ids) {
                sub_ids[matches] = sub->id;
            }
            matches++;
        }

        sub = sub->next;
    }

    pthread_mutex_unlock(&mgr->lock);
    return matches;
}

int sub_count_client(struct sub_manager *mgr, int client_id)
{
    int count = 0;

    pthread_mutex_lock(&mgr->lock);

    struct subscription *sub = mgr->subscriptions;
    while (sub) {
        if (sub->client_id == client_id) {
            count++;
        }
        sub = sub->next;
    }

    pthread_mutex_unlock(&mgr->lock);
    return count;
}

int sub_count_total(struct sub_manager *mgr)
{
    pthread_mutex_lock(&mgr->lock);
    int count = mgr->count;
    pthread_mutex_unlock(&mgr->lock);
    return count;
}
