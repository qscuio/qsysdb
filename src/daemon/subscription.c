/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * subscription.c - Subscription management with trie-based matching
 *
 * This implementation uses a trie (prefix tree) for efficient subscription
 * matching. Instead of O(n) linear scan through all subscriptions, paths
 * are matched in O(k) time where k is the path length.
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

/*
 * Allocate a new trie node
 */
static struct sub_trie_node *trie_node_alloc(struct sub_manager *mgr)
{
    struct sub_trie_node *node = calloc(1, sizeof(*node));
    if (node) {
        mgr->trie_node_count++;
    }
    return node;
}

/*
 * Free a trie node and all its children recursively
 */
static void trie_node_free(struct sub_manager *mgr, struct sub_trie_node *node)
{
    if (!node) return;

    for (int i = 0; i < SUB_TRIE_CHILDREN; i++) {
        if (node->children[i]) {
            trie_node_free(mgr, node->children[i]);
        }
    }

    /* Note: subscriptions are freed separately via the main list */
    mgr->trie_node_count--;
    free(node);
}

/*
 * Insert a subscription into the trie
 */
static int trie_insert(struct sub_manager *mgr, struct subscription *sub)
{
    struct sub_trie_node *node = mgr->trie_root;
    const char *path = sub->pattern;
    size_t len = sub->pattern_len;

    /* Traverse/create trie path */
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)path[i];
        if (c >= SUB_TRIE_CHILDREN) {
            c = '_';  /* Map invalid chars to underscore */
        }

        if (!node->children[c]) {
            node->children[c] = trie_node_alloc(mgr);
            if (!node->children[c]) {
                return QSYSDB_ERR_NOMEM;
            }
        }
        node = node->children[c];
    }

    /* Add subscription to appropriate list at this node */
    if (sub->prefix_match) {
        sub->trie_next = node->prefix_subs;
        node->prefix_subs = sub;
        node->prefix_count++;
    } else {
        sub->trie_next = node->exact_subs;
        node->exact_subs = sub;
        node->exact_count++;
    }

    return QSYSDB_OK;
}

/*
 * Remove a subscription from the trie
 */
static void trie_remove(struct sub_manager *mgr, struct subscription *sub)
{
    struct sub_trie_node *node = mgr->trie_root;
    const char *path = sub->pattern;
    size_t len = sub->pattern_len;

    /* Traverse to the node */
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)path[i];
        if (c >= SUB_TRIE_CHILDREN) {
            c = '_';
        }
        if (!node->children[c]) {
            return;  /* Not found in trie */
        }
        node = node->children[c];
    }

    /* Remove from appropriate list */
    struct subscription **pp;
    if (sub->prefix_match) {
        pp = &node->prefix_subs;
        while (*pp) {
            if (*pp == sub) {
                *pp = sub->trie_next;
                node->prefix_count--;
                return;
            }
            pp = &(*pp)->trie_next;
        }
    } else {
        pp = &node->exact_subs;
        while (*pp) {
            if (*pp == sub) {
                *pp = sub->trie_next;
                node->exact_count--;
                return;
            }
            pp = &(*pp)->trie_next;
        }
    }
}

/*
 * Collect matching subscriptions during trie traversal
 */
struct match_context {
    int *client_ids;
    int *sub_ids;
    int max_matches;
    int count;
};

static void collect_prefix_matches(struct sub_trie_node *node,
                                   struct match_context *ctx)
{
    if (!node || ctx->count >= ctx->max_matches) return;

    /* Collect all prefix subscriptions at this node */
    struct subscription *sub = node->prefix_subs;
    while (sub && ctx->count < ctx->max_matches) {
        if (ctx->client_ids) {
            ctx->client_ids[ctx->count] = sub->client_id;
        }
        if (ctx->sub_ids) {
            ctx->sub_ids[ctx->count] = sub->id;
        }
        ctx->count++;
        sub = sub->trie_next;
    }
}

int sub_manager_init(struct sub_manager *mgr)
{
    memset(mgr, 0, sizeof(*mgr));
    mgr->subscriptions = NULL;
    mgr->next_id = 1;
    mgr->count = 0;
    mgr->trie_node_count = 0;

    /* Allocate root trie node */
    mgr->trie_root = calloc(1, sizeof(struct sub_trie_node));
    if (!mgr->trie_root) {
        return QSYSDB_ERR_NOMEM;
    }
    mgr->trie_node_count = 1;

    if (pthread_mutex_init(&mgr->lock, NULL) != 0) {
        free(mgr->trie_root);
        return QSYSDB_ERR_INTERNAL;
    }

    return QSYSDB_OK;
}

void sub_manager_shutdown(struct sub_manager *mgr)
{
    pthread_mutex_lock(&mgr->lock);

    /* Free all subscriptions */
    struct subscription *sub = mgr->subscriptions;
    while (sub) {
        struct subscription *next = sub->next;
        free(sub);
        sub = next;
    }
    mgr->subscriptions = NULL;
    mgr->count = 0;

    /* Free trie */
    if (mgr->trie_root) {
        trie_node_free(mgr, mgr->trie_root);
        mgr->trie_root = NULL;
    }

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

    /* Insert into trie for efficient matching */
    int ret = trie_insert(mgr, sub);
    if (ret != QSYSDB_OK) {
        pthread_mutex_unlock(&mgr->lock);
        free(sub);
        return ret;
    }

    /* Add to head of main list (for iteration/cleanup) */
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

            /* Remove from trie */
            trie_remove(mgr, sub);

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

            /* Remove from trie */
            trie_remove(mgr, sub);

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

/*
 * Trie-based subscription matching - O(k) where k = path length
 *
 * Algorithm:
 * 1. Traverse the trie following the path characters
 * 2. At each node visited, collect any prefix subscriptions (they match this path)
 * 3. At the final node, collect exact match subscriptions
 */
int sub_match(struct sub_manager *mgr, const char *path, size_t path_len,
              int *client_ids, int *sub_ids, int max_matches)
{
    struct match_context ctx = {
        .client_ids = client_ids,
        .sub_ids = sub_ids,
        .max_matches = max_matches,
        .count = 0
    };

    pthread_mutex_lock(&mgr->lock);

    struct sub_trie_node *node = mgr->trie_root;

    /* Traverse trie following path */
    for (size_t i = 0; i <= path_len && node != NULL; i++) {
        /* At each node, collect prefix subscriptions that use wildcard */
        /* These subscriptions match any path starting with pattern/ */
        collect_prefix_matches(node, &ctx);

        if (ctx.count >= max_matches) {
            break;
        }

        /* At the end of the path, collect exact matches */
        if (i == path_len) {
            struct subscription *sub = node->exact_subs;
            while (sub && ctx.count < max_matches) {
                if (client_ids) {
                    client_ids[ctx.count] = sub->client_id;
                }
                if (sub_ids) {
                    sub_ids[ctx.count] = sub->id;
                }
                ctx.count++;
                sub = sub->trie_next;
            }
            break;
        }

        /* Move to next node */
        unsigned char c = (unsigned char)path[i];
        if (c >= SUB_TRIE_CHILDREN) {
            c = '_';
        }
        node = node->children[c];
    }

    pthread_mutex_unlock(&mgr->lock);
    return ctx.count;
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
