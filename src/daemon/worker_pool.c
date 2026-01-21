/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * worker_pool.c - Multi-threaded worker pool for request processing
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include <qsysdb/types.h>
#include <qsysdb/protocol.h>
#include "worker_pool.h"
#include "server.h"

/*
 * Worker thread function
 */
static void *worker_thread(void *arg)
{
    struct worker_pool *pool = arg;

    while (pool->running) {
        struct work_item *item = NULL;

        /* Get work from queue */
        pthread_mutex_lock(&pool->queue_lock);

        while (pool->running && pool->queue_head == NULL) {
            pthread_cond_wait(&pool->queue_not_empty, &pool->queue_lock);
        }

        if (!pool->running) {
            pthread_mutex_unlock(&pool->queue_lock);
            break;
        }

        /* Dequeue item */
        item = pool->queue_head;
        pool->queue_head = item->next;
        if (pool->queue_head == NULL) {
            pool->queue_tail = NULL;
        }
        pool->queue_size--;

        /* Signal that queue has space */
        pthread_cond_signal(&pool->queue_not_full);

        pthread_mutex_unlock(&pool->queue_lock);

        /* Process the work item */
        if (item && item->msg_data) {
            struct qsysdb_msg_header *hdr =
                (struct qsysdb_msg_header *)item->msg_data;

            pool->process_fn(item->client, hdr,
                             item->msg_data + sizeof(*hdr));

            __atomic_add_fetch(&pool->total_processed, 1, __ATOMIC_RELAXED);

            free(item->msg_data);
        }

        free(item);
    }

    return NULL;
}

int worker_pool_init(struct worker_pool *pool, int num_threads,
                     void (*process_fn)(struct client_conn *client,
                                        struct qsysdb_msg_header *hdr,
                                        void *payload))
{
    memset(pool, 0, sizeof(*pool));

    if (num_threads <= 0) {
        num_threads = WORKER_POOL_DEFAULT_THREADS;
    }
    if (num_threads > WORKER_POOL_MAX_THREADS) {
        num_threads = WORKER_POOL_MAX_THREADS;
    }

    pool->threads = calloc(num_threads, sizeof(pthread_t));
    if (!pool->threads) {
        return QSYSDB_ERR_NOMEM;
    }

    pool->num_threads = num_threads;
    pool->running = false;
    pool->queue_head = NULL;
    pool->queue_tail = NULL;
    pool->queue_size = 0;
    pool->queue_max = WORKER_POOL_QUEUE_SIZE;
    pool->total_processed = 0;
    pool->total_queued = 0;
    pool->queue_full_count = 0;
    pool->process_fn = process_fn;

    if (pthread_mutex_init(&pool->queue_lock, NULL) != 0) {
        free(pool->threads);
        return QSYSDB_ERR_INTERNAL;
    }

    if (pthread_cond_init(&pool->queue_not_empty, NULL) != 0) {
        pthread_mutex_destroy(&pool->queue_lock);
        free(pool->threads);
        return QSYSDB_ERR_INTERNAL;
    }

    if (pthread_cond_init(&pool->queue_not_full, NULL) != 0) {
        pthread_cond_destroy(&pool->queue_not_empty);
        pthread_mutex_destroy(&pool->queue_lock);
        free(pool->threads);
        return QSYSDB_ERR_INTERNAL;
    }

    return QSYSDB_OK;
}

int worker_pool_start(struct worker_pool *pool)
{
    pool->running = true;

    for (int i = 0; i < pool->num_threads; i++) {
        if (pthread_create(&pool->threads[i], NULL, worker_thread, pool) != 0) {
            /* Stop already created threads */
            pool->running = false;
            pthread_cond_broadcast(&pool->queue_not_empty);

            for (int j = 0; j < i; j++) {
                pthread_join(pool->threads[j], NULL);
            }
            return QSYSDB_ERR_INTERNAL;
        }
    }

    return QSYSDB_OK;
}

void worker_pool_stop(struct worker_pool *pool)
{
    pool->running = false;

    /* Wake up all workers */
    pthread_mutex_lock(&pool->queue_lock);
    pthread_cond_broadcast(&pool->queue_not_empty);
    pthread_mutex_unlock(&pool->queue_lock);

    /* Wait for workers to finish */
    for (int i = 0; i < pool->num_threads; i++) {
        pthread_join(pool->threads[i], NULL);
    }
}

void worker_pool_shutdown(struct worker_pool *pool)
{
    /* Free any remaining items in queue */
    pthread_mutex_lock(&pool->queue_lock);
    struct work_item *item = pool->queue_head;
    while (item) {
        struct work_item *next = item->next;
        free(item->msg_data);
        free(item);
        item = next;
    }
    pool->queue_head = NULL;
    pool->queue_tail = NULL;
    pool->queue_size = 0;
    pthread_mutex_unlock(&pool->queue_lock);

    pthread_cond_destroy(&pool->queue_not_full);
    pthread_cond_destroy(&pool->queue_not_empty);
    pthread_mutex_destroy(&pool->queue_lock);
    free(pool->threads);
    pool->threads = NULL;
}

int worker_pool_submit(struct worker_pool *pool, struct client_conn *client,
                       void *msg_data, size_t msg_len)
{
    /* Allocate work item */
    struct work_item *item = malloc(sizeof(*item));
    if (!item) {
        return QSYSDB_ERR_NOMEM;
    }

    /* Copy message data (so caller can reuse buffer) */
    item->msg_data = malloc(msg_len);
    if (!item->msg_data) {
        free(item);
        return QSYSDB_ERR_NOMEM;
    }

    memcpy(item->msg_data, msg_data, msg_len);
    item->client = client;
    item->msg_len = msg_len;
    item->next = NULL;

    pthread_mutex_lock(&pool->queue_lock);

    /* Check if queue is full */
    if (pool->queue_size >= pool->queue_max) {
        pthread_mutex_unlock(&pool->queue_lock);
        pool->queue_full_count++;
        free(item->msg_data);
        free(item);
        return QSYSDB_ERR_FULL;
    }

    /* Enqueue */
    if (pool->queue_tail) {
        pool->queue_tail->next = item;
    } else {
        pool->queue_head = item;
    }
    pool->queue_tail = item;
    pool->queue_size++;
    pool->total_queued++;

    /* Signal worker */
    pthread_cond_signal(&pool->queue_not_empty);

    pthread_mutex_unlock(&pool->queue_lock);

    return QSYSDB_OK;
}

void worker_pool_stats(struct worker_pool *pool, int *queue_size,
                       uint64_t *total_processed, uint64_t *queue_full_count)
{
    if (queue_size) {
        *queue_size = pool->queue_size;
    }
    if (total_processed) {
        *total_processed = pool->total_processed;
    }
    if (queue_full_count) {
        *queue_full_count = pool->queue_full_count;
    }
}
