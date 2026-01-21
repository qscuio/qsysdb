/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * worker_pool.h - Multi-threaded worker pool for request processing
 *
 * This worker pool allows parallel processing of client requests while
 * the main event loop handles I/O. This improves throughput for 10+ clients.
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#ifndef QSYSDB_WORKER_POOL_H
#define QSYSDB_WORKER_POOL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>

/* Default configuration */
#define WORKER_POOL_DEFAULT_THREADS     8
#define WORKER_POOL_MAX_THREADS         64
#define WORKER_POOL_QUEUE_SIZE          4096

/* Forward declarations */
struct client_conn;
struct qsysdb_msg_header;

/*
 * Work item for the queue
 */
struct work_item {
    struct client_conn *client;
    uint8_t *msg_data;              /* Copied message data */
    size_t msg_len;
    struct work_item *next;
};

/*
 * Worker pool context
 */
struct worker_pool {
    /* Thread management */
    pthread_t *threads;
    int num_threads;
    volatile bool running;

    /* Work queue (lock-free would be better, but mutex is simpler) */
    struct work_item *queue_head;
    struct work_item *queue_tail;
    int queue_size;
    int queue_max;

    /* Synchronization */
    pthread_mutex_t queue_lock;
    pthread_cond_t queue_not_empty;
    pthread_cond_t queue_not_full;

    /* Statistics */
    uint64_t total_processed;
    uint64_t total_queued;
    uint64_t queue_full_count;

    /* Callback for processing */
    void (*process_fn)(struct client_conn *client,
                       struct qsysdb_msg_header *hdr,
                       void *payload);
};

/*
 * Initialize worker pool
 */
int worker_pool_init(struct worker_pool *pool, int num_threads,
                     void (*process_fn)(struct client_conn *client,
                                        struct qsysdb_msg_header *hdr,
                                        void *payload));

/*
 * Start worker threads
 */
int worker_pool_start(struct worker_pool *pool);

/*
 * Stop worker pool
 */
void worker_pool_stop(struct worker_pool *pool);

/*
 * Shutdown and cleanup
 */
void worker_pool_shutdown(struct worker_pool *pool);

/*
 * Submit work to the pool
 * Returns 0 on success, QSYSDB_ERR_FULL if queue is full
 */
int worker_pool_submit(struct worker_pool *pool, struct client_conn *client,
                       void *msg_data, size_t msg_len);

/*
 * Get pool statistics
 */
void worker_pool_stats(struct worker_pool *pool, int *queue_size,
                       uint64_t *total_processed, uint64_t *queue_full_count);

#endif /* QSYSDB_WORKER_POOL_H */
