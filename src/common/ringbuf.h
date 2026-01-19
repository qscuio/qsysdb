/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * ringbuf.h - Lock-free ring buffer for notifications
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#ifndef QSYSDB_RINGBUF_H
#define QSYSDB_RINGBUF_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdatomic.h>

#include <qsysdb/types.h>

/*
 * Ring buffer header
 *
 * This is a single-producer, multiple-consumer ring buffer.
 * The producer (daemon) writes notifications, and multiple consumers
 * (clients and kernel) can read them.
 *
 * Each consumer maintains its own tail pointer to track read position.
 * The producer only updates the head.
 */
struct qsysdb_ringbuf {
    uint32_t magic;                 /* QSYSDB_RING_MAGIC */
    uint32_t version;
    uint32_t entry_size;            /* Size of each entry */
    uint32_t entry_count;           /* Number of entries (power of 2) */
    uint32_t mask;                  /* entry_count - 1 for fast modulo */
    uint32_t reserved;

    /* Producer state (written by daemon only) */
    _Alignas(64) atomic_uint_fast64_t head;  /* Next write position */

    /* Consumer tail pointers are maintained externally */

    /* Statistics */
    atomic_uint_fast64_t total_published;
    atomic_uint_fast64_t total_dropped;      /* Dropped due to overflow */

    /* Padding to ensure entries start on cache line */
    uint8_t pad[64 - 24];

    /* Entries follow: notification entries[entry_count] */
};

#define QSYSDB_RING_MAGIC   0x52494E47  /* "RING" */

/*
 * Consumer state (maintained per-consumer, not in shared memory)
 */
struct ringbuf_consumer {
    uint64_t tail;                  /* Last read position */
    uint64_t dropped;               /* Count of dropped notifications */
};

/*
 * Calculate required memory size for ring buffer
 */
static inline size_t ringbuf_required_size(uint32_t entry_count,
                                           uint32_t entry_size)
{
    return sizeof(struct qsysdb_ringbuf) +
           (size_t)entry_count * entry_size;
}

/*
 * Initialize a ring buffer in memory
 */
int ringbuf_init(void *mem, size_t mem_size,
                 uint32_t entry_count, uint32_t entry_size);

/*
 * Get ring buffer from memory pointer
 */
struct qsysdb_ringbuf *ringbuf_get(void *mem);

/*
 * Initialize a consumer
 */
void ringbuf_consumer_init(struct qsysdb_ringbuf *ring,
                           struct ringbuf_consumer *consumer);

/*
 * Publish a notification (producer only)
 * Returns 0 on success, QSYSDB_ERR_FULL if buffer is full
 */
int ringbuf_publish(struct qsysdb_ringbuf *ring,
                    const struct qsysdb_notification *notif);

/*
 * Read the next notification (consumer)
 * Returns 0 on success, QSYSDB_ERR_AGAIN if no new data
 */
int ringbuf_consume(struct qsysdb_ringbuf *ring,
                    struct ringbuf_consumer *consumer,
                    struct qsysdb_notification *notif);

/*
 * Peek at the next notification without consuming
 */
int ringbuf_peek(struct qsysdb_ringbuf *ring,
                 struct ringbuf_consumer *consumer,
                 struct qsysdb_notification *notif);

/*
 * Check if there are pending notifications
 */
bool ringbuf_has_data(struct qsysdb_ringbuf *ring,
                      struct ringbuf_consumer *consumer);

/*
 * Get number of pending notifications
 */
uint64_t ringbuf_pending_count(struct qsysdb_ringbuf *ring,
                               struct ringbuf_consumer *consumer);

/*
 * Skip ahead to current head (discard unread notifications)
 */
void ringbuf_consumer_reset(struct qsysdb_ringbuf *ring,
                            struct ringbuf_consumer *consumer);

/*
 * Get statistics
 */
void ringbuf_stats(struct qsysdb_ringbuf *ring,
                   uint64_t *head, uint64_t *total_published,
                   uint64_t *total_dropped);

#endif /* QSYSDB_RINGBUF_H */
