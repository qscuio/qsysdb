/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * ringbuf.c - Lock-free ring buffer implementation
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#include <string.h>
#include <stdatomic.h>

#include <qsysdb/types.h>
#include "ringbuf.h"

/* Check if n is a power of 2 */
static inline bool is_power_of_2(uint32_t n)
{
    return n && !(n & (n - 1));
}

/* Get pointer to entry at index */
static inline void *entry_ptr(struct qsysdb_ringbuf *ring, uint64_t index)
{
    uint32_t slot = (uint32_t)(index & ring->mask);
    return (char *)(ring + 1) + (size_t)slot * ring->entry_size;
}

int ringbuf_init(void *mem, size_t mem_size,
                 uint32_t entry_count, uint32_t entry_size)
{
    /* Validate parameters */
    if (!is_power_of_2(entry_count)) {
        return QSYSDB_ERR_INVALID;
    }

    size_t required = ringbuf_required_size(entry_count, entry_size);
    if (mem_size < required) {
        return QSYSDB_ERR_NOMEM;
    }

    struct qsysdb_ringbuf *ring = (struct qsysdb_ringbuf *)mem;
    memset(ring, 0, sizeof(*ring));

    ring->magic = QSYSDB_RING_MAGIC;
    ring->version = 1;
    ring->entry_size = entry_size;
    ring->entry_count = entry_count;
    ring->mask = entry_count - 1;

    atomic_store(&ring->head, 0);
    atomic_store(&ring->total_published, 0);
    atomic_store(&ring->total_dropped, 0);

    /* Zero the entry area */
    memset(ring + 1, 0, (size_t)entry_count * entry_size);

    return QSYSDB_OK;
}

struct qsysdb_ringbuf *ringbuf_get(void *mem)
{
    struct qsysdb_ringbuf *ring = (struct qsysdb_ringbuf *)mem;
    if (ring->magic != QSYSDB_RING_MAGIC) {
        return NULL;
    }
    return ring;
}

void ringbuf_consumer_init(struct qsysdb_ringbuf *ring,
                           struct ringbuf_consumer *consumer)
{
    /* Start at current head (don't see historical data) */
    consumer->tail = atomic_load(&ring->head);
    consumer->dropped = 0;
}

int ringbuf_publish(struct qsysdb_ringbuf *ring,
                    const struct qsysdb_notification *notif)
{
    /*
     * Single producer, so we can simply increment head.
     * We use release ordering to ensure the notification data
     * is visible before the head update.
     */

    uint64_t head = atomic_load_explicit(&ring->head, memory_order_relaxed);
    void *slot = entry_ptr(ring, head);

    /* Copy notification to slot */
    memcpy(slot, notif, sizeof(*notif));

    /* Memory barrier to ensure data is written before head update */
    atomic_thread_fence(memory_order_release);

    /* Advance head */
    atomic_store_explicit(&ring->head, head + 1, memory_order_release);
    atomic_fetch_add_explicit(&ring->total_published, 1, memory_order_relaxed);

    return QSYSDB_OK;
}

int ringbuf_consume(struct qsysdb_ringbuf *ring,
                    struct ringbuf_consumer *consumer,
                    struct qsysdb_notification *notif)
{
    /*
     * Read the current head with acquire ordering to see
     * all writes up to that point.
     */
    uint64_t head = atomic_load_explicit(&ring->head, memory_order_acquire);

    if (consumer->tail == head) {
        return QSYSDB_ERR_AGAIN;  /* No new data */
    }

    /*
     * Check for overrun: if we're more than entry_count behind,
     * we've lost some notifications.
     */
    if (head - consumer->tail > ring->entry_count) {
        uint64_t lost = head - consumer->tail - ring->entry_count;
        consumer->dropped += lost;
        consumer->tail = head - ring->entry_count;
    }

    /* Read the notification */
    void *slot = entry_ptr(ring, consumer->tail);

    /* Memory barrier to ensure we read after checking head */
    atomic_thread_fence(memory_order_acquire);

    memcpy(notif, slot, sizeof(*notif));

    /* Advance our tail */
    consumer->tail++;

    return QSYSDB_OK;
}

int ringbuf_peek(struct qsysdb_ringbuf *ring,
                 struct ringbuf_consumer *consumer,
                 struct qsysdb_notification *notif)
{
    uint64_t head = atomic_load_explicit(&ring->head, memory_order_acquire);

    if (consumer->tail == head) {
        return QSYSDB_ERR_AGAIN;
    }

    /* Handle overrun */
    uint64_t tail = consumer->tail;
    if (head - tail > ring->entry_count) {
        tail = head - ring->entry_count;
    }

    void *slot = entry_ptr(ring, tail);
    atomic_thread_fence(memory_order_acquire);
    memcpy(notif, slot, sizeof(*notif));

    return QSYSDB_OK;
}

bool ringbuf_has_data(struct qsysdb_ringbuf *ring,
                      struct ringbuf_consumer *consumer)
{
    uint64_t head = atomic_load_explicit(&ring->head, memory_order_acquire);
    return consumer->tail != head;
}

uint64_t ringbuf_pending_count(struct qsysdb_ringbuf *ring,
                               struct ringbuf_consumer *consumer)
{
    uint64_t head = atomic_load_explicit(&ring->head, memory_order_acquire);

    if (consumer->tail >= head) {
        return 0;
    }

    uint64_t pending = head - consumer->tail;

    /* Cap at entry_count (older entries have been overwritten) */
    if (pending > ring->entry_count) {
        pending = ring->entry_count;
    }

    return pending;
}

void ringbuf_consumer_reset(struct qsysdb_ringbuf *ring,
                            struct ringbuf_consumer *consumer)
{
    consumer->tail = atomic_load_explicit(&ring->head, memory_order_acquire);
}

void ringbuf_stats(struct qsysdb_ringbuf *ring,
                   uint64_t *head, uint64_t *total_published,
                   uint64_t *total_dropped)
{
    if (head) {
        *head = atomic_load_explicit(&ring->head, memory_order_relaxed);
    }
    if (total_published) {
        *total_published = atomic_load_explicit(&ring->total_published,
                                                memory_order_relaxed);
    }
    if (total_dropped) {
        *total_dropped = atomic_load_explicit(&ring->total_dropped,
                                              memory_order_relaxed);
    }
}
