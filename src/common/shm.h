/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * shm.h - Shared memory management
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#ifndef QSYSDB_SHM_H
#define QSYSDB_SHM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>

#include <qsysdb/types.h>
#include "radix_tree.h"
#include "ringbuf.h"

/*
 * Shared memory region layout:
 *
 * +---------------------------+
 * | qsysdb_shm_header         |  (4KB aligned)
 * +---------------------------+
 * | Radix tree index region   |  (configurable size)
 * +---------------------------+
 * | Data region               |  (bulk of memory)
 * +---------------------------+
 * | Ring buffer               |  (for notifications)
 * +---------------------------+
 */

/*
 * Shared memory context (daemon side)
 */
struct qsysdb_shm {
    char name[64];                  /* Shared memory name */
    int fd;                         /* File descriptor */
    size_t size;                    /* Total size */
    void *base;                     /* Mapped base address */

    /* Pointers into the mapped region */
    struct qsysdb_shm_header *header;
    struct radix_tree *index;
    void *data_base;
    struct qsysdb_ringbuf *ring;
};

/*
 * Free block header structure (placed at start of free block in data region)
 * Minimum allocation size must be >= sizeof(struct shm_free_block)
 */
struct shm_free_block {
    uint32_t magic;                 /* Validation magic (SHM_FREE_MAGIC) */
    uint32_t size;                  /* Size of this free block (including header) */
    uint32_t next_offset;           /* Offset to next free block (0 = end of list) */
    uint32_t prev_offset;           /* Offset to previous free block (for coalescing) */
};

#define SHM_FREE_MAGIC      0x46524545  /* "FREE" */
#define SHM_MIN_ALLOC_SIZE  32          /* Minimum allocation size (must fit free_block header) */

/*
 * Data region allocator entry (deprecated, kept for reference)
 */
struct shm_alloc_entry {
    uint32_t offset;                /* Offset in data region */
    uint32_t size;                  /* Size of allocation */
    uint32_t next_free;             /* Next free block (for free list) */
    uint32_t flags;
};

#define SHM_ALLOC_FLAG_FREE  0x01

/*
 * Create and initialize shared memory
 */
int qsysdb_shm_create(struct qsysdb_shm *shm, const char *name,
                      size_t size);

/*
 * Open existing shared memory (client side)
 */
int qsysdb_shm_open(struct qsysdb_shm *shm, const char *name,
                    bool readonly);

/*
 * Close shared memory
 */
void qsysdb_shm_close(struct qsysdb_shm *shm);

/*
 * Unlink (delete) shared memory
 */
int qsysdb_shm_unlink(const char *name);

/*
 * Lock for reading (multiple readers allowed)
 */
int qsysdb_shm_rdlock(struct qsysdb_shm *shm);

/*
 * Lock for writing (exclusive)
 */
int qsysdb_shm_wrlock(struct qsysdb_shm *shm);

/*
 * Unlock
 */
int qsysdb_shm_unlock(struct qsysdb_shm *shm);

/*
 * Allocate memory in data region
 * Returns offset from data_base, or 0 on failure
 */
uint32_t qsysdb_shm_alloc(struct qsysdb_shm *shm, size_t size);

/*
 * Free memory in data region
 */
void qsysdb_shm_free(struct qsysdb_shm *shm, uint32_t offset, size_t size);

/*
 * Get pointer from data region offset
 */
static inline void *qsysdb_shm_data_ptr(struct qsysdb_shm *shm,
                                        uint32_t offset)
{
    if (offset == 0) {
        return NULL;
    }
    return (char *)shm->data_base + offset;
}

/*
 * Get offset from data region pointer
 */
static inline uint32_t qsysdb_shm_data_offset(struct qsysdb_shm *shm,
                                              void *ptr)
{
    if (ptr == NULL || ptr < shm->data_base) {
        return 0;
    }
    return (uint32_t)((char *)ptr - (char *)shm->data_base);
}

/*
 * Increment global sequence number
 */
uint64_t qsysdb_shm_next_sequence(struct qsysdb_shm *shm);

/*
 * Get current sequence number
 */
uint64_t qsysdb_shm_get_sequence(struct qsysdb_shm *shm);

/*
 * Publish a notification to the ring buffer
 */
int qsysdb_shm_notify(struct qsysdb_shm *shm,
                      const struct qsysdb_notification *notif);

/*
 * Get database statistics
 */
void qsysdb_shm_stats(struct qsysdb_shm *shm,
                      uint64_t *entry_count, uint64_t *data_used,
                      uint64_t *data_total, uint64_t *sequence);

/*
 * Kernel spinlock operations (for kernel module coordination)
 * These use atomic operations on header->lock_state
 */
void qsysdb_shm_kernel_lock(struct qsysdb_shm_header *header);
void qsysdb_shm_kernel_unlock(struct qsysdb_shm_header *header);
bool qsysdb_shm_kernel_trylock(struct qsysdb_shm_header *header);

/*
 * Seqlock helpers for kernel-userspace synchronization
 */
static inline uint64_t qsysdb_shm_read_begin(struct qsysdb_shm_header *header)
{
    uint64_t seq;
    do {
        seq = __atomic_load_n(&header->write_sequence, __ATOMIC_ACQUIRE);
    } while (seq & 1);  /* Wait if write in progress */
    return seq;
}

static inline bool qsysdb_shm_read_retry(struct qsysdb_shm_header *header,
                                         uint64_t start_seq)
{
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    return __atomic_load_n(&header->write_sequence, __ATOMIC_RELAXED) != start_seq;
}

static inline void qsysdb_shm_write_begin(struct qsysdb_shm_header *header)
{
    __atomic_add_fetch(&header->write_sequence, 1, __ATOMIC_RELEASE);
}

static inline void qsysdb_shm_write_end(struct qsysdb_shm_header *header)
{
    __atomic_add_fetch(&header->write_sequence, 1, __ATOMIC_RELEASE);
}

#endif /* QSYSDB_SHM_H */
