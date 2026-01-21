/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * shm.c - Shared memory management implementation
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <pthread.h>

#include <qsysdb/types.h>
#include "shm.h"
#include "radix_tree.h"
#include "ringbuf.h"

/* Default region sizes as percentage of total */
#define INDEX_REGION_PERCENT    15
#define RING_REGION_PERCENT     5
/* Data region gets the remainder */

/* Minimum sizes */
#define MIN_INDEX_SIZE  (256 * 1024)    /* 256KB */
#define MIN_DATA_SIZE   (512 * 1024)    /* 512KB */
#define MIN_RING_SIZE   (64 * 1024)     /* 64KB */

/* Page size for alignment */
static size_t page_size = 0;

static size_t get_page_size(void)
{
    if (page_size == 0) {
        page_size = (size_t)sysconf(_SC_PAGESIZE);
    }
    return page_size;
}

static size_t align_to_page(size_t size)
{
    size_t ps = get_page_size();
    return (size + ps - 1) & ~(ps - 1);
}

int qsysdb_shm_create(struct qsysdb_shm *shm, const char *name, size_t size)
{
    int ret;

    memset(shm, 0, sizeof(*shm));
    strncpy(shm->name, name, sizeof(shm->name) - 1);

    /* Enforce minimum size */
    if (size < QSYSDB_SHM_SIZE_MIN) {
        size = QSYSDB_SHM_SIZE_MIN;
    }
    if (size > QSYSDB_SHM_SIZE_MAX) {
        return QSYSDB_ERR_INVALID;
    }

    shm->size = align_to_page(size);

    /* Create shared memory object */
    shm->fd = shm_open(name, O_RDWR | O_CREAT | O_EXCL, 0666);
    if (shm->fd < 0) {
        if (errno == EEXIST) {
            /* Already exists, try to unlink and recreate */
            shm_unlink(name);
            shm->fd = shm_open(name, O_RDWR | O_CREAT | O_EXCL, 0666);
        }
        if (shm->fd < 0) {
            return QSYSDB_ERR_IO;
        }
    }

    /* Set size */
    if (ftruncate(shm->fd, (off_t)shm->size) < 0) {
        close(shm->fd);
        shm_unlink(name);
        return QSYSDB_ERR_IO;
    }

    /* Map the memory */
    shm->base = mmap(NULL, shm->size, PROT_READ | PROT_WRITE,
                     MAP_SHARED, shm->fd, 0);
    if (shm->base == MAP_FAILED) {
        close(shm->fd);
        shm_unlink(name);
        return QSYSDB_ERR_NOMEM;
    }

    /* Calculate region sizes */
    size_t header_size = align_to_page(sizeof(struct qsysdb_shm_header));
    size_t remaining = shm->size - header_size;

    size_t index_size = (remaining * INDEX_REGION_PERCENT) / 100;
    size_t ring_size = (remaining * RING_REGION_PERCENT) / 100;

    /* Enforce minimums */
    if (index_size < MIN_INDEX_SIZE) index_size = MIN_INDEX_SIZE;
    if (ring_size < MIN_RING_SIZE) ring_size = MIN_RING_SIZE;

    /* Align to page boundaries */
    index_size = align_to_page(index_size);
    ring_size = align_to_page(ring_size);

    size_t data_size = remaining - index_size - ring_size;
    if (data_size < MIN_DATA_SIZE) {
        munmap(shm->base, shm->size);
        close(shm->fd);
        shm_unlink(name);
        return QSYSDB_ERR_NOMEM;
    }

    /* Calculate offsets */
    uint32_t index_offset = (uint32_t)header_size;
    uint32_t data_offset = index_offset + (uint32_t)index_size;
    uint32_t ring_offset = data_offset + (uint32_t)data_size;

    /* Initialize header */
    shm->header = (struct qsysdb_shm_header *)shm->base;
    memset(shm->header, 0, sizeof(*shm->header));

    shm->header->magic = QSYSDB_MAGIC;
    shm->header->version = QSYSDB_VERSION;
    shm->header->size = shm->size;
    shm->header->sequence = 1;

    shm->header->index_offset = index_offset;
    shm->header->index_size = (uint32_t)index_size;
    shm->header->data_offset = data_offset;
    shm->header->data_size = (uint32_t)data_size;
    shm->header->ring_offset = ring_offset;
    shm->header->ring_size = (uint32_t)ring_size;

    shm->header->data_used = 8;  /* Reserve offset 0 as invalid/error */
    shm->header->entry_count = 0;
    shm->header->node_count = 0;
    shm->header->free_list_head = 0;
    shm->header->free_list_count = 0;
    shm->header->bytes_freed = 0;
    shm->header->bytes_reused = 0;
    shm->header->lock_state = 0;
    shm->header->writer_pid = 0;
    shm->header->write_sequence = 0;

    /* Initialize pthread rwlock */
    pthread_rwlockattr_t attr;
    pthread_rwlockattr_init(&attr);
    pthread_rwlockattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
    pthread_rwlock_t *lock = (pthread_rwlock_t *)shm->header->pthread_lock;
    pthread_rwlock_init(lock, &attr);
    pthread_rwlockattr_destroy(&attr);

    /* Set up region pointers */
    shm->index = (struct radix_tree *)((char *)shm->base + index_offset);
    shm->data_base = (char *)shm->base + data_offset;
    shm->ring = (struct qsysdb_ringbuf *)((char *)shm->base + ring_offset);

    /* Initialize radix tree - use available index memory (no artificial cap) */
    uint32_t max_nodes = (uint32_t)(index_size / sizeof(struct radix_node));
    /* Cap only if memory allows less than configured pool size */
    if (max_nodes > QSYSDB_RADIX_POOL_SIZE) {
        max_nodes = QSYSDB_RADIX_POOL_SIZE;
    }
    ret = radix_tree_init(shm->index, index_size, max_nodes);
    if (ret != QSYSDB_OK) {
        munmap(shm->base, shm->size);
        close(shm->fd);
        shm_unlink(name);
        return ret;
    }

    /* Initialize ring buffer */
    uint32_t ring_entries = QSYSDB_RING_SIZE;
    uint32_t entry_size = sizeof(struct qsysdb_notification);
    ret = ringbuf_init(shm->ring, ring_size, ring_entries, entry_size);
    if (ret != QSYSDB_OK) {
        munmap(shm->base, shm->size);
        close(shm->fd);
        shm_unlink(name);
        return ret;
    }

    /* Memory barrier to ensure all initialization is visible */
    __atomic_thread_fence(__ATOMIC_RELEASE);

    return QSYSDB_OK;
}

int qsysdb_shm_open(struct qsysdb_shm *shm, const char *name, bool readonly)
{
    memset(shm, 0, sizeof(*shm));
    strncpy(shm->name, name, sizeof(shm->name) - 1);

    /* Open existing shared memory */
    int flags = readonly ? O_RDONLY : O_RDWR;
    shm->fd = shm_open(name, flags, 0);
    if (shm->fd < 0) {
        return QSYSDB_ERR_NOTFOUND;
    }

    /* Get size */
    struct stat st;
    if (fstat(shm->fd, &st) < 0) {
        close(shm->fd);
        return QSYSDB_ERR_IO;
    }
    shm->size = (size_t)st.st_size;

    /* Map the memory */
    int prot = readonly ? PROT_READ : (PROT_READ | PROT_WRITE);
    shm->base = mmap(NULL, shm->size, prot, MAP_SHARED, shm->fd, 0);
    if (shm->base == MAP_FAILED) {
        close(shm->fd);
        return QSYSDB_ERR_NOMEM;
    }

    /* Verify header */
    shm->header = (struct qsysdb_shm_header *)shm->base;

    __atomic_thread_fence(__ATOMIC_ACQUIRE);

    if (shm->header->magic != QSYSDB_MAGIC) {
        munmap(shm->base, shm->size);
        close(shm->fd);
        return QSYSDB_ERR_PROTO;
    }

    if (shm->header->version != QSYSDB_VERSION) {
        munmap(shm->base, shm->size);
        close(shm->fd);
        return QSYSDB_ERR_PROTO;
    }

    /* Set up region pointers */
    shm->index = (struct radix_tree *)
        ((char *)shm->base + shm->header->index_offset);
    shm->data_base = (char *)shm->base + shm->header->data_offset;
    shm->ring = (struct qsysdb_ringbuf *)
        ((char *)shm->base + shm->header->ring_offset);

    /* Verify substructures */
    if (radix_tree_get(shm->index) == NULL) {
        munmap(shm->base, shm->size);
        close(shm->fd);
        return QSYSDB_ERR_PROTO;
    }

    if (ringbuf_get(shm->ring) == NULL) {
        munmap(shm->base, shm->size);
        close(shm->fd);
        return QSYSDB_ERR_PROTO;
    }

    return QSYSDB_OK;
}

void qsysdb_shm_close(struct qsysdb_shm *shm)
{
    if (shm->base && shm->base != MAP_FAILED) {
        munmap(shm->base, shm->size);
        shm->base = NULL;
    }

    if (shm->fd >= 0) {
        close(shm->fd);
        shm->fd = -1;
    }

    shm->header = NULL;
    shm->index = NULL;
    shm->data_base = NULL;
    shm->ring = NULL;
}

int qsysdb_shm_unlink(const char *name)
{
    if (shm_unlink(name) < 0) {
        if (errno == ENOENT) {
            return QSYSDB_OK;  /* Already gone */
        }
        return QSYSDB_ERR_IO;
    }
    return QSYSDB_OK;
}

int qsysdb_shm_rdlock(struct qsysdb_shm *shm)
{
    pthread_rwlock_t *lock = (pthread_rwlock_t *)shm->header->pthread_lock;
    if (pthread_rwlock_rdlock(lock) != 0) {
        return QSYSDB_ERR_BUSY;
    }
    return QSYSDB_OK;
}

int qsysdb_shm_wrlock(struct qsysdb_shm *shm)
{
    pthread_rwlock_t *lock = (pthread_rwlock_t *)shm->header->pthread_lock;
    if (pthread_rwlock_wrlock(lock) != 0) {
        return QSYSDB_ERR_BUSY;
    }
    shm->header->writer_pid = (uint32_t)getpid();
    return QSYSDB_OK;
}

int qsysdb_shm_unlock(struct qsysdb_shm *shm)
{
    shm->header->writer_pid = 0;
    pthread_rwlock_t *lock = (pthread_rwlock_t *)shm->header->pthread_lock;
    if (pthread_rwlock_unlock(lock) != 0) {
        return QSYSDB_ERR_INTERNAL;
    }
    return QSYSDB_OK;
}

/*
 * Free list allocator for data region with best-fit allocation strategy
 *
 * Allocation strategy:
 * 1. First, search free list for best-fit block (smallest block that fits)
 * 2. If found, split block if remainder is >= SHM_MIN_ALLOC_SIZE
 * 3. If not found, bump-allocate from end of data region
 *
 * Free strategy:
 * 1. Add block to free list
 * 2. Try to coalesce with adjacent free blocks (TODO: requires boundary tags)
 */

/* Get free block pointer from offset */
static inline struct shm_free_block *get_free_block(struct qsysdb_shm *shm,
                                                     uint32_t offset)
{
    if (offset == 0) return NULL;
    return (struct shm_free_block *)((char *)shm->data_base + offset);
}

uint32_t qsysdb_shm_alloc(struct qsysdb_shm *shm, size_t size)
{
    /* Align size to 8 bytes and enforce minimum */
    size = QSYSDB_ALIGN8(size);
    if (size < SHM_MIN_ALLOC_SIZE) {
        size = SHM_MIN_ALLOC_SIZE;
    }

    uint32_t alloc_size = (uint32_t)size;

    /* Search free list for best-fit block */
    uint32_t best_offset = 0;
    uint32_t best_size = UINT32_MAX;
    uint32_t best_prev_offset = 0;
    uint32_t prev_offset = 0;
    uint32_t curr_offset = shm->header->free_list_head;

    while (curr_offset != 0) {
        struct shm_free_block *block = get_free_block(shm, curr_offset);
        if (block->magic != SHM_FREE_MAGIC) {
            /* Corrupted free list - skip */
            break;
        }

        if (block->size >= alloc_size && block->size < best_size) {
            best_offset = curr_offset;
            best_size = block->size;
            best_prev_offset = prev_offset;

            /* Exact fit - stop searching */
            if (block->size == alloc_size) {
                break;
            }
        }

        prev_offset = curr_offset;
        curr_offset = block->next_offset;
    }

    /* Found a suitable block in free list */
    if (best_offset != 0) {
        struct shm_free_block *block = get_free_block(shm, best_offset);
        uint32_t remaining = block->size - alloc_size;

        /* Check if we should split this block */
        if (remaining >= SHM_MIN_ALLOC_SIZE) {
            /* Create new free block with remainder */
            uint32_t new_free_offset = best_offset + alloc_size;
            struct shm_free_block *new_block = get_free_block(shm, new_free_offset);
            new_block->magic = SHM_FREE_MAGIC;
            new_block->size = remaining;
            new_block->next_offset = block->next_offset;
            new_block->prev_offset = best_prev_offset;

            /* Update list links */
            if (best_prev_offset == 0) {
                shm->header->free_list_head = new_free_offset;
            } else {
                struct shm_free_block *prev_block = get_free_block(shm, best_prev_offset);
                prev_block->next_offset = new_free_offset;
            }
        } else {
            /* Use entire block - remove from free list */
            if (best_prev_offset == 0) {
                shm->header->free_list_head = block->next_offset;
            } else {
                struct shm_free_block *prev_block = get_free_block(shm, best_prev_offset);
                prev_block->next_offset = block->next_offset;
            }
            shm->header->free_list_count--;
        }

        /* Track reused bytes */
        shm->header->bytes_reused += alloc_size;

        /* Clear the free block header (caller's data starts here) */
        memset(block, 0, sizeof(*block));

        return best_offset;
    }

    /* No suitable free block found - bump allocate */
    uint32_t data_size = shm->header->data_size;
    uint32_t data_used = shm->header->data_used;

    if (data_used + alloc_size > data_size) {
        return 0;  /* Out of space */
    }

    uint32_t offset = data_used;
    shm->header->data_used = data_used + alloc_size;

    return offset;
}

void qsysdb_shm_free(struct qsysdb_shm *shm, uint32_t offset, size_t size)
{
    if (offset == 0) return;

    /* Align size */
    size = QSYSDB_ALIGN8(size);
    if (size < SHM_MIN_ALLOC_SIZE) {
        size = SHM_MIN_ALLOC_SIZE;
    }

    /* Initialize free block header */
    struct shm_free_block *block = get_free_block(shm, offset);
    block->magic = SHM_FREE_MAGIC;
    block->size = (uint32_t)size;
    block->prev_offset = 0;

    /* Insert at head of free list (O(1) insertion) */
    block->next_offset = shm->header->free_list_head;
    shm->header->free_list_head = offset;
    shm->header->free_list_count++;
    shm->header->bytes_freed += size;

    /*
     * Note: Coalescing adjacent free blocks could be implemented here
     * but requires boundary tags or scanning. For now, we rely on
     * best-fit allocation to minimize fragmentation.
     *
     * A more advanced implementation could:
     * 1. Keep free list sorted by offset for efficient coalescing
     * 2. Use boundary tags to detect adjacent free blocks
     * 3. Implement periodic compaction
     */
}

uint64_t qsysdb_shm_next_sequence(struct qsysdb_shm *shm)
{
    return __atomic_add_fetch(&shm->header->sequence, 1, __ATOMIC_SEQ_CST);
}

uint64_t qsysdb_shm_get_sequence(struct qsysdb_shm *shm)
{
    return __atomic_load_n(&shm->header->sequence, __ATOMIC_ACQUIRE);
}

int qsysdb_shm_notify(struct qsysdb_shm *shm,
                      const struct qsysdb_notification *notif)
{
    int ret = ringbuf_publish(shm->ring, notif);
    if (ret == QSYSDB_OK) {
        __atomic_add_fetch(&shm->header->total_notifications, 1,
                           __ATOMIC_RELAXED);
    }
    return ret;
}

void qsysdb_shm_stats(struct qsysdb_shm *shm,
                      uint64_t *entry_count, uint64_t *data_used,
                      uint64_t *data_total, uint64_t *sequence)
{
    if (entry_count) {
        *entry_count = shm->header->entry_count;
    }
    if (data_used) {
        *data_used = shm->header->data_used;
    }
    if (data_total) {
        *data_total = shm->header->data_size;
    }
    if (sequence) {
        *sequence = qsysdb_shm_get_sequence(shm);
    }
}

/*
 * Kernel spinlock using atomic operations
 */
void qsysdb_shm_kernel_lock(struct qsysdb_shm_header *header)
{
    while (__atomic_test_and_set(&header->lock_state, __ATOMIC_ACQUIRE)) {
        /* Spin - use memory barrier as portable pause hint */
        while (__atomic_load_n(&header->lock_state, __ATOMIC_RELAXED)) {
            __atomic_thread_fence(__ATOMIC_SEQ_CST);
        }
    }
}

void qsysdb_shm_kernel_unlock(struct qsysdb_shm_header *header)
{
    __atomic_clear(&header->lock_state, __ATOMIC_RELEASE);
}

bool qsysdb_shm_kernel_trylock(struct qsysdb_shm_header *header)
{
    return !__atomic_test_and_set(&header->lock_state, __ATOMIC_ACQUIRE);
}

/*
 * Get current timestamp in nanoseconds
 */
uint64_t qsysdb_timestamp_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}
