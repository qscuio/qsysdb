/*
 * QSysDB - Unit tests for shared memory management
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>

#include <qsysdb/types.h>
#include "common/shm.h"
#include "common/ringbuf.h"

#define TEST(name) static void test_##name(void)
#define RUN_TEST(name) do { \
    printf("  " #name "... "); \
    test_##name(); \
    printf("OK\n"); \
} while(0)

#define TEST_SHM_NAME "/qsysdb_test_shm"
#define TEST_SHM_SIZE (4 * 1024 * 1024)  /* 4MB for tests */

/* Clean up any leftover test SHM */
static void cleanup_test_shm(void)
{
    shm_unlink(TEST_SHM_NAME);
}

TEST(create_and_open)
{
    cleanup_test_shm();

    struct qsysdb_shm *shm = qsysdb_shm_create(TEST_SHM_NAME, TEST_SHM_SIZE);
    assert(shm != NULL);
    assert(shm->base != NULL);
    assert(shm->size >= TEST_SHM_SIZE);

    struct qsysdb_shm_header *hdr = shm->base;
    assert(hdr->magic == QSYSDB_MAGIC);
    assert(hdr->version == QSYSDB_VERSION);

    qsysdb_shm_close(shm);

    /* Now open existing */
    shm = qsysdb_shm_open(TEST_SHM_NAME, false);
    assert(shm != NULL);

    hdr = shm->base;
    assert(hdr->magic == QSYSDB_MAGIC);

    qsysdb_shm_close(shm);
    cleanup_test_shm();
}

TEST(header_fields)
{
    cleanup_test_shm();

    struct qsysdb_shm *shm = qsysdb_shm_create(TEST_SHM_NAME, TEST_SHM_SIZE);
    assert(shm != NULL);

    struct qsysdb_shm_header *hdr = shm->base;

    /* Check all header fields are properly initialized */
    assert(hdr->magic == QSYSDB_MAGIC);
    assert(hdr->version == QSYSDB_VERSION);
    assert(hdr->size == TEST_SHM_SIZE);
    assert(hdr->sequence == 0);
    assert(hdr->index_offset > 0);
    assert(hdr->index_size > 0);
    assert(hdr->data_offset > hdr->index_offset);
    assert(hdr->data_size > 0);
    assert(hdr->ring_offset > hdr->data_offset);
    assert(hdr->ring_size > 0);

    /* Verify no overlap between regions */
    uint32_t index_end = hdr->index_offset + hdr->index_size;
    uint32_t data_end = hdr->data_offset + hdr->data_size;
    assert(index_end <= hdr->data_offset);
    assert(data_end <= hdr->ring_offset);

    qsysdb_shm_close(shm);
    cleanup_test_shm();
}

TEST(alloc_basic)
{
    cleanup_test_shm();

    struct qsysdb_shm *shm = qsysdb_shm_create(TEST_SHM_NAME, TEST_SHM_SIZE);
    assert(shm != NULL);

    /* Allocate some memory */
    uint32_t off1 = qsysdb_shm_alloc(shm, 100);
    assert(off1 != 0);

    uint32_t off2 = qsysdb_shm_alloc(shm, 200);
    assert(off2 != 0);
    assert(off2 != off1);

    /* Allocations should not overlap */
    assert(off2 >= off1 + 100 || off1 >= off2 + 200);

    qsysdb_shm_close(shm);
    cleanup_test_shm();
}

TEST(alloc_many)
{
    cleanup_test_shm();

    struct qsysdb_shm *shm = qsysdb_shm_create(TEST_SHM_NAME, TEST_SHM_SIZE);
    assert(shm != NULL);

    uint32_t offsets[100];
    size_t alloc_size = 256;

    /* Allocate many blocks */
    for (int i = 0; i < 100; i++) {
        offsets[i] = qsysdb_shm_alloc(shm, alloc_size);
        assert(offsets[i] != 0);

        /* Write something to verify no corruption */
        void *ptr = qsysdb_shm_ptr(shm, offsets[i]);
        memset(ptr, i & 0xFF, alloc_size);
    }

    /* Verify data integrity */
    for (int i = 0; i < 100; i++) {
        unsigned char *ptr = qsysdb_shm_ptr(shm, offsets[i]);
        for (size_t j = 0; j < alloc_size; j++) {
            assert(ptr[j] == (i & 0xFF));
        }
    }

    qsysdb_shm_close(shm);
    cleanup_test_shm();
}

TEST(alloc_large)
{
    cleanup_test_shm();

    struct qsysdb_shm *shm = qsysdb_shm_create(TEST_SHM_NAME, TEST_SHM_SIZE);
    assert(shm != NULL);

    /* Allocate a large block */
    size_t large_size = 64 * 1024;  /* 64KB */
    uint32_t off = qsysdb_shm_alloc(shm, large_size);
    assert(off != 0);

    /* Write and verify */
    char *ptr = qsysdb_shm_ptr(shm, off);
    memset(ptr, 'X', large_size);

    for (size_t i = 0; i < large_size; i++) {
        assert(ptr[i] == 'X');
    }

    qsysdb_shm_close(shm);
    cleanup_test_shm();
}

TEST(ptr_conversion)
{
    cleanup_test_shm();

    struct qsysdb_shm *shm = qsysdb_shm_create(TEST_SHM_NAME, TEST_SHM_SIZE);
    assert(shm != NULL);

    uint32_t off = qsysdb_shm_alloc(shm, 100);
    assert(off != 0);

    void *ptr = qsysdb_shm_ptr(shm, off);
    assert(ptr != NULL);

    /* Converting back should give same offset */
    uint32_t off2 = qsysdb_shm_offset(shm, ptr);
    assert(off2 == off);

    /* Offset 0 should give NULL */
    assert(qsysdb_shm_ptr(shm, 0) == NULL);

    qsysdb_shm_close(shm);
    cleanup_test_shm();
}

TEST(sequence_operations)
{
    cleanup_test_shm();

    struct qsysdb_shm *shm = qsysdb_shm_create(TEST_SHM_NAME, TEST_SHM_SIZE);
    assert(shm != NULL);

    struct qsysdb_shm_header *hdr = shm->base;
    assert(hdr->sequence == 0);

    /* Begin write should increment sequence to odd */
    qsysdb_shm_write_begin(shm);
    assert((hdr->sequence & 1) == 1);  /* Odd = write in progress */

    qsysdb_shm_write_end(shm);
    assert((hdr->sequence & 1) == 0);  /* Even = stable */
    assert(hdr->sequence == 2);

    /* Another write cycle */
    qsysdb_shm_write_begin(shm);
    qsysdb_shm_write_end(shm);
    assert(hdr->sequence == 4);

    qsysdb_shm_close(shm);
    cleanup_test_shm();
}

TEST(read_sequence)
{
    cleanup_test_shm();

    struct qsysdb_shm *shm = qsysdb_shm_create(TEST_SHM_NAME, TEST_SHM_SIZE);
    assert(shm != NULL);

    uint64_t seq;
    bool valid;

    /* Initial state should be valid for reading */
    seq = qsysdb_shm_read_begin(shm);
    assert((seq & 1) == 0);  /* Should be even (stable) */

    valid = qsysdb_shm_read_validate(shm, seq);
    assert(valid == true);

    /* Start a write - read should see it's unstable */
    qsysdb_shm_write_begin(shm);

    seq = qsysdb_shm_read_begin(shm);
    assert((seq & 1) == 1);  /* Odd during write */

    qsysdb_shm_write_end(shm);

    /* After write ends, validation should fail for old seq */
    valid = qsysdb_shm_read_validate(shm, seq);
    assert(valid == false);

    /* New read should be valid */
    seq = qsysdb_shm_read_begin(shm);
    valid = qsysdb_shm_read_validate(shm, seq);
    assert(valid == true);

    qsysdb_shm_close(shm);
    cleanup_test_shm();
}

TEST(ringbuf_init)
{
    cleanup_test_shm();

    struct qsysdb_shm *shm = qsysdb_shm_create(TEST_SHM_NAME, TEST_SHM_SIZE);
    assert(shm != NULL);

    struct qsysdb_shm_header *hdr = shm->base;
    struct qsysdb_ringbuf *ring = (struct qsysdb_ringbuf *)
        ((char *)shm->base + hdr->ring_offset);

    assert(ring->head == 0);
    assert(ring->tail == 0);
    assert(ring->size > 0);
    assert((ring->size & (ring->size - 1)) == 0);  /* Power of 2 */
    assert(ring->mask == ring->size - 1);

    qsysdb_shm_close(shm);
    cleanup_test_shm();
}

TEST(ringbuf_write_read)
{
    cleanup_test_shm();

    struct qsysdb_shm *shm = qsysdb_shm_create(TEST_SHM_NAME, TEST_SHM_SIZE);
    assert(shm != NULL);

    struct qsysdb_shm_header *hdr = shm->base;
    struct qsysdb_ringbuf *ring = (struct qsysdb_ringbuf *)
        ((char *)shm->base + hdr->ring_offset);

    /* Write a notification */
    struct qsysdb_notification notif = {0};
    notif.sequence = 1;
    notif.event_type = QSYSDB_EVENT_CREATE;
    strcpy(notif.path, "/test/path");

    int ret = qsysdb_ringbuf_write(ring, &notif);
    assert(ret == 0);

    /* Read it back */
    uint64_t reader_pos = 0;
    struct qsysdb_notification read_notif;
    ret = qsysdb_ringbuf_read(ring, &reader_pos, &read_notif);
    assert(ret == 0);
    assert(read_notif.sequence == 1);
    assert(read_notif.event_type == QSYSDB_EVENT_CREATE);
    assert(strcmp(read_notif.path, "/test/path") == 0);
    assert(reader_pos == 1);

    /* No more data */
    ret = qsysdb_ringbuf_read(ring, &reader_pos, &read_notif);
    assert(ret == -1);

    qsysdb_shm_close(shm);
    cleanup_test_shm();
}

TEST(ringbuf_multiple)
{
    cleanup_test_shm();

    struct qsysdb_shm *shm = qsysdb_shm_create(TEST_SHM_NAME, TEST_SHM_SIZE);
    assert(shm != NULL);

    struct qsysdb_shm_header *hdr = shm->base;
    struct qsysdb_ringbuf *ring = (struct qsysdb_ringbuf *)
        ((char *)shm->base + hdr->ring_offset);

    /* Write multiple notifications */
    for (int i = 0; i < 50; i++) {
        struct qsysdb_notification notif = {0};
        notif.sequence = i + 1;
        notif.event_type = QSYSDB_EVENT_UPDATE;
        snprintf(notif.path, sizeof(notif.path), "/entry/%d", i);

        int ret = qsysdb_ringbuf_write(ring, &notif);
        assert(ret == 0);
    }

    /* Read them all back */
    uint64_t reader_pos = 0;
    for (int i = 0; i < 50; i++) {
        struct qsysdb_notification read_notif;
        int ret = qsysdb_ringbuf_read(ring, &reader_pos, &read_notif);
        assert(ret == 0);
        assert(read_notif.sequence == (uint64_t)(i + 1));

        char expected[QSYSDB_MAX_PATH];
        snprintf(expected, sizeof(expected), "/entry/%d", i);
        assert(strcmp(read_notif.path, expected) == 0);
    }

    /* No more data */
    struct qsysdb_notification notif;
    int ret = qsysdb_ringbuf_read(ring, &reader_pos, &notif);
    assert(ret == -1);

    qsysdb_shm_close(shm);
    cleanup_test_shm();
}

TEST(readonly_open)
{
    cleanup_test_shm();

    /* Create with write access */
    struct qsysdb_shm *shm_rw = qsysdb_shm_create(TEST_SHM_NAME, TEST_SHM_SIZE);
    assert(shm_rw != NULL);

    /* Write some data */
    uint32_t off = qsysdb_shm_alloc(shm_rw, 100);
    assert(off != 0);
    char *ptr = qsysdb_shm_ptr(shm_rw, off);
    strcpy(ptr, "test data");

    /* Open read-only */
    struct qsysdb_shm *shm_ro = qsysdb_shm_open(TEST_SHM_NAME, true);
    assert(shm_ro != NULL);

    /* Should be able to read */
    char *ro_ptr = qsysdb_shm_ptr(shm_ro, off);
    assert(strcmp(ro_ptr, "test data") == 0);

    qsysdb_shm_close(shm_ro);
    qsysdb_shm_close(shm_rw);
    cleanup_test_shm();
}

int main(void)
{
    printf("Running shared memory tests...\n");

    RUN_TEST(create_and_open);
    RUN_TEST(header_fields);
    RUN_TEST(alloc_basic);
    RUN_TEST(alloc_many);
    RUN_TEST(alloc_large);
    RUN_TEST(ptr_conversion);
    RUN_TEST(sequence_operations);
    RUN_TEST(read_sequence);
    RUN_TEST(ringbuf_init);
    RUN_TEST(ringbuf_write_read);
    RUN_TEST(ringbuf_multiple);
    RUN_TEST(readonly_open);

    printf("\nAll shared memory tests passed!\n");
    return 0;
}
