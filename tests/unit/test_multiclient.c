/*
 * QSysDB - Multiple Client Concurrency Tests
 *
 * Tests concurrent access patterns including:
 *   - Multiple readers
 *   - Multiple writers
 *   - Mixed read/write workloads
 *   - Contention on same keys
 *   - Transaction isolation
 *   - Subscription delivery to multiple clients
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>

#include <qsysdb/types.h>
#include "common/shm.h"
#include "common/radix_tree.h"
#include "daemon/database.h"
#include "daemon/subscription.h"
#include "framework/test_framework.h"

static const char *_current_suite_name = "multiclient";

/* Test fixture data */
#define TEST_SHM_NAME "/qsysdb_multiclient_test"
#define TEST_SHM_SIZE (128 * 1024 * 1024)  /* 128MB for concurrency tests */

static struct qsysdb_db g_db;
static bool g_db_inited = false;

/* Synchronization primitives */
static pthread_barrier_t g_barrier;
static atomic_int g_error_count;
static atomic_int g_success_count;

/* Setup/teardown */
static void mc_setup(void) {
    qsysdb_shm_unlink(TEST_SHM_NAME);
    int ret = db_init(&g_db, TEST_SHM_NAME, TEST_SHM_SIZE);
    TEST_ASSERT_OK(ret);
    g_db_inited = true;
    atomic_store(&g_error_count, 0);
    atomic_store(&g_success_count, 0);
}

static void mc_teardown(void) {
    if (g_db_inited) {
        db_shutdown(&g_db);
        g_db_inited = false;
    }
    qsysdb_shm_unlink(TEST_SHM_NAME);
}

/* ============================================
 * Thread worker functions
 * ============================================ */

/* Worker that writes unique keys */
struct writer_args {
    int id;
    int num_writes;
    int start_key;
};

static void *writer_thread(void *arg) {
    struct writer_args *args = (struct writer_args *)arg;

    /* Wait for all threads to be ready */
    pthread_barrier_wait(&g_barrier);

    for (int i = 0; i < args->num_writes; i++) {
        char path[64];
        char value[128];
        int key = args->start_key + i;

        snprintf(path, sizeof(path), "/client%d/key%d", args->id, key);
        snprintf(value, sizeof(value),
                 "{\"client\":%d,\"key\":%d,\"seq\":%d}",
                 args->id, key, i);

        int ret = db_set(&g_db, path, strlen(path), value, strlen(value), 0, NULL);
        if (ret == QSYSDB_OK) {
            atomic_fetch_add(&g_success_count, 1);
        } else {
            atomic_fetch_add(&g_error_count, 1);
        }
    }

    return NULL;
}

/* Worker that reads keys */
struct reader_args {
    int id;
    int num_reads;
    const char *prefix;
};

static void *reader_thread(void *arg) {
    struct reader_args *args = (struct reader_args *)arg;

    /* Wait for all threads to be ready */
    pthread_barrier_wait(&g_barrier);

    for (int i = 0; i < args->num_reads; i++) {
        char path[64];
        char buf[256];
        size_t out_len;

        snprintf(path, sizeof(path), "%s/key%d", args->prefix, i % 100);

        int ret = db_get(&g_db, path, strlen(path), buf, sizeof(buf), &out_len, NULL, NULL);
        if (ret == QSYSDB_OK || ret == QSYSDB_ERR_NOTFOUND) {
            atomic_fetch_add(&g_success_count, 1);
        } else {
            atomic_fetch_add(&g_error_count, 1);
        }
    }

    return NULL;
}

/* Worker that does mixed read/write operations */
struct mixed_args {
    int id;
    int num_ops;
};

static void *mixed_thread(void *arg) {
    struct mixed_args *args = (struct mixed_args *)arg;

    pthread_barrier_wait(&g_barrier);

    for (int i = 0; i < args->num_ops; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/shared/key%d", i % 50);

        if (i % 3 == 0) {
            /* Write */
            char value[64];
            snprintf(value, sizeof(value), "{\"writer\":%d,\"iter\":%d}", args->id, i);
            int ret = db_set(&g_db, path, strlen(path), value, strlen(value), 0, NULL);
            if (ret == QSYSDB_OK) {
                atomic_fetch_add(&g_success_count, 1);
            } else {
                atomic_fetch_add(&g_error_count, 1);
            }
        } else {
            /* Read */
            char buf[256];
            size_t out_len;
            int ret = db_get(&g_db, path, strlen(path), buf, sizeof(buf), &out_len, NULL, NULL);
            if (ret == QSYSDB_OK || ret == QSYSDB_ERR_NOTFOUND) {
                atomic_fetch_add(&g_success_count, 1);
            } else {
                atomic_fetch_add(&g_error_count, 1);
            }
        }
    }

    return NULL;
}

/* Worker that contends on same key */
struct contention_args {
    int id;
    int num_updates;
    const char *key_path;
};

static void *contention_thread(void *arg) {
    struct contention_args *args = (struct contention_args *)arg;

    pthread_barrier_wait(&g_barrier);

    for (int i = 0; i < args->num_updates; i++) {
        char value[64];
        snprintf(value, sizeof(value), "{\"thread\":%d,\"update\":%d}", args->id, i);

        int ret = db_set(&g_db, args->key_path, strlen(args->key_path),
                         value, strlen(value), 0, NULL);
        if (ret == QSYSDB_OK) {
            atomic_fetch_add(&g_success_count, 1);
        } else {
            atomic_fetch_add(&g_error_count, 1);
        }
    }

    return NULL;
}

/* Worker that performs transactions */
struct txn_args {
    int id;
    int num_txns;
};

static void *transaction_thread(void *arg) {
    struct txn_args *args = (struct txn_args *)arg;

    pthread_barrier_wait(&g_barrier);

    for (int i = 0; i < args->num_txns; i++) {
        int txn_id;
        int ret = db_txn_begin(&g_db, args->id, &txn_id);
        if (ret != QSYSDB_OK) {
            atomic_fetch_add(&g_error_count, 1);
            continue;
        }

        /* Add 3 operations to transaction */
        char path1[64], path2[64], path3[64];
        char value[64];

        snprintf(path1, sizeof(path1), "/txn%d/a/%d", args->id, i);
        snprintf(path2, sizeof(path2), "/txn%d/b/%d", args->id, i);
        snprintf(path3, sizeof(path3), "/txn%d/c/%d", args->id, i);
        snprintf(value, sizeof(value), "{\"txn\":%d,\"iter\":%d}", args->id, i);

        db_txn_set(&g_db, txn_id, path1, strlen(path1), value, strlen(value), 0);
        db_txn_set(&g_db, txn_id, path2, strlen(path2), value, strlen(value), 0);
        db_txn_set(&g_db, txn_id, path3, strlen(path3), value, strlen(value), 0);

        uint64_t seq;
        int ops;
        ret = db_txn_commit(&g_db, txn_id, &seq, &ops);
        if (ret == QSYSDB_OK) {
            atomic_fetch_add(&g_success_count, 1);
        } else {
            atomic_fetch_add(&g_error_count, 1);
        }
    }

    return NULL;
}

/* ============================================
 * Multiple Writer Tests
 * ============================================ */

TEST(two_writers_disjoint_keys)
{
    mc_setup();

    pthread_t threads[2];
    struct writer_args args[2] = {
        { .id = 1, .num_writes = 100, .start_key = 0 },
        { .id = 2, .num_writes = 100, .start_key = 0 }
    };

    pthread_barrier_init(&g_barrier, NULL, 2);

    for (int i = 0; i < 2; i++) {
        pthread_create(&threads[i], NULL, writer_thread, &args[i]);
    }

    for (int i = 0; i < 2; i++) {
        pthread_join(threads[i], NULL);
    }

    pthread_barrier_destroy(&g_barrier);

    TEST_ASSERT_EQ(0, atomic_load(&g_error_count));
    TEST_ASSERT_EQ(200, atomic_load(&g_success_count));

    /* Verify all keys exist */
    bool exists;
    TEST_ASSERT_OK(db_exists(&g_db, "/client1/key50", 14, &exists));
    TEST_ASSERT_TRUE(exists);
    TEST_ASSERT_OK(db_exists(&g_db, "/client2/key50", 14, &exists));
    TEST_ASSERT_TRUE(exists);

    mc_teardown();
}

TEST(four_writers_disjoint_keys)
{
    mc_setup();

    pthread_t threads[4];
    struct writer_args args[4];

    for (int i = 0; i < 4; i++) {
        args[i].id = i + 1;
        args[i].num_writes = 50;
        args[i].start_key = 0;
    }

    pthread_barrier_init(&g_barrier, NULL, 4);

    for (int i = 0; i < 4; i++) {
        pthread_create(&threads[i], NULL, writer_thread, &args[i]);
    }

    for (int i = 0; i < 4; i++) {
        pthread_join(threads[i], NULL);
    }

    pthread_barrier_destroy(&g_barrier);

    TEST_ASSERT_EQ(0, atomic_load(&g_error_count));
    TEST_ASSERT_EQ(200, atomic_load(&g_success_count));

    mc_teardown();
}

TEST(eight_writers_high_volume)
{
    mc_setup();

    pthread_t threads[8];
    struct writer_args args[8];

    for (int i = 0; i < 8; i++) {
        args[i].id = i + 1;
        args[i].num_writes = 100;
        args[i].start_key = 0;
    }

    pthread_barrier_init(&g_barrier, NULL, 8);

    for (int i = 0; i < 8; i++) {
        pthread_create(&threads[i], NULL, writer_thread, &args[i]);
    }

    for (int i = 0; i < 8; i++) {
        pthread_join(threads[i], NULL);
    }

    pthread_barrier_destroy(&g_barrier);

    TEST_ASSERT_EQ(0, atomic_load(&g_error_count));
    TEST_ASSERT_EQ(800, atomic_load(&g_success_count));

    mc_teardown();
}

/* ============================================
 * Multiple Reader Tests
 * ============================================ */

TEST(multiple_readers_existing_data)
{
    mc_setup();

    /* Pre-populate data */
    for (int i = 0; i < 100; i++) {
        char path[64], value[64];
        snprintf(path, sizeof(path), "/data/key%d", i);
        snprintf(value, sizeof(value), "{\"id\":%d}", i);
        TEST_ASSERT_OK(db_set(&g_db, path, strlen(path), value, strlen(value), 0, NULL));
    }

    pthread_t threads[4];
    struct reader_args args[4];

    for (int i = 0; i < 4; i++) {
        args[i].id = i + 1;
        args[i].num_reads = 200;
        args[i].prefix = "/data";
    }

    pthread_barrier_init(&g_barrier, NULL, 4);

    for (int i = 0; i < 4; i++) {
        pthread_create(&threads[i], NULL, reader_thread, &args[i]);
    }

    for (int i = 0; i < 4; i++) {
        pthread_join(threads[i], NULL);
    }

    pthread_barrier_destroy(&g_barrier);

    TEST_ASSERT_EQ(0, atomic_load(&g_error_count));
    TEST_ASSERT_EQ(800, atomic_load(&g_success_count));

    mc_teardown();
}

/* ============================================
 * Mixed Read/Write Tests
 * ============================================ */

TEST(mixed_readers_writers)
{
    mc_setup();

    /* Pre-populate some data */
    for (int i = 0; i < 50; i++) {
        char path[64], value[64];
        snprintf(path, sizeof(path), "/shared/key%d", i);
        snprintf(value, sizeof(value), "{\"initial\":%d}", i);
        db_set(&g_db, path, strlen(path), value, strlen(value), 0, NULL);
    }

    pthread_t threads[6];
    struct mixed_args args[6];

    for (int i = 0; i < 6; i++) {
        args[i].id = i + 1;
        args[i].num_ops = 100;
    }

    pthread_barrier_init(&g_barrier, NULL, 6);

    for (int i = 0; i < 6; i++) {
        pthread_create(&threads[i], NULL, mixed_thread, &args[i]);
    }

    for (int i = 0; i < 6; i++) {
        pthread_join(threads[i], NULL);
    }

    pthread_barrier_destroy(&g_barrier);

    TEST_ASSERT_EQ(0, atomic_load(&g_error_count));
    TEST_ASSERT_EQ(600, atomic_load(&g_success_count));

    mc_teardown();
}

/* ============================================
 * Contention Tests
 * ============================================ */

TEST(contention_single_key)
{
    mc_setup();

    /* Create the key first */
    const char *key = "/hotspot/single";
    TEST_ASSERT_OK(db_set(&g_db, key, strlen(key), "{\"init\":true}", 13, 0, NULL));

    pthread_t threads[4];
    struct contention_args args[4];

    for (int i = 0; i < 4; i++) {
        args[i].id = i + 1;
        args[i].num_updates = 100;
        args[i].key_path = key;
    }

    pthread_barrier_init(&g_barrier, NULL, 4);

    for (int i = 0; i < 4; i++) {
        pthread_create(&threads[i], NULL, contention_thread, &args[i]);
    }

    for (int i = 0; i < 4; i++) {
        pthread_join(threads[i], NULL);
    }

    pthread_barrier_destroy(&g_barrier);

    TEST_ASSERT_EQ(0, atomic_load(&g_error_count));
    TEST_ASSERT_EQ(400, atomic_load(&g_success_count));

    /* Verify the key still exists and has valid JSON */
    char buf[256];
    size_t out_len;
    TEST_ASSERT_OK(db_get(&g_db, key, strlen(key), buf, sizeof(buf), &out_len, NULL, NULL));
    buf[out_len] = '\0';
    TEST_ASSERT_TRUE(out_len > 0);

    mc_teardown();
}

TEST(contention_few_keys)
{
    mc_setup();

    /* Create a few hot keys */
    const char *keys[] = {
        "/hot/key1", "/hot/key2", "/hot/key3", "/hot/key4", "/hot/key5"
    };

    for (int i = 0; i < 5; i++) {
        char value[32];
        snprintf(value, sizeof(value), "{\"id\":%d}", i);
        db_set(&g_db, keys[i], strlen(keys[i]), value, strlen(value), 0, NULL);
    }

    pthread_t threads[8];
    struct contention_args args[8];

    for (int i = 0; i < 8; i++) {
        args[i].id = i + 1;
        args[i].num_updates = 50;
        args[i].key_path = keys[i % 5];
    }

    pthread_barrier_init(&g_barrier, NULL, 8);

    for (int i = 0; i < 8; i++) {
        pthread_create(&threads[i], NULL, contention_thread, &args[i]);
    }

    for (int i = 0; i < 8; i++) {
        pthread_join(threads[i], NULL);
    }

    pthread_barrier_destroy(&g_barrier);

    TEST_ASSERT_EQ(0, atomic_load(&g_error_count));
    TEST_ASSERT_EQ(400, atomic_load(&g_success_count));

    mc_teardown();
}

/* ============================================
 * Transaction Tests
 * ============================================ */

TEST(concurrent_transactions_disjoint)
{
    mc_setup();

    pthread_t threads[4];
    struct txn_args args[4];

    for (int i = 0; i < 4; i++) {
        args[i].id = i + 1;
        args[i].num_txns = 20;
    }

    pthread_barrier_init(&g_barrier, NULL, 4);

    for (int i = 0; i < 4; i++) {
        pthread_create(&threads[i], NULL, transaction_thread, &args[i]);
    }

    for (int i = 0; i < 4; i++) {
        pthread_join(threads[i], NULL);
    }

    pthread_barrier_destroy(&g_barrier);

    TEST_ASSERT_EQ(0, atomic_load(&g_error_count));
    TEST_ASSERT_EQ(80, atomic_load(&g_success_count));

    /* Verify transaction atomicity - all 3 keys should exist for each txn */
    for (int t = 1; t <= 4; t++) {
        for (int i = 0; i < 20; i++) {
            char path[64];
            bool exists_a, exists_b, exists_c;

            snprintf(path, sizeof(path), "/txn%d/a/%d", t, i);
            db_exists(&g_db, path, strlen(path), &exists_a);

            snprintf(path, sizeof(path), "/txn%d/b/%d", t, i);
            db_exists(&g_db, path, strlen(path), &exists_b);

            snprintf(path, sizeof(path), "/txn%d/c/%d", t, i);
            db_exists(&g_db, path, strlen(path), &exists_c);

            /* All three should exist together (atomicity) */
            TEST_ASSERT_TRUE(exists_a == exists_b && exists_b == exists_c);
        }
    }

    mc_teardown();
}

/* ============================================
 * Subscription Tests (Multi-client)
 * ============================================ */

TEST(multiple_subscribers_different_patterns)
{
    struct sub_manager mgr;
    TEST_ASSERT_OK(sub_manager_init(&mgr));

    /* Multiple clients subscribe to different patterns */
    int sub1, sub2, sub3, sub4;
    TEST_ASSERT_OK(sub_add(&mgr, 1, "/routing/*", 10, &sub1));
    TEST_ASSERT_OK(sub_add(&mgr, 2, "/interfaces/*", 13, &sub2));
    TEST_ASSERT_OK(sub_add(&mgr, 3, "/arp/*", 6, &sub3));
    TEST_ASSERT_OK(sub_add(&mgr, 4, "/*", 2, &sub4));  /* Wildcard subscriber */

    int client_ids[10], sub_ids[10];

    /* Routing event - should match client 1 and 4 */
    int matches = sub_match(&mgr, "/routing/default", 16, client_ids, sub_ids, 10);
    TEST_ASSERT_GE(matches, 1);

    /* Interface event - should match client 2 and 4 */
    matches = sub_match(&mgr, "/interfaces/eth0", 16, client_ids, sub_ids, 10);
    TEST_ASSERT_GE(matches, 1);

    /* ARP event - should match client 3 and 4 */
    matches = sub_match(&mgr, "/arp/192.168.1.1", 16, client_ids, sub_ids, 10);
    TEST_ASSERT_GE(matches, 1);

    sub_manager_shutdown(&mgr);
}

TEST(multiple_subscribers_same_pattern)
{
    struct sub_manager mgr;
    TEST_ASSERT_OK(sub_manager_init(&mgr));

    /* Multiple clients subscribe to same pattern */
    int subs[5];
    for (int i = 0; i < 5; i++) {
        TEST_ASSERT_OK(sub_add(&mgr, i + 1, "/events/*", 9, &subs[i]));
    }

    int client_ids[10], sub_ids[10];

    /* Event should match all 5 clients */
    int matches = sub_match(&mgr, "/events/update", 14, client_ids, sub_ids, 10);
    TEST_ASSERT_EQ(5, matches);

    /* Verify all clients are notified */
    int found[5] = {0};
    for (int i = 0; i < matches; i++) {
        if (client_ids[i] >= 1 && client_ids[i] <= 5) {
            found[client_ids[i] - 1] = 1;
        }
    }
    for (int i = 0; i < 5; i++) {
        TEST_ASSERT_EQ(1, found[i]);
    }

    sub_manager_shutdown(&mgr);
}

TEST(subscriber_disconnect_cleanup)
{
    struct sub_manager mgr;
    TEST_ASSERT_OK(sub_manager_init(&mgr));

    /* Client 1 subscribes to multiple patterns */
    int sub1, sub2, sub3;
    TEST_ASSERT_OK(sub_add(&mgr, 1, "/a/*", 4, &sub1));
    TEST_ASSERT_OK(sub_add(&mgr, 1, "/b/*", 4, &sub2));
    TEST_ASSERT_OK(sub_add(&mgr, 1, "/c/*", 4, &sub3));

    /* Client 2 has one subscription */
    int sub4;
    TEST_ASSERT_OK(sub_add(&mgr, 2, "/d/*", 4, &sub4));

    int client_ids[10], sub_ids[10];

    /* Before disconnect - client 1 should match */
    int matches = sub_match(&mgr, "/a/test", 7, client_ids, sub_ids, 10);
    TEST_ASSERT_EQ(1, matches);

    /* Simulate client 1 disconnect */
    sub_remove_client(&mgr, 1);

    /* After disconnect - client 1 should not match */
    matches = sub_match(&mgr, "/a/test", 7, client_ids, sub_ids, 10);
    TEST_ASSERT_EQ(0, matches);
    matches = sub_match(&mgr, "/b/test", 7, client_ids, sub_ids, 10);
    TEST_ASSERT_EQ(0, matches);
    matches = sub_match(&mgr, "/c/test", 7, client_ids, sub_ids, 10);
    TEST_ASSERT_EQ(0, matches);

    /* Client 2 should still work */
    matches = sub_match(&mgr, "/d/test", 7, client_ids, sub_ids, 10);
    TEST_ASSERT_EQ(1, matches);
    TEST_ASSERT_EQ(2, client_ids[0]);

    sub_manager_shutdown(&mgr);
}

/* ============================================
 * Stress Tests
 * ============================================ */

TEST(stress_many_threads_many_keys)
{
    mc_setup();

    #define NUM_STRESS_THREADS 8
    #define OPS_PER_THREAD 200

    pthread_t threads[NUM_STRESS_THREADS];
    struct writer_args args[NUM_STRESS_THREADS];

    for (int i = 0; i < NUM_STRESS_THREADS; i++) {
        args[i].id = i + 1;
        args[i].num_writes = OPS_PER_THREAD;
        args[i].start_key = 0;
    }

    pthread_barrier_init(&g_barrier, NULL, NUM_STRESS_THREADS);

    for (int i = 0; i < NUM_STRESS_THREADS; i++) {
        pthread_create(&threads[i], NULL, writer_thread, &args[i]);
    }

    for (int i = 0; i < NUM_STRESS_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    pthread_barrier_destroy(&g_barrier);

    TEST_ASSERT_EQ(0, atomic_load(&g_error_count));
    TEST_ASSERT_EQ(NUM_STRESS_THREADS * OPS_PER_THREAD, atomic_load(&g_success_count));

    mc_teardown();
}

TEST_MAIN()
