/*
 * QSysDB - Comprehensive Benchmark Suite
 *
 * Benchmarks for all major components including:
 *   - JSON validation
 *   - Radix tree operations
 *   - Database operations (set, get, delete)
 *   - Transaction performance
 *   - Subscription matching
 *   - Throughput tests
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <qsysdb/types.h>
#include "common/radix_tree.h"
#include "common/shm.h"
#include "daemon/database.h"
#include "daemon/subscription.h"
#include "framework/benchmark.h"

/* External declarations from json.c */
extern int qsysdb_json_validate(const char *json, size_t len);
extern int qsysdb_json_validate_str(const char *json);

/* ============================================
 * JSON Benchmark Data
 * ============================================ */

static const char *json_simple = "{\"key\":\"value\"}";
static const char *json_nested = "{\"a\":{\"b\":{\"c\":{\"d\":\"deep\"}}}}";
static const char *json_array = "[1,2,3,4,5,6,7,8,9,10]";
static char *json_large = NULL;
static size_t json_large_len = 0;

static void json_bench_setup(void *userdata) {
    (void)userdata;
    if (!json_large) {
        /* Create a ~10KB JSON document */
        json_large = malloc(12000);
        strcpy(json_large, "{\"items\":[");
        size_t pos = strlen(json_large);
        for (int i = 0; i < 100; i++) {
            pos += snprintf(json_large + pos, 12000 - pos,
                           "{\"id\":%d,\"name\":\"item%d\",\"value\":%d}%s",
                           i, i, i * 100, i < 99 ? "," : "");
        }
        strcat(json_large, "]}");
        json_large_len = strlen(json_large);
    }
}

/* ============================================
 * JSON Benchmarks
 * ============================================ */

BENCHMARK(json, validate_simple)
{
    int result = qsysdb_json_validate_str(json_simple);
    BENCH_DO_NOT_OPTIMIZE(result);
}

BENCHMARK(json, validate_nested)
{
    int result = qsysdb_json_validate_str(json_nested);
    BENCH_DO_NOT_OPTIMIZE(result);
}

BENCHMARK(json, validate_array)
{
    int result = qsysdb_json_validate_str(json_array);
    BENCH_DO_NOT_OPTIMIZE(result);
}

BENCHMARK_F(json, validate_large, json_bench_setup, NULL, NULL)
{
    int result = qsysdb_json_validate(json_large, json_large_len);
    BENCH_DO_NOT_OPTIMIZE(result);
}

BENCHMARK(json, validate_number)
{
    int result = qsysdb_json_validate_str("12345.6789e+10");
    BENCH_DO_NOT_OPTIMIZE(result);
}

BENCHMARK(json, validate_string_with_escapes)
{
    int result = qsysdb_json_validate_str("\"hello\\nworld\\t\\\"quoted\\\"\"");
    BENCH_DO_NOT_OPTIMIZE(result);
}

/* ============================================
 * Radix Tree Benchmark Data
 * ============================================ */

static void *radix_mem = NULL;
static struct radix_tree *radix_tree = NULL;
static char radix_paths[1000][64];
static int radix_path_count = 0;
static int radix_paths_generated = 0;

/* Radix tree memory size - each node is ~1KB, so 5MB = ~5000 nodes */
#define RADIX_BENCH_MEM_SIZE (5 * 1024 * 1024)
#define RADIX_BENCH_MAX_NODES 4000

static void radix_bench_setup(void *userdata) {
    (void)userdata;
    if (!radix_mem) {
        radix_mem = malloc(RADIX_BENCH_MEM_SIZE);
        if (!radix_mem) {
            fprintf(stderr, "Failed to allocate radix memory\n");
            return;
        }
    }
    memset(radix_mem, 0, RADIX_BENCH_MEM_SIZE);
    radix_tree_init(radix_mem, RADIX_BENCH_MEM_SIZE, RADIX_BENCH_MAX_NODES);
    radix_tree = radix_tree_get(radix_mem);

    /* Pre-generate paths (only once) */
    if (!radix_paths_generated) {
        for (int i = 0; i < 1000; i++) {
            snprintf(radix_paths[i], sizeof(radix_paths[i]), "/bench/entry/%d", i);
        }
        radix_path_count = 1000;
        radix_paths_generated = 1;
    }
}

static void radix_bench_teardown(void *userdata) {
    (void)userdata;
    /* No-op: setup will reinit the tree */
}

/* ============================================
 * Radix Tree Benchmarks
 * ============================================ */

BENCHMARK_F(radix, insert_single, radix_bench_setup, radix_bench_teardown, NULL)
{
    uint32_t off = radix_tree_insert(radix_tree, radix_mem, "/test/key", 9, 100);
    BENCH_DO_NOT_OPTIMIZE(off);
}

BENCHMARK_F(radix, lookup_existing, radix_bench_setup, NULL, NULL)
{
    /* Insert once for lookup test */
    static int inserted = 0;
    if (!inserted) {
        radix_tree_insert(radix_tree, radix_mem, "/lookup/key", 11, 100);
        inserted = 1;
    }
    uint32_t val = radix_tree_lookup(radix_tree, radix_mem, "/lookup/key", 11);
    BENCH_DO_NOT_OPTIMIZE(val);
}

BENCHMARK_F(radix, lookup_nonexistent, radix_bench_setup, NULL, NULL)
{
    uint32_t val = radix_tree_lookup(radix_tree, radix_mem, "/missing/path", 13);
    BENCH_DO_NOT_OPTIMIZE(val);
}

BENCHMARK_F(radix, insert_100, radix_bench_setup, radix_bench_teardown, NULL)
{
    for (int i = 0; i < 100; i++) {
        radix_tree_insert(radix_tree, radix_mem, radix_paths[i], strlen(radix_paths[i]), i);
    }
    BENCH_CLOBBER();
}

BENCHMARK_F(radix, insert_1000, radix_bench_setup, radix_bench_teardown, NULL)
{
    for (int i = 0; i < 1000; i++) {
        radix_tree_insert(radix_tree, radix_mem, radix_paths[i], strlen(radix_paths[i]), i);
    }
    BENCH_CLOBBER();
}

/* Pre-populate for lookup benchmarks */
static void radix_populate_setup(void *userdata) {
    radix_bench_setup(userdata);
    for (int i = 0; i < 1000; i++) {
        radix_tree_insert(radix_tree, radix_mem, radix_paths[i], strlen(radix_paths[i]), i + 1);
    }
}

BENCHMARK_F(radix, lookup_populated_1000, radix_populate_setup, radix_bench_teardown, NULL)
{
    static int idx = 0;
    uint32_t val = radix_tree_lookup(radix_tree, radix_mem,
                                      radix_paths[idx % 1000],
                                      strlen(radix_paths[idx % 1000]));
    idx++;
    BENCH_DO_NOT_OPTIMIZE(val);
}

/* ============================================
 * Database Benchmark Data
 * ============================================ */

#define DB_BENCH_SHM_NAME "/qsysdb_bench"
#define DB_BENCH_SHM_SIZE (128 * 1024 * 1024)

static struct qsysdb_db db_bench;
static int db_bench_inited = 0;
static char db_paths[10000][64];
static char db_values[100][256];
static int db_paths_generated = 0;

static void db_bench_setup(void *userdata) {
    (void)userdata;
    if (!db_bench_inited) {
        qsysdb_shm_unlink(DB_BENCH_SHM_NAME);
        int ret = db_init(&db_bench, DB_BENCH_SHM_NAME, DB_BENCH_SHM_SIZE);
        if (ret != QSYSDB_OK) {
            fprintf(stderr, "Failed to init db for benchmark: %d\n", ret);
            return;
        }
        db_bench_inited = 1;
    }

    /* Pre-generate paths and values (only once) */
    if (!db_paths_generated) {
        for (int i = 0; i < 10000; i++) {
            snprintf(db_paths[i], sizeof(db_paths[i]), "/bench/data/%d", i);
        }
        for (int i = 0; i < 100; i++) {
            snprintf(db_values[i], sizeof(db_values[i]),
                     "{\"id\":%d,\"name\":\"item%d\",\"value\":%d}", i, i, i * 100);
        }
        db_paths_generated = 1;
    }
}

static void db_bench_reset(void *userdata) {
    (void)userdata;
    /* Keep db initialized, just clear data for next benchmark */
}

/* ============================================
 * Database Benchmarks
 * ============================================ */

BENCHMARK_F(database, set_simple, db_bench_setup, NULL, NULL)
{
    static int idx = 0;
    int ret = db_set(&db_bench, db_paths[idx % 10000], strlen(db_paths[idx % 10000]),
                     "{\"v\":1}", 7, 0, NULL);
    idx++;
    BENCH_DO_NOT_OPTIMIZE(ret);
}

BENCHMARK_F(database, set_medium_value, db_bench_setup, NULL, NULL)
{
    static int idx = 0;
    int ret = db_set(&db_bench, db_paths[idx % 10000], strlen(db_paths[idx % 10000]),
                     db_values[idx % 100], strlen(db_values[idx % 100]), 0, NULL);
    idx++;
    BENCH_DO_NOT_OPTIMIZE(ret);
}

/* Pre-populate for get benchmarks */
static int db_populated = 0;

static void db_populate_setup(void *userdata) {
    db_bench_setup(userdata);
    if (!db_populated && db_bench_inited) {
        for (int i = 0; i < 1000; i++) {
            db_set(&db_bench, db_paths[i], strlen(db_paths[i]),
                   db_values[i % 100], strlen(db_values[i % 100]), 0, NULL);
        }
        db_populated = 1;
    }
}

BENCHMARK_F(database, get_existing, db_populate_setup, NULL, NULL)
{
    static int idx = 0;
    char buf[512];
    size_t out_len;
    int ret = db_get(&db_bench, db_paths[idx % 1000], strlen(db_paths[idx % 1000]),
                     buf, sizeof(buf), &out_len, NULL, NULL);
    idx++;
    BENCH_DO_NOT_OPTIMIZE(ret);
}

BENCHMARK_F(database, get_nonexistent, db_bench_setup, NULL, NULL)
{
    char buf[512];
    size_t out_len;
    int ret = db_get(&db_bench, "/missing/path/that/does/not/exist", 34,
                     buf, sizeof(buf), &out_len, NULL, NULL);
    BENCH_DO_NOT_OPTIMIZE(ret);
}

BENCHMARK_F(database, exists_true, db_populate_setup, NULL, NULL)
{
    static int idx = 0;
    bool exists;
    int ret = db_exists(&db_bench, db_paths[idx % 1000], strlen(db_paths[idx % 1000]), &exists);
    idx++;
    BENCH_DO_NOT_OPTIMIZE(ret);
}

BENCHMARK_F(database, exists_false, db_bench_setup, NULL, NULL)
{
    bool exists;
    int ret = db_exists(&db_bench, "/missing/path", 13, &exists);
    BENCH_DO_NOT_OPTIMIZE(ret);
}

/* ============================================
 * Transaction Benchmarks
 * ============================================ */

BENCHMARK_F(transaction, begin_commit_empty, db_bench_setup, NULL, NULL)
{
    int txn_id;
    db_txn_begin(&db_bench, 1, &txn_id);
    uint64_t seq;
    int ops;
    int ret = db_txn_commit(&db_bench, txn_id, &seq, &ops);
    BENCH_DO_NOT_OPTIMIZE(ret);
}

BENCHMARK_F(transaction, begin_abort, db_bench_setup, NULL, NULL)
{
    int txn_id;
    db_txn_begin(&db_bench, 1, &txn_id);
    db_txn_abort(&db_bench, txn_id);
    BENCH_CLOBBER();
}

BENCHMARK_F(transaction, 10_ops_commit, db_bench_setup, NULL, NULL)
{
    static int batch = 0;
    int txn_id;
    db_txn_begin(&db_bench, 1, &txn_id);

    for (int i = 0; i < 10; i++) {
        int idx = (batch * 10 + i) % 10000;
        db_txn_set(&db_bench, txn_id, db_paths[idx], strlen(db_paths[idx]),
                   "{\"txn\":true}", 12, 0);
    }

    uint64_t seq;
    int ops;
    int ret = db_txn_commit(&db_bench, txn_id, &seq, &ops);
    batch++;
    BENCH_DO_NOT_OPTIMIZE(ret);
}

/* ============================================
 * Subscription Benchmarks
 * ============================================ */

static struct sub_manager sub_bench_mgr;
static int sub_bench_inited = 0;
static char sub_patterns[100][64];
static char sub_test_paths[1000][64];

static void sub_bench_setup(void *userdata) {
    (void)userdata;
    if (!sub_bench_inited) {
        sub_manager_init(&sub_bench_mgr);

        /* Pre-generate patterns and test paths */
        for (int i = 0; i < 100; i++) {
            snprintf(sub_patterns[i], sizeof(sub_patterns[i]), "/events/type%d/*", i);
        }
        for (int i = 0; i < 1000; i++) {
            snprintf(sub_test_paths[i], sizeof(sub_test_paths[i]),
                     "/events/type%d/event%d", i % 100, i);
        }
        sub_bench_inited = 1;
    }
}

static void sub_bench_reset(void *userdata) {
    (void)userdata;
    if (sub_bench_inited) {
        sub_manager_shutdown(&sub_bench_mgr);
        sub_bench_inited = 0;
        sub_bench_setup(NULL);
    }
}

BENCHMARK_F(subscription, add_subscription, sub_bench_setup, sub_bench_reset, NULL)
{
    static int idx = 0;
    int sub_id;
    int ret = sub_add(&sub_bench_mgr, 1, sub_patterns[idx % 100],
                      strlen(sub_patterns[idx % 100]), &sub_id);
    idx++;
    BENCH_DO_NOT_OPTIMIZE(ret);
}

/* Pre-populate subscriptions */
static int subs_populated = 0;

static void sub_populate_setup(void *userdata) {
    sub_bench_setup(userdata);
    if (!subs_populated) {
        for (int i = 0; i < 100; i++) {
            int sub_id;
            sub_add(&sub_bench_mgr, i % 10, sub_patterns[i], strlen(sub_patterns[i]), &sub_id);
        }
        subs_populated = 1;
    }
}

BENCHMARK_F(subscription, match_with_100_subs, sub_populate_setup, NULL, NULL)
{
    static int idx = 0;
    int client_ids[10], sub_ids[10];
    int matches = sub_match(&sub_bench_mgr, sub_test_paths[idx % 1000],
                            strlen(sub_test_paths[idx % 1000]),
                            client_ids, sub_ids, 10);
    idx++;
    BENCH_DO_NOT_OPTIMIZE(matches);
}

BENCHMARK_F(subscription, match_no_subscribers, sub_bench_setup, NULL, NULL)
{
    int client_ids[10], sub_ids[10];
    int matches = sub_match(&sub_bench_mgr, "/unsubscribed/path", 18,
                            client_ids, sub_ids, 10);
    BENCH_DO_NOT_OPTIMIZE(matches);
}

/* ============================================
 * Scalability Benchmarks (for 10+ clients, 100K+ entries)
 * ============================================ */

/* Large subscription test - simulates 10 clients with 100 subscriptions each */
static int scale_subs_populated = 0;
static struct sub_manager scale_sub_mgr;
static int scale_sub_inited = 0;
static char scale_patterns[1000][64];
static char scale_paths[10000][64];

static void scale_sub_setup(void *userdata) {
    (void)userdata;
    if (!scale_sub_inited) {
        sub_manager_init(&scale_sub_mgr);

        /* Generate patterns for 10 clients with 100 subscriptions each */
        for (int client = 0; client < 10; client++) {
            for (int i = 0; i < 100; i++) {
                int idx = client * 100 + i;
                snprintf(scale_patterns[idx], sizeof(scale_patterns[idx]),
                         "/client%d/events/type%d/*", client, i);
            }
        }
        /* Generate test paths */
        for (int i = 0; i < 10000; i++) {
            int client = i % 10;
            int type = (i / 10) % 100;
            snprintf(scale_paths[i], sizeof(scale_paths[i]),
                     "/client%d/events/type%d/event%d", client, type, i);
        }
        scale_sub_inited = 1;
    }
}

static void scale_sub_populate(void *userdata) {
    scale_sub_setup(userdata);
    if (!scale_subs_populated) {
        /* Add 1000 subscriptions (10 clients x 100 each) */
        for (int i = 0; i < 1000; i++) {
            int sub_id;
            sub_add(&scale_sub_mgr, i / 100, scale_patterns[i],
                    strlen(scale_patterns[i]), &sub_id);
        }
        scale_subs_populated = 1;
    }
}

BENCHMARK_F(scalability, match_with_1000_subs, scale_sub_populate, NULL, NULL)
{
    static int idx = 0;
    int client_ids[100], sub_ids[100];
    int matches = sub_match(&scale_sub_mgr, scale_paths[idx % 10000],
                            strlen(scale_paths[idx % 10000]),
                            client_ids, sub_ids, 100);
    idx++;
    BENCH_DO_NOT_OPTIMIZE(matches);
}

BENCHMARK_F(scalability, add_1000_subscriptions, scale_sub_setup, NULL, NULL)
{
    struct sub_manager temp_mgr;
    sub_manager_init(&temp_mgr);

    for (int i = 0; i < 1000; i++) {
        int sub_id;
        sub_add(&temp_mgr, i / 100, scale_patterns[i],
                strlen(scale_patterns[i]), &sub_id);
    }

    sub_manager_shutdown(&temp_mgr);
    BENCH_CLOBBER();
}

/* High-volume database operations */
static int scale_db_inited = 0;
static struct qsysdb_db scale_db;
static char scale_db_paths[100000][48];
static char scale_db_value[512];
static int scale_db_paths_generated = 0;

static void scale_db_setup(void *userdata) {
    (void)userdata;
    if (!scale_db_inited) {
        qsysdb_shm_unlink("/qsysdb_scale_bench");
        int ret = db_init(&scale_db, "/qsysdb_scale_bench", 512 * 1024 * 1024);
        if (ret != QSYSDB_OK) {
            fprintf(stderr, "Failed to init scale db: %d\n", ret);
            return;
        }
        scale_db_inited = 1;
    }

    if (!scale_db_paths_generated) {
        /* Generate 100K unique paths */
        for (int i = 0; i < 100000; i++) {
            int client = i % 10;
            int category = (i / 10) % 100;
            snprintf(scale_db_paths[i], sizeof(scale_db_paths[i]),
                     "/c%d/cat%d/entry%d", client, category, i);
        }
        snprintf(scale_db_value, sizeof(scale_db_value),
                 "{\"id\":0,\"data\":\"benchmark_test_value\",\"status\":\"active\"}");
        scale_db_paths_generated = 1;
    }
}

BENCHMARK_F(scalability, set_10000_entries, scale_db_setup, NULL, NULL)
{
    for (int i = 0; i < 10000; i++) {
        db_set(&scale_db, scale_db_paths[i], strlen(scale_db_paths[i]),
               scale_db_value, strlen(scale_db_value), 0, NULL);
    }
    BENCH_CLOBBER();
}

/* Pre-populate with 50K entries for get/exists tests */
static int scale_db_populated = 0;

static void scale_db_populate(void *userdata) {
    scale_db_setup(userdata);
    if (!scale_db_populated && scale_db_inited) {
        for (int i = 0; i < 50000; i++) {
            db_set(&scale_db, scale_db_paths[i], strlen(scale_db_paths[i]),
                   scale_db_value, strlen(scale_db_value), 0, NULL);
        }
        scale_db_populated = 1;
    }
}

BENCHMARK_F(scalability, get_from_50K_entries, scale_db_populate, NULL, NULL)
{
    static int idx = 0;
    char buf[512];
    size_t out_len;
    int ret = db_get(&scale_db, scale_db_paths[idx % 50000],
                     strlen(scale_db_paths[idx % 50000]),
                     buf, sizeof(buf), &out_len, NULL, NULL);
    idx++;
    BENCH_DO_NOT_OPTIMIZE(ret);
}

BENCHMARK_F(scalability, exists_in_50K_entries, scale_db_populate, NULL, NULL)
{
    static int idx = 0;
    bool exists;
    int ret = db_exists(&scale_db, scale_db_paths[idx % 50000],
                        strlen(scale_db_paths[idx % 50000]), &exists);
    idx++;
    BENCH_DO_NOT_OPTIMIZE(ret);
}

/* Memory reclamation test - delete and reinsert */
BENCHMARK_F(scalability, delete_reinsert_cycle, scale_db_populate, NULL, NULL)
{
    static int idx = 0;
    int path_idx = idx % 50000;

    /* Delete an entry */
    db_delete(&scale_db, scale_db_paths[path_idx],
              strlen(scale_db_paths[path_idx]));

    /* Reinsert with new value */
    db_set(&scale_db, scale_db_paths[path_idx],
           strlen(scale_db_paths[path_idx]),
           scale_db_value, strlen(scale_db_value), 0, NULL);

    idx++;
    BENCH_CLOBBER();
}

/* ============================================
 * Throughput Benchmarks
 * ============================================ */

BENCHMARK_F(throughput, set_get_cycle, db_bench_setup, NULL, NULL)
{
    static int idx = 0;
    char buf[512];
    size_t out_len;

    /* Set then immediately get */
    db_set(&db_bench, db_paths[idx % 10000], strlen(db_paths[idx % 10000]),
           "{\"cycle\":true}", 14, 0, NULL);
    int ret = db_get(&db_bench, db_paths[idx % 10000], strlen(db_paths[idx % 10000]),
                     buf, sizeof(buf), &out_len, NULL, NULL);
    idx++;
    BENCH_DO_NOT_OPTIMIZE(ret);
}

BENCHMARK_F(throughput, 100_sequential_sets, db_bench_setup, db_bench_reset, NULL)
{
    for (int i = 0; i < 100; i++) {
        db_set(&db_bench, db_paths[i], strlen(db_paths[i]),
               "{\"seq\":true}", 12, 0, NULL);
    }
    BENCH_CLOBBER();
}

BENCHMARK_F(throughput, 100_sequential_gets, db_populate_setup, NULL, NULL)
{
    char buf[512];
    size_t out_len;
    for (int i = 0; i < 100; i++) {
        db_get(&db_bench, db_paths[i % 1000], strlen(db_paths[i % 1000]),
               buf, sizeof(buf), &out_len, NULL, NULL);
    }
    BENCH_CLOBBER();
}

/* ============================================
 * Memory/Allocation Benchmarks
 * ============================================ */

BENCHMARK(memory, malloc_free_64)
{
    void *ptr = malloc(64);
    BENCH_DO_NOT_OPTIMIZE(ptr);
    free(ptr);
}

BENCHMARK(memory, malloc_free_4k)
{
    void *ptr = malloc(4096);
    BENCH_DO_NOT_OPTIMIZE(ptr);
    free(ptr);
}

BENCHMARK(memory, memset_4k)
{
    static char buf[4096];
    memset(buf, 0, sizeof(buf));
    BENCH_CLOBBER();
}

BENCHMARK(memory, memcpy_4k)
{
    static char src[4096] = {1};
    static char dst[4096];
    memcpy(dst, src, sizeof(src));
    BENCH_CLOBBER();
}

/* ============================================
 * String Operation Benchmarks
 * ============================================ */

BENCHMARK(string, strlen_short)
{
    size_t len = strlen("/short/path");
    BENCH_DO_NOT_OPTIMIZE(len);
}

BENCHMARK(string, strlen_long)
{
    size_t len = strlen("/very/long/path/that/goes/deep/into/hierarchy/with/many/segments");
    BENCH_DO_NOT_OPTIMIZE(len);
}

BENCHMARK(string, strcmp_equal)
{
    int cmp = strcmp("/test/path", "/test/path");
    BENCH_DO_NOT_OPTIMIZE(cmp);
}

BENCHMARK(string, strcmp_different)
{
    int cmp = strcmp("/test/path/a", "/test/path/b");
    BENCH_DO_NOT_OPTIMIZE(cmp);
}

/* ============================================
 * Cleanup
 * ============================================ */

__attribute__((destructor))
static void bench_cleanup(void) {
    if (json_large) {
        free(json_large);
        json_large = NULL;
    }
    if (radix_mem) {
        free(radix_mem);
        radix_mem = NULL;
    }
    if (db_bench_inited) {
        db_shutdown(&db_bench);
        qsysdb_shm_unlink(DB_BENCH_SHM_NAME);
    }
    if (sub_bench_inited) {
        sub_manager_shutdown(&sub_bench_mgr);
    }
    /* Cleanup scalability benchmarks */
    if (scale_sub_inited) {
        sub_manager_shutdown(&scale_sub_mgr);
    }
    if (scale_db_inited) {
        db_shutdown(&scale_db);
        qsysdb_shm_unlink("/qsysdb_scale_bench");
    }
}

BENCHMARK_MAIN()
