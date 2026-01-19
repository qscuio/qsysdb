/*
 * QSysDB - Integration tests
 *
 * Tests the full database operations through the daemon
 * Note: These tests require the daemon to NOT be running,
 * as they create their own in-process database.
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <pthread.h>

#include <qsysdb/types.h>
#include "common/shm.h"
#include "common/radix_tree.h"
#include "daemon/database.h"
#include "daemon/subscription.h"

#define TEST(name) static void test_##name(void)
#define RUN_TEST(name) do { \
    printf("  " #name "... "); \
    fflush(stdout); \
    test_##name(); \
    printf("OK\n"); \
} while(0)

#define TEST_SHM_NAME "/qsysdb_integration_test"
#define TEST_SHM_SIZE (64 * 1024 * 1024)  /* 64MB for integration tests */

static struct qsysdb_db g_db;
static bool g_db_inited = false;

/* Setup and teardown */
static void setup(void)
{
    qsysdb_shm_unlink(TEST_SHM_NAME);
    int ret = db_init(&g_db, TEST_SHM_NAME, TEST_SHM_SIZE);
    if (ret != QSYSDB_OK) {
        fprintf(stderr, "db_init failed with error code: %d\n", ret);
    }
    assert(ret == QSYSDB_OK);
    g_db_inited = true;
}

static void teardown(void)
{
    if (g_db_inited) {
        db_shutdown(&g_db);
        g_db_inited = false;
    }
    qsysdb_shm_unlink(TEST_SHM_NAME);
}

TEST(db_init)
{
    setup();

    assert(g_db.initialized == true);
    assert(g_db.shm.header != NULL);
    assert(g_db.shm.header->magic == QSYSDB_MAGIC);

    teardown();
}

TEST(db_set_get)
{
    setup();

    /* Set a value */
    const char *path = "/test/key";
    const char *value = "{\"value\":42}";
    uint64_t version = 0;
    int ret = db_set(&g_db, path, strlen(path), value, strlen(value), 0, &version);
    if (ret != QSYSDB_OK) {
        fprintf(stderr, "db_set failed with error: %d\n", ret);
    }
    assert(ret == QSYSDB_OK);

    /* Get it back */
    char buf[1024];
    size_t out_len = 0;
    uint64_t out_version = 0, out_timestamp = 0;
    ret = db_get(&g_db, path, strlen(path), buf, sizeof(buf), &out_len,
                 &out_version, &out_timestamp);
    assert(ret == QSYSDB_OK);
    buf[out_len] = '\0';
    assert(strcmp(buf, "{\"value\":42}") == 0);

    teardown();
}

TEST(db_set_get_multiple)
{
    setup();

    /* Set multiple values */
    assert(db_set(&g_db, "/a/b/c", 6, "{\"level\":3}", 11, 0, NULL) == QSYSDB_OK);
    assert(db_set(&g_db, "/a/b", 4, "{\"level\":2}", 11, 0, NULL) == QSYSDB_OK);
    assert(db_set(&g_db, "/a", 2, "{\"level\":1}", 11, 0, NULL) == QSYSDB_OK);
    assert(db_set(&g_db, "/x/y", 4, "{\"other\":true}", 14, 0, NULL) == QSYSDB_OK);

    /* Retrieve each */
    char buf[1024];
    size_t out_len;
    
    assert(db_get(&g_db, "/a", 2, buf, sizeof(buf), &out_len, NULL, NULL) == QSYSDB_OK);
    buf[out_len] = '\0';
    assert(strcmp(buf, "{\"level\":1}") == 0);

    assert(db_get(&g_db, "/a/b", 4, buf, sizeof(buf), &out_len, NULL, NULL) == QSYSDB_OK);
    buf[out_len] = '\0';
    assert(strcmp(buf, "{\"level\":2}") == 0);

    assert(db_get(&g_db, "/a/b/c", 6, buf, sizeof(buf), &out_len, NULL, NULL) == QSYSDB_OK);
    buf[out_len] = '\0';
    assert(strcmp(buf, "{\"level\":3}") == 0);

    assert(db_get(&g_db, "/x/y", 4, buf, sizeof(buf), &out_len, NULL, NULL) == QSYSDB_OK);
    buf[out_len] = '\0';
    assert(strcmp(buf, "{\"other\":true}") == 0);

    teardown();
}

TEST(db_update)
{
    setup();

    /* Initial set */
    assert(db_set(&g_db, "/key", 4, "{\"v\":1}", 7, 0, NULL) == QSYSDB_OK);

    char buf[1024];
    size_t out_len;
    assert(db_get(&g_db, "/key", 4, buf, sizeof(buf), &out_len, NULL, NULL) == QSYSDB_OK);
    buf[out_len] = '\0';
    assert(strcmp(buf, "{\"v\":1}") == 0);

    /* Update */
    assert(db_set(&g_db, "/key", 4, "{\"v\":2}", 7, 0, NULL) == QSYSDB_OK);

    assert(db_get(&g_db, "/key", 4, buf, sizeof(buf), &out_len, NULL, NULL) == QSYSDB_OK);
    buf[out_len] = '\0';
    assert(strcmp(buf, "{\"v\":2}") == 0);

    /* Another update */
    const char *v3 = "{\"v\":999,\"updated\":true}";
    assert(db_set(&g_db, "/key", 4, v3, strlen(v3), 0, NULL) == QSYSDB_OK);

    assert(db_get(&g_db, "/key", 4, buf, sizeof(buf), &out_len, NULL, NULL) == QSYSDB_OK);
    buf[out_len] = '\0';
    assert(strcmp(buf, v3) == 0);

    teardown();
}

TEST(db_delete)
{
    setup();

    /* Set and verify */
    assert(db_set(&g_db, "/delete/me", 10, "\"test\"", 6, 0, NULL) == QSYSDB_OK);
    bool exists = false;
    assert(db_exists(&g_db, "/delete/me", 10, &exists) == QSYSDB_OK);
    assert(exists == true);

    /* Delete */
    int ret = db_delete(&g_db, "/delete/me", 10);
    assert(ret == QSYSDB_OK);

    /* Should not exist anymore */
    assert(db_exists(&g_db, "/delete/me", 10, &exists) == QSYSDB_OK);
    assert(exists == false);

    char buf[64];
    size_t out_len;
    ret = db_get(&g_db, "/delete/me", 10, buf, sizeof(buf), &out_len, NULL, NULL);
    assert(ret == QSYSDB_ERR_NOTFOUND);

    teardown();
}

TEST(db_exists)
{
    setup();

    bool exists = false;
    assert(db_exists(&g_db, "/nonexistent", 12, &exists) == QSYSDB_OK);
    assert(exists == false);

    assert(db_set(&g_db, "/exists", 7, "true", 4, 0, NULL) == QSYSDB_OK);
    assert(db_exists(&g_db, "/exists", 7, &exists) == QSYSDB_OK);
    assert(exists == true);

    assert(db_delete(&g_db, "/exists", 7) == QSYSDB_OK);
    assert(db_exists(&g_db, "/exists", 7, &exists) == QSYSDB_OK);
    assert(exists == false);

    teardown();
}

TEST(db_list)
{
    setup();

    /* Create a hierarchy */
    assert(db_set(&g_db, "/config/a", 9, "1", 1, 0, NULL) == QSYSDB_OK);
    assert(db_set(&g_db, "/config/b", 9, "2", 1, 0, NULL) == QSYSDB_OK);
    assert(db_set(&g_db, "/config/c", 9, "3", 1, 0, NULL) == QSYSDB_OK);
    assert(db_set(&g_db, "/data/x", 7, "\"x\"", 3, 0, NULL) == QSYSDB_OK);
    assert(db_set(&g_db, "/data/y", 7, "\"y\"", 3, 0, NULL) == QSYSDB_OK);

    /* List /config */
    char **paths = NULL;
    size_t count = 0;
    int ret = db_list(&g_db, "/config", 7, &paths, &count, 100);
    assert(ret == QSYSDB_OK);
    if (count != 3) {
        fprintf(stderr, "db_list /config returned count=%zu (expected 3)\n", count);
        for (size_t i = 0; i < count; i++) {
            fprintf(stderr, "  [%zu]: %s\n", i, paths[i]);
        }
    }
    assert(count == 3);
    db_list_free(paths, count);

    /* List /data */
    ret = db_list(&g_db, "/data", 5, &paths, &count, 100);
    assert(ret == QSYSDB_OK);
    assert(count == 2);
    db_list_free(paths, count);

    /* List all */
    ret = db_list(&g_db, "/", 1, &paths, &count, 100);
    assert(ret == QSYSDB_OK);
    assert(count == 5);
    db_list_free(paths, count);

    teardown();
}

TEST(db_delete_tree)
{
    setup();

    /* Create a tree */
    assert(db_set(&g_db, "/tree/a", 7, "1", 1, 0, NULL) == QSYSDB_OK);
    assert(db_set(&g_db, "/tree/b", 7, "2", 1, 0, NULL) == QSYSDB_OK);
    assert(db_set(&g_db, "/tree/sub/x", 11, "3", 1, 0, NULL) == QSYSDB_OK);
    assert(db_set(&g_db, "/other", 6, "\"keep\"", 6, 0, NULL) == QSYSDB_OK);

    /* Delete tree */
    size_t deleted = 0;
    int ret = db_delete_tree(&g_db, "/tree", 5, &deleted);
    assert(ret == QSYSDB_OK);
    assert(deleted == 3);

    /* Tree should be gone */
    bool exists;
    assert(db_exists(&g_db, "/tree/a", 7, &exists) == QSYSDB_OK);
    assert(exists == false);
    assert(db_exists(&g_db, "/tree/b", 7, &exists) == QSYSDB_OK);
    assert(exists == false);
    assert(db_exists(&g_db, "/tree/sub/x", 11, &exists) == QSYSDB_OK);
    assert(exists == false);

    /* Other should still exist */
    assert(db_exists(&g_db, "/other", 6, &exists) == QSYSDB_OK);
    assert(exists == true);

    teardown();
}

TEST(db_invalid_json)
{
    setup();

    /* Invalid JSON should be rejected */
    int ret = db_set(&g_db, "/bad", 4, "not json", 8, 0, NULL);
    assert(ret == QSYSDB_ERR_BADJSON);

    ret = db_set(&g_db, "/bad", 4, "{broken", 7, 0, NULL);
    assert(ret == QSYSDB_ERR_BADJSON);

    ret = db_set(&g_db, "/bad", 4, "[1,2,", 5, 0, NULL);
    assert(ret == QSYSDB_ERR_BADJSON);

    /* Valid JSON should work */
    ret = db_set(&g_db, "/good", 5, "\"valid string\"", 14, 0, NULL);
    assert(ret == QSYSDB_OK);

    teardown();
}

TEST(db_invalid_path)
{
    setup();

    /* Paths must start with / */
    int ret = db_set(&g_db, "no/leading/slash", 16, "1", 1, 0, NULL);
    assert(ret == QSYSDB_ERR_BADPATH);

    /* Empty path is invalid */
    ret = db_set(&g_db, "", 0, "1", 1, 0, NULL);
    assert(ret == QSYSDB_ERR_INVALID);

    /* Just / is valid */
    ret = db_set(&g_db, "/", 1, "{\"root\":true}", 13, 0, NULL);
    assert(ret == QSYSDB_OK);

    teardown();
}

TEST(db_large_value)
{
    setup();

    /* Create a large JSON value */
    char *large = malloc(32 * 1024);
    assert(large != NULL);

    strcpy(large, "{\"data\":\"");
    size_t pos = strlen(large);
    for (int i = 0; i < 30000; i++) {
        large[pos++] = 'a' + (i % 26);
    }
    strcpy(large + pos, "\"}");
    size_t large_len = strlen(large);

    /* Should be able to store it */
    int ret = db_set(&g_db, "/large", 6, large, large_len, 0, NULL);
    assert(ret == QSYSDB_OK);

    /* And retrieve it */
    char *buf = malloc(64 * 1024);
    assert(buf != NULL);
    size_t out_len;
    ret = db_get(&g_db, "/large", 6, buf, 64 * 1024, &out_len, NULL, NULL);
    assert(ret == QSYSDB_OK);
    buf[out_len] = '\0';
    assert(strcmp(buf, large) == 0);

    free(large);
    free(buf);
    teardown();
}

TEST(db_many_entries)
{
    setup();

    /* Insert many entries */
    for (int i = 0; i < 500; i++) {
        char path[64];
        char value[64];
        snprintf(path, sizeof(path), "/entry/%d", i);
        snprintf(value, sizeof(value), "{\"id\":%d}", i);

        int ret = db_set(&g_db, path, strlen(path), value, strlen(value), 0, NULL);
        assert(ret == QSYSDB_OK);
    }

    /* Verify all exist and have correct values */
    for (int i = 0; i < 500; i++) {
        char path[64];
        char expected[64];
        char buf[128];
        size_t out_len;

        snprintf(path, sizeof(path), "/entry/%d", i);
        snprintf(expected, sizeof(expected), "{\"id\":%d}", i);

        int ret = db_get(&g_db, path, strlen(path), buf, sizeof(buf), &out_len, NULL, NULL);
        assert(ret == QSYSDB_OK);
        buf[out_len] = '\0';
        assert(strcmp(buf, expected) == 0);
    }

    /* Delete half */
    for (int i = 0; i < 500; i += 2) {
        char path[64];
        snprintf(path, sizeof(path), "/entry/%d", i);
        assert(db_delete(&g_db, path, strlen(path)) == QSYSDB_OK);
    }

    /* Verify correct ones remain */
    for (int i = 0; i < 500; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/entry/%d", i);
        bool exists;
        db_exists(&g_db, path, strlen(path), &exists);
        if (i % 2 == 0) {
            assert(exists == false);
        } else {
            assert(exists == true);
        }
    }

    teardown();
}

TEST(subscription_basic)
{
    struct sub_manager mgr;
    assert(sub_manager_init(&mgr) == QSYSDB_OK);

    /* Subscribe to a path */
    int sub_id = 0;
    int ret = sub_add(&mgr, 1, "/test/*", 7, &sub_id);
    assert(ret == QSYSDB_OK);
    assert(sub_id > 0);

    /* Check if path matches */
    int client_ids[10], sub_ids[10];
    int matches = sub_match(&mgr, "/test/foo", 9, client_ids, sub_ids, 10);
    assert(matches == 1);

    /* Should NOT match */
    matches = sub_match(&mgr, "/other/path", 11, client_ids, sub_ids, 10);
    assert(matches == 0);

    sub_remove(&mgr, sub_id);
    sub_manager_shutdown(&mgr);
}

TEST(subscription_exact_match)
{
    struct sub_manager mgr;
    assert(sub_manager_init(&mgr) == QSYSDB_OK);

    /* Exact path subscription */
    int sub_id = 0;
    int ret = sub_add(&mgr, 1, "/specific/path", 14, &sub_id);
    assert(ret == QSYSDB_OK);
    assert(sub_id > 0);

    int client_ids[10], sub_ids[10];
    
    /* Exact match */
    int matches = sub_match(&mgr, "/specific/path", 14, client_ids, sub_ids, 10);
    assert(matches == 1);

    /* Should NOT match */
    matches = sub_match(&mgr, "/specific/path/child", 20, client_ids, sub_ids, 10);
    assert(matches == 0);

    matches = sub_match(&mgr, "/specific", 9, client_ids, sub_ids, 10);
    assert(matches == 0);

    sub_remove(&mgr, sub_id);
    sub_manager_shutdown(&mgr);
}

TEST(subscription_multiple)
{
    struct sub_manager mgr;
    assert(sub_manager_init(&mgr) == QSYSDB_OK);

    /* Two subscriptions */
    int sub1 = 0, sub2 = 0;
    assert(sub_add(&mgr, 1, "/a/*", 4, &sub1) == QSYSDB_OK);
    assert(sub_add(&mgr, 2, "/b/*", 4, &sub2) == QSYSDB_OK);
    assert(sub1 != sub2);

    int client_ids[10], sub_ids[10];

    /* Match /a - only first should fire */
    int matches = sub_match(&mgr, "/a/x", 4, client_ids, sub_ids, 10);
    assert(matches == 1);
    assert(client_ids[0] == 1);

    /* Match /b - only second should fire */
    matches = sub_match(&mgr, "/b/y", 4, client_ids, sub_ids, 10);
    assert(matches == 1);
    assert(client_ids[0] == 2);

    /* Unsubscribe first */
    sub_remove(&mgr, sub1);

    /* Match /a - should not fire anymore */
    matches = sub_match(&mgr, "/a/z", 4, client_ids, sub_ids, 10);
    assert(matches == 0);

    sub_remove(&mgr, sub2);
    sub_manager_shutdown(&mgr);
}

TEST(transaction_basic)
{
    setup();

    /* Begin transaction */
    int txn_id = 0;
    int ret = db_txn_begin(&g_db, 1, &txn_id);
    assert(ret == QSYSDB_OK);
    assert(txn_id > 0);

    /* Add operations */
    assert(db_txn_set(&g_db, txn_id, "/txn/a", 6, "1", 1, 0) == QSYSDB_OK);
    assert(db_txn_set(&g_db, txn_id, "/txn/b", 6, "2", 1, 0) == QSYSDB_OK);
    assert(db_txn_set(&g_db, txn_id, "/txn/c", 6, "3", 1, 0) == QSYSDB_OK);

    /* Before commit - should not be visible */
    bool exists;
    assert(db_exists(&g_db, "/txn/a", 6, &exists) == QSYSDB_OK);
    assert(exists == false);
    assert(db_exists(&g_db, "/txn/b", 6, &exists) == QSYSDB_OK);
    assert(exists == false);
    assert(db_exists(&g_db, "/txn/c", 6, &exists) == QSYSDB_OK);
    assert(exists == false);

    /* Commit */
    uint64_t sequence = 0;
    int op_count = 0;
    ret = db_txn_commit(&g_db, txn_id, &sequence, &op_count);
    assert(ret == QSYSDB_OK);
    assert(op_count == 3);

    /* After commit - all should be visible */
    assert(db_exists(&g_db, "/txn/a", 6, &exists) == QSYSDB_OK);
    assert(exists == true);
    assert(db_exists(&g_db, "/txn/b", 6, &exists) == QSYSDB_OK);
    assert(exists == true);
    assert(db_exists(&g_db, "/txn/c", 6, &exists) == QSYSDB_OK);
    assert(exists == true);

    char buf[64];
    size_t out_len;
    assert(db_get(&g_db, "/txn/a", 6, buf, sizeof(buf), &out_len, NULL, NULL) == QSYSDB_OK);
    buf[out_len] = '\0';
    assert(strcmp(buf, "1") == 0);

    teardown();
}

TEST(transaction_abort)
{
    setup();

    /* Set initial value */
    assert(db_set(&g_db, "/abort/key", 10, "\"initial\"", 9, 0, NULL) == QSYSDB_OK);

    /* Begin transaction */
    int txn_id = 0;
    assert(db_txn_begin(&g_db, 1, &txn_id) == QSYSDB_OK);

    /* Modify in transaction */
    assert(db_txn_set(&g_db, txn_id, "/abort/key", 10, "\"modified\"", 10, 0) == QSYSDB_OK);
    assert(db_txn_set(&g_db, txn_id, "/abort/new", 10, "\"new\"", 5, 0) == QSYSDB_OK);

    /* Abort */
    db_txn_abort(&g_db, txn_id);

    /* Original value should remain */
    char buf[64];
    size_t out_len;
    assert(db_get(&g_db, "/abort/key", 10, buf, sizeof(buf), &out_len, NULL, NULL) == QSYSDB_OK);
    buf[out_len] = '\0';
    assert(strcmp(buf, "\"initial\"") == 0);

    /* New key should not exist */
    bool exists;
    assert(db_exists(&g_db, "/abort/new", 10, &exists) == QSYSDB_OK);
    assert(exists == false);

    teardown();
}

TEST(transaction_delete)
{
    setup();

    /* Set initial values */
    assert(db_set(&g_db, "/del/a", 6, "1", 1, 0, NULL) == QSYSDB_OK);
    assert(db_set(&g_db, "/del/b", 6, "2", 1, 0, NULL) == QSYSDB_OK);

    /* Transaction with delete */
    int txn_id = 0;
    assert(db_txn_begin(&g_db, 1, &txn_id) == QSYSDB_OK);

    assert(db_txn_delete(&g_db, txn_id, "/del/a", 6) == QSYSDB_OK);
    assert(db_txn_set(&g_db, txn_id, "/del/c", 6, "3", 1, 0) == QSYSDB_OK);

    /* Before commit */
    bool exists;
    assert(db_exists(&g_db, "/del/a", 6, &exists) == QSYSDB_OK);
    assert(exists == true);
    assert(db_exists(&g_db, "/del/c", 6, &exists) == QSYSDB_OK);
    assert(exists == false);

    /* Commit */
    uint64_t seq;
    int ops;
    assert(db_txn_commit(&g_db, txn_id, &seq, &ops) == QSYSDB_OK);

    /* After commit */
    assert(db_exists(&g_db, "/del/a", 6, &exists) == QSYSDB_OK);
    assert(exists == false);
    assert(db_exists(&g_db, "/del/b", 6, &exists) == QSYSDB_OK);
    assert(exists == true);
    assert(db_exists(&g_db, "/del/c", 6, &exists) == QSYSDB_OK);
    assert(exists == true);

    teardown();
}

int main(void)
{
    printf("Running integration tests...\n");

    RUN_TEST(db_init);
    RUN_TEST(db_set_get);
    RUN_TEST(db_set_get_multiple);
    RUN_TEST(db_update);
    RUN_TEST(db_delete);
    RUN_TEST(db_exists);
    RUN_TEST(db_list);
    RUN_TEST(db_delete_tree);
    RUN_TEST(db_invalid_json);
    RUN_TEST(db_invalid_path);
    RUN_TEST(db_large_value);
    RUN_TEST(db_many_entries);
    RUN_TEST(subscription_basic);
    RUN_TEST(subscription_exact_match);
    RUN_TEST(subscription_multiple);
    RUN_TEST(transaction_basic);
    RUN_TEST(transaction_abort);
    RUN_TEST(transaction_delete);

    printf("\nAll integration tests passed!\n");
    return 0;
}
