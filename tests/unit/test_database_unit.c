/*
 * QSysDB - Comprehensive Database Unit Tests
 *
 * Tests all database operations including:
 *   - Initialization and shutdown
 *   - CRUD operations (set, get, delete, exists)
 *   - List operations
 *   - Tree deletion
 *   - Transactions
 *   - Error handling
 *   - Edge cases and stress tests
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <qsysdb/types.h>
#include "common/shm.h"
#include "common/radix_tree.h"
#include "daemon/database.h"
#include "daemon/subscription.h"
#include "framework/test_framework.h"

static const char *_current_suite_name = "database";

/* Test fixture data */
#define TEST_SHM_NAME "/qsysdb_db_unit_test"
#define TEST_SHM_SIZE (64 * 1024 * 1024)  /* 64MB */

static struct qsysdb_db g_db;
static bool g_db_inited = false;

/* Setup/teardown */
static void db_setup(void) {
    qsysdb_shm_unlink(TEST_SHM_NAME);
    int ret = db_init(&g_db, TEST_SHM_NAME, TEST_SHM_SIZE);
    TEST_ASSERT_OK(ret);
    g_db_inited = true;
}

static void db_teardown(void) {
    if (g_db_inited) {
        db_shutdown(&g_db);
        g_db_inited = false;
    }
    qsysdb_shm_unlink(TEST_SHM_NAME);
}

/* ============================================
 * Initialization Tests
 * ============================================ */

TEST(init_success)
{
    db_setup();

    TEST_ASSERT_TRUE(g_db.initialized);
    TEST_ASSERT_NOT_NULL(g_db.shm.header);
    TEST_ASSERT_EQ(QSYSDB_MAGIC, g_db.shm.header->magic);

    db_teardown();
}

TEST(init_sets_version)
{
    db_setup();

    TEST_ASSERT_EQ(QSYSDB_VERSION, g_db.shm.header->version);

    db_teardown();
}

TEST(init_entry_count_zero)
{
    db_setup();

    TEST_ASSERT_EQ(0, g_db.shm.header->entry_count);

    db_teardown();
}

/* ============================================
 * Set/Get Basic Tests
 * ============================================ */

TEST(set_get_simple)
{
    db_setup();

    const char *path = "/test/key";
    const char *value = "{\"value\":42}";

    TEST_ASSERT_OK(db_set(&g_db, path, strlen(path), value, strlen(value), 0, NULL));

    char buf[1024];
    size_t out_len = 0;
    TEST_ASSERT_OK(db_get(&g_db, path, strlen(path), buf, sizeof(buf), &out_len, NULL, NULL));

    buf[out_len] = '\0';
    TEST_ASSERT_STR_EQ(value, buf);

    db_teardown();
}

TEST(set_get_with_version)
{
    db_setup();

    uint64_t version = 0;
    TEST_ASSERT_OK(db_set(&g_db, "/key", 4, "\"val\"", 5, 0, &version));
    TEST_ASSERT_GT(version, 0);

    uint64_t out_version = 0;
    char buf[64];
    size_t out_len;
    TEST_ASSERT_OK(db_get(&g_db, "/key", 4, buf, sizeof(buf), &out_len, &out_version, NULL));
    TEST_ASSERT_EQ(version, out_version);

    db_teardown();
}

TEST(set_get_with_timestamp)
{
    db_setup();

    TEST_ASSERT_OK(db_set(&g_db, "/key", 4, "1", 1, 0, NULL));

    uint64_t timestamp = 0;
    char buf[64];
    size_t out_len;
    TEST_ASSERT_OK(db_get(&g_db, "/key", 4, buf, sizeof(buf), &out_len, NULL, &timestamp));
    TEST_ASSERT_GT(timestamp, 0);

    db_teardown();
}

TEST(set_multiple_keys)
{
    db_setup();

    TEST_ASSERT_OK(db_set(&g_db, "/a/b/c", 6, "{\"level\":3}", 11, 0, NULL));
    TEST_ASSERT_OK(db_set(&g_db, "/a/b", 4, "{\"level\":2}", 11, 0, NULL));
    TEST_ASSERT_OK(db_set(&g_db, "/a", 2, "{\"level\":1}", 11, 0, NULL));
    TEST_ASSERT_OK(db_set(&g_db, "/x/y", 4, "{\"other\":true}", 14, 0, NULL));

    char buf[1024];
    size_t out_len;

    TEST_ASSERT_OK(db_get(&g_db, "/a", 2, buf, sizeof(buf), &out_len, NULL, NULL));
    buf[out_len] = '\0';
    TEST_ASSERT_STR_EQ("{\"level\":1}", buf);

    TEST_ASSERT_OK(db_get(&g_db, "/a/b", 4, buf, sizeof(buf), &out_len, NULL, NULL));
    buf[out_len] = '\0';
    TEST_ASSERT_STR_EQ("{\"level\":2}", buf);

    TEST_ASSERT_OK(db_get(&g_db, "/a/b/c", 6, buf, sizeof(buf), &out_len, NULL, NULL));
    buf[out_len] = '\0';
    TEST_ASSERT_STR_EQ("{\"level\":3}", buf);

    db_teardown();
}

TEST(set_update_existing)
{
    db_setup();

    TEST_ASSERT_OK(db_set(&g_db, "/key", 4, "{\"v\":1}", 7, 0, NULL));

    char buf[1024];
    size_t out_len;
    TEST_ASSERT_OK(db_get(&g_db, "/key", 4, buf, sizeof(buf), &out_len, NULL, NULL));
    buf[out_len] = '\0';
    TEST_ASSERT_STR_EQ("{\"v\":1}", buf);

    /* Update */
    TEST_ASSERT_OK(db_set(&g_db, "/key", 4, "{\"v\":2}", 7, 0, NULL));
    TEST_ASSERT_OK(db_get(&g_db, "/key", 4, buf, sizeof(buf), &out_len, NULL, NULL));
    buf[out_len] = '\0';
    TEST_ASSERT_STR_EQ("{\"v\":2}", buf);

    /* Another update with longer value */
    const char *v3 = "{\"v\":999,\"updated\":true}";
    TEST_ASSERT_OK(db_set(&g_db, "/key", 4, v3, strlen(v3), 0, NULL));
    TEST_ASSERT_OK(db_get(&g_db, "/key", 4, buf, sizeof(buf), &out_len, NULL, NULL));
    buf[out_len] = '\0';
    TEST_ASSERT_STR_EQ(v3, buf);

    db_teardown();
}

TEST(get_nonexistent)
{
    db_setup();

    char buf[64];
    size_t out_len;
    TEST_ASSERT_ERR(db_get(&g_db, "/missing", 8, buf, sizeof(buf), &out_len, NULL, NULL),
                    QSYSDB_ERR_NOTFOUND);

    db_teardown();
}

/* ============================================
 * Delete Tests
 * ============================================ */

TEST(delete_existing)
{
    db_setup();

    TEST_ASSERT_OK(db_set(&g_db, "/delete/me", 10, "\"test\"", 6, 0, NULL));

    bool exists = false;
    TEST_ASSERT_OK(db_exists(&g_db, "/delete/me", 10, &exists));
    TEST_ASSERT_TRUE(exists);

    TEST_ASSERT_OK(db_delete(&g_db, "/delete/me", 10));

    TEST_ASSERT_OK(db_exists(&g_db, "/delete/me", 10, &exists));
    TEST_ASSERT_FALSE(exists);

    db_teardown();
}

TEST(delete_nonexistent)
{
    db_setup();

    /* Deleting non-existent should return NOTFOUND */
    TEST_ASSERT_ERR(db_delete(&g_db, "/missing", 8), QSYSDB_ERR_NOTFOUND);

    db_teardown();
}

TEST(delete_and_reinsert)
{
    db_setup();

    TEST_ASSERT_OK(db_set(&g_db, "/key", 4, "\"v1\"", 4, 0, NULL));
    TEST_ASSERT_OK(db_delete(&g_db, "/key", 4));

    bool exists;
    TEST_ASSERT_OK(db_exists(&g_db, "/key", 4, &exists));
    TEST_ASSERT_FALSE(exists);

    TEST_ASSERT_OK(db_set(&g_db, "/key", 4, "\"v2\"", 4, 0, NULL));
    TEST_ASSERT_OK(db_exists(&g_db, "/key", 4, &exists));
    TEST_ASSERT_TRUE(exists);

    char buf[64];
    size_t out_len;
    TEST_ASSERT_OK(db_get(&g_db, "/key", 4, buf, sizeof(buf), &out_len, NULL, NULL));
    buf[out_len] = '\0';
    TEST_ASSERT_STR_EQ("\"v2\"", buf);

    db_teardown();
}

/* ============================================
 * Exists Tests
 * ============================================ */

TEST(exists_true)
{
    db_setup();

    TEST_ASSERT_OK(db_set(&g_db, "/exists", 7, "true", 4, 0, NULL));

    bool exists = false;
    TEST_ASSERT_OK(db_exists(&g_db, "/exists", 7, &exists));
    TEST_ASSERT_TRUE(exists);

    db_teardown();
}

TEST(exists_false)
{
    db_setup();

    bool exists = true;
    TEST_ASSERT_OK(db_exists(&g_db, "/nonexistent", 12, &exists));
    TEST_ASSERT_FALSE(exists);

    db_teardown();
}

TEST(exists_after_delete)
{
    db_setup();

    TEST_ASSERT_OK(db_set(&g_db, "/test", 5, "1", 1, 0, NULL));

    bool exists;
    TEST_ASSERT_OK(db_exists(&g_db, "/test", 5, &exists));
    TEST_ASSERT_TRUE(exists);

    TEST_ASSERT_OK(db_delete(&g_db, "/test", 5));

    TEST_ASSERT_OK(db_exists(&g_db, "/test", 5, &exists));
    TEST_ASSERT_FALSE(exists);

    db_teardown();
}

/* ============================================
 * List Tests
 * ============================================ */

TEST(list_paths)
{
    db_setup();

    TEST_ASSERT_OK(db_set(&g_db, "/config/a", 9, "1", 1, 0, NULL));
    TEST_ASSERT_OK(db_set(&g_db, "/config/b", 9, "2", 1, 0, NULL));
    TEST_ASSERT_OK(db_set(&g_db, "/config/c", 9, "3", 1, 0, NULL));
    TEST_ASSERT_OK(db_set(&g_db, "/data/x", 7, "\"x\"", 3, 0, NULL));
    TEST_ASSERT_OK(db_set(&g_db, "/data/y", 7, "\"y\"", 3, 0, NULL));

    char **paths = NULL;
    size_t count = 0;

    TEST_ASSERT_OK(db_list(&g_db, "/config", 7, &paths, &count, 100));
    TEST_ASSERT_EQ(3, count);
    db_list_free(paths, count);

    TEST_ASSERT_OK(db_list(&g_db, "/data", 5, &paths, &count, 100));
    TEST_ASSERT_EQ(2, count);
    db_list_free(paths, count);

    TEST_ASSERT_OK(db_list(&g_db, "/", 1, &paths, &count, 100));
    TEST_ASSERT_EQ(5, count);
    db_list_free(paths, count);

    db_teardown();
}

TEST(list_empty_prefix)
{
    db_setup();

    char **paths = NULL;
    size_t count = 0;

    TEST_ASSERT_OK(db_list(&g_db, "/nothing", 8, &paths, &count, 100));
    TEST_ASSERT_EQ(0, count);

    db_teardown();
}

TEST(list_with_limit)
{
    db_setup();

    for (int i = 0; i < 10; i++) {
        char path[64], value[16];
        snprintf(path, sizeof(path), "/items/%d", i);
        snprintf(value, sizeof(value), "%d", i);
        TEST_ASSERT_OK(db_set(&g_db, path, strlen(path), value, strlen(value), 0, NULL));
    }

    char **paths = NULL;
    size_t count = 0;

    /* Limit to 5 */
    TEST_ASSERT_OK(db_list(&g_db, "/items", 6, &paths, &count, 5));
    TEST_ASSERT_EQ(5, count);
    db_list_free(paths, count);

    db_teardown();
}

/* ============================================
 * Delete Tree Tests
 * ============================================ */

TEST(delete_tree_basic)
{
    db_setup();

    TEST_ASSERT_OK(db_set(&g_db, "/tree/a", 7, "1", 1, 0, NULL));
    TEST_ASSERT_OK(db_set(&g_db, "/tree/b", 7, "2", 1, 0, NULL));
    TEST_ASSERT_OK(db_set(&g_db, "/tree/sub/x", 11, "3", 1, 0, NULL));
    TEST_ASSERT_OK(db_set(&g_db, "/other", 6, "\"keep\"", 6, 0, NULL));

    size_t deleted = 0;
    TEST_ASSERT_OK(db_delete_tree(&g_db, "/tree", 5, &deleted));
    TEST_ASSERT_EQ(3, deleted);

    bool exists;
    TEST_ASSERT_OK(db_exists(&g_db, "/tree/a", 7, &exists));
    TEST_ASSERT_FALSE(exists);
    TEST_ASSERT_OK(db_exists(&g_db, "/tree/b", 7, &exists));
    TEST_ASSERT_FALSE(exists);
    TEST_ASSERT_OK(db_exists(&g_db, "/tree/sub/x", 11, &exists));
    TEST_ASSERT_FALSE(exists);

    /* /other should still exist */
    TEST_ASSERT_OK(db_exists(&g_db, "/other", 6, &exists));
    TEST_ASSERT_TRUE(exists);

    db_teardown();
}

TEST(delete_tree_nonexistent)
{
    db_setup();

    size_t deleted = 0;
    TEST_ASSERT_OK(db_delete_tree(&g_db, "/missing", 8, &deleted));
    TEST_ASSERT_EQ(0, deleted);

    db_teardown();
}

/* ============================================
 * JSON Validation Tests
 * ============================================ */

TEST(reject_invalid_json)
{
    db_setup();

    TEST_ASSERT_ERR(db_set(&g_db, "/bad", 4, "not json", 8, 0, NULL), QSYSDB_ERR_BADJSON);
    TEST_ASSERT_ERR(db_set(&g_db, "/bad", 4, "{broken", 7, 0, NULL), QSYSDB_ERR_BADJSON);
    TEST_ASSERT_ERR(db_set(&g_db, "/bad", 4, "[1,2,", 5, 0, NULL), QSYSDB_ERR_BADJSON);

    db_teardown();
}

TEST(accept_valid_json_types)
{
    db_setup();

    TEST_ASSERT_OK(db_set(&g_db, "/obj", 4, "{}", 2, 0, NULL));
    TEST_ASSERT_OK(db_set(&g_db, "/arr", 4, "[]", 2, 0, NULL));
    TEST_ASSERT_OK(db_set(&g_db, "/str", 4, "\"hello\"", 7, 0, NULL));
    TEST_ASSERT_OK(db_set(&g_db, "/num", 4, "42", 2, 0, NULL));
    TEST_ASSERT_OK(db_set(&g_db, "/bool", 5, "true", 4, 0, NULL));
    TEST_ASSERT_OK(db_set(&g_db, "/null", 5, "null", 4, 0, NULL));

    db_teardown();
}

/* ============================================
 * Path Validation Tests
 * ============================================ */

TEST(reject_invalid_path)
{
    db_setup();

    /* Paths must start with / */
    TEST_ASSERT_ERR(db_set(&g_db, "no/leading/slash", 16, "1", 1, 0, NULL), QSYSDB_ERR_BADPATH);

    db_teardown();
}

TEST(reject_empty_path)
{
    db_setup();

    TEST_ASSERT_ERR(db_set(&g_db, "", 0, "1", 1, 0, NULL), QSYSDB_ERR_INVALID);

    db_teardown();
}

TEST(accept_root_path)
{
    db_setup();

    TEST_ASSERT_OK(db_set(&g_db, "/", 1, "{\"root\":true}", 13, 0, NULL));

    char buf[64];
    size_t out_len;
    TEST_ASSERT_OK(db_get(&g_db, "/", 1, buf, sizeof(buf), &out_len, NULL, NULL));

    db_teardown();
}

/* ============================================
 * Large Value Tests
 * ============================================ */

TEST(large_value)
{
    db_setup();

    /* Create a large JSON value (~32KB) */
    char *large = malloc(32 * 1024);
    TEST_ASSERT_NOT_NULL(large);

    strcpy(large, "{\"data\":\"");
    size_t pos = strlen(large);
    for (int i = 0; i < 30000; i++) {
        large[pos++] = 'a' + (i % 26);
    }
    strcpy(large + pos, "\"}");
    size_t large_len = strlen(large);

    TEST_ASSERT_OK(db_set(&g_db, "/large", 6, large, large_len, 0, NULL));

    char *buf = malloc(64 * 1024);
    TEST_ASSERT_NOT_NULL(buf);

    size_t out_len;
    TEST_ASSERT_OK(db_get(&g_db, "/large", 6, buf, 64 * 1024, &out_len, NULL, NULL));
    buf[out_len] = '\0';
    TEST_ASSERT_STR_EQ(large, buf);

    free(large);
    free(buf);
    db_teardown();
}

/* ============================================
 * Many Entries Tests
 * ============================================ */

TEST(many_entries)
{
    db_setup();

    /* Insert many entries */
    for (int i = 0; i < 500; i++) {
        char path[64], value[64];
        snprintf(path, sizeof(path), "/entry/%d", i);
        snprintf(value, sizeof(value), "{\"id\":%d}", i);
        TEST_ASSERT_OK(db_set(&g_db, path, strlen(path), value, strlen(value), 0, NULL));
    }

    /* Verify all exist with correct values */
    for (int i = 0; i < 500; i++) {
        char path[64], expected[64], buf[128];
        size_t out_len;

        snprintf(path, sizeof(path), "/entry/%d", i);
        snprintf(expected, sizeof(expected), "{\"id\":%d}", i);

        TEST_ASSERT_OK(db_get(&g_db, path, strlen(path), buf, sizeof(buf), &out_len, NULL, NULL));
        buf[out_len] = '\0';
        TEST_ASSERT_STR_EQ(expected, buf);
    }

    db_teardown();
}

TEST(delete_half_entries)
{
    db_setup();

    for (int i = 0; i < 500; i++) {
        char path[64], value[64];
        snprintf(path, sizeof(path), "/entry/%d", i);
        snprintf(value, sizeof(value), "{\"id\":%d}", i);
        db_set(&g_db, path, strlen(path), value, strlen(value), 0, NULL);
    }

    /* Delete even entries */
    for (int i = 0; i < 500; i += 2) {
        char path[64];
        snprintf(path, sizeof(path), "/entry/%d", i);
        db_delete(&g_db, path, strlen(path));
    }

    /* Verify correct ones remain */
    for (int i = 0; i < 500; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/entry/%d", i);
        bool exists;
        db_exists(&g_db, path, strlen(path), &exists);
        if (i % 2 == 0) {
            TEST_ASSERT_FALSE(exists);
        } else {
            TEST_ASSERT_TRUE(exists);
        }
    }

    db_teardown();
}

/* ============================================
 * Transaction Tests
 * ============================================ */

TEST(transaction_basic)
{
    db_setup();

    int txn_id = 0;
    TEST_ASSERT_OK(db_txn_begin(&g_db, 1, &txn_id));
    TEST_ASSERT_GT(txn_id, 0);

    TEST_ASSERT_OK(db_txn_set(&g_db, txn_id, "/txn/a", 6, "1", 1, 0));
    TEST_ASSERT_OK(db_txn_set(&g_db, txn_id, "/txn/b", 6, "2", 1, 0));
    TEST_ASSERT_OK(db_txn_set(&g_db, txn_id, "/txn/c", 6, "3", 1, 0));

    /* Before commit - should not be visible */
    bool exists;
    TEST_ASSERT_OK(db_exists(&g_db, "/txn/a", 6, &exists));
    TEST_ASSERT_FALSE(exists);

    /* Commit */
    uint64_t sequence = 0;
    int op_count = 0;
    TEST_ASSERT_OK(db_txn_commit(&g_db, txn_id, &sequence, &op_count));
    TEST_ASSERT_EQ(3, op_count);

    /* After commit - all should be visible */
    TEST_ASSERT_OK(db_exists(&g_db, "/txn/a", 6, &exists));
    TEST_ASSERT_TRUE(exists);
    TEST_ASSERT_OK(db_exists(&g_db, "/txn/b", 6, &exists));
    TEST_ASSERT_TRUE(exists);
    TEST_ASSERT_OK(db_exists(&g_db, "/txn/c", 6, &exists));
    TEST_ASSERT_TRUE(exists);

    db_teardown();
}

TEST(transaction_abort)
{
    db_setup();

    TEST_ASSERT_OK(db_set(&g_db, "/abort/key", 10, "\"initial\"", 9, 0, NULL));

    int txn_id = 0;
    TEST_ASSERT_OK(db_txn_begin(&g_db, 1, &txn_id));

    TEST_ASSERT_OK(db_txn_set(&g_db, txn_id, "/abort/key", 10, "\"modified\"", 10, 0));
    TEST_ASSERT_OK(db_txn_set(&g_db, txn_id, "/abort/new", 10, "\"new\"", 5, 0));

    db_txn_abort(&g_db, txn_id);

    /* Original value should remain */
    char buf[64];
    size_t out_len;
    TEST_ASSERT_OK(db_get(&g_db, "/abort/key", 10, buf, sizeof(buf), &out_len, NULL, NULL));
    buf[out_len] = '\0';
    TEST_ASSERT_STR_EQ("\"initial\"", buf);

    /* New key should not exist */
    bool exists;
    TEST_ASSERT_OK(db_exists(&g_db, "/abort/new", 10, &exists));
    TEST_ASSERT_FALSE(exists);

    db_teardown();
}

TEST(transaction_delete)
{
    db_setup();

    TEST_ASSERT_OK(db_set(&g_db, "/del/a", 6, "1", 1, 0, NULL));
    TEST_ASSERT_OK(db_set(&g_db, "/del/b", 6, "2", 1, 0, NULL));

    int txn_id = 0;
    TEST_ASSERT_OK(db_txn_begin(&g_db, 1, &txn_id));

    TEST_ASSERT_OK(db_txn_delete(&g_db, txn_id, "/del/a", 6));
    TEST_ASSERT_OK(db_txn_set(&g_db, txn_id, "/del/c", 6, "3", 1, 0));

    /* Before commit - /del/a still exists */
    bool exists;
    TEST_ASSERT_OK(db_exists(&g_db, "/del/a", 6, &exists));
    TEST_ASSERT_TRUE(exists);

    uint64_t seq;
    int ops;
    TEST_ASSERT_OK(db_txn_commit(&g_db, txn_id, &seq, &ops));

    /* After commit */
    TEST_ASSERT_OK(db_exists(&g_db, "/del/a", 6, &exists));
    TEST_ASSERT_FALSE(exists);
    TEST_ASSERT_OK(db_exists(&g_db, "/del/b", 6, &exists));
    TEST_ASSERT_TRUE(exists);
    TEST_ASSERT_OK(db_exists(&g_db, "/del/c", 6, &exists));
    TEST_ASSERT_TRUE(exists);

    db_teardown();
}

TEST(transaction_mixed_operations)
{
    db_setup();

    /* Setup initial state */
    TEST_ASSERT_OK(db_set(&g_db, "/mix/existing", 13, "\"old\"", 5, 0, NULL));

    int txn_id = 0;
    TEST_ASSERT_OK(db_txn_begin(&g_db, 1, &txn_id));

    /* Mix of operations */
    TEST_ASSERT_OK(db_txn_set(&g_db, txn_id, "/mix/new1", 9, "1", 1, 0));
    TEST_ASSERT_OK(db_txn_set(&g_db, txn_id, "/mix/existing", 13, "\"updated\"", 9, 0));
    TEST_ASSERT_OK(db_txn_set(&g_db, txn_id, "/mix/new2", 9, "2", 1, 0));

    uint64_t seq;
    int ops;
    TEST_ASSERT_OK(db_txn_commit(&g_db, txn_id, &seq, &ops));

    /* Verify */
    char buf[64];
    size_t out_len;
    TEST_ASSERT_OK(db_get(&g_db, "/mix/existing", 13, buf, sizeof(buf), &out_len, NULL, NULL));
    buf[out_len] = '\0';
    TEST_ASSERT_STR_EQ("\"updated\"", buf);

    bool exists;
    TEST_ASSERT_OK(db_exists(&g_db, "/mix/new1", 9, &exists));
    TEST_ASSERT_TRUE(exists);
    TEST_ASSERT_OK(db_exists(&g_db, "/mix/new2", 9, &exists));
    TEST_ASSERT_TRUE(exists);

    db_teardown();
}

/* ============================================
 * Subscription Tests
 * ============================================ */

TEST(subscription_basic)
{
    struct sub_manager mgr;
    TEST_ASSERT_OK(sub_manager_init(&mgr));

    int sub_id = 0;
    TEST_ASSERT_OK(sub_add(&mgr, 1, "/test/*", 7, &sub_id));
    TEST_ASSERT_GT(sub_id, 0);

    int client_ids[10], sub_ids[10];
    int matches = sub_match(&mgr, "/test/foo", 9, client_ids, sub_ids, 10);
    TEST_ASSERT_EQ(1, matches);

    matches = sub_match(&mgr, "/other/path", 11, client_ids, sub_ids, 10);
    TEST_ASSERT_EQ(0, matches);

    sub_remove(&mgr, sub_id);
    sub_manager_shutdown(&mgr);
}

TEST(subscription_exact_match)
{
    struct sub_manager mgr;
    TEST_ASSERT_OK(sub_manager_init(&mgr));

    int sub_id = 0;
    TEST_ASSERT_OK(sub_add(&mgr, 1, "/specific/path", 14, &sub_id));

    int client_ids[10], sub_ids[10];

    int matches = sub_match(&mgr, "/specific/path", 14, client_ids, sub_ids, 10);
    TEST_ASSERT_EQ(1, matches);

    matches = sub_match(&mgr, "/specific/path/child", 20, client_ids, sub_ids, 10);
    TEST_ASSERT_EQ(0, matches);

    matches = sub_match(&mgr, "/specific", 9, client_ids, sub_ids, 10);
    TEST_ASSERT_EQ(0, matches);

    sub_remove(&mgr, sub_id);
    sub_manager_shutdown(&mgr);
}

TEST(subscription_multiple)
{
    struct sub_manager mgr;
    TEST_ASSERT_OK(sub_manager_init(&mgr));

    int sub1 = 0, sub2 = 0;
    TEST_ASSERT_OK(sub_add(&mgr, 1, "/a/*", 4, &sub1));
    TEST_ASSERT_OK(sub_add(&mgr, 2, "/b/*", 4, &sub2));
    TEST_ASSERT_NE(sub1, sub2);

    int client_ids[10], sub_ids[10];

    int matches = sub_match(&mgr, "/a/x", 4, client_ids, sub_ids, 10);
    TEST_ASSERT_EQ(1, matches);
    TEST_ASSERT_EQ(1, client_ids[0]);

    matches = sub_match(&mgr, "/b/y", 4, client_ids, sub_ids, 10);
    TEST_ASSERT_EQ(1, matches);
    TEST_ASSERT_EQ(2, client_ids[0]);

    sub_remove(&mgr, sub1);

    matches = sub_match(&mgr, "/a/z", 4, client_ids, sub_ids, 10);
    TEST_ASSERT_EQ(0, matches);

    sub_remove(&mgr, sub2);
    sub_manager_shutdown(&mgr);
}

TEST(subscription_remove_all_for_client)
{
    struct sub_manager mgr;
    TEST_ASSERT_OK(sub_manager_init(&mgr));

    int sub1, sub2, sub3;
    TEST_ASSERT_OK(sub_add(&mgr, 1, "/a/*", 4, &sub1));
    TEST_ASSERT_OK(sub_add(&mgr, 1, "/b/*", 4, &sub2));
    TEST_ASSERT_OK(sub_add(&mgr, 2, "/c/*", 4, &sub3));

    /* Remove all for client 1 */
    sub_remove_client(&mgr, 1);

    int client_ids[10], sub_ids[10];

    /* Client 1 subscriptions should be gone */
    TEST_ASSERT_EQ(0, sub_match(&mgr, "/a/x", 4, client_ids, sub_ids, 10));
    TEST_ASSERT_EQ(0, sub_match(&mgr, "/b/x", 4, client_ids, sub_ids, 10));

    /* Client 2 subscription should remain */
    TEST_ASSERT_EQ(1, sub_match(&mgr, "/c/x", 4, client_ids, sub_ids, 10));

    sub_manager_shutdown(&mgr);
}

TEST_MAIN()
