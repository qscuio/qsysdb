/*
 * QSysDB - Comprehensive Radix Tree Unit Tests
 *
 * Tests all aspects of the radix tree implementation including:
 *   - Initialization
 *   - Insert, lookup, delete operations
 *   - Iteration and prefix matching
 *   - Edge cases (deep paths, many entries)
 *   - Memory management
 *   - Statistics tracking
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <qsysdb/types.h>
#include "common/radix_tree.h"
#include "framework/test_framework.h"

static const char *_current_suite_name = "radix_tree";

/* Test fixture data */
static void *g_mem = NULL;
static size_t g_mem_size = 0;
static struct radix_tree *g_tree = NULL;

/* Setup: allocate memory and initialize tree
 * Note: Each radix_node is ~1KB due to children[256] array,
 * so we need about 1MB per 1000 nodes
 */
static void radix_setup(void) {
    g_mem_size = 16 * 1024 * 1024;  /* 16MB for tests */
    g_mem = malloc(g_mem_size);
    TEST_ASSERT_NOT_NULL(g_mem);
    memset(g_mem, 0, g_mem_size);

    int ret = radix_tree_init(g_mem, g_mem_size, 10000);
    TEST_ASSERT_OK(ret);

    g_tree = radix_tree_get(g_mem);
    TEST_ASSERT_NOT_NULL(g_tree);
}

/* Teardown: free memory */
static void radix_teardown(void) {
    if (g_mem) {
        free(g_mem);
        g_mem = NULL;
    }
    g_tree = NULL;
}

/* ============================================
 * Initialization Tests
 * ============================================ */

TEST(init_success)
{
    radix_setup();

    TEST_ASSERT_EQ(RADIX_TREE_MAGIC, g_tree->magic);
    TEST_ASSERT_EQ(0, g_tree->entry_count);

    radix_teardown();
}

TEST(init_with_various_sizes)
{
    /* Test with different memory sizes
     * Each node is ~1KB, so we need ~2MB for 1000 nodes */
    size_t sizes[] = {2 * 1024 * 1024, 4 * 1024 * 1024, 8 * 1024 * 1024};
    uint32_t max_nodes[] = {1000, 2000, 4000};

    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        void *mem = malloc(sizes[i]);
        TEST_ASSERT_NOT_NULL(mem);
        memset(mem, 0, sizes[i]);

        int ret = radix_tree_init(mem, sizes[i], max_nodes[i]);
        TEST_ASSERT_OK(ret);

        struct radix_tree *tree = radix_tree_get(mem);
        TEST_ASSERT_NOT_NULL(tree);
        TEST_ASSERT_EQ(RADIX_TREE_MAGIC, tree->magic);

        free(mem);
    }
}

TEST(init_get_returns_valid_tree)
{
    radix_setup();

    struct radix_tree *tree = radix_tree_get(g_mem);
    TEST_ASSERT_NOT_NULL(tree);
    TEST_ASSERT_EQ(g_tree, tree);

    radix_teardown();
}

/* ============================================
 * Basic Insert/Lookup Tests
 * ============================================ */

TEST(insert_single)
{
    radix_setup();

    uint32_t off = radix_tree_insert(g_tree, g_mem, "/test", 5, 100);
    TEST_ASSERT_NE(0, off);
    TEST_ASSERT_EQ(1, g_tree->entry_count);

    radix_teardown();
}

TEST(lookup_single)
{
    radix_setup();

    radix_tree_insert(g_tree, g_mem, "/test", 5, 100);

    uint32_t val = radix_tree_lookup(g_tree, g_mem, "/test", 5);
    TEST_ASSERT_EQ(100, val);

    radix_teardown();
}

TEST(insert_multiple_distinct)
{
    radix_setup();

    TEST_ASSERT_NE(0, radix_tree_insert(g_tree, g_mem, "/a", 2, 1));
    TEST_ASSERT_NE(0, radix_tree_insert(g_tree, g_mem, "/b", 2, 2));
    TEST_ASSERT_NE(0, radix_tree_insert(g_tree, g_mem, "/c", 2, 3));

    TEST_ASSERT_EQ(3, g_tree->entry_count);

    TEST_ASSERT_EQ(1, radix_tree_lookup(g_tree, g_mem, "/a", 2));
    TEST_ASSERT_EQ(2, radix_tree_lookup(g_tree, g_mem, "/b", 2));
    TEST_ASSERT_EQ(3, radix_tree_lookup(g_tree, g_mem, "/c", 2));

    radix_teardown();
}

TEST(insert_hierarchical_paths)
{
    radix_setup();

    TEST_ASSERT_NE(0, radix_tree_insert(g_tree, g_mem, "/a", 2, 1));
    TEST_ASSERT_NE(0, radix_tree_insert(g_tree, g_mem, "/a/b", 4, 2));
    TEST_ASSERT_NE(0, radix_tree_insert(g_tree, g_mem, "/a/b/c", 6, 3));

    TEST_ASSERT_EQ(1, radix_tree_lookup(g_tree, g_mem, "/a", 2));
    TEST_ASSERT_EQ(2, radix_tree_lookup(g_tree, g_mem, "/a/b", 4));
    TEST_ASSERT_EQ(3, radix_tree_lookup(g_tree, g_mem, "/a/b/c", 6));

    radix_teardown();
}

TEST(lookup_nonexistent)
{
    radix_setup();

    radix_tree_insert(g_tree, g_mem, "/exists", 7, 100);

    TEST_ASSERT_EQ(0, radix_tree_lookup(g_tree, g_mem, "/missing", 8));
    TEST_ASSERT_EQ(0, radix_tree_lookup(g_tree, g_mem, "/exist", 6));  /* Prefix */
    TEST_ASSERT_EQ(0, radix_tree_lookup(g_tree, g_mem, "/existss", 8));  /* Suffix */

    radix_teardown();
}

TEST(lookup_empty_tree)
{
    radix_setup();

    TEST_ASSERT_EQ(0, radix_tree_lookup(g_tree, g_mem, "/anything", 9));

    radix_teardown();
}

/* ============================================
 * Exists Tests
 * ============================================ */

TEST(exists_true)
{
    radix_setup();

    radix_tree_insert(g_tree, g_mem, "/test", 5, 100);

    TEST_ASSERT_TRUE(radix_tree_exists(g_tree, g_mem, "/test", 5));

    radix_teardown();
}

TEST(exists_false)
{
    radix_setup();

    radix_tree_insert(g_tree, g_mem, "/test", 5, 100);

    TEST_ASSERT_FALSE(radix_tree_exists(g_tree, g_mem, "/other", 6));

    radix_teardown();
}

TEST(exists_empty_tree)
{
    radix_setup();

    TEST_ASSERT_FALSE(radix_tree_exists(g_tree, g_mem, "/anything", 9));

    radix_teardown();
}

/* ============================================
 * Delete Tests
 * ============================================ */

TEST(delete_single)
{
    radix_setup();

    radix_tree_insert(g_tree, g_mem, "/test", 5, 100);
    TEST_ASSERT_EQ(1, g_tree->entry_count);

    uint32_t deleted = radix_tree_delete(g_tree, g_mem, "/test", 5);
    TEST_ASSERT_EQ(100, deleted);
    TEST_ASSERT_EQ(0, g_tree->entry_count);

    TEST_ASSERT_FALSE(radix_tree_exists(g_tree, g_mem, "/test", 5));

    radix_teardown();
}

TEST(delete_nonexistent)
{
    radix_setup();

    radix_tree_insert(g_tree, g_mem, "/exists", 7, 100);

    uint32_t deleted = radix_tree_delete(g_tree, g_mem, "/missing", 8);
    TEST_ASSERT_EQ(0, deleted);
    TEST_ASSERT_EQ(1, g_tree->entry_count);

    radix_teardown();
}

TEST(delete_one_of_many)
{
    radix_setup();

    radix_tree_insert(g_tree, g_mem, "/a", 2, 1);
    radix_tree_insert(g_tree, g_mem, "/b", 2, 2);
    radix_tree_insert(g_tree, g_mem, "/c", 2, 3);

    uint32_t deleted = radix_tree_delete(g_tree, g_mem, "/b", 2);
    TEST_ASSERT_EQ(2, deleted);
    TEST_ASSERT_EQ(2, g_tree->entry_count);

    TEST_ASSERT_EQ(1, radix_tree_lookup(g_tree, g_mem, "/a", 2));
    TEST_ASSERT_EQ(0, radix_tree_lookup(g_tree, g_mem, "/b", 2));
    TEST_ASSERT_EQ(3, radix_tree_lookup(g_tree, g_mem, "/c", 2));

    radix_teardown();
}

TEST(delete_then_reinsert)
{
    radix_setup();

    radix_tree_insert(g_tree, g_mem, "/key", 4, 100);
    radix_tree_delete(g_tree, g_mem, "/key", 4);

    TEST_ASSERT_FALSE(radix_tree_exists(g_tree, g_mem, "/key", 4));

    radix_tree_insert(g_tree, g_mem, "/key", 4, 200);
    TEST_ASSERT_EQ(200, radix_tree_lookup(g_tree, g_mem, "/key", 4));

    radix_teardown();
}

TEST(delete_parent_keeps_child)
{
    radix_setup();

    radix_tree_insert(g_tree, g_mem, "/parent", 7, 1);
    radix_tree_insert(g_tree, g_mem, "/parent/child", 13, 2);

    radix_tree_delete(g_tree, g_mem, "/parent", 7);

    TEST_ASSERT_FALSE(radix_tree_exists(g_tree, g_mem, "/parent", 7));
    TEST_ASSERT_TRUE(radix_tree_exists(g_tree, g_mem, "/parent/child", 13));
    TEST_ASSERT_EQ(2, radix_tree_lookup(g_tree, g_mem, "/parent/child", 13));

    radix_teardown();
}

TEST(delete_child_keeps_parent)
{
    radix_setup();

    radix_tree_insert(g_tree, g_mem, "/parent", 7, 1);
    radix_tree_insert(g_tree, g_mem, "/parent/child", 13, 2);

    radix_tree_delete(g_tree, g_mem, "/parent/child", 13);

    TEST_ASSERT_TRUE(radix_tree_exists(g_tree, g_mem, "/parent", 7));
    TEST_ASSERT_FALSE(radix_tree_exists(g_tree, g_mem, "/parent/child", 13));
    TEST_ASSERT_EQ(1, radix_tree_lookup(g_tree, g_mem, "/parent", 7));

    radix_teardown();
}

/* ============================================
 * Overwrite Tests
 * ============================================ */

TEST(overwrite_value)
{
    radix_setup();

    radix_tree_insert(g_tree, g_mem, "/key", 4, 100);
    TEST_ASSERT_EQ(100, radix_tree_lookup(g_tree, g_mem, "/key", 4));

    radix_tree_insert(g_tree, g_mem, "/key", 4, 200);
    TEST_ASSERT_EQ(200, radix_tree_lookup(g_tree, g_mem, "/key", 4));

    /* Entry count should not increase */
    TEST_ASSERT_EQ(1, g_tree->entry_count);

    radix_teardown();
}

TEST(overwrite_multiple_times)
{
    radix_setup();

    for (int i = 1; i <= 10; i++) {
        radix_tree_insert(g_tree, g_mem, "/key", 4, i * 100);
        TEST_ASSERT_EQ(i * 100, radix_tree_lookup(g_tree, g_mem, "/key", 4));
    }

    TEST_ASSERT_EQ(1, g_tree->entry_count);

    radix_teardown();
}

/* ============================================
 * Iteration Tests
 * ============================================ */

struct iter_ctx {
    char paths[200][QSYSDB_MAX_PATH];
    uint32_t offsets[200];
    int count;
};

static int iter_callback(const char *path, uint32_t offset, void *userdata) {
    struct iter_ctx *ctx = userdata;
    if (ctx->count < 200) {
        strncpy(ctx->paths[ctx->count], path, QSYSDB_MAX_PATH - 1);
        ctx->paths[ctx->count][QSYSDB_MAX_PATH - 1] = '\0';
        ctx->offsets[ctx->count] = offset;
        ctx->count++;
    }
    return 0;
}

TEST(iterate_all_entries)
{
    radix_setup();

    radix_tree_insert(g_tree, g_mem, "/a", 2, 1);
    radix_tree_insert(g_tree, g_mem, "/b", 2, 2);
    radix_tree_insert(g_tree, g_mem, "/c", 2, 3);

    struct iter_ctx ctx = {0};
    radix_tree_iterate(g_tree, g_mem, NULL, 0, iter_callback, &ctx);

    TEST_ASSERT_EQ(3, ctx.count);

    radix_teardown();
}

TEST(iterate_empty_tree)
{
    radix_setup();

    struct iter_ctx ctx = {0};
    radix_tree_iterate(g_tree, g_mem, NULL, 0, iter_callback, &ctx);

    TEST_ASSERT_EQ(0, ctx.count);

    radix_teardown();
}

TEST(iterate_with_prefix)
{
    radix_setup();

    radix_tree_insert(g_tree, g_mem, "/config/a", 9, 1);
    radix_tree_insert(g_tree, g_mem, "/config/b", 9, 2);
    radix_tree_insert(g_tree, g_mem, "/data/x", 7, 3);
    radix_tree_insert(g_tree, g_mem, "/data/y", 7, 4);

    /* Iterate all */
    struct iter_ctx ctx = {0};
    radix_tree_iterate(g_tree, g_mem, NULL, 0, iter_callback, &ctx);
    TEST_ASSERT_EQ(4, ctx.count);

    radix_teardown();
}

TEST(iterate_returns_correct_values)
{
    radix_setup();

    radix_tree_insert(g_tree, g_mem, "/test1", 6, 100);
    radix_tree_insert(g_tree, g_mem, "/test2", 6, 200);

    struct iter_ctx ctx = {0};
    radix_tree_iterate(g_tree, g_mem, NULL, 0, iter_callback, &ctx);

    TEST_ASSERT_EQ(2, ctx.count);

    /* Verify at least one of them */
    bool found100 = false, found200 = false;
    for (int i = 0; i < ctx.count; i++) {
        if (ctx.offsets[i] == 100) found100 = true;
        if (ctx.offsets[i] == 200) found200 = true;
    }
    TEST_ASSERT_TRUE(found100);
    TEST_ASSERT_TRUE(found200);

    radix_teardown();
}

/* ============================================
 * Many Entries Tests
 * ============================================ */

TEST(insert_100_entries)
{
    radix_setup();

    for (int i = 0; i < 100; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/entry/%d", i);
        uint32_t off = radix_tree_insert(g_tree, g_mem, path, strlen(path), i + 1);
        TEST_ASSERT_NE(0, off);
    }

    TEST_ASSERT_EQ(100, g_tree->entry_count);

    /* Verify all entries */
    for (int i = 0; i < 100; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/entry/%d", i);
        uint32_t val = radix_tree_lookup(g_tree, g_mem, path, strlen(path));
        TEST_ASSERT_EQ(i + 1, val);
    }

    radix_teardown();
}

TEST(insert_500_entries)
{
    radix_setup();

    for (int i = 0; i < 500; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/item/group%d/entry%d", i / 50, i);
        uint32_t off = radix_tree_insert(g_tree, g_mem, path, strlen(path), i + 1);
        TEST_ASSERT_NE(0, off);
    }

    TEST_ASSERT_EQ(500, g_tree->entry_count);

    radix_teardown();
}

TEST(delete_half_entries)
{
    radix_setup();

    /* Insert 100 entries */
    for (int i = 0; i < 100; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/del/%d", i);
        radix_tree_insert(g_tree, g_mem, path, strlen(path), i + 1);
    }

    /* Delete even entries */
    for (int i = 0; i < 100; i += 2) {
        char path[64];
        snprintf(path, sizeof(path), "/del/%d", i);
        radix_tree_delete(g_tree, g_mem, path, strlen(path));
    }

    TEST_ASSERT_EQ(50, g_tree->entry_count);

    /* Verify odd entries still exist */
    for (int i = 1; i < 100; i += 2) {
        char path[64];
        snprintf(path, sizeof(path), "/del/%d", i);
        TEST_ASSERT_TRUE(radix_tree_exists(g_tree, g_mem, path, strlen(path)));
    }

    radix_teardown();
}

/* ============================================
 * Deep Path Tests
 * ============================================ */

TEST(deep_nested_paths)
{
    radix_setup();

    radix_tree_insert(g_tree, g_mem, "/a/b/c/d/e/f/g", 13, 100);
    radix_tree_insert(g_tree, g_mem, "/a/b/c/d/e/f", 11, 200);
    radix_tree_insert(g_tree, g_mem, "/a/b/c", 5, 300);

    TEST_ASSERT_EQ(100, radix_tree_lookup(g_tree, g_mem, "/a/b/c/d/e/f/g", 13));
    TEST_ASSERT_EQ(200, radix_tree_lookup(g_tree, g_mem, "/a/b/c/d/e/f", 11));
    TEST_ASSERT_EQ(300, radix_tree_lookup(g_tree, g_mem, "/a/b/c", 5));

    /* Intermediate paths should not exist */
    TEST_ASSERT_EQ(0, radix_tree_lookup(g_tree, g_mem, "/a/b", 3));
    TEST_ASSERT_EQ(0, radix_tree_lookup(g_tree, g_mem, "/a/b/c/d", 7));

    radix_teardown();
}

TEST(very_deep_path)
{
    radix_setup();

    /* Create a path with 20 levels */
    char path[QSYSDB_MAX_PATH] = "/";
    for (int i = 0; i < 20 && strlen(path) < QSYSDB_MAX_PATH - 3; i++) {
        strcat(path, "l/");
    }
    path[strlen(path) - 1] = '\0';  /* Remove trailing / */

    radix_tree_insert(g_tree, g_mem, path, strlen(path), 999);
    TEST_ASSERT_EQ(999, radix_tree_lookup(g_tree, g_mem, path, strlen(path)));

    radix_teardown();
}

/* ============================================
 * Statistics Tests
 * ============================================ */

TEST(stats_empty_tree)
{
    radix_setup();

    uint32_t node_count, entry_count, max_nodes;
    radix_tree_stats(g_tree, &node_count, &entry_count, &max_nodes);

    TEST_ASSERT_EQ(0, entry_count);
    TEST_ASSERT_EQ(10000, max_nodes);

    radix_teardown();
}

TEST(stats_after_inserts)
{
    radix_setup();

    radix_tree_insert(g_tree, g_mem, "/a", 2, 1);
    radix_tree_insert(g_tree, g_mem, "/b", 2, 2);
    radix_tree_insert(g_tree, g_mem, "/c", 2, 3);

    uint32_t node_count, entry_count, max_nodes;
    radix_tree_stats(g_tree, &node_count, &entry_count, &max_nodes);

    TEST_ASSERT_EQ(3, entry_count);
    TEST_ASSERT_GT(node_count, 0);

    radix_teardown();
}

TEST(stats_after_deletes)
{
    radix_setup();

    radix_tree_insert(g_tree, g_mem, "/a", 2, 1);
    radix_tree_insert(g_tree, g_mem, "/b", 2, 2);
    radix_tree_insert(g_tree, g_mem, "/c", 2, 3);

    radix_tree_delete(g_tree, g_mem, "/b", 2);

    uint32_t node_count, entry_count, max_nodes;
    radix_tree_stats(g_tree, &node_count, &entry_count, &max_nodes);

    TEST_ASSERT_EQ(2, entry_count);

    radix_teardown();
}

/* ============================================
 * Edge Cases Tests
 * ============================================ */

TEST(root_path)
{
    radix_setup();

    radix_tree_insert(g_tree, g_mem, "/", 1, 100);
    TEST_ASSERT_EQ(100, radix_tree_lookup(g_tree, g_mem, "/", 1));

    radix_teardown();
}

TEST(similar_paths)
{
    radix_setup();

    radix_tree_insert(g_tree, g_mem, "/test", 5, 1);
    radix_tree_insert(g_tree, g_mem, "/test1", 6, 2);
    radix_tree_insert(g_tree, g_mem, "/test12", 7, 3);
    radix_tree_insert(g_tree, g_mem, "/tester", 7, 4);

    TEST_ASSERT_EQ(1, radix_tree_lookup(g_tree, g_mem, "/test", 5));
    TEST_ASSERT_EQ(2, radix_tree_lookup(g_tree, g_mem, "/test1", 6));
    TEST_ASSERT_EQ(3, radix_tree_lookup(g_tree, g_mem, "/test12", 7));
    TEST_ASSERT_EQ(4, radix_tree_lookup(g_tree, g_mem, "/tester", 7));

    radix_teardown();
}

TEST(path_with_numbers)
{
    radix_setup();

    radix_tree_insert(g_tree, g_mem, "/agent/123", 10, 123);
    radix_tree_insert(g_tree, g_mem, "/agent/456", 10, 456);

    TEST_ASSERT_EQ(123, radix_tree_lookup(g_tree, g_mem, "/agent/123", 10));
    TEST_ASSERT_EQ(456, radix_tree_lookup(g_tree, g_mem, "/agent/456", 10));

    radix_teardown();
}

TEST(long_path_names)
{
    radix_setup();

    char long_segment[100];
    memset(long_segment, 'x', sizeof(long_segment) - 1);
    long_segment[sizeof(long_segment) - 1] = '\0';

    char path[QSYSDB_MAX_PATH];
    snprintf(path, sizeof(path), "/%s", long_segment);

    radix_tree_insert(g_tree, g_mem, path, strlen(path), 999);
    TEST_ASSERT_EQ(999, radix_tree_lookup(g_tree, g_mem, path, strlen(path)));

    radix_teardown();
}

TEST(path_case_sensitivity)
{
    radix_setup();

    radix_tree_insert(g_tree, g_mem, "/Test", 5, 1);
    radix_tree_insert(g_tree, g_mem, "/test", 5, 2);
    radix_tree_insert(g_tree, g_mem, "/TEST", 5, 3);

    /* Paths should be case-sensitive */
    TEST_ASSERT_EQ(1, radix_tree_lookup(g_tree, g_mem, "/Test", 5));
    TEST_ASSERT_EQ(2, radix_tree_lookup(g_tree, g_mem, "/test", 5));
    TEST_ASSERT_EQ(3, radix_tree_lookup(g_tree, g_mem, "/TEST", 5));

    TEST_ASSERT_EQ(3, g_tree->entry_count);

    radix_teardown();
}

TEST(special_characters_in_path)
{
    radix_setup();

    radix_tree_insert(g_tree, g_mem, "/path-with-dash", 15, 1);
    radix_tree_insert(g_tree, g_mem, "/path_with_underscore", 21, 2);
    radix_tree_insert(g_tree, g_mem, "/path.with.dots", 15, 3);

    TEST_ASSERT_EQ(1, radix_tree_lookup(g_tree, g_mem, "/path-with-dash", 15));
    TEST_ASSERT_EQ(2, radix_tree_lookup(g_tree, g_mem, "/path_with_underscore", 21));
    TEST_ASSERT_EQ(3, radix_tree_lookup(g_tree, g_mem, "/path.with.dots", 15));

    radix_teardown();
}

/* ============================================
 * Stress Tests
 * ============================================ */

TEST(insert_delete_cycle)
{
    radix_setup();

    /* Verify starting from clean slate */
    TEST_ASSERT_EQ(0, g_tree->entry_count);

    /* Insert 100 entries */
    for (int i = 0; i < 100; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/cycle/%d", i);
        radix_tree_insert(g_tree, g_mem, path, strlen(path), i + 1);
    }
    TEST_ASSERT_EQ(100, g_tree->entry_count);

    /* Delete first 50 entries */
    for (int i = 0; i < 50; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/cycle/%d", i);
        radix_tree_delete(g_tree, g_mem, path, strlen(path));
    }
    TEST_ASSERT_EQ(50, g_tree->entry_count);

    /* Insert 50 more entries with different paths */
    for (int i = 100; i < 150; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/cycle/%d", i);
        radix_tree_insert(g_tree, g_mem, path, strlen(path), i + 1);
    }

    /* Final count: 50 (remaining) + 50 (new) = 100 */
    TEST_ASSERT_EQ(100, g_tree->entry_count);

    radix_teardown();
}

TEST(repeated_operations_same_key)
{
    radix_setup();

    for (int i = 0; i < 50; i++) {
        radix_tree_insert(g_tree, g_mem, "/repeated", 9, i);
        TEST_ASSERT_EQ(i, radix_tree_lookup(g_tree, g_mem, "/repeated", 9));

        if (i % 5 == 0) {
            radix_tree_delete(g_tree, g_mem, "/repeated", 9);
            TEST_ASSERT_FALSE(radix_tree_exists(g_tree, g_mem, "/repeated", 9));
        }
    }

    radix_teardown();
}

TEST_MAIN()
