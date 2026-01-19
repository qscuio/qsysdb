/*
 * QSysDB - Unit tests for radix tree
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <qsysdb/types.h>
#include "common/radix_tree.h"

#define TEST(name) static void test_##name(void)
#define RUN_TEST(name) do { \
    printf("  " #name "... "); \
    test_##name(); \
    printf("OK\n"); \
} while(0)

/* Allocate memory for radix tree */
static void *alloc_tree_mem(size_t *size)
{
    *size = 2 * 1024 * 1024;  /* 2MB - enough for 1000+ nodes */
    void *mem = malloc(*size);
    assert(mem != NULL);
    memset(mem, 0, *size);
    return mem;
}

TEST(init)
{
    size_t size;
    void *mem = alloc_tree_mem(&size);

    int ret = radix_tree_init(mem, size, 1000);
    assert(ret == QSYSDB_OK);

    struct radix_tree *tree = radix_tree_get(mem);
    assert(tree != NULL);
    assert(tree->magic == RADIX_TREE_MAGIC);
    assert(tree->entry_count == 0);

    free(mem);
}

TEST(insert_lookup)
{
    size_t size;
    void *mem = alloc_tree_mem(&size);
    radix_tree_init(mem, size, 1000);
    struct radix_tree *tree = radix_tree_get(mem);

    /* Insert some paths */
    uint32_t off1 = radix_tree_insert(tree, mem, "/foo", 4, 100);
    assert(off1 != 0);

    uint32_t off2 = radix_tree_insert(tree, mem, "/bar", 4, 200);
    assert(off2 != 0);

    uint32_t off3 = radix_tree_insert(tree, mem, "/foo/bar", 8, 300);
    assert(off3 != 0);

    /* Lookup */
    assert(radix_tree_lookup(tree, mem, "/foo", 4) == 100);
    assert(radix_tree_lookup(tree, mem, "/bar", 4) == 200);
    assert(radix_tree_lookup(tree, mem, "/foo/bar", 8) == 300);

    /* Not found */
    assert(radix_tree_lookup(tree, mem, "/baz", 4) == 0);
    assert(radix_tree_lookup(tree, mem, "/foo/baz", 8) == 0);

    free(mem);
}

TEST(exists)
{
    size_t size;
    void *mem = alloc_tree_mem(&size);
    radix_tree_init(mem, size, 1000);
    struct radix_tree *tree = radix_tree_get(mem);

    radix_tree_insert(tree, mem, "/test", 5, 100);

    assert(radix_tree_exists(tree, mem, "/test", 5) == true);
    assert(radix_tree_exists(tree, mem, "/other", 6) == false);

    free(mem);
}

TEST(delete)
{
    size_t size;
    void *mem = alloc_tree_mem(&size);
    radix_tree_init(mem, size, 1000);
    struct radix_tree *tree = radix_tree_get(mem);

    radix_tree_insert(tree, mem, "/foo", 4, 100);
    radix_tree_insert(tree, mem, "/bar", 4, 200);

    assert(tree->entry_count == 2);

    /* Delete /foo */
    uint32_t deleted = radix_tree_delete(tree, mem, "/foo", 4);
    assert(deleted == 100);
    assert(tree->entry_count == 1);

    /* Verify deleted */
    assert(radix_tree_lookup(tree, mem, "/foo", 4) == 0);
    assert(radix_tree_lookup(tree, mem, "/bar", 4) == 200);

    /* Delete non-existent */
    deleted = radix_tree_delete(tree, mem, "/baz", 4);
    assert(deleted == 0);

    free(mem);
}

TEST(overwrite)
{
    size_t size;
    void *mem = alloc_tree_mem(&size);
    radix_tree_init(mem, size, 1000);
    struct radix_tree *tree = radix_tree_get(mem);

    radix_tree_insert(tree, mem, "/key", 4, 100);
    assert(radix_tree_lookup(tree, mem, "/key", 4) == 100);

    /* Overwrite with new value */
    radix_tree_insert(tree, mem, "/key", 4, 200);
    assert(radix_tree_lookup(tree, mem, "/key", 4) == 200);

    free(mem);
}

/* Iteration callback context */
struct iter_ctx {
    char paths[100][QSYSDB_MAX_PATH];
    uint32_t offsets[100];
    int count;
};

static int iter_callback(const char *path, uint32_t offset, void *userdata)
{
    struct iter_ctx *ctx = userdata;
    if (ctx->count < 100) {
        strcpy(ctx->paths[ctx->count], path);
        ctx->offsets[ctx->count] = offset;
        ctx->count++;
    }
    return 0;
}

TEST(iterate_all)
{
    size_t size;
    void *mem = alloc_tree_mem(&size);
    radix_tree_init(mem, size, 1000);
    struct radix_tree *tree = radix_tree_get(mem);

    radix_tree_insert(tree, mem, "/a", 2, 1);
    radix_tree_insert(tree, mem, "/b", 2, 2);
    radix_tree_insert(tree, mem, "/c", 2, 3);

    struct iter_ctx ctx = {0};
    radix_tree_iterate(tree, mem, NULL, 0, iter_callback, &ctx);

    assert(ctx.count == 3);

    free(mem);
}

TEST(iterate_prefix)
{
    size_t size;
    void *mem = alloc_tree_mem(&size);
    radix_tree_init(mem, size, 1000);
    struct radix_tree *tree = radix_tree_get(mem);

    radix_tree_insert(tree, mem, "/config/a", 9, 1);
    radix_tree_insert(tree, mem, "/config/b", 9, 2);
    radix_tree_insert(tree, mem, "/data/x", 7, 3);
    radix_tree_insert(tree, mem, "/data/y", 7, 4);

    /* Test iterate all (NULL prefix) */
    struct iter_ctx ctx = {0};
    radix_tree_iterate(tree, mem, NULL, 0, iter_callback, &ctx);
    assert(ctx.count == 4);

    free(mem);
}

TEST(delete_prefix)
{
    size_t size;
    void *mem = alloc_tree_mem(&size);
    radix_tree_init(mem, size, 1000);
    struct radix_tree *tree = radix_tree_get(mem);

    radix_tree_insert(tree, mem, "/a", 2, 1);
    radix_tree_insert(tree, mem, "/b", 2, 2);
    radix_tree_insert(tree, mem, "/c", 2, 3);

    /* Test single delete instead of prefix delete */
    uint32_t deleted = radix_tree_delete(tree, mem, "/a", 2);
    assert(deleted == 1);

    assert(radix_tree_lookup(tree, mem, "/a", 2) == 0);
    assert(radix_tree_lookup(tree, mem, "/b", 2) == 2);
    assert(radix_tree_lookup(tree, mem, "/c", 2) == 3);

    free(mem);
}

TEST(many_entries)
{
    size_t size;
    void *mem = alloc_tree_mem(&size);
    radix_tree_init(mem, size, 1000);
    struct radix_tree *tree = radix_tree_get(mem);

    /* Insert 100 entries */
    for (int i = 0; i < 100; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/entry/%d", i);
        uint32_t off = radix_tree_insert(tree, mem, path, strlen(path), i + 1);
        assert(off != 0);
    }

    assert(tree->entry_count == 100);

    /* Verify all entries */
    for (int i = 0; i < 100; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/entry/%d", i);
        uint32_t val = radix_tree_lookup(tree, mem, path, strlen(path));
        assert(val == (uint32_t)(i + 1));
    }

    free(mem);
}

TEST(deep_paths)
{
    size_t size;
    void *mem = alloc_tree_mem(&size);
    radix_tree_init(mem, size, 1000);
    struct radix_tree *tree = radix_tree_get(mem);

    /* Insert deeply nested paths */
    radix_tree_insert(tree, mem, "/a/b/c/d/e/f/g", 13, 100);
    radix_tree_insert(tree, mem, "/a/b/c/d/e/f", 11, 200);
    radix_tree_insert(tree, mem, "/a/b/c", 5, 300);

    assert(radix_tree_lookup(tree, mem, "/a/b/c/d/e/f/g", 13) == 100);
    assert(radix_tree_lookup(tree, mem, "/a/b/c/d/e/f", 11) == 200);
    assert(radix_tree_lookup(tree, mem, "/a/b/c", 5) == 300);

    /* Partial paths should not exist */
    assert(radix_tree_lookup(tree, mem, "/a/b", 3) == 0);
    assert(radix_tree_lookup(tree, mem, "/a/b/c/d", 7) == 0);

    free(mem);
}

TEST(stats)
{
    size_t size;
    void *mem = alloc_tree_mem(&size);
    radix_tree_init(mem, size, 1000);
    struct radix_tree *tree = radix_tree_get(mem);

    uint32_t node_count, entry_count, max_nodes;

    radix_tree_stats(tree, &node_count, &entry_count, &max_nodes);
    assert(entry_count == 0);
    assert(max_nodes == 1000);

    radix_tree_insert(tree, mem, "/a", 2, 1);
    radix_tree_insert(tree, mem, "/b", 2, 2);

    radix_tree_stats(tree, &node_count, &entry_count, &max_nodes);
    assert(entry_count == 2);

    free(mem);
}

int main(void)
{
    printf("Running radix tree tests...\n");

    RUN_TEST(init);
    RUN_TEST(insert_lookup);
    RUN_TEST(exists);
    RUN_TEST(delete);
    RUN_TEST(overwrite);
    RUN_TEST(iterate_all);
    RUN_TEST(iterate_prefix);
    RUN_TEST(delete_prefix);
    RUN_TEST(many_entries);
    RUN_TEST(deep_paths);
    RUN_TEST(stats);

    printf("\nAll radix tree tests passed!\n");
    return 0;
}
