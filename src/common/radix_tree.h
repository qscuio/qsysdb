/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * radix_tree.h - Radix tree (patricia trie) for path indexing
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#ifndef QSYSDB_RADIX_TREE_H
#define QSYSDB_RADIX_TREE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <qsysdb/types.h>

/*
 * Radix tree node
 *
 * The tree is stored in a contiguous memory region using offsets instead
 * of pointers, allowing it to be placed in shared memory.
 */
struct radix_node {
    uint32_t children[256];     /* Offsets to child nodes (0 = no child) */
    uint32_t entry_offset;      /* Offset to data entry (0 = no entry) */
    uint32_t parent_offset;     /* Offset to parent node */
    uint16_t prefix_len;        /* Length of compressed prefix */
    uint16_t child_count;       /* Number of non-null children */
    uint8_t  edge_char;         /* Character on edge from parent */
    uint8_t  flags;             /* Node flags */
    uint16_t reserved;
    char prefix[QSYSDB_RADIX_PREFIX_MAX]; /* Compressed prefix */
};

/* Node flags */
#define RADIX_FLAG_NONE     0x00
#define RADIX_FLAG_ROOT     0x01
#define RADIX_FLAG_LEAF     0x02

/*
 * Radix tree header (at start of memory region)
 */
struct radix_tree {
    uint32_t magic;             /* Validation magic */
    uint32_t version;           /* Tree version */
    uint32_t node_count;        /* Number of allocated nodes */
    uint32_t entry_count;       /* Number of entries (leafs with data) */
    uint32_t max_nodes;         /* Maximum nodes (pool size) */
    uint32_t free_head;         /* Head of free list */
    uint32_t root_offset;       /* Offset to root node */
    uint32_t reserved;
    /* Followed by: radix_node nodes[max_nodes] */
};

#define RADIX_TREE_MAGIC    0x52414458  /* "RADX" */

/*
 * Iterator for tree traversal
 */
struct radix_iterator {
    struct radix_tree *tree;
    void *base;                 /* Base address of memory region */
    uint32_t stack[QSYSDB_MAX_PATH];  /* Stack of node offsets */
    int stack_depth;
    char path[QSYSDB_MAX_PATH]; /* Current path being built */
    size_t path_len;
    const char *prefix;         /* Prefix filter (NULL = all) */
    size_t prefix_len;
};

/*
 * Callback for tree iteration
 * Returns 0 to continue, non-zero to stop
 */
typedef int (*radix_visit_fn)(const char *path, uint32_t entry_offset,
                              void *userdata);

/*
 * Initialize a radix tree in the given memory region
 */
int radix_tree_init(void *mem, size_t mem_size, uint32_t max_nodes);

/*
 * Get the radix tree header from memory
 */
struct radix_tree *radix_tree_get(void *mem);

/*
 * Insert a path into the tree
 * Returns the offset where the entry should be stored, or 0 on error
 */
uint32_t radix_tree_insert(struct radix_tree *tree, void *base,
                           const char *path, size_t path_len,
                           uint32_t entry_offset);

/*
 * Look up a path in the tree
 * Returns the entry offset, or 0 if not found
 */
uint32_t radix_tree_lookup(struct radix_tree *tree, void *base,
                           const char *path, size_t path_len);

/*
 * Delete a path from the tree
 * Returns the entry offset that was removed, or 0 if not found
 */
uint32_t radix_tree_delete(struct radix_tree *tree, void *base,
                           const char *path, size_t path_len);

/*
 * Check if a path exists in the tree
 */
bool radix_tree_exists(struct radix_tree *tree, void *base,
                       const char *path, size_t path_len);

/*
 * Iterate over all entries with a given prefix
 */
int radix_tree_iterate(struct radix_tree *tree, void *base,
                       const char *prefix, size_t prefix_len,
                       radix_visit_fn callback, void *userdata);

/*
 * Delete all entries with a given prefix
 * Returns the number of entries deleted
 */
int radix_tree_delete_prefix(struct radix_tree *tree, void *base,
                             const char *prefix, size_t prefix_len);

/*
 * Get statistics
 */
void radix_tree_stats(struct radix_tree *tree, uint32_t *node_count,
                      uint32_t *entry_count, uint32_t *max_nodes);

/*
 * Initialize an iterator
 */
void radix_iter_init(struct radix_iterator *iter, struct radix_tree *tree,
                     void *base, const char *prefix, size_t prefix_len);

/*
 * Get next entry from iterator
 * Returns 1 if an entry was found, 0 if iteration complete
 */
int radix_iter_next(struct radix_iterator *iter, const char **path,
                    size_t *path_len, uint32_t *entry_offset);

#endif /* QSYSDB_RADIX_TREE_H */
