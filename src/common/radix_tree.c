/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * radix_tree.c - Radix tree (patricia trie) implementation
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>  /* For debug output */

#include <qsysdb/types.h>
#include "radix_tree.h"

/* Get node pointer from offset */
static inline struct radix_node *node_ptr(void *base, uint32_t offset)
{
    if (offset == 0) {
        return NULL;
    }
    return (struct radix_node *)((char *)base + offset);
}

/* Get offset from node pointer */
static inline uint32_t node_offset(void *base, struct radix_node *node)
{
    if (node == NULL) {
        return 0;
    }
    return (uint32_t)((char *)node - (char *)base);
}

/* Calculate offset for node at index */
static inline uint32_t node_index_offset(struct radix_tree *tree, uint32_t idx)
{
    (void)tree;
    return sizeof(struct radix_tree) + idx * sizeof(struct radix_node);
}

/* Allocate a new node from the free list */
static struct radix_node *alloc_node(struct radix_tree *tree, void *base)
{
    if (tree->free_head == 0) {
        /* No free nodes available */
        return NULL;
    }

    uint32_t offset = tree->free_head;
    struct radix_node *node = node_ptr(base, offset);

    /* Update free list head */
    tree->free_head = node->entry_offset;  /* Reuse entry_offset as next ptr */
    tree->node_count++;

    /* Initialize the node */
    memset(node, 0, sizeof(*node));

    return node;
}

/* Free a node back to the free list */
static void free_node(struct radix_tree *tree, void *base,
                      struct radix_node *node)
{
    uint32_t offset = node_offset(base, node);

    /* Add to head of free list */
    node->entry_offset = tree->free_head;
    tree->free_head = offset;
    tree->node_count--;
}

/*
 * Initialize a radix tree in memory
 */
int radix_tree_init(void *mem, size_t mem_size, uint32_t max_nodes)
{
    size_t required = sizeof(struct radix_tree) +
                      max_nodes * sizeof(struct radix_node);

    if (mem_size < required) {
        return QSYSDB_ERR_NOMEM;
    }

    struct radix_tree *tree = (struct radix_tree *)mem;
    memset(tree, 0, sizeof(*tree));

    tree->magic = RADIX_TREE_MAGIC;
    tree->version = 1;
    tree->max_nodes = max_nodes;
    tree->node_count = 0;
    tree->entry_count = 0;

    /* Initialize free list */
    tree->free_head = node_index_offset(tree, 0);
    for (uint32_t i = 0; i < max_nodes - 1; i++) {
        struct radix_node *node = (struct radix_node *)
            ((char *)mem + node_index_offset(tree, i));
        node->entry_offset = node_index_offset(tree, i + 1);
    }
    /* Last node points to nothing */
    struct radix_node *last = (struct radix_node *)
        ((char *)mem + node_index_offset(tree, max_nodes - 1));
    last->entry_offset = 0;

    /* Allocate root node */
    struct radix_node *root = alloc_node(tree, mem);
    if (root == NULL) {
        return QSYSDB_ERR_NOMEM;
    }
    root->flags = RADIX_FLAG_ROOT;
    tree->root_offset = node_offset(mem, root);

    return QSYSDB_OK;
}

struct radix_tree *radix_tree_get(void *mem)
{
    struct radix_tree *tree = (struct radix_tree *)mem;
    if (tree->magic != RADIX_TREE_MAGIC) {
        return NULL;
    }
    return tree;
}

/*
 * Find the node for a given path, or the deepest matching node
 */
static struct radix_node *find_node(struct radix_tree *tree, void *base,
                                    const char *path, size_t path_len,
                                    size_t *matched_len, bool create)
{
    struct radix_node *node = node_ptr(base, tree->root_offset);
    size_t pos = 0;

    while (pos < path_len && node != NULL) {
        unsigned char c = (unsigned char)path[pos];
        uint32_t child_offset = node->children[c];

        if (child_offset == 0) {
            /* No child for this character */
            if (create) {
                /* Create new node */
                struct radix_node *child = alloc_node(tree, base);
                if (child == NULL) {
                    *matched_len = pos;
                    return node;
                }
                child->parent_offset = node_offset(base, node);
                child->edge_char = c;
                node->children[c] = node_offset(base, child);
                node->child_count++;
                node = child;
                pos++;

                /* Store remaining path as prefix if it fits */
                size_t remaining = path_len - pos;
                if (remaining > 0 && remaining <= QSYSDB_RADIX_PREFIX_MAX) {
                    memcpy(node->prefix, path + pos, remaining);
                    node->prefix_len = (uint16_t)remaining;
                    pos = path_len;
                }
            } else {
                break;
            }
        } else {
            struct radix_node *child = node_ptr(base, child_offset);
            pos++;

            /* Check prefix match */
            if (child->prefix_len > 0) {
                size_t remaining = path_len - pos;
                size_t cmp_len = (remaining < child->prefix_len) ?
                                 remaining : child->prefix_len;

                if (memcmp(path + pos, child->prefix, cmp_len) != 0) {
                    /* Prefix mismatch */
                    if (create) {
                        /* Need to split the node */
                        size_t match_pos = 0;
                        while (match_pos < cmp_len &&
                               path[pos + match_pos] == child->prefix[match_pos]) {
                            match_pos++;
                        }

                        if (match_pos < child->prefix_len) {
                            /* Split: create intermediate node */
                            struct radix_node *split = alloc_node(tree, base);
                            if (split == NULL) {
                                *matched_len = pos;
                                return node;
                            }

                            /* Set up split node */
                            split->parent_offset = node->children[c] ?
                                node_ptr(base, node->children[c])->parent_offset :
                                node_offset(base, node);
                            split->edge_char = c;

                            /* Copy matched prefix to split node */
                            if (match_pos > 0) {
                                memcpy(split->prefix, child->prefix, match_pos);
                                split->prefix_len = (uint16_t)match_pos;
                            }

                            /* Update child to continue from split */
                            unsigned char split_char =
                                (unsigned char)child->prefix[match_pos];
                            memmove(child->prefix, child->prefix + match_pos + 1,
                                    child->prefix_len - match_pos - 1);
                            child->prefix_len -= (match_pos + 1);
                            child->parent_offset = node_offset(base, split);
                            child->edge_char = split_char;

                            split->children[split_char] = child_offset;
                            split->child_count = 1;

                            /* Update parent to point to split */
                            node->children[c] = node_offset(base, split);

                            /* Continue from split node */
                            node = split;
                            pos += match_pos;
                            continue;
                        }
                    } else {
                        break;
                    }
                }

                if (remaining < child->prefix_len) {
                    /* Path ends in middle of prefix */
                    if (create) {
                        /* Split node at this point */
                        struct radix_node *split = alloc_node(tree, base);
                        if (split == NULL) {
                            *matched_len = pos;
                            return node;
                        }

                        split->parent_offset = node_offset(base, node);
                        split->edge_char = c;
                        memcpy(split->prefix, child->prefix, remaining);
                        split->prefix_len = (uint16_t)remaining;

                        unsigned char next_char =
                            (unsigned char)child->prefix[remaining];
                        memmove(child->prefix, child->prefix + remaining + 1,
                                child->prefix_len - remaining - 1);
                        child->prefix_len -= (remaining + 1);
                        child->parent_offset = node_offset(base, split);
                        child->edge_char = next_char;

                        split->children[next_char] = child_offset;
                        split->child_count = 1;
                        node->children[c] = node_offset(base, split);

                        *matched_len = path_len;
                        return split;
                    } else {
                        break;
                    }
                }

                pos += child->prefix_len;
            }

            node = child;
        }
    }

    *matched_len = pos;
    return node;
}

uint32_t radix_tree_insert(struct radix_tree *tree, void *base,
                           const char *path, size_t path_len,
                           uint32_t entry_offset)
{
    size_t matched;
    struct radix_node *node = find_node(tree, base, path, path_len,
                                        &matched, true);

    if (node == NULL || matched != path_len) {
        return 0;  /* Failed to create path */
    }

    if (node->entry_offset == 0) {
        tree->entry_count++;
    }

    node->entry_offset = entry_offset;
    node->flags |= RADIX_FLAG_LEAF;

    return entry_offset;
}

uint32_t radix_tree_lookup(struct radix_tree *tree, void *base,
                           const char *path, size_t path_len)
{
    size_t matched;
    struct radix_node *node = find_node(tree, base, path, path_len,
                                        &matched, false);

    if (node == NULL || matched != path_len) {
        return 0;
    }

    return node->entry_offset;
}

uint32_t radix_tree_delete(struct radix_tree *tree, void *base,
                           const char *path, size_t path_len)
{
    size_t matched;
    struct radix_node *node = find_node(tree, base, path, path_len,
                                        &matched, false);

    if (node == NULL || matched != path_len || node->entry_offset == 0) {
        return 0;
    }

    uint32_t entry_offset = node->entry_offset;
    node->entry_offset = 0;
    node->flags &= ~RADIX_FLAG_LEAF;
    tree->entry_count--;

    /* Clean up empty nodes */
    while (node != NULL && !(node->flags & RADIX_FLAG_ROOT)) {
        if (node->entry_offset != 0 || node->child_count > 0) {
            break;  /* Node still in use */
        }

        struct radix_node *parent = node_ptr(base, node->parent_offset);
        if (parent != NULL) {
            parent->children[node->edge_char] = 0;
            parent->child_count--;
        }

        free_node(tree, base, node);
        node = parent;
    }

    return entry_offset;
}

bool radix_tree_exists(struct radix_tree *tree, void *base,
                       const char *path, size_t path_len)
{
    return radix_tree_lookup(tree, base, path, path_len) != 0;
}

/* Helper for iteration */
static int iterate_subtree(struct radix_tree *tree, void *base,
                           struct radix_node *node, char *path_buf,
                           size_t path_pos, radix_visit_fn callback,
                           void *userdata)
{
    if (node == NULL) {
        return 0;
    }

    /* Add prefix to path */
    if (node->prefix_len > 0) {
        if (path_pos + node->prefix_len >= QSYSDB_MAX_PATH) {
            return 0;
        }
        memcpy(path_buf + path_pos, node->prefix, node->prefix_len);
        path_pos += node->prefix_len;
    }

    /* Visit this node if it has an entry */
    if (node->entry_offset != 0) {
        path_buf[path_pos] = '\0';
        int ret = callback(path_buf, node->entry_offset, userdata);
        if (ret != 0) {
            return ret;
        }
    }

    /* Visit children */
    for (int c = 0; c < 256; c++) {
        if (node->children[c] != 0) {
            if (path_pos >= QSYSDB_MAX_PATH - 1) {
                continue;
            }
            path_buf[path_pos] = (char)c;

            struct radix_node *child = node_ptr(base, node->children[c]);
            int ret = iterate_subtree(tree, base, child, path_buf,
                                      path_pos + 1, callback, userdata);
            if (ret != 0) {
                return ret;
            }
        }
    }

    return 0;
}

int radix_tree_iterate(struct radix_tree *tree, void *base,
                       const char *prefix, size_t prefix_len,
                       radix_visit_fn callback, void *userdata)
{
    char path_buf[QSYSDB_MAX_PATH];
    size_t matched;

    if (prefix == NULL || prefix_len == 0) {
        /* Iterate entire tree */
        struct radix_node *root = node_ptr(base, tree->root_offset);
        return iterate_subtree(tree, base, root, path_buf, 0,
                               callback, userdata);
    }

    /* Find the node matching the prefix */
    struct radix_node *node = find_node(tree, base, prefix, prefix_len,
                                        &matched, false);

#ifdef DEBUG_RADIX
    fprintf(stderr, "radix_tree_iterate: prefix='%.*s' prefix_len=%zu matched=%zu node=%p\n",
            (int)prefix_len, prefix, prefix_len, matched, (void*)node);
#endif
    /* TEMP DEBUG */
    fprintf(stderr, "[DEBUG] radix_tree_iterate: prefix='%.*s' len=%zu matched=%zu node=%p\n",
            (int)prefix_len, prefix, prefix_len, matched, (void*)node);

    if (node == NULL) {
        return 0;  /* No matches */
    }

    /* Copy prefix to path buffer */
    memcpy(path_buf, prefix, matched);

    /* If we didn't match the full prefix, check if we're in a node's prefix */
    if (matched < prefix_len) {
        /* 
         * find_node may have stopped because the search prefix ends inside
         * a child node's compressed prefix. The last matched character
         * (prefix[matched-1]) was the edge to that child. We need to check
         * if the child's prefix starts with the remaining search prefix.
         */
        if (matched > 0) {
            unsigned char edge_char = (unsigned char)prefix[matched - 1];
            fprintf(stderr, "[DEBUG] partial match: matched=%zu, edge_char='%c' child=%u\n",
                    matched, edge_char, node->children[edge_char]);
            if (node->children[edge_char] != 0) {
                struct radix_node *child = node_ptr(base, node->children[edge_char]);
                /* remaining = how much of prefix is left after the edge character */
                size_t remaining = prefix_len - matched;
                fprintf(stderr, "[DEBUG] child prefix_len=%u remaining=%zu child_prefix='%.*s' search_remaining='%.*s'\n",
                        child->prefix_len, remaining, child->prefix_len, child->prefix,
                        (int)remaining, prefix + matched);
                /* Check if the child's prefix starts with the remaining search prefix */
                if (child->prefix_len >= remaining &&
                    memcmp(child->prefix, prefix + matched, remaining) == 0) {
                    /* Match! The remaining search prefix is contained in child's prefix.
                     * Build the path with the full prefix first, then continue with
                     * the portion of child->prefix AFTER the matched part.
                     * 
                     * E.g., search for "/tree" with child->prefix = "ree/a"
                     * - matched tells us the edge char position ("/t" = path_buf[0..1], edge='t')
                     * - path_buf already has "/" (0..matched-1)
                     * - We need to rebuild: copy prefix up to matched-1 (already there)
                     * - Then edge char (prefix[matched-1] = 't' at position matched-1)
                     * - Then "ree" (portion of child prefix matching our search)
                     * - path_pos should be at prefix_len (e.g., 5 for "/tree")
                     * - Then iterate_subtree adds remaining of child->prefix after 'ree'
                     * 
                     * The issue is iterate_subtree adds the FULL child->prefix.
                     * We need to NOT add the part we already matched (remaining bytes).
                     */
                    
                    /* Build the path buffer with the search prefix */
                    memcpy(path_buf, prefix, prefix_len);
                    
                    /* Now iterate, but we need to skip 'remaining' bytes of the child's prefix.
                     * We do this by adding remaining bytes manually and then visiting children. */
                    size_t skip_prefix = remaining;
                    size_t pos = prefix_len;
                    
                    /* Add the rest of child's prefix after the matched portion */
                    size_t extra_prefix = child->prefix_len - skip_prefix;
                    if (extra_prefix > 0 && pos + extra_prefix < QSYSDB_MAX_PATH) {
                        memcpy(path_buf + pos, child->prefix + skip_prefix, extra_prefix);
                        pos += extra_prefix;
                    }
                    
                    /* Visit this node if it has an entry */
                    if (child->entry_offset != 0) {
                        path_buf[pos] = '\0';
                        int ret = callback(path_buf, child->entry_offset, userdata);
                        if (ret != 0) {
                            return ret;
                        }
                    }
                    
                    /* Visit children */
                    for (int ch = 0; ch < 256; ch++) {
                        if (child->children[ch] != 0) {
                            if (pos >= QSYSDB_MAX_PATH - 1) continue;
                            path_buf[pos] = (char)ch;
                            struct radix_node *grandchild = node_ptr(base, child->children[ch]);
                            int ret = iterate_subtree(tree, base, grandchild, path_buf,
                                                      pos + 1, callback, userdata);
                            if (ret != 0) {
                                return ret;
                            }
                        }
                    }
                    return 0;
                }
            }
        }
        
        /* Also check if the next character in prefix has a child */
        unsigned char c = (unsigned char)prefix[matched];
        if (node->children[c] != 0) {
            struct radix_node *child = node_ptr(base, node->children[c]);
            size_t remaining = prefix_len - matched - 1;
            if (child->prefix_len >= remaining &&
                memcmp(child->prefix, prefix + matched + 1, remaining) == 0) {
                /* Match continues in child's prefix */
                path_buf[matched] = (char)c;
                memcpy(path_buf + matched + 1, prefix + matched + 1, remaining);
                return iterate_subtree(tree, base, child, path_buf,
                                       prefix_len, callback, userdata);
            }
        }
        return 0;  /* Prefix not found */
    }

    return iterate_subtree(tree, base, node, path_buf, matched,
                           callback, userdata);
}

/* Helper for delete_prefix */
struct delete_ctx {
    struct radix_tree *tree;
    void *base;
    int count;
};

static int delete_visitor(const char *path, uint32_t entry_offset,
                          void *userdata)
{
    struct delete_ctx *ctx = userdata;
    (void)entry_offset;

    radix_tree_delete(ctx->tree, ctx->base, path, strlen(path));
    ctx->count++;

    return 0;  /* Continue */
}

int radix_tree_delete_prefix(struct radix_tree *tree, void *base,
                             const char *prefix, size_t prefix_len)
{
    struct delete_ctx ctx = {
        .tree = tree,
        .base = base,
        .count = 0
    };

    /* Collect and delete all matching entries */
    radix_tree_iterate(tree, base, prefix, prefix_len,
                       delete_visitor, &ctx);

    return ctx.count;
}

void radix_tree_stats(struct radix_tree *tree, uint32_t *node_count,
                      uint32_t *entry_count, uint32_t *max_nodes)
{
    if (node_count) *node_count = tree->node_count;
    if (entry_count) *entry_count = tree->entry_count;
    if (max_nodes) *max_nodes = tree->max_nodes;
}

void radix_iter_init(struct radix_iterator *iter, struct radix_tree *tree,
                     void *base, const char *prefix, size_t prefix_len)
{
    memset(iter, 0, sizeof(*iter));
    iter->tree = tree;
    iter->base = base;
    iter->prefix = prefix;
    iter->prefix_len = prefix_len;

    /* Find starting node */
    if (prefix && prefix_len > 0) {
        size_t matched;
        struct radix_node *node = find_node(tree, base, prefix, prefix_len,
                                            &matched, false);
        if (node && matched == prefix_len) {
            iter->stack[0] = node_offset(base, node);
            iter->stack_depth = 1;
            memcpy(iter->path, prefix, prefix_len);
            iter->path_len = prefix_len;
        }
    } else {
        iter->stack[0] = tree->root_offset;
        iter->stack_depth = 1;
    }
}

int radix_iter_next(struct radix_iterator *iter, const char **path,
                    size_t *path_len, uint32_t *entry_offset)
{
    /* Simple DFS iteration - not optimized for very deep trees */
    while (iter->stack_depth > 0) {
        uint32_t offset = iter->stack[iter->stack_depth - 1];
        struct radix_node *node = node_ptr(iter->base, offset);

        if (node == NULL) {
            iter->stack_depth--;
            continue;
        }

        /* Check if this node has an entry we haven't returned */
        if (node->entry_offset != 0) {
            *path = iter->path;
            *path_len = iter->path_len;
            *entry_offset = node->entry_offset;

            /* Move to next (mark this node as processed by clearing entry) */
            /* Note: This is a simplified iterator - in production, we'd
               track visited state separately */
            iter->stack_depth--;
            return 1;
        }

        iter->stack_depth--;

        /* Push children onto stack */
        for (int c = 255; c >= 0; c--) {
            if (node->children[c] != 0) {
                if (iter->stack_depth < QSYSDB_MAX_PATH) {
                    iter->stack[iter->stack_depth++] = node->children[c];
                }
            }
        }
    }

    return 0;  /* Iteration complete */
}
