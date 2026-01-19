/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * kqsysdb.h - Kernel module header
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT OR GPL-2.0
 */

#ifndef KQSYSDB_H
#define KQSYSDB_H

#include <linux/types.h>
#include <linux/spinlock.h>

/*
 * Constants (must match userspace definitions)
 */
#define QSYSDB_MAGIC            0x51535944
#define QSYSDB_VERSION          1
#define QSYSDB_MAX_PATH         256
#define QSYSDB_MAX_VALUE        (64 * 1024)
#define QSYSDB_SHM_NAME         "/qsysdb"

/*
 * Generic Netlink configuration
 */
#define QSYSDB_GENL_NAME        "QSYSDB"
#define QSYSDB_GENL_VERSION     1
#define QSYSDB_GENL_MC_GROUP    "qsysdb_events"

/*
 * Netlink commands
 */
enum kqsysdb_nl_commands {
    KQSYSDB_CMD_UNSPEC = 0,
    KQSYSDB_CMD_SET,
    KQSYSDB_CMD_GET,
    KQSYSDB_CMD_DELETE,
    KQSYSDB_CMD_SUBSCRIBE,
    KQSYSDB_CMD_UNSUBSCRIBE,
    KQSYSDB_CMD_NOTIFY,
    KQSYSDB_CMD_KERN_UPDATE,
    KQSYSDB_CMD_SYNC,
    __KQSYSDB_CMD_MAX,
};
#define KQSYSDB_CMD_MAX (__KQSYSDB_CMD_MAX - 1)

/*
 * Netlink attributes
 */
enum kqsysdb_nl_attrs {
    KQSYSDB_ATTR_UNSPEC = 0,
    KQSYSDB_ATTR_PATH,
    KQSYSDB_ATTR_VALUE,
    KQSYSDB_ATTR_EVENT_TYPE,
    KQSYSDB_ATTR_SEQUENCE,
    KQSYSDB_ATTR_VERSION,
    KQSYSDB_ATTR_TIMESTAMP,
    KQSYSDB_ATTR_FLAGS,
    KQSYSDB_ATTR_ERROR,
    KQSYSDB_ATTR_PATTERN,
    KQSYSDB_ATTR_SUB_ID,
    __KQSYSDB_ATTR_MAX,
};
#define KQSYSDB_ATTR_MAX (__KQSYSDB_ATTR_MAX - 1)

/*
 * Event types
 */
enum kqsysdb_event_type {
    KQSYSDB_EVENT_NONE = 0,
    KQSYSDB_EVENT_CREATE,
    KQSYSDB_EVENT_UPDATE,
    KQSYSDB_EVENT_DELETE,
    KQSYSDB_EVENT_DELETE_TREE,
    KQSYSDB_EVENT_SNAPSHOT,
};

/*
 * Error codes
 */
#define KQSYSDB_OK              0
#define KQSYSDB_ERR_NOMEM       (-1)
#define KQSYSDB_ERR_INVALID     (-2)
#define KQSYSDB_ERR_NOTFOUND    (-3)
#define KQSYSDB_ERR_EXISTS      (-4)
#define KQSYSDB_ERR_FULL        (-5)
#define KQSYSDB_ERR_TOOBIG      (-6)
#define KQSYSDB_ERR_BADPATH     (-7)
#define KQSYSDB_ERR_BADJSON     (-8)
#define KQSYSDB_ERR_NOTREADY    (-9)

/*
 * Subscription callback type
 */
typedef void (*kqsysdb_notify_fn)(const char *path, const char *value,
                                   int event_type, void *data);

/*
 * Kernel subscription structure
 */
struct kqsysdb_subscription {
    int id;
    char pattern[QSYSDB_MAX_PATH];
    size_t pattern_len;
    bool prefix_match;
    kqsysdb_notify_fn callback;
    void *data;
    struct list_head list;
};

/*
 * Public API for other kernel modules
 */

/**
 * kqsysdb_get - Read a value from the database
 * @path: Path to read (must start with '/')
 * @buf: Buffer to store the value
 * @buflen: Size of buffer
 *
 * Returns: Number of bytes read on success, negative error code on failure
 *
 * Context: Process context. May sleep.
 */
int kqsysdb_get(const char *path, char *buf, size_t buflen);

/**
 * kqsysdb_set - Write a value to the database
 * @path: Path to write (must start with '/')
 * @json_value: JSON value string to store
 *
 * Returns: 0 on success, negative error code on failure
 *
 * Context: Process context. May sleep.
 */
int kqsysdb_set(const char *path, const char *json_value);

/**
 * kqsysdb_delete - Delete a value from the database
 * @path: Path to delete
 *
 * Returns: 0 on success, negative error code on failure
 *
 * Context: Process context. May sleep.
 */
int kqsysdb_delete(const char *path);

/**
 * kqsysdb_exists - Check if a path exists
 * @path: Path to check
 *
 * Returns: 1 if exists, 0 if not, negative error code on failure
 *
 * Context: Process context or atomic. Does not sleep.
 */
int kqsysdb_exists(const char *path);

/**
 * kqsysdb_subscribe - Subscribe to changes on a path pattern
 * @pattern: Path pattern (exact match or prefix with '*')
 * @callback: Function to call on changes (called in softirq context)
 * @data: User data passed to callback
 *
 * Returns: Subscription ID (>0) on success, negative error code on failure
 *
 * Context: Process context. May sleep.
 */
int kqsysdb_subscribe(const char *pattern, kqsysdb_notify_fn callback,
                      void *data);

/**
 * kqsysdb_unsubscribe - Remove a subscription
 * @sub_id: Subscription ID returned by kqsysdb_subscribe
 *
 * Context: Process context. May sleep.
 */
void kqsysdb_unsubscribe(int sub_id);

/**
 * kqsysdb_ready - Check if the database is ready
 *
 * Returns: 1 if ready, 0 if not
 *
 * Context: Any.
 */
int kqsysdb_ready(void);

#endif /* KQSYSDB_H */
