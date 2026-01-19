/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * protocol.h - Wire protocol definitions for socket and netlink communication
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#ifndef QSYSDB_PROTOCOL_H
#define QSYSDB_PROTOCOL_H

#include <qsysdb/types.h>

/*
 * Message types for Unix socket protocol
 */
enum qsysdb_msg_type {
    /* Requests (client -> daemon) */
    QSYSDB_MSG_CONNECT_REQ = 1,
    QSYSDB_MSG_DISCONNECT_REQ,
    QSYSDB_MSG_SET_REQ,
    QSYSDB_MSG_GET_REQ,
    QSYSDB_MSG_DELETE_REQ,
    QSYSDB_MSG_EXISTS_REQ,
    QSYSDB_MSG_LIST_REQ,
    QSYSDB_MSG_DELETE_TREE_REQ,
    QSYSDB_MSG_SUBSCRIBE_REQ,
    QSYSDB_MSG_UNSUBSCRIBE_REQ,
    QSYSDB_MSG_TXN_BEGIN_REQ,
    QSYSDB_MSG_TXN_SET_REQ,
    QSYSDB_MSG_TXN_DELETE_REQ,
    QSYSDB_MSG_TXN_COMMIT_REQ,
    QSYSDB_MSG_TXN_ABORT_REQ,
    QSYSDB_MSG_SNAPSHOT_SAVE_REQ,
    QSYSDB_MSG_SNAPSHOT_LOAD_REQ,
    QSYSDB_MSG_STATS_REQ,
    QSYSDB_MSG_PING_REQ,

    /* Responses (daemon -> client) */
    QSYSDB_MSG_CONNECT_RSP = 100,
    QSYSDB_MSG_DISCONNECT_RSP,
    QSYSDB_MSG_SET_RSP,
    QSYSDB_MSG_GET_RSP,
    QSYSDB_MSG_DELETE_RSP,
    QSYSDB_MSG_EXISTS_RSP,
    QSYSDB_MSG_LIST_RSP,
    QSYSDB_MSG_DELETE_TREE_RSP,
    QSYSDB_MSG_SUBSCRIBE_RSP,
    QSYSDB_MSG_UNSUBSCRIBE_RSP,
    QSYSDB_MSG_TXN_BEGIN_RSP,
    QSYSDB_MSG_TXN_SET_RSP,
    QSYSDB_MSG_TXN_DELETE_RSP,
    QSYSDB_MSG_TXN_COMMIT_RSP,
    QSYSDB_MSG_TXN_ABORT_RSP,
    QSYSDB_MSG_SNAPSHOT_SAVE_RSP,
    QSYSDB_MSG_SNAPSHOT_LOAD_RSP,
    QSYSDB_MSG_STATS_RSP,
    QSYSDB_MSG_PONG_RSP,

    /* Asynchronous notifications (daemon -> client) */
    QSYSDB_MSG_NOTIFICATION = 200,
    QSYSDB_MSG_ERROR,
};

/*
 * Message header
 * All messages start with this header
 */
struct qsysdb_msg_header {
    uint32_t magic;             /* QSYSDB_MSG_MAGIC */
    uint32_t version;           /* Protocol version */
    uint32_t msg_type;          /* Message type (qsysdb_msg_type) */
    uint32_t msg_len;           /* Total message length including header */
    uint64_t request_id;        /* Request ID for matching responses */
    int32_t  error_code;        /* Error code (0 for success) */
    uint32_t reserved;          /* Reserved for future use */
};

/*
 * Connect request
 */
struct qsysdb_msg_connect_req {
    struct qsysdb_msg_header hdr;
    uint32_t flags;             /* Connection flags */
    uint32_t client_version;    /* Client library version */
    char client_name[64];       /* Client identifier */
};

/*
 * Connect response
 */
struct qsysdb_msg_connect_rsp {
    struct qsysdb_msg_header hdr;
    int32_t client_id;          /* Assigned client ID */
    uint32_t server_version;    /* Server version */
    uint32_t flags;             /* Server capability flags */
    char shm_name[64];          /* Shared memory name (if SHM enabled) */
};

/*
 * Set request
 */
struct qsysdb_msg_set_req {
    struct qsysdb_msg_header hdr;
    uint32_t flags;             /* Entry flags */
    uint16_t path_len;          /* Length of path */
    uint16_t value_len;         /* Length of value */
    /* Followed by: path (path_len bytes) + value (value_len bytes) */
    char data[];
};

/*
 * Set response
 */
struct qsysdb_msg_set_rsp {
    struct qsysdb_msg_header hdr;
    uint64_t version;           /* New entry version */
    uint64_t sequence;          /* Global sequence number */
};

/*
 * Get request
 */
struct qsysdb_msg_get_req {
    struct qsysdb_msg_header hdr;
    uint16_t path_len;
    uint16_t reserved;
    char path[];
};

/*
 * Get response
 */
struct qsysdb_msg_get_rsp {
    struct qsysdb_msg_header hdr;
    uint64_t version;           /* Entry version */
    uint64_t timestamp_ns;      /* Entry timestamp */
    uint32_t flags;             /* Entry flags */
    uint16_t value_len;         /* Length of value */
    uint16_t reserved;
    char value[];               /* JSON value */
};

/*
 * Delete request
 */
struct qsysdb_msg_delete_req {
    struct qsysdb_msg_header hdr;
    uint16_t path_len;
    uint16_t reserved;
    char path[];
};

/*
 * Delete response
 */
struct qsysdb_msg_delete_rsp {
    struct qsysdb_msg_header hdr;
    uint64_t sequence;          /* Global sequence number */
};

/*
 * Exists request
 */
struct qsysdb_msg_exists_req {
    struct qsysdb_msg_header hdr;
    uint16_t path_len;
    uint16_t reserved;
    char path[];
};

/*
 * Exists response
 */
struct qsysdb_msg_exists_rsp {
    struct qsysdb_msg_header hdr;
    uint32_t exists;            /* 1 if exists, 0 otherwise */
    uint32_t reserved;
};

/*
 * List request
 */
struct qsysdb_msg_list_req {
    struct qsysdb_msg_header hdr;
    uint32_t max_results;       /* Maximum number of results (0 = unlimited) */
    uint16_t prefix_len;
    uint16_t reserved;
    char prefix[];              /* Path prefix to list */
};

/*
 * List response
 */
struct qsysdb_msg_list_rsp {
    struct qsysdb_msg_header hdr;
    uint32_t count;             /* Number of paths returned */
    uint32_t total;             /* Total matching paths (may be > count) */
    /* Followed by: count null-terminated paths */
    char paths[];
};

/*
 * Delete tree request
 */
struct qsysdb_msg_delete_tree_req {
    struct qsysdb_msg_header hdr;
    uint16_t prefix_len;
    uint16_t reserved;
    char prefix[];
};

/*
 * Delete tree response
 */
struct qsysdb_msg_delete_tree_rsp {
    struct qsysdb_msg_header hdr;
    uint32_t deleted_count;     /* Number of entries deleted */
    uint32_t reserved;
    uint64_t sequence;
};

/*
 * Subscribe request
 */
struct qsysdb_msg_subscribe_req {
    struct qsysdb_msg_header hdr;
    uint32_t flags;             /* Subscription flags */
    uint16_t pattern_len;
    uint16_t reserved;
    char pattern[];             /* Path pattern (may include wildcards) */
};

/*
 * Subscribe response
 */
struct qsysdb_msg_subscribe_rsp {
    struct qsysdb_msg_header hdr;
    int32_t subscription_id;    /* Subscription ID (for unsubscribe) */
    uint32_t reserved;
};

/*
 * Unsubscribe request
 */
struct qsysdb_msg_unsubscribe_req {
    struct qsysdb_msg_header hdr;
    int32_t subscription_id;
    uint32_t reserved;
};

/*
 * Unsubscribe response
 */
struct qsysdb_msg_unsubscribe_rsp {
    struct qsysdb_msg_header hdr;
};

/*
 * Transaction begin request
 */
struct qsysdb_msg_txn_begin_req {
    struct qsysdb_msg_header hdr;
    uint32_t flags;
    uint32_t reserved;
};

/*
 * Transaction begin response
 */
struct qsysdb_msg_txn_begin_rsp {
    struct qsysdb_msg_header hdr;
    int32_t txn_id;             /* Transaction ID */
    uint32_t reserved;
};

/*
 * Transaction set request (same as regular set)
 */
struct qsysdb_msg_txn_set_req {
    struct qsysdb_msg_header hdr;
    int32_t txn_id;
    uint32_t flags;
    uint16_t path_len;
    uint16_t value_len;
    char data[];
};

/*
 * Transaction delete request
 */
struct qsysdb_msg_txn_delete_req {
    struct qsysdb_msg_header hdr;
    int32_t txn_id;
    uint16_t path_len;
    uint16_t reserved;
    char path[];
};

/*
 * Transaction commit request
 */
struct qsysdb_msg_txn_commit_req {
    struct qsysdb_msg_header hdr;
    int32_t txn_id;
    uint32_t reserved;
};

/*
 * Transaction commit response
 */
struct qsysdb_msg_txn_commit_rsp {
    struct qsysdb_msg_header hdr;
    uint64_t sequence;          /* Final sequence number */
    uint32_t op_count;          /* Number of operations committed */
    uint32_t reserved;
};

/*
 * Transaction abort request
 */
struct qsysdb_msg_txn_abort_req {
    struct qsysdb_msg_header hdr;
    int32_t txn_id;
    uint32_t reserved;
};

/*
 * Snapshot save/load request
 */
struct qsysdb_msg_snapshot_req {
    struct qsysdb_msg_header hdr;
    uint32_t flags;
    uint16_t path_len;          /* 0 to use default path */
    uint16_t reserved;
    char path[];                /* Optional custom path */
};

/*
 * Snapshot save/load response
 */
struct qsysdb_msg_snapshot_rsp {
    struct qsysdb_msg_header hdr;
    uint64_t entry_count;       /* Number of entries in snapshot */
    uint64_t size_bytes;        /* Size of snapshot file */
    uint64_t timestamp_ns;      /* Snapshot timestamp */
};

/*
 * Statistics request (no additional fields)
 */
struct qsysdb_msg_stats_req {
    struct qsysdb_msg_header hdr;
};

/*
 * Statistics response
 */
struct qsysdb_msg_stats_rsp {
    struct qsysdb_msg_header hdr;
    uint64_t entry_count;
    uint64_t total_size;
    uint64_t used_size;
    uint64_t sequence;
    uint64_t total_sets;
    uint64_t total_gets;
    uint64_t total_deletes;
    uint64_t total_notifications;
    uint32_t client_count;
    uint32_t subscription_count;
    uint64_t uptime_ns;
    uint64_t reserved[4];
};

/*
 * Notification message (async, daemon -> client)
 */
struct qsysdb_msg_notification {
    struct qsysdb_msg_header hdr;
    int32_t subscription_id;    /* Which subscription matched */
    uint32_t event_type;        /* Event type */
    uint64_t sequence;          /* Global sequence number */
    uint64_t entry_version;     /* Entry version after change */
    uint64_t timestamp_ns;      /* Event timestamp */
    uint16_t path_len;
    uint16_t value_len;         /* 0 for DELETE events */
    uint32_t reserved;
    char data[];                /* path + value (if present) */
};

/*
 * Error message
 */
struct qsysdb_msg_error {
    struct qsysdb_msg_header hdr;
    uint64_t original_request_id;
    uint16_t message_len;
    uint16_t reserved;
    uint32_t reserved2;
    char message[];             /* Human-readable error message */
};

/*
 * Generic Netlink commands (for kernel communication)
 */
enum qsysdb_nl_commands {
    QSYSDB_NL_CMD_UNSPEC = 0,
    QSYSDB_NL_CMD_SET,          /* Set a value */
    QSYSDB_NL_CMD_GET,          /* Get a value */
    QSYSDB_NL_CMD_DELETE,       /* Delete a value */
    QSYSDB_NL_CMD_SUBSCRIBE,    /* Subscribe to changes */
    QSYSDB_NL_CMD_UNSUBSCRIBE,  /* Unsubscribe */
    QSYSDB_NL_CMD_NOTIFY,       /* Notification (daemon -> kernel) */
    QSYSDB_NL_CMD_KERN_UPDATE,  /* Update notification (kernel -> daemon) */
    QSYSDB_NL_CMD_SYNC,         /* Synchronize shared memory */
    __QSYSDB_NL_CMD_MAX,
};
#define QSYSDB_NL_CMD_MAX (__QSYSDB_NL_CMD_MAX - 1)

/*
 * Generic Netlink attributes
 */
enum qsysdb_nl_attrs {
    QSYSDB_NL_ATTR_UNSPEC = 0,
    QSYSDB_NL_ATTR_PATH,        /* Path string (NLA_NUL_STRING) */
    QSYSDB_NL_ATTR_VALUE,       /* JSON value (NLA_NUL_STRING) */
    QSYSDB_NL_ATTR_EVENT_TYPE,  /* Event type (NLA_U32) */
    QSYSDB_NL_ATTR_SEQUENCE,    /* Sequence number (NLA_U64) */
    QSYSDB_NL_ATTR_VERSION,     /* Entry version (NLA_U64) */
    QSYSDB_NL_ATTR_TIMESTAMP,   /* Timestamp in ns (NLA_U64) */
    QSYSDB_NL_ATTR_FLAGS,       /* Flags (NLA_U32) */
    QSYSDB_NL_ATTR_ERROR,       /* Error code (NLA_S32) */
    QSYSDB_NL_ATTR_PATTERN,     /* Subscription pattern (NLA_NUL_STRING) */
    QSYSDB_NL_ATTR_SUB_ID,      /* Subscription ID (NLA_S32) */
    __QSYSDB_NL_ATTR_MAX,
};
#define QSYSDB_NL_ATTR_MAX (__QSYSDB_NL_ATTR_MAX - 1)

/*
 * Helper functions for message creation
 */
#ifndef __KERNEL__
#include <string.h>

static inline void qsysdb_msg_init(struct qsysdb_msg_header *hdr,
                                   uint32_t type, uint32_t len,
                                   uint64_t request_id)
{
    memset(hdr, 0, sizeof(*hdr));
    hdr->magic = QSYSDB_MSG_MAGIC;
    hdr->version = QSYSDB_PROTOCOL_VERSION;
    hdr->msg_type = type;
    hdr->msg_len = len;
    hdr->request_id = request_id;
}

static inline int qsysdb_msg_validate(const struct qsysdb_msg_header *hdr,
                                      size_t received_len)
{
    if (received_len < sizeof(*hdr))
        return QSYSDB_ERR_PROTO;
    if (hdr->magic != QSYSDB_MSG_MAGIC)
        return QSYSDB_ERR_PROTO;
    if (hdr->version != QSYSDB_PROTOCOL_VERSION)
        return QSYSDB_ERR_PROTO;
    if (hdr->msg_len > received_len)
        return QSYSDB_ERR_PROTO;
    return QSYSDB_OK;
}
#endif /* !__KERNEL__ */

#endif /* QSYSDB_PROTOCOL_H */
