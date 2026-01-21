/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * types.h - Core type definitions and constants
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#ifndef QSYSDB_TYPES_H
#define QSYSDB_TYPES_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/limits.h>
#else
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <limits.h>
#endif

/*
 * Magic numbers and version
 */
#define QSYSDB_MAGIC            0x51535944  /* "QSYD" */
#define QSYSDB_MSG_MAGIC        0x51534442  /* "QSDB" */
#define QSYSDB_VERSION          1
#define QSYSDB_PROTOCOL_VERSION 1

/*
 * Size limits
 */
#define QSYSDB_MAX_PATH         256         /* Maximum path length */
#define QSYSDB_MAX_VALUE        (64 * 1024) /* 64KB max JSON value */
#define QSYSDB_MAX_CLIENTS      1024        /* Maximum concurrent clients */
#define QSYSDB_MAX_SUBSCRIPTIONS 65536      /* Maximum total subscriptions (increased for scale) */

/*
 * Shared memory configuration
 */
#define QSYSDB_SHM_NAME         "/qsysdb"
#define QSYSDB_SHM_SIZE_DEFAULT (256 * 1024 * 1024) /* 256MB default (increased for 10+ clients with 100K+ entries) */
#define QSYSDB_SHM_SIZE_MIN     (1 * 1024 * 1024)   /* 1MB minimum */
#define QSYSDB_SHM_SIZE_MAX     (4ULL * 1024 * 1024 * 1024) /* 4GB maximum */

/*
 * Socket configuration
 */
#define QSYSDB_SOCKET_PATH      "/var/run/qsysdb/qsysdb.sock"
#define QSYSDB_SOCKET_BACKLOG   128

/*
 * TCP configuration
 */
#define QSYSDB_TCP_PORT_DEFAULT 5959        /* Default TCP port */
#define QSYSDB_TCP_BIND_DEFAULT "0.0.0.0"   /* Default bind address */
#define QSYSDB_TCP_KEEPALIVE    1           /* Enable TCP keepalive */
#define QSYSDB_TCP_NODELAY      1           /* Disable Nagle's algorithm */

/*
 * Ring buffer configuration
 */
#define QSYSDB_RING_SIZE        65536       /* Number of notification entries (increased for scale) */
#define QSYSDB_RING_ENTRY_SIZE  512         /* Size of each notification */

/*
 * Radix tree configuration
 */
#define QSYSDB_RADIX_POOL_SIZE  (256 * 1024) /* Number of pre-allocated nodes (increased for 100K+ entries) */
#define QSYSDB_RADIX_PREFIX_MAX 14          /* Maximum compressed prefix length */

/*
 * Timeouts (in milliseconds)
 */
#define QSYSDB_CONNECT_TIMEOUT  5000
#define QSYSDB_READ_TIMEOUT     30000
#define QSYSDB_WRITE_TIMEOUT    30000

/*
 * Snapshot configuration
 */
#define QSYSDB_SNAPSHOT_DIR     "/var/lib/qsysdb"
#define QSYSDB_SNAPSHOT_FILE    "snapshot.qsdb"
#define QSYSDB_SNAPSHOT_MAGIC   0x51534E50  /* "QSNP" */
#define QSYSDB_SNAPSHOT_VERSION 1

/*
 * Netlink configuration
 */
#define QSYSDB_GENL_NAME        "QSYSDB"
#define QSYSDB_GENL_VERSION     1
#define QSYSDB_GENL_MC_GROUP    "qsysdb_events"

/*
 * Event types for notifications
 */
enum qsysdb_event_type {
    QSYSDB_EVENT_NONE = 0,
    QSYSDB_EVENT_CREATE,        /* New key created */
    QSYSDB_EVENT_UPDATE,        /* Existing key updated */
    QSYSDB_EVENT_DELETE,        /* Key deleted */
    QSYSDB_EVENT_DELETE_TREE,   /* Subtree deleted */
    QSYSDB_EVENT_SNAPSHOT,      /* Snapshot created/restored */
    __QSYSDB_EVENT_MAX
};

/*
 * Entry flags
 */
#define QSYSDB_FLAG_NONE        0x00000000
#define QSYSDB_FLAG_DELETED     0x00000001  /* Entry marked for deletion */
#define QSYSDB_FLAG_LOCKED      0x00000002  /* Entry is locked for transaction */
#define QSYSDB_FLAG_KERNEL      0x00000004  /* Entry created by kernel */
#define QSYSDB_FLAG_PERSISTENT  0x00000008  /* Include in snapshots */
#define QSYSDB_FLAG_EPHEMERAL   0x00000010  /* Delete when creator disconnects */

/*
 * Connection flags
 */
#define QSYSDB_CONN_NONE        0x00000000
#define QSYSDB_CONN_READONLY    0x00000001  /* Read-only connection */
#define QSYSDB_CONN_SHM         0x00000002  /* Use shared memory fast path */
#define QSYSDB_CONN_KERNEL      0x00000004  /* Kernel-space connection */
#define QSYSDB_CONN_ADMIN       0x00000008  /* Administrative privileges */
#define QSYSDB_CONN_TCP         0x00000010  /* TCP connection (remote) */
#define QSYSDB_CONN_UNIX        0x00000020  /* Unix domain socket connection */

/*
 * Error codes
 */
enum qsysdb_error {
    QSYSDB_OK = 0,
    QSYSDB_ERR_NOMEM = -1,          /* Out of memory */
    QSYSDB_ERR_INVALID = -2,        /* Invalid argument */
    QSYSDB_ERR_NOTFOUND = -3,       /* Key not found */
    QSYSDB_ERR_EXISTS = -4,         /* Key already exists */
    QSYSDB_ERR_FULL = -5,           /* Database full */
    QSYSDB_ERR_TOOBIG = -6,         /* Value too large */
    QSYSDB_ERR_BADPATH = -7,        /* Invalid path format */
    QSYSDB_ERR_BADJSON = -8,        /* Invalid JSON */
    QSYSDB_ERR_CONNECT = -9,        /* Connection failed */
    QSYSDB_ERR_DISCONNECTED = -10,  /* Connection lost */
    QSYSDB_ERR_TIMEOUT = -11,       /* Operation timed out */
    QSYSDB_ERR_BUSY = -12,          /* Resource busy */
    QSYSDB_ERR_PERM = -13,          /* Permission denied */
    QSYSDB_ERR_IO = -14,            /* I/O error */
    QSYSDB_ERR_PROTO = -15,         /* Protocol error */
    QSYSDB_ERR_INTERNAL = -16,      /* Internal error */
    QSYSDB_ERR_AGAIN = -17,         /* Try again */
    QSYSDB_ERR_NOTSUP = -18,        /* Not supported */
    QSYSDB_ERR_TXN = -19,           /* Transaction error */
    QSYSDB_ERR_CONFLICT = -20,      /* Conflict detected */
};

/*
 * Shared memory header structure
 * This structure is placed at the beginning of the shared memory region
 */
struct qsysdb_shm_header {
    uint32_t magic;                 /* QSYSDB_MAGIC */
    uint32_t version;               /* QSYSDB_VERSION */
    uint64_t size;                  /* Total shared memory size */
    uint64_t sequence;              /* Global change sequence number */

    /* Region offsets and sizes */
    uint32_t index_offset;          /* Offset to radix tree index */
    uint32_t index_size;            /* Size of index region */
    uint32_t data_offset;           /* Offset to data region */
    uint32_t data_size;             /* Size of data region */
    uint32_t ring_offset;           /* Offset to notification ring buffer */
    uint32_t ring_size;             /* Size of ring buffer region */

    /* Allocation tracking */
    uint32_t data_used;             /* Bytes used in data region */
    uint32_t entry_count;           /* Number of entries */
    uint32_t node_count;            /* Number of radix tree nodes */
    uint32_t free_list_head;        /* Head of free block list (offset in data region) */
    uint32_t free_list_count;       /* Number of blocks in free list */
    uint64_t bytes_freed;           /* Total bytes freed (for stats) */
    uint64_t bytes_reused;          /* Total bytes reused from free list */

    /* Synchronization */
    uint32_t lock_state;            /* Spinlock for kernel access */
    uint32_t writer_pid;            /* PID of current writer (0 if none) */
    uint64_t write_sequence;        /* Sequence for seqlock pattern */

    /* Statistics */
    uint64_t total_sets;            /* Total set operations */
    uint64_t total_gets;            /* Total get operations */
    uint64_t total_deletes;         /* Total delete operations */
    uint64_t total_notifications;   /* Total notifications sent */

    /* Reserved for future use */
    uint8_t reserved[64];

    /* Userspace pthread rwlock (after reserved to maintain alignment) */
    uint8_t pthread_lock[64];       /* Space for pthread_rwlock_t */
};

/*
 * Database entry structure
 * Stored in the data region of shared memory
 */
struct qsysdb_entry {
    uint32_t path_hash;             /* Hash of the path for quick comparison */
    uint16_t path_len;              /* Length of path (not including null) */
    uint16_t value_len;             /* Length of value (not including null) */
    uint64_t version;               /* Entry version (incremented on update) */
    uint64_t timestamp_ns;          /* Creation/modification timestamp */
    uint32_t flags;                 /* Entry flags */
    uint32_t next_offset;           /* Offset to next entry (for hash collision) */
    char data[];                    /* path + '\0' + JSON value + '\0' */
};

/*
 * Notification structure
 * Stored in the ring buffer
 */
struct qsysdb_notification {
    uint64_t sequence;              /* Notification sequence number */
    uint32_t event_type;            /* Event type (qsysdb_event_type) */
    uint32_t path_len;              /* Length of path */
    uint64_t timestamp_ns;          /* Event timestamp */
    uint64_t entry_version;         /* Version of affected entry */
    char path[QSYSDB_MAX_PATH];     /* Path that changed */
};

/*
 * Subscription structure (used in daemon)
 */
struct qsysdb_subscription {
    int id;                         /* Unique subscription ID */
    int client_id;                  /* Owning client ID */
    uint32_t flags;                 /* Subscription flags */
    char pattern[QSYSDB_MAX_PATH];  /* Path pattern (may include wildcards) */
    uint64_t last_sequence;         /* Last sequence number delivered */
};

/*
 * Transaction operation
 */
struct qsysdb_txn_op {
    int op_type;                    /* SET or DELETE */
    char path[QSYSDB_MAX_PATH];
    char *value;                    /* NULL for DELETE */
    size_t value_len;
};

/*
 * Helper macros
 */
#define QSYSDB_ENTRY_SIZE(path_len, value_len) \
    (sizeof(struct qsysdb_entry) + (path_len) + 1 + (value_len) + 1)

#define QSYSDB_ENTRY_PATH(entry) \
    ((entry)->data)

#define QSYSDB_ENTRY_VALUE(entry) \
    ((entry)->data + (entry)->path_len + 1)

#define QSYSDB_ALIGN(x, a) \
    (((x) + ((a) - 1)) & ~((a) - 1))

#define QSYSDB_ALIGN8(x)  QSYSDB_ALIGN(x, 8)
#define QSYSDB_ALIGN16(x) QSYSDB_ALIGN(x, 16)

/*
 * Path validation macros
 */
#define QSYSDB_PATH_CHAR_VALID(c) \
    (((c) >= 'a' && (c) <= 'z') || \
     ((c) >= 'A' && (c) <= 'Z') || \
     ((c) >= '0' && (c) <= '9') || \
     (c) == '_' || (c) == '-' || (c) == '.' || (c) == '/')

/*
 * Compile-time assertions
 */
#ifndef __KERNEL__
_Static_assert(sizeof(struct qsysdb_shm_header) <= 4096,
               "SHM header must fit in one page");
_Static_assert(sizeof(struct qsysdb_notification) <= QSYSDB_RING_ENTRY_SIZE,
               "Notification must fit in ring entry");
#endif

#endif /* QSYSDB_TYPES_H */
