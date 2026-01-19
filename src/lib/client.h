/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * client.h - Internal client structures
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#ifndef QSYSDB_CLIENT_H
#define QSYSDB_CLIENT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>

#include <qsysdb/types.h>
#include <qsysdb/qsysdb.h>
#include "common/shm.h"
#include "common/ringbuf.h"

/* Forward declaration */
struct transport_ops;

/* Maximum local subscriptions per connection */
#define MAX_LOCAL_SUBS  256

/*
 * Local subscription info
 */
struct local_subscription {
    int id;                         /* Server-assigned ID */
    char pattern[QSYSDB_MAX_PATH];
    qsysdb_callback_t callback;
    void *userdata;
    bool active;
};

/*
 * Socket type
 */
enum socket_type {
    SOCK_TYPE_UNIX,
    SOCK_TYPE_TCP
};

/*
 * Client connection structure
 */
struct qsysdb {
    /* Connection type */
    enum {
        CONN_SOCKET,
        CONN_SHM
    } conn_type;

    /* Socket connection */
    int sock_fd;
    enum socket_type sock_type;
    char socket_path[256];  /* For Unix sockets */
    char tcp_host[256];     /* For TCP connections */
    uint16_t tcp_port;      /* For TCP connections */

    /* Transport operations (Unix or TCP) */
    const struct transport_ops *transport;

    /* Shared memory connection */
    struct qsysdb_shm shm;
    struct ringbuf_consumer ring_consumer;

    /* Connection state */
    int client_id;
    uint32_t flags;
    bool connected;
    int last_error;

    /* Message handling */
    uint64_t next_request_id;
    uint8_t *recv_buf;
    size_t recv_buf_size;
    size_t recv_len;

    /* Local subscriptions */
    struct local_subscription subscriptions[MAX_LOCAL_SUBS];
    int subscription_count;

    /* Active transaction */
    struct qsysdb_txn *active_txn;

    /* Thread safety */
    pthread_mutex_t lock;
};

/*
 * Transaction structure
 */
struct qsysdb_txn {
    struct qsysdb *db;
    int txn_id;
    bool committed;
    bool aborted;
};

/*
 * Internal functions
 */

/* Send a request and wait for response */
int client_request(struct qsysdb *db, void *req, size_t req_len,
                   void *rsp, size_t rsp_size, size_t *rsp_len);

/* Process incoming notifications */
int client_process_notifications(struct qsysdb *db);

/* Find local subscription by server ID */
struct local_subscription *client_find_subscription(struct qsysdb *db, int id);

#endif /* QSYSDB_CLIENT_H */
