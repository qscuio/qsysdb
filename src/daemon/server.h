/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * server.h - Network server (Unix domain sockets + TCP)
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#ifndef QSYSDB_SERVER_H
#define QSYSDB_SERVER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/epoll.h>
#include <pthread.h>

#include <qsysdb/types.h>
#include <qsysdb/protocol.h>
#include <qsysdb/cluster.h>
#include "database.h"
#include "subscription.h"
#include "worker_pool.h"

/* Forward declarations */
struct server;

/*
 * Connection type
 */
enum conn_type {
    CONN_TYPE_UNIX,                 /* Unix domain socket */
    CONN_TYPE_TCP                   /* TCP socket */
};

/*
 * Client connection
 */
struct client_conn {
    int fd;                         /* Socket file descriptor */
    int id;                         /* Client ID */
    uint32_t flags;                 /* Connection flags */
    enum conn_type type;            /* Connection type */
    char name[64];                  /* Client name */
    char remote_addr[64];           /* Remote address (for TCP) */
    uint16_t remote_port;           /* Remote port (for TCP) */

    /* Receive buffer */
    uint8_t *recv_buf;
    size_t recv_buf_size;
    size_t recv_len;

    /* Send buffer */
    uint8_t *send_buf;
    size_t send_buf_size;
    size_t send_len;
    size_t send_offset;

    /* Active transaction */
    int txn_id;

    /* Ring buffer consumer for notifications */
    struct ringbuf_consumer ring_consumer;

    /* Link to server */
    struct server *server;

    /* Client list linkage */
    struct client_conn *next;
    struct client_conn *prev;
};

/*
 * Server configuration
 */
struct server_config {
    /* Unix socket settings */
    bool unix_enabled;
    char unix_path[256];

    /* TCP settings */
    bool tcp_enabled;
    char tcp_bind[64];
    uint16_t tcp_port;

    /* Worker pool settings */
    bool worker_pool_enabled;
    int worker_threads;             /* Number of worker threads (0 = auto detect) */

    /* Cluster settings */
    bool cluster_enabled;
    qsysdb_cluster_config_t cluster;
};

/*
 * Server context
 */
struct server {
    int unix_fd;                    /* Unix domain listening socket */
    int tcp_fd;                     /* TCP listening socket */
    int epoll_fd;                   /* epoll instance */

    /* Configuration */
    struct server_config config;

    /* Client management */
    struct client_conn *clients;    /* Linked list of clients */
    int client_count;
    int next_client_id;
    pthread_mutex_t clients_lock;

    /* Database reference */
    struct qsysdb_db *db;

    /* Subscription manager */
    struct sub_manager *sub_mgr;

    /* Server state */
    volatile bool running;
    pthread_t event_thread;

    /* Worker pool for parallel request processing */
    struct worker_pool *worker_pool;
    bool use_worker_pool;

    /* Cluster support */
    qsysdb_cluster_t *cluster;

    /* Statistics */
    uint64_t total_connections;
    uint64_t total_requests;
    uint64_t unix_connections;
    uint64_t tcp_connections;
};

/*
 * Initialize server configuration with defaults
 */
void server_config_init(struct server_config *config);

/*
 * Initialize the server
 */
int server_init(struct server *srv, struct server_config *config,
                struct qsysdb_db *db, struct sub_manager *sub_mgr);

/*
 * Enable TCP server
 */
int server_enable_tcp(struct server *srv, const char *bind_addr, uint16_t port);

/*
 * Start the server event loop
 */
int server_start(struct server *srv);

/*
 * Stop the server
 */
void server_stop(struct server *srv);

/*
 * Shutdown and cleanup
 */
void server_shutdown(struct server *srv);

/*
 * Send a notification to matching clients
 */
int server_broadcast_notification(struct server *srv,
                                  const struct qsysdb_notification *notif);

/*
 * Get server statistics
 */
void server_stats(struct server *srv, int *client_count,
                  uint64_t *total_connections, uint64_t *total_requests);

/*
 * Enable cluster mode
 */
int server_enable_cluster(struct server *srv, qsysdb_cluster_config_t *config);

/*
 * Check if this server is the cluster leader
 */
bool server_is_leader(struct server *srv);

/*
 * Forward a write request to the leader (for follower nodes)
 */
int server_forward_to_leader(struct server *srv, struct client_conn *client,
                             struct qsysdb_msg_header *hdr, void *payload);

#endif /* QSYSDB_SERVER_H */
