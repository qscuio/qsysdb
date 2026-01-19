/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * server.c - Network server (Unix domain sockets + TCP)
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pthread.h>

#include <qsysdb/types.h>
#include <qsysdb/protocol.h>
#include "server.h"
#include "database.h"
#include "subscription.h"
#include "common/ringbuf.h"

#define MAX_EVENTS      64
#define RECV_BUF_SIZE   (128 * 1024)
#define SEND_BUF_SIZE   (128 * 1024)

/* Forward declarations */
static int handle_client_message(struct client_conn *client,
                                 struct qsysdb_msg_header *hdr,
                                 void *payload);
static void client_disconnect(struct client_conn *client);

static int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static struct client_conn *client_create(struct server *srv, int fd,
                                          enum conn_type type)
{
    struct client_conn *client = calloc(1, sizeof(*client));
    if (!client) return NULL;

    client->fd = fd;
    client->id = srv->next_client_id++;
    client->flags = 0;
    client->type = type;
    client->txn_id = -1;
    client->server = srv;

    client->recv_buf = malloc(RECV_BUF_SIZE);
    client->send_buf = malloc(SEND_BUF_SIZE);
    if (!client->recv_buf || !client->send_buf) {
        free(client->recv_buf);
        free(client->send_buf);
        free(client);
        return NULL;
    }

    client->recv_buf_size = RECV_BUF_SIZE;
    client->send_buf_size = SEND_BUF_SIZE;
    client->recv_len = 0;
    client->send_len = 0;
    client->send_offset = 0;

    /* Initialize ring buffer consumer */
    ringbuf_consumer_init(srv->db->shm.ring, &client->ring_consumer);

    return client;
}

static void client_destroy(struct client_conn *client)
{
    if (client->fd >= 0) {
        close(client->fd);
    }
    free(client->recv_buf);
    free(client->send_buf);
    free(client);
}

static int client_send(struct client_conn *client, const void *data, size_t len)
{
    if (client->send_len + len > client->send_buf_size) {
        return QSYSDB_ERR_FULL;
    }

    memcpy(client->send_buf + client->send_len, data, len);
    client->send_len += len;

    /* Try to send immediately */
    while (client->send_offset < client->send_len) {
        ssize_t n = send(client->fd, client->send_buf + client->send_offset,
                         client->send_len - client->send_offset, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;  /* Would block, try later */
            }
            return QSYSDB_ERR_IO;
        }
        client->send_offset += (size_t)n;
    }

    /* Reset if all data sent */
    if (client->send_offset == client->send_len) {
        client->send_offset = 0;
        client->send_len = 0;
    }

    return QSYSDB_OK;
}

static int send_response(struct client_conn *client, uint32_t msg_type,
                         uint64_t request_id, int error_code,
                         const void *payload, size_t payload_len)
{
    struct qsysdb_msg_header hdr;
    qsysdb_msg_init(&hdr, msg_type,
                    (uint32_t)(sizeof(hdr) + payload_len), request_id);
    hdr.error_code = error_code;

    int ret = client_send(client, &hdr, sizeof(hdr));
    if (ret != QSYSDB_OK) return ret;

    if (payload && payload_len > 0) {
        ret = client_send(client, payload, payload_len);
    }

    return ret;
}

static int handle_connect(struct client_conn *client,
                          struct qsysdb_msg_connect_req *req)
{
    client->flags |= req->flags;
    snprintf(client->name, sizeof(client->name), "%s", req->client_name);

    struct qsysdb_msg_connect_rsp rsp = {0};
    qsysdb_msg_init(&rsp.hdr, QSYSDB_MSG_CONNECT_RSP,
                    sizeof(rsp), req->hdr.request_id);
    rsp.client_id = client->id;
    rsp.server_version = QSYSDB_VERSION;

    /* TCP clients cannot use shared memory fast path */
    if (client->type == CONN_TYPE_TCP) {
        rsp.flags = QSYSDB_CONN_TCP;
        rsp.shm_name[0] = '\0';
    } else {
        rsp.flags = QSYSDB_CONN_UNIX | QSYSDB_CONN_SHM;
        snprintf(rsp.shm_name, sizeof(rsp.shm_name), "%s",
                 client->server->db->shm.name);
    }

    return client_send(client, &rsp, sizeof(rsp));
}

static int handle_set(struct client_conn *client,
                      struct qsysdb_msg_set_req *req)
{
    const char *path = req->data;
    const char *value = req->data + req->path_len;
    uint64_t version = 0;

    int ret = db_set(client->server->db, path, req->path_len,
                     value, req->value_len, req->flags, &version);

    struct qsysdb_msg_set_rsp rsp = {0};
    qsysdb_msg_init(&rsp.hdr, QSYSDB_MSG_SET_RSP,
                    sizeof(rsp), req->hdr.request_id);
    rsp.hdr.error_code = ret;
    rsp.version = version;
    rsp.sequence = client->server->db->shm.header->sequence;

    return client_send(client, &rsp, sizeof(rsp));
}

static int handle_get(struct client_conn *client,
                      struct qsysdb_msg_get_req *req)
{
    char value_buf[QSYSDB_MAX_VALUE];
    size_t value_len = 0;
    uint64_t version = 0, timestamp = 0;

    int ret = db_get(client->server->db, req->path, req->path_len,
                     value_buf, sizeof(value_buf), &value_len,
                     &version, &timestamp);

    size_t rsp_size = sizeof(struct qsysdb_msg_get_rsp) + value_len;
    struct qsysdb_msg_get_rsp *rsp = alloca(rsp_size);
    memset(rsp, 0, sizeof(*rsp));

    qsysdb_msg_init(&rsp->hdr, QSYSDB_MSG_GET_RSP,
                    (uint32_t)rsp_size, req->hdr.request_id);
    rsp->hdr.error_code = ret;

    if (ret == QSYSDB_OK) {
        rsp->version = version;
        rsp->timestamp_ns = timestamp;
        rsp->value_len = (uint16_t)value_len;
        memcpy(rsp->value, value_buf, value_len);
    }

    return client_send(client, rsp, rsp_size);
}

static int handle_delete(struct client_conn *client,
                         struct qsysdb_msg_delete_req *req)
{
    int ret = db_delete(client->server->db, req->path, req->path_len);

    struct qsysdb_msg_delete_rsp rsp = {0};
    qsysdb_msg_init(&rsp.hdr, QSYSDB_MSG_DELETE_RSP,
                    sizeof(rsp), req->hdr.request_id);
    rsp.hdr.error_code = ret;
    rsp.sequence = client->server->db->shm.header->sequence;

    return client_send(client, &rsp, sizeof(rsp));
}

static int handle_exists(struct client_conn *client,
                         struct qsysdb_msg_exists_req *req)
{
    bool exists = false;
    int ret = db_exists(client->server->db, req->path, req->path_len, &exists);

    struct qsysdb_msg_exists_rsp rsp = {0};
    qsysdb_msg_init(&rsp.hdr, QSYSDB_MSG_EXISTS_RSP,
                    sizeof(rsp), req->hdr.request_id);
    rsp.hdr.error_code = ret;
    rsp.exists = exists ? 1 : 0;

    return client_send(client, &rsp, sizeof(rsp));
}

static int handle_subscribe(struct client_conn *client,
                            struct qsysdb_msg_subscribe_req *req)
{
    int sub_id = 0;
    int ret = sub_add(client->server->sub_mgr, client->id,
                      req->pattern, req->pattern_len, &sub_id);

    struct qsysdb_msg_subscribe_rsp rsp = {0};
    qsysdb_msg_init(&rsp.hdr, QSYSDB_MSG_SUBSCRIBE_RSP,
                    sizeof(rsp), req->hdr.request_id);
    rsp.hdr.error_code = ret;
    rsp.subscription_id = sub_id;

    return client_send(client, &rsp, sizeof(rsp));
}

static int handle_unsubscribe(struct client_conn *client,
                              struct qsysdb_msg_unsubscribe_req *req)
{
    int ret = sub_remove(client->server->sub_mgr, req->subscription_id);

    struct qsysdb_msg_unsubscribe_rsp rsp = {0};
    qsysdb_msg_init(&rsp.hdr, QSYSDB_MSG_UNSUBSCRIBE_RSP,
                    sizeof(rsp), req->hdr.request_id);
    rsp.hdr.error_code = ret;

    return client_send(client, &rsp, sizeof(rsp));
}

static int handle_ping(struct client_conn *client,
                       struct qsysdb_msg_header *req)
{
    struct qsysdb_msg_header rsp = {0};
    qsysdb_msg_init(&rsp, QSYSDB_MSG_PONG_RSP, sizeof(rsp), req->request_id);
    return client_send(client, &rsp, sizeof(rsp));
}

static int handle_stats(struct client_conn *client,
                        struct qsysdb_msg_stats_req *req)
{
    struct qsysdb_msg_stats_rsp rsp = {0};
    qsysdb_msg_init(&rsp.hdr, QSYSDB_MSG_STATS_RSP,
                    sizeof(rsp), req->hdr.request_id);

    db_stats(client->server->db, &rsp.entry_count, &rsp.used_size,
             &rsp.total_size, &rsp.sequence, &rsp.total_sets,
             &rsp.total_gets, &rsp.total_deletes);

    rsp.client_count = (uint32_t)client->server->client_count;
    rsp.subscription_count = (uint32_t)sub_count_total(client->server->sub_mgr);

    return client_send(client, &rsp, sizeof(rsp));
}

static int handle_client_message(struct client_conn *client,
                                 struct qsysdb_msg_header *hdr,
                                 void *payload)
{
    (void)payload;  /* Payload is part of the message structure */

    client->server->total_requests++;

    switch (hdr->msg_type) {
    case QSYSDB_MSG_CONNECT_REQ:
        return handle_connect(client, (struct qsysdb_msg_connect_req *)hdr);

    case QSYSDB_MSG_SET_REQ:
        return handle_set(client, (struct qsysdb_msg_set_req *)hdr);

    case QSYSDB_MSG_GET_REQ:
        return handle_get(client, (struct qsysdb_msg_get_req *)hdr);

    case QSYSDB_MSG_DELETE_REQ:
        return handle_delete(client, (struct qsysdb_msg_delete_req *)hdr);

    case QSYSDB_MSG_EXISTS_REQ:
        return handle_exists(client, (struct qsysdb_msg_exists_req *)hdr);

    case QSYSDB_MSG_SUBSCRIBE_REQ:
        return handle_subscribe(client, (struct qsysdb_msg_subscribe_req *)hdr);

    case QSYSDB_MSG_UNSUBSCRIBE_REQ:
        return handle_unsubscribe(client, (struct qsysdb_msg_unsubscribe_req *)hdr);

    case QSYSDB_MSG_PING_REQ:
        return handle_ping(client, hdr);

    case QSYSDB_MSG_STATS_REQ:
        return handle_stats(client, (struct qsysdb_msg_stats_req *)hdr);

    default:
        return send_response(client, QSYSDB_MSG_ERROR, hdr->request_id,
                             QSYSDB_ERR_NOTSUP, NULL, 0);
    }
}

static void handle_client_data(struct client_conn *client)
{
    /* Try to receive data */
    ssize_t n = recv(client->fd, client->recv_buf + client->recv_len,
                     client->recv_buf_size - client->recv_len, 0);

    if (n <= 0) {
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return;  /* No data available */
        }
        client_disconnect(client);
        return;
    }

    client->recv_len += (size_t)n;

    /* Process complete messages */
    while (client->recv_len >= sizeof(struct qsysdb_msg_header)) {
        struct qsysdb_msg_header *hdr =
            (struct qsysdb_msg_header *)client->recv_buf;

        /* Validate header */
        int ret = qsysdb_msg_validate(hdr, client->recv_len);
        if (ret != QSYSDB_OK) {
            client_disconnect(client);
            return;
        }

        if (hdr->msg_len > client->recv_len) {
            break;  /* Need more data */
        }

        /* Process the message */
        handle_client_message(client, hdr, client->recv_buf + sizeof(*hdr));

        /* Remove processed message from buffer */
        size_t remaining = client->recv_len - hdr->msg_len;
        if (remaining > 0) {
            memmove(client->recv_buf, client->recv_buf + hdr->msg_len, remaining);
        }
        client->recv_len = remaining;
    }
}

static void client_disconnect(struct client_conn *client)
{
    struct server *srv = client->server;

    /* Remove from epoll */
    epoll_ctl(srv->epoll_fd, EPOLL_CTL_DEL, client->fd, NULL);

    /* Remove subscriptions */
    sub_remove_client(srv->sub_mgr, client->id);

    /* Abort any active transaction */
    if (client->txn_id >= 0) {
        db_txn_abort(srv->db, client->txn_id);
    }

    /* Remove from client list */
    pthread_mutex_lock(&srv->clients_lock);
    if (client->prev) {
        client->prev->next = client->next;
    } else {
        srv->clients = client->next;
    }
    if (client->next) {
        client->next->prev = client->prev;
    }
    srv->client_count--;
    pthread_mutex_unlock(&srv->clients_lock);

    client_destroy(client);
}

static void add_client_to_server(struct server *srv, struct client_conn *client)
{
    /* Add to epoll */
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
    ev.data.ptr = client;
    if (epoll_ctl(srv->epoll_fd, EPOLL_CTL_ADD, client->fd, &ev) < 0) {
        client_destroy(client);
        return;
    }

    /* Add to client list */
    pthread_mutex_lock(&srv->clients_lock);
    client->next = srv->clients;
    if (srv->clients) {
        srv->clients->prev = client;
    }
    srv->clients = client;
    srv->client_count++;
    srv->total_connections++;
    pthread_mutex_unlock(&srv->clients_lock);
}

static void handle_new_unix_connection(struct server *srv)
{
    struct sockaddr_un addr;
    socklen_t addr_len = sizeof(addr);

    int fd = accept(srv->unix_fd, (struct sockaddr *)&addr, &addr_len);
    if (fd < 0) {
        return;
    }

    set_nonblocking(fd);

    struct client_conn *client = client_create(srv, fd, CONN_TYPE_UNIX);
    if (!client) {
        close(fd);
        return;
    }

    client->flags |= QSYSDB_CONN_UNIX;
    snprintf(client->remote_addr, sizeof(client->remote_addr), "unix");

    srv->unix_connections++;
    add_client_to_server(srv, client);
}

static void handle_new_tcp_connection(struct server *srv)
{
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    int fd = accept(srv->tcp_fd, (struct sockaddr *)&addr, &addr_len);
    if (fd < 0) {
        return;
    }

    set_nonblocking(fd);

    /* Set TCP options */
    int optval = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval));
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval));

    struct client_conn *client = client_create(srv, fd, CONN_TYPE_TCP);
    if (!client) {
        close(fd);
        return;
    }

    client->flags |= QSYSDB_CONN_TCP;
    inet_ntop(AF_INET, &addr.sin_addr, client->remote_addr,
              sizeof(client->remote_addr));
    client->remote_port = ntohs(addr.sin_port);

    srv->tcp_connections++;
    add_client_to_server(srv, client);
}

/* Tags to identify listen sockets in epoll */
#define EPOLL_TAG_UNIX  ((void *)1)
#define EPOLL_TAG_TCP   ((void *)2)

static void *event_loop(void *arg)
{
    struct server *srv = arg;
    struct epoll_event events[MAX_EVENTS];

    while (srv->running) {
        int nfds = epoll_wait(srv->epoll_fd, events, MAX_EVENTS, 100);

        for (int i = 0; i < nfds; i++) {
            if (events[i].data.ptr == EPOLL_TAG_UNIX) {
                /* New Unix socket connection */
                handle_new_unix_connection(srv);
            } else if (events[i].data.ptr == EPOLL_TAG_TCP) {
                /* New TCP connection */
                handle_new_tcp_connection(srv);
            } else {
                /* Client activity */
                struct client_conn *client = events[i].data.ptr;

                if (events[i].events & (EPOLLERR | EPOLLHUP)) {
                    client_disconnect(client);
                } else {
                    if (events[i].events & EPOLLIN) {
                        handle_client_data(client);
                    }
                    if (events[i].events & EPOLLOUT) {
                        /* Try to send pending data */
                        while (client->send_offset < client->send_len) {
                            ssize_t n = send(client->fd,
                                             client->send_buf + client->send_offset,
                                             client->send_len - client->send_offset,
                                             MSG_NOSIGNAL);
                            if (n < 0) {
                                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                    break;
                                }
                                client_disconnect(client);
                                break;
                            }
                            client->send_offset += (size_t)n;
                        }
                        if (client->send_offset == client->send_len) {
                            client->send_offset = 0;
                            client->send_len = 0;
                        }
                    }
                }
            }
        }
    }

    return NULL;
}

void server_config_init(struct server_config *config)
{
    memset(config, 0, sizeof(*config));
    config->unix_enabled = true;
    snprintf(config->unix_path, sizeof(config->unix_path), "%s",
             QSYSDB_SOCKET_PATH);
    config->tcp_enabled = false;
    snprintf(config->tcp_bind, sizeof(config->tcp_bind), "%s",
             QSYSDB_TCP_BIND_DEFAULT);
    config->tcp_port = QSYSDB_TCP_PORT_DEFAULT;
}

static int setup_unix_socket(struct server *srv)
{
    const char *socket_path = srv->config.unix_path;

    /* Remove existing socket file */
    unlink(socket_path);

    /* Create socket */
    srv->unix_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (srv->unix_fd < 0) {
        return QSYSDB_ERR_IO;
    }

    /* Bind */
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    size_t path_len = strlen(socket_path);
    if (path_len >= sizeof(addr.sun_path)) {
        path_len = sizeof(addr.sun_path) - 1;
    }
    memcpy(addr.sun_path, socket_path, path_len);
    addr.sun_path[path_len] = '\0';

    if (bind(srv->unix_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(srv->unix_fd);
        srv->unix_fd = -1;
        return QSYSDB_ERR_IO;
    }

    /* Listen */
    if (listen(srv->unix_fd, QSYSDB_SOCKET_BACKLOG) < 0) {
        close(srv->unix_fd);
        srv->unix_fd = -1;
        unlink(socket_path);
        return QSYSDB_ERR_IO;
    }

    set_nonblocking(srv->unix_fd);

    /* Add listen socket to epoll */
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.ptr = EPOLL_TAG_UNIX;
    if (epoll_ctl(srv->epoll_fd, EPOLL_CTL_ADD, srv->unix_fd, &ev) < 0) {
        close(srv->unix_fd);
        srv->unix_fd = -1;
        unlink(socket_path);
        return QSYSDB_ERR_IO;
    }

    return QSYSDB_OK;
}

static int setup_tcp_socket(struct server *srv)
{
    const char *bind_addr = srv->config.tcp_bind;
    uint16_t port = srv->config.tcp_port;

    /* Create TCP socket */
    srv->tcp_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (srv->tcp_fd < 0) {
        return QSYSDB_ERR_IO;
    }

    /* Set socket options */
    int optval = 1;
    setsockopt(srv->tcp_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    setsockopt(srv->tcp_fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));

    /* Bind */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, bind_addr, &addr.sin_addr) <= 0) {
        close(srv->tcp_fd);
        srv->tcp_fd = -1;
        return QSYSDB_ERR_INVALID;
    }

    if (bind(srv->tcp_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(srv->tcp_fd);
        srv->tcp_fd = -1;
        return QSYSDB_ERR_IO;
    }

    /* Listen */
    if (listen(srv->tcp_fd, QSYSDB_SOCKET_BACKLOG) < 0) {
        close(srv->tcp_fd);
        srv->tcp_fd = -1;
        return QSYSDB_ERR_IO;
    }

    set_nonblocking(srv->tcp_fd);

    /* Add TCP socket to epoll */
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.ptr = EPOLL_TAG_TCP;
    if (epoll_ctl(srv->epoll_fd, EPOLL_CTL_ADD, srv->tcp_fd, &ev) < 0) {
        close(srv->tcp_fd);
        srv->tcp_fd = -1;
        return QSYSDB_ERR_IO;
    }

    return QSYSDB_OK;
}

int server_init(struct server *srv, struct server_config *config,
                struct qsysdb_db *db, struct sub_manager *sub_mgr)
{
    memset(srv, 0, sizeof(*srv));
    srv->unix_fd = -1;
    srv->tcp_fd = -1;
    srv->epoll_fd = -1;

    if (config) {
        memcpy(&srv->config, config, sizeof(*config));
    } else {
        server_config_init(&srv->config);
    }

    srv->db = db;
    srv->sub_mgr = sub_mgr;
    srv->next_client_id = 1;

    if (pthread_mutex_init(&srv->clients_lock, NULL) != 0) {
        return QSYSDB_ERR_INTERNAL;
    }

    /* Create epoll instance */
    srv->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (srv->epoll_fd < 0) {
        return QSYSDB_ERR_IO;
    }

    /* Setup Unix socket if enabled */
    if (srv->config.unix_enabled) {
        int ret = setup_unix_socket(srv);
        if (ret != QSYSDB_OK) {
            close(srv->epoll_fd);
            return ret;
        }
    }

    /* Setup TCP socket if enabled */
    if (srv->config.tcp_enabled) {
        int ret = setup_tcp_socket(srv);
        if (ret != QSYSDB_OK) {
            if (srv->unix_fd >= 0) {
                close(srv->unix_fd);
                unlink(srv->config.unix_path);
            }
            close(srv->epoll_fd);
            return ret;
        }
    }

    return QSYSDB_OK;
}

int server_enable_tcp(struct server *srv, const char *bind_addr, uint16_t port)
{
    if (srv->tcp_fd >= 0) {
        /* TCP already enabled */
        return QSYSDB_OK;
    }

    if (bind_addr) {
        snprintf(srv->config.tcp_bind, sizeof(srv->config.tcp_bind),
                 "%s", bind_addr);
    }
    if (port > 0) {
        srv->config.tcp_port = port;
    }
    srv->config.tcp_enabled = true;

    return setup_tcp_socket(srv);
}

int server_start(struct server *srv)
{
    srv->running = true;

    if (pthread_create(&srv->event_thread, NULL, event_loop, srv) != 0) {
        srv->running = false;
        return QSYSDB_ERR_INTERNAL;
    }

    return QSYSDB_OK;
}

void server_stop(struct server *srv)
{
    srv->running = false;

    if (srv->event_thread) {
        pthread_join(srv->event_thread, NULL);
    }
}

void server_shutdown(struct server *srv)
{
    server_stop(srv);

    /* Disconnect all clients */
    pthread_mutex_lock(&srv->clients_lock);
    while (srv->clients) {
        struct client_conn *client = srv->clients;
        srv->clients = client->next;
        client_destroy(client);
    }
    pthread_mutex_unlock(&srv->clients_lock);

    if (srv->unix_fd >= 0) {
        close(srv->unix_fd);
        srv->unix_fd = -1;
    }
    if (srv->tcp_fd >= 0) {
        close(srv->tcp_fd);
        srv->tcp_fd = -1;
    }
    if (srv->epoll_fd >= 0) {
        close(srv->epoll_fd);
        srv->epoll_fd = -1;
    }

    if (srv->config.unix_enabled) {
        unlink(srv->config.unix_path);
    }
    pthread_mutex_destroy(&srv->clients_lock);
}

int server_broadcast_notification(struct server *srv,
                                  const struct qsysdb_notification *notif)
{
    int client_ids[QSYSDB_MAX_CLIENTS];
    int sub_ids[QSYSDB_MAX_CLIENTS];

    int match_count = sub_match(srv->sub_mgr, notif->path, notif->path_len,
                                client_ids, sub_ids, QSYSDB_MAX_CLIENTS);

    if (match_count == 0) {
        return QSYSDB_OK;
    }

    /* Build notification message */
    size_t msg_size = sizeof(struct qsysdb_msg_notification) +
                      notif->path_len + 1;  /* +1 for null terminator */
    struct qsysdb_msg_notification *msg = alloca(msg_size);
    memset(msg, 0, sizeof(*msg));

    qsysdb_msg_init(&msg->hdr, QSYSDB_MSG_NOTIFICATION,
                    (uint32_t)msg_size, 0);
    msg->event_type = notif->event_type;
    msg->sequence = notif->sequence;
    msg->entry_version = notif->entry_version;
    msg->timestamp_ns = notif->timestamp_ns;
    msg->path_len = (uint16_t)notif->path_len;
    memcpy(msg->data, notif->path, notif->path_len);

    /* Send to matching clients */
    pthread_mutex_lock(&srv->clients_lock);

    for (int i = 0; i < match_count; i++) {
        int client_id = client_ids[i];

        /* Find client */
        struct client_conn *client = srv->clients;
        while (client) {
            if (client->id == client_id) {
                msg->subscription_id = sub_ids[i];
                client_send(client, msg, msg_size);
                break;
            }
            client = client->next;
        }
    }

    pthread_mutex_unlock(&srv->clients_lock);

    return QSYSDB_OK;
}

void server_stats(struct server *srv, int *client_count,
                  uint64_t *total_connections, uint64_t *total_requests)
{
    if (client_count) *client_count = srv->client_count;
    if (total_connections) *total_connections = srv->total_connections;
    if (total_requests) *total_requests = srv->total_requests;
}
