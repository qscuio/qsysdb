/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * async_client.c - Professional async client implementation
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
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>

#include <qsysdb/types.h>
#include <qsysdb/protocol.h>
#include <qsysdb/async.h>

/* ============================================
 * Internal Structures
 * ============================================ */

#define MAX_PENDING_OPS     1024
#define MAX_WATCHES         256
#define RECV_BUF_SIZE       (2 * 1024 * 1024)
#define SEND_BUF_SIZE       (1 * 1024 * 1024)
#define MAX_BATCH_OPS       256
#define MAX_CLUSTER_SERVERS 16

/* Pending operation */
struct qsysdb_op {
    uint64_t request_id;
    int type;                       /* Message type */
    void *callback;                 /* Generic callback pointer */
    void *userdata;
    bool cancelled;
    struct qsysdb_op *next;
};

/* Watch (subscription) */
struct qsysdb_watch {
    qsysdb_async_t *client;
    int subscription_id;
    char *pattern;
    bool started;
    bool paused;
    bool get_initial;
    int queue_size;

    /* Handlers */
    qsysdb_event_fn on_event;
    void *on_event_data;
    qsysdb_event_fn on_create;
    void *on_create_data;
    qsysdb_event_fn on_update;
    void *on_update_data;
    qsysdb_event_fn on_delete;
    void *on_delete_data;

    struct qsysdb_watch *next;
};

/* Batch operation */
struct batch_entry {
    int op_type;                    /* QSYSDB_MSG_SET_REQ or DELETE */
    char *path;
    char *value;                    /* NULL for delete */
};

struct qsysdb_batch {
    qsysdb_async_t *client;
    struct batch_entry *entries;
    int count;
    int capacity;
};

/* Cluster server entry */
struct cluster_server {
    char host[256];
    uint16_t port;
    int fd;
    bool connected;
    bool is_leader;
    uint64_t latency_us;        /* RTT in microseconds */
};

/* Async client */
struct qsysdb_async {
    /* Connection state */
    int fd;
    bool connected;
    bool connecting;
    int conn_flags;

    /* Connection target */
    enum { CONN_UNIX, CONN_TCP } conn_type;
    char *socket_path;
    char *tcp_host;
    uint16_t tcp_port;

    /* Reconnection */
    bool auto_reconnect;
    int reconnect_interval_ms;

    /* Buffers */
    uint8_t *recv_buf;
    size_t recv_buf_size;
    size_t recv_len;

    uint8_t *send_buf;
    size_t send_buf_size;
    size_t send_len;
    size_t send_offset;

    /* Request tracking */
    uint64_t next_request_id;
    struct qsysdb_op *pending_ops;
    int pending_count;

    /* Watches */
    struct qsysdb_watch *watches;
    int watch_count;

    /* Client ID (from server) */
    int client_id;

    /* Handlers */
    qsysdb_state_fn on_state;
    void *on_state_data;
    qsysdb_error_fn on_error;
    void *on_error_data;

    /* Run loop control */
    volatile bool running;

    /* Statistics */
    qsysdb_client_stats_t stats;

    /* Cluster support */
    bool cluster_mode;
    struct cluster_server servers[MAX_CLUSTER_SERVERS];
    int server_count;
    int current_server;         /* Index of primary server */
    int leader_index;           /* Index of known leader (-1 if unknown) */

    /* Thread safety */
    pthread_mutex_t lock;
};

/* ============================================
 * Internal Helpers
 * ============================================ */

static int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void invoke_error(qsysdb_async_t *client, int error, const char *msg)
{
    if (client->on_error) {
        client->on_error(client, error, msg, client->on_error_data);
    }
}

static void invoke_state_change(qsysdb_async_t *client, bool connected)
{
    if (client->on_state) {
        client->on_state(client, connected, client->on_state_data);
    }
}

static struct qsysdb_op *find_op_by_request_id(qsysdb_async_t *client, uint64_t id)
{
    struct qsysdb_op *op = client->pending_ops;
    struct qsysdb_op *prev = NULL;

    while (op) {
        if (op->request_id == id) {
            /* Remove from list */
            if (prev) {
                prev->next = op->next;
            } else {
                client->pending_ops = op->next;
            }
            client->pending_count--;
            return op;
        }
        prev = op;
        op = op->next;
    }
    return NULL;
}

static struct qsysdb_watch *find_watch_by_sub_id(qsysdb_async_t *client, int sub_id)
{
    struct qsysdb_watch *w = client->watches;
    while (w) {
        if (w->subscription_id == sub_id) {
            return w;
        }
        w = w->next;
    }
    return NULL;
}

static int queue_send(qsysdb_async_t *client, void *data, size_t len)
{
    if (client->send_len + len > client->send_buf_size) {
        return QSYSDB_ERR_FULL;
    }
    memcpy(client->send_buf + client->send_len, data, len);
    client->send_len += len;
    client->stats.bytes_sent += len;
    return QSYSDB_OK;
}

static struct qsysdb_op *create_op(qsysdb_async_t *client, int type,
                                    void *callback, void *userdata)
{
    struct qsysdb_op *op = calloc(1, sizeof(*op));
    if (!op) return NULL;

    op->request_id = client->next_request_id++;
    op->type = type;
    op->callback = callback;
    op->userdata = userdata;
    op->cancelled = false;

    /* Add to pending list */
    op->next = client->pending_ops;
    client->pending_ops = op;
    client->pending_count++;

    return op;
}

/* ============================================
 * Connection Management
 * ============================================ */

qsysdb_async_t *qsysdb_async_new(void)
{
    qsysdb_async_t *client = calloc(1, sizeof(*client));
    if (!client) return NULL;

    client->fd = -1;
    client->next_request_id = 1;

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

    pthread_mutex_init(&client->lock, NULL);

    return client;
}

void qsysdb_async_free(qsysdb_async_t *client)
{
    if (!client) return;

    qsysdb_async_disconnect(client);

    /* Free pending ops */
    struct qsysdb_op *op = client->pending_ops;
    while (op) {
        struct qsysdb_op *next = op->next;
        free(op);
        op = next;
    }

    /* Free watches */
    struct qsysdb_watch *w = client->watches;
    while (w) {
        struct qsysdb_watch *next = w->next;
        free(w->pattern);
        free(w);
        w = next;
    }

    free(client->socket_path);
    free(client->tcp_host);
    free(client->recv_buf);
    free(client->send_buf);
    pthread_mutex_destroy(&client->lock);
    free(client);
}

void qsysdb_async_on_state(qsysdb_async_t *client,
                           qsysdb_state_fn handler, void *userdata)
{
    client->on_state = handler;
    client->on_state_data = userdata;
}

void qsysdb_async_on_error(qsysdb_async_t *client,
                           qsysdb_error_fn handler, void *userdata)
{
    client->on_error = handler;
    client->on_error_data = userdata;
}

void qsysdb_async_set_reconnect(qsysdb_async_t *client,
                                 bool auto_reconnect, int interval_ms)
{
    client->auto_reconnect = auto_reconnect;
    client->reconnect_interval_ms = interval_ms > 0 ? interval_ms : 1000;
}

static int do_connect_unix(qsysdb_async_t *client, const char *path)
{
    client->fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (client->fd < 0) {
        return QSYSDB_ERR_IO;
    }

    set_nonblocking(client->fd);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    int ret = connect(client->fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0 && errno != EINPROGRESS) {
        close(client->fd);
        client->fd = -1;
        return QSYSDB_ERR_CONNECT;
    }

    client->connecting = (errno == EINPROGRESS);
    return QSYSDB_OK;
}

static int do_connect_tcp(qsysdb_async_t *client, const char *host, uint16_t port)
{
    client->fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (client->fd < 0) {
        return QSYSDB_ERR_IO;
    }

    set_nonblocking(client->fd);

    int opt = 1;
    setsockopt(client->fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
    setsockopt(client->fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        close(client->fd);
        client->fd = -1;
        return QSYSDB_ERR_INVALID;
    }

    int ret = connect(client->fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0 && errno != EINPROGRESS) {
        close(client->fd);
        client->fd = -1;
        return QSYSDB_ERR_CONNECT;
    }

    client->connecting = (errno == EINPROGRESS);
    return QSYSDB_OK;
}

static int send_connect_request(qsysdb_async_t *client)
{
    struct qsysdb_msg_connect_req req = {0};
    qsysdb_msg_init(&req.hdr, QSYSDB_MSG_CONNECT_REQ,
                    sizeof(req), client->next_request_id++);
    req.client_version = QSYSDB_VERSION;
    req.flags = client->conn_flags;
    snprintf(req.client_name, sizeof(req.client_name), "async-client-%d", getpid());

    return queue_send(client, &req, sizeof(req));
}

int qsysdb_async_connect(qsysdb_async_t *client,
                         const char *socket_path, int flags)
{
    if (client->connected || client->connecting) {
        return QSYSDB_ERR_BUSY;
    }

    const char *path = socket_path ? socket_path : QSYSDB_SOCKET_PATH;
    free(client->socket_path);
    client->socket_path = strdup(path);
    client->conn_type = CONN_UNIX;
    client->conn_flags = flags;

    int ret = do_connect_unix(client, path);
    if (ret != QSYSDB_OK) {
        return ret;
    }

    if (!client->connecting) {
        /* Connected immediately */
        client->connected = true;
        send_connect_request(client);
        invoke_state_change(client, true);
    }

    return QSYSDB_OK;
}

int qsysdb_async_connect_tcp(qsysdb_async_t *client,
                              const char *host, uint16_t port, int flags)
{
    if (client->connected || client->connecting) {
        return QSYSDB_ERR_BUSY;
    }

    const char *h = host ? host : "127.0.0.1";
    uint16_t p = port > 0 ? port : QSYSDB_TCP_PORT_DEFAULT;

    free(client->tcp_host);
    client->tcp_host = strdup(h);
    client->tcp_port = p;
    client->conn_type = CONN_TCP;
    client->conn_flags = flags;

    int ret = do_connect_tcp(client, h, p);
    if (ret != QSYSDB_OK) {
        return ret;
    }

    if (!client->connecting) {
        client->connected = true;
        send_connect_request(client);
        invoke_state_change(client, true);
    }

    return QSYSDB_OK;
}

void qsysdb_async_disconnect(qsysdb_async_t *client)
{
    if (client->fd >= 0) {
        close(client->fd);
        client->fd = -1;
    }

    bool was_connected = client->connected;
    client->connected = false;
    client->connecting = false;
    client->recv_len = 0;
    client->send_len = 0;
    client->send_offset = 0;

    if (was_connected) {
        invoke_state_change(client, false);
    }
}

bool qsysdb_async_is_connected(qsysdb_async_t *client)
{
    return client->connected;
}

/* ============================================
 * Event Loop Integration
 * ============================================ */

int qsysdb_async_fd(qsysdb_async_t *client)
{
    return client->fd;
}

int qsysdb_async_events(qsysdb_async_t *client)
{
    int events = QSYSDB_WAIT_READ;  /* Always want to read */
    if (client->send_len > client->send_offset || client->connecting) {
        events |= QSYSDB_WAIT_WRITE;  /* Have data to send or connecting */
    }
    return events;
}

static void handle_response(qsysdb_async_t *client, struct qsysdb_msg_header *hdr)
{
    struct qsysdb_op *op = find_op_by_request_id(client, hdr->request_id);
    if (!op || op->cancelled) {
        free(op);
        return;
    }

    client->stats.ops_completed++;
    if (hdr->error_code != QSYSDB_OK) {
        client->stats.ops_failed++;
    }

    switch (hdr->msg_type) {
    case QSYSDB_MSG_CONNECT_RSP: {
        struct qsysdb_msg_connect_rsp *rsp = (struct qsysdb_msg_connect_rsp *)hdr;
        client->client_id = rsp->client_id;
        /* Connect doesn't have a user callback */
        break;
    }

    case QSYSDB_MSG_SET_RSP: {
        struct qsysdb_msg_set_rsp *rsp = (struct qsysdb_msg_set_rsp *)hdr;
        if (op->callback) {
            qsysdb_result_t result = {
                .error = hdr->error_code,
                .version = rsp->version,
                .sequence = rsp->sequence
            };
            ((qsysdb_complete_fn)op->callback)(&result, op->userdata);
        }
        break;
    }

    case QSYSDB_MSG_GET_RSP: {
        struct qsysdb_msg_get_rsp *rsp = (struct qsysdb_msg_get_rsp *)hdr;
        if (op->callback) {
            qsysdb_get_result_t result = {
                .base = {
                    .error = hdr->error_code,
                    .version = rsp->version,
                    .timestamp = rsp->timestamp_ns
                },
                .value = (const char *)rsp->value,
                .value_len = rsp->value_len
            };
            ((qsysdb_get_fn)op->callback)(&result, op->userdata);
        }
        break;
    }

    case QSYSDB_MSG_DELETE_RSP:
    case QSYSDB_MSG_EXISTS_RSP: {
        if (op->callback) {
            qsysdb_result_t result = {
                .error = hdr->error_code
            };
            ((qsysdb_complete_fn)op->callback)(&result, op->userdata);
        }
        break;
    }

    case QSYSDB_MSG_SUBSCRIBE_RSP: {
        struct qsysdb_msg_subscribe_rsp *rsp = (struct qsysdb_msg_subscribe_rsp *)hdr;
        /* Find watch and set subscription ID */
        /* The watch callback will handle this */
        (void)rsp;
        break;
    }

    default:
        break;
    }

    free(op);
}

static void handle_notification(qsysdb_async_t *client, struct qsysdb_msg_notification *notif)
{
    client->stats.events_received++;

    struct qsysdb_watch *w = find_watch_by_sub_id(client, notif->subscription_id);
    if (!w || w->paused) {
        return;
    }

    qsysdb_event_t event = {
        .type = (int)notif->event_type,
        .path = (const char *)notif->data,
        .path_len = notif->path_len,
        .value = NULL,  /* TODO: Fetch value if needed */
        .version = notif->entry_version,
        .timestamp = notif->timestamp_ns,
        .sequence = notif->sequence,
        .subscription_id = notif->subscription_id
    };

    /* Call specific handler based on event type */
    qsysdb_event_fn handler = NULL;
    void *handler_data = NULL;

    switch (notif->event_type) {
    case QSYSDB_EVENT_CREATE:
        handler = w->on_create ? w->on_create : w->on_event;
        handler_data = w->on_create ? w->on_create_data : w->on_event_data;
        break;
    case QSYSDB_EVENT_UPDATE:
        handler = w->on_update ? w->on_update : w->on_event;
        handler_data = w->on_update ? w->on_update_data : w->on_event_data;
        break;
    case QSYSDB_EVENT_DELETE:
    case QSYSDB_EVENT_DELETE_TREE:
        handler = w->on_delete ? w->on_delete : w->on_event;
        handler_data = w->on_delete ? w->on_delete_data : w->on_event_data;
        break;
    default:
        handler = w->on_event;
        handler_data = w->on_event_data;
        break;
    }

    if (handler) {
        handler(&event, handler_data);
    }
}

static int process_messages(qsysdb_async_t *client)
{
    int processed = 0;

    while (client->recv_len >= sizeof(struct qsysdb_msg_header)) {
        struct qsysdb_msg_header *hdr = (struct qsysdb_msg_header *)client->recv_buf;

        int ret = qsysdb_msg_validate(hdr, client->recv_len);
        if (ret != QSYSDB_OK) {
            invoke_error(client, ret, "Invalid message received");
            qsysdb_async_disconnect(client);
            return -1;
        }

        if (hdr->msg_len > client->recv_len) {
            break;  /* Need more data */
        }

        /* Handle message */
        if (hdr->msg_type == QSYSDB_MSG_NOTIFICATION) {
            handle_notification(client, (struct qsysdb_msg_notification *)hdr);
        } else {
            handle_response(client, hdr);
        }

        processed++;

        /* Remove processed message */
        size_t remaining = client->recv_len - hdr->msg_len;
        if (remaining > 0) {
            memmove(client->recv_buf, client->recv_buf + hdr->msg_len, remaining);
        }
        client->recv_len = remaining;
    }

    return processed;
}

int qsysdb_async_process(qsysdb_async_t *client)
{
    if (client->fd < 0) {
        return QSYSDB_ERR_DISCONNECTED;
    }

    /* Handle connecting state */
    if (client->connecting) {
        int err = 0;
        socklen_t len = sizeof(err);
        getsockopt(client->fd, SOL_SOCKET, SO_ERROR, &err, &len);

        if (err != 0) {
            invoke_error(client, QSYSDB_ERR_CONNECT, "Connection failed");
            qsysdb_async_disconnect(client);
            return QSYSDB_ERR_CONNECT;
        }

        client->connecting = false;
        client->connected = true;
        send_connect_request(client);
        invoke_state_change(client, true);
    }

    /* Try to send pending data */
    while (client->send_offset < client->send_len) {
        ssize_t n = send(client->fd, client->send_buf + client->send_offset,
                         client->send_len - client->send_offset, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;  /* Would block */
            }
            invoke_error(client, QSYSDB_ERR_IO, "Send failed");
            qsysdb_async_disconnect(client);
            return QSYSDB_ERR_IO;
        }
        client->send_offset += n;
    }

    /* Reset send buffer if fully sent */
    if (client->send_offset == client->send_len) {
        client->send_offset = 0;
        client->send_len = 0;
    }

    /* Try to receive data */
    ssize_t n = recv(client->fd, client->recv_buf + client->recv_len,
                     client->recv_buf_size - client->recv_len, 0);
    if (n < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            invoke_error(client, QSYSDB_ERR_IO, "Receive failed");
            qsysdb_async_disconnect(client);
            return QSYSDB_ERR_IO;
        }
    } else if (n == 0) {
        /* Connection closed */
        invoke_error(client, QSYSDB_ERR_DISCONNECTED, "Connection closed");
        qsysdb_async_disconnect(client);
        return QSYSDB_ERR_DISCONNECTED;
    } else {
        client->recv_len += n;
        client->stats.bytes_received += n;
    }

    /* Process received messages */
    return process_messages(client);
}

int qsysdb_async_poll(qsysdb_async_t *client, int timeout_ms)
{
    if (client->fd < 0) {
        return QSYSDB_ERR_DISCONNECTED;
    }

    struct pollfd pfd = {
        .fd = client->fd,
        .events = POLLIN
    };

    if (client->send_len > client->send_offset || client->connecting) {
        pfd.events |= POLLOUT;
    }

    int ret = poll(&pfd, 1, timeout_ms);
    if (ret < 0) {
        if (errno == EINTR) {
            return 0;
        }
        return QSYSDB_ERR_IO;
    }

    if (ret == 0) {
        return 0;  /* Timeout */
    }

    if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
        qsysdb_async_disconnect(client);
        return QSYSDB_ERR_DISCONNECTED;
    }

    return qsysdb_async_process(client);
}

int qsysdb_async_run(qsysdb_async_t *client)
{
    client->running = true;

    while (client->running && client->connected) {
        int ret = qsysdb_async_poll(client, 100);
        if (ret < 0 && ret != QSYSDB_ERR_AGAIN) {
            return ret;
        }
    }

    return QSYSDB_OK;
}

void qsysdb_async_stop(qsysdb_async_t *client)
{
    client->running = false;
}

/* ============================================
 * Async Operations
 * ============================================ */

qsysdb_op_t *qsysdb_async_set(qsysdb_async_t *client,
                               const char *path, const char *value,
                               qsysdb_complete_fn callback, void *userdata)
{
    return qsysdb_async_set_ex(client, path, value, 0, callback, userdata);
}

qsysdb_op_t *qsysdb_async_set_ex(qsysdb_async_t *client,
                                  const char *path, const char *value,
                                  uint32_t flags,
                                  qsysdb_complete_fn callback, void *userdata)
{
    if (!client->connected) return NULL;

    size_t path_len = strlen(path);
    size_t value_len = strlen(value);
    size_t msg_size = sizeof(struct qsysdb_msg_set_req) + path_len + 1 + value_len + 1;

    struct qsysdb_op *op = create_op(client, QSYSDB_MSG_SET_REQ, callback, userdata);
    if (!op) return NULL;

    uint8_t *msg = alloca(msg_size);
    struct qsysdb_msg_set_req *req = (struct qsysdb_msg_set_req *)msg;
    memset(req, 0, sizeof(*req));

    qsysdb_msg_init(&req->hdr, QSYSDB_MSG_SET_REQ, msg_size, op->request_id);
    req->path_len = path_len;
    req->value_len = value_len;
    req->flags = flags;

    char *data = (char *)(req + 1);
    memcpy(data, path, path_len + 1);
    memcpy(data + path_len + 1, value, value_len + 1);

    if (queue_send(client, msg, msg_size) != QSYSDB_OK) {
        op->cancelled = true;
        return NULL;
    }

    client->stats.ops_sent++;
    return op;
}

qsysdb_op_t *qsysdb_async_get(qsysdb_async_t *client,
                               const char *path,
                               qsysdb_get_fn callback, void *userdata)
{
    if (!client->connected) return NULL;

    size_t path_len = strlen(path);
    size_t msg_size = sizeof(struct qsysdb_msg_get_req) + path_len + 1;

    struct qsysdb_op *op = create_op(client, QSYSDB_MSG_GET_REQ, callback, userdata);
    if (!op) return NULL;

    uint8_t *msg = alloca(msg_size);
    struct qsysdb_msg_get_req *req = (struct qsysdb_msg_get_req *)msg;
    memset(req, 0, sizeof(*req));

    qsysdb_msg_init(&req->hdr, QSYSDB_MSG_GET_REQ, msg_size, op->request_id);
    req->path_len = path_len;
    memcpy(req->path, path, path_len + 1);

    if (queue_send(client, msg, msg_size) != QSYSDB_OK) {
        op->cancelled = true;
        return NULL;
    }

    client->stats.ops_sent++;
    return op;
}

qsysdb_op_t *qsysdb_async_delete(qsysdb_async_t *client,
                                  const char *path,
                                  qsysdb_complete_fn callback, void *userdata)
{
    if (!client->connected) return NULL;

    size_t path_len = strlen(path);
    size_t msg_size = sizeof(struct qsysdb_msg_delete_req) + path_len + 1;

    struct qsysdb_op *op = create_op(client, QSYSDB_MSG_DELETE_REQ, callback, userdata);
    if (!op) return NULL;

    uint8_t *msg = alloca(msg_size);
    struct qsysdb_msg_delete_req *req = (struct qsysdb_msg_delete_req *)msg;
    memset(req, 0, sizeof(*req));

    qsysdb_msg_init(&req->hdr, QSYSDB_MSG_DELETE_REQ, msg_size, op->request_id);
    req->path_len = path_len;
    memcpy(req->path, path, path_len + 1);

    if (queue_send(client, msg, msg_size) != QSYSDB_OK) {
        op->cancelled = true;
        return NULL;
    }

    client->stats.ops_sent++;
    return op;
}

qsysdb_op_t *qsysdb_async_exists(qsysdb_async_t *client,
                                  const char *path,
                                  qsysdb_complete_fn callback, void *userdata)
{
    if (!client->connected) return NULL;

    size_t path_len = strlen(path);
    size_t msg_size = sizeof(struct qsysdb_msg_exists_req) + path_len + 1;

    struct qsysdb_op *op = create_op(client, QSYSDB_MSG_EXISTS_REQ, callback, userdata);
    if (!op) return NULL;

    uint8_t *msg = alloca(msg_size);
    struct qsysdb_msg_exists_req *req = (struct qsysdb_msg_exists_req *)msg;
    memset(req, 0, sizeof(*req));

    qsysdb_msg_init(&req->hdr, QSYSDB_MSG_EXISTS_REQ, msg_size, op->request_id);
    req->path_len = path_len;
    memcpy(req->path, path, path_len + 1);

    if (queue_send(client, msg, msg_size) != QSYSDB_OK) {
        op->cancelled = true;
        return NULL;
    }

    client->stats.ops_sent++;
    return op;
}

qsysdb_op_t *qsysdb_async_list(qsysdb_async_t *client,
                                const char *prefix,
                                qsysdb_list_fn callback, void *userdata)
{
    /* TODO: Implement list with streaming response */
    (void)client; (void)prefix; (void)callback; (void)userdata;
    return NULL;
}

qsysdb_op_t *qsysdb_async_delete_tree(qsysdb_async_t *client,
                                       const char *prefix,
                                       qsysdb_complete_fn callback, void *userdata)
{
    /* TODO: Implement delete tree */
    (void)client; (void)prefix; (void)callback; (void)userdata;
    return NULL;
}

void qsysdb_op_cancel(qsysdb_op_t *op)
{
    if (op) {
        op->cancelled = true;
    }
}

/* ============================================
 * Watch (Subscription) API
 * ============================================ */

qsysdb_watch_t *qsysdb_watch_create(qsysdb_async_t *client)
{
    if (!client) return NULL;

    qsysdb_watch_t *w = calloc(1, sizeof(*w));
    if (!w) return NULL;

    w->client = client;
    w->subscription_id = -1;
    return w;
}

qsysdb_watch_t *qsysdb_watch_pattern(qsysdb_watch_t *watch, const char *pattern)
{
    if (!watch) return NULL;
    if (!pattern) return watch;

    free(watch->pattern);
    watch->pattern = strdup(pattern);
    return watch;
}

qsysdb_watch_t *qsysdb_watch_on_event(qsysdb_watch_t *watch,
                                       qsysdb_event_fn handler, void *userdata)
{
    if (!watch) return NULL;
    watch->on_event = handler;
    watch->on_event_data = userdata;
    return watch;
}

qsysdb_watch_t *qsysdb_watch_on_create(qsysdb_watch_t *watch,
                                        qsysdb_event_fn handler, void *userdata)
{
    if (!watch) return NULL;
    watch->on_create = handler;
    watch->on_create_data = userdata;
    return watch;
}

qsysdb_watch_t *qsysdb_watch_on_update(qsysdb_watch_t *watch,
                                        qsysdb_event_fn handler, void *userdata)
{
    if (!watch) return NULL;
    watch->on_update = handler;
    watch->on_update_data = userdata;
    return watch;
}

qsysdb_watch_t *qsysdb_watch_on_delete(qsysdb_watch_t *watch,
                                        qsysdb_event_fn handler, void *userdata)
{
    if (!watch) return NULL;
    watch->on_delete = handler;
    watch->on_delete_data = userdata;
    return watch;
}

qsysdb_watch_t *qsysdb_watch_get_initial(qsysdb_watch_t *watch, bool enable)
{
    if (!watch) return NULL;
    watch->get_initial = enable;
    return watch;
}

qsysdb_watch_t *qsysdb_watch_queue_size(qsysdb_watch_t *watch, int queue_size)
{
    if (!watch) return NULL;
    watch->queue_size = queue_size;
    return watch;
}

int qsysdb_watch_start(qsysdb_watch_t *watch)
{
    if (!watch || !watch->client) return QSYSDB_ERR_INVALID;
    if (!watch->pattern || !watch->client->connected) {
        return QSYSDB_ERR_INVALID;
    }

    size_t pattern_len = strlen(watch->pattern);
    size_t msg_size = sizeof(struct qsysdb_msg_subscribe_req) + pattern_len + 1;

    uint8_t *msg = alloca(msg_size);
    struct qsysdb_msg_subscribe_req *req = (struct qsysdb_msg_subscribe_req *)msg;
    memset(req, 0, sizeof(*req));

    qsysdb_msg_init(&req->hdr, QSYSDB_MSG_SUBSCRIBE_REQ,
                    msg_size, watch->client->next_request_id++);
    req->pattern_len = pattern_len;
    memcpy(req->pattern, watch->pattern, pattern_len + 1);

    if (queue_send(watch->client, msg, msg_size) != QSYSDB_OK) {
        return QSYSDB_ERR_FULL;
    }

    /* Add to watch list */
    watch->next = watch->client->watches;
    watch->client->watches = watch;
    watch->client->watch_count++;
    watch->started = true;

    /* TODO: Need to handle subscribe response to get subscription_id */
    watch->subscription_id = watch->client->watch_count;

    return watch->subscription_id;
}

void qsysdb_watch_stop(qsysdb_watch_t *watch)
{
    if (!watch) return;

    qsysdb_async_t *client = watch->client;

    if (client) {
        /* Remove from list */
        qsysdb_watch_t **pp = &client->watches;
        while (*pp) {
            if (*pp == watch) {
                *pp = watch->next;
                client->watch_count--;
                break;
            }
            pp = &(*pp)->next;
        }

        /* Send unsubscribe */
        if (watch->started && watch->subscription_id > 0) {
            struct qsysdb_msg_unsubscribe_req req = {0};
            qsysdb_msg_init(&req.hdr, QSYSDB_MSG_UNSUBSCRIBE_REQ,
                            sizeof(req), client->next_request_id++);
            req.subscription_id = watch->subscription_id;
            queue_send(client, &req, sizeof(req));
        }
    }

    free(watch->pattern);
    free(watch);
}

void qsysdb_watch_pause(qsysdb_watch_t *watch)
{
    if (watch) watch->paused = true;
}

void qsysdb_watch_resume(qsysdb_watch_t *watch)
{
    if (watch) watch->paused = false;
}

/* ============================================
 * Batch Operations
 * ============================================ */

qsysdb_batch_t *qsysdb_batch_create(qsysdb_async_t *client)
{
    if (!client) return NULL;

    qsysdb_batch_t *batch = calloc(1, sizeof(*batch));
    if (!batch) return NULL;

    batch->client = client;
    batch->capacity = 16;
    batch->entries = calloc(batch->capacity, sizeof(struct batch_entry));
    if (!batch->entries) {
        free(batch);
        return NULL;
    }

    return batch;
}

qsysdb_batch_t *qsysdb_batch_set(qsysdb_batch_t *batch,
                                  const char *path, const char *value)
{
    if (!batch) return NULL;
    if (batch->count >= batch->capacity) {
        int new_cap = batch->capacity * 2;
        struct batch_entry *new_entries = realloc(batch->entries,
                                                   new_cap * sizeof(struct batch_entry));
        if (!new_entries) return batch;
        batch->entries = new_entries;
        batch->capacity = new_cap;
    }

    struct batch_entry *e = &batch->entries[batch->count++];
    e->op_type = QSYSDB_MSG_SET_REQ;
    e->path = strdup(path);
    e->value = strdup(value);

    return batch;
}

qsysdb_batch_t *qsysdb_batch_delete(qsysdb_batch_t *batch, const char *path)
{
    if (!batch) return NULL;
    if (batch->count >= batch->capacity) {
        int new_cap = batch->capacity * 2;
        struct batch_entry *new_entries = realloc(batch->entries,
                                                   new_cap * sizeof(struct batch_entry));
        if (!new_entries) return batch;
        batch->entries = new_entries;
        batch->capacity = new_cap;
    }

    struct batch_entry *e = &batch->entries[batch->count++];
    e->op_type = QSYSDB_MSG_DELETE_REQ;
    e->path = strdup(path);
    e->value = NULL;

    return batch;
}

int qsysdb_batch_count(qsysdb_batch_t *batch)
{
    if (!batch) return 0;
    return batch->count;
}

qsysdb_op_t *qsysdb_batch_execute(qsysdb_batch_t *batch,
                                   qsysdb_batch_fn callback, void *userdata)
{
    if (!batch || !batch->client) {
        qsysdb_batch_cancel(batch);
        return NULL;
    }

    /* TODO: Implement using transaction protocol */
    /* For now, execute operations individually */
    (void)callback; (void)userdata;

    for (int i = 0; i < batch->count; i++) {
        struct batch_entry *e = &batch->entries[i];
        if (e->op_type == QSYSDB_MSG_SET_REQ) {
            qsysdb_async_set(batch->client, e->path, e->value, NULL, NULL);
        } else {
            qsysdb_async_delete(batch->client, e->path, NULL, NULL);
        }
    }

    qsysdb_batch_cancel(batch);
    return NULL;
}

void qsysdb_batch_cancel(qsysdb_batch_t *batch)
{
    if (!batch) return;
    for (int i = 0; i < batch->count; i++) {
        free(batch->entries[i].path);
        free(batch->entries[i].value);
    }
    free(batch->entries);
    free(batch);
}

/* ============================================
 * Synchronous Convenience Functions
 * ============================================ */

struct sync_ctx {
    bool done;
    int error;
    char *value_buf;
    size_t value_buflen;
};

static void sync_complete(qsysdb_result_t *result, void *userdata)
{
    struct sync_ctx *ctx = userdata;
    ctx->error = result->error;
    ctx->done = true;
}

static void sync_get_complete(qsysdb_get_result_t *result, void *userdata)
{
    struct sync_ctx *ctx = userdata;
    ctx->error = result->base.error;
    if (result->base.error == QSYSDB_OK && ctx->value_buf) {
        size_t copy_len = result->value_len < ctx->value_buflen - 1 ?
                          result->value_len : ctx->value_buflen - 1;
        memcpy(ctx->value_buf, result->value, copy_len);
        ctx->value_buf[copy_len] = '\0';
    }
    ctx->done = true;
}

int qsysdb_async_set_sync(qsysdb_async_t *client,
                           const char *path, const char *value)
{
    if (!client || !client->connected) {
        return QSYSDB_ERR_DISCONNECTED;
    }

    struct sync_ctx ctx = {0};
    qsysdb_op_t *op = qsysdb_async_set(client, path, value, sync_complete, &ctx);
    if (!op) {
        return QSYSDB_ERR_DISCONNECTED;
    }

    while (!ctx.done && client->connected) {
        qsysdb_async_poll(client, 100);
    }

    return ctx.error;
}

int qsysdb_async_get_sync(qsysdb_async_t *client,
                           const char *path, char *buf, size_t buflen)
{
    if (!client || !client->connected) {
        return QSYSDB_ERR_DISCONNECTED;
    }

    struct sync_ctx ctx = {
        .value_buf = buf,
        .value_buflen = buflen
    };
    qsysdb_op_t *op = qsysdb_async_get(client, path, sync_get_complete, &ctx);
    if (!op) {
        return QSYSDB_ERR_DISCONNECTED;
    }

    while (!ctx.done && client->connected) {
        qsysdb_async_poll(client, 100);
    }

    return ctx.error;
}

int qsysdb_async_delete_sync(qsysdb_async_t *client, const char *path)
{
    if (!client || !client->connected) {
        return QSYSDB_ERR_DISCONNECTED;
    }

    struct sync_ctx ctx = {0};
    qsysdb_op_t *op = qsysdb_async_delete(client, path, sync_complete, &ctx);
    if (!op) {
        return QSYSDB_ERR_DISCONNECTED;
    }

    while (!ctx.done && client->connected) {
        qsysdb_async_poll(client, 100);
    }

    return ctx.error;
}

/* ============================================
 * Utility Functions
 * ============================================ */

int qsysdb_async_pending_count(qsysdb_async_t *client)
{
    return client->pending_count;
}

int qsysdb_async_watch_count(qsysdb_async_t *client)
{
    return client->watch_count;
}

void qsysdb_async_get_stats(qsysdb_async_t *client, qsysdb_client_stats_t *stats)
{
    *stats = client->stats;
    stats->pending_ops = client->pending_count;
    stats->active_watches = client->watch_count;
}

/* ============================================
 * Cluster Support
 * ============================================ */

void qsysdb_async_set_cluster_mode(qsysdb_async_t *client, bool enabled)
{
    if (!client) return;
    pthread_mutex_lock(&client->lock);
    client->cluster_mode = enabled;
    if (!enabled) {
        /* Reset cluster state when disabling */
        client->leader_index = -1;
    }
    pthread_mutex_unlock(&client->lock);
}

int qsysdb_async_add_server(qsysdb_async_t *client, const char *host, uint16_t port)
{
    if (!client || !host)
        return QSYSDB_ERR_INVALID;

    pthread_mutex_lock(&client->lock);

    if (client->server_count >= MAX_CLUSTER_SERVERS) {
        pthread_mutex_unlock(&client->lock);
        return QSYSDB_ERR_FULL;
    }

    int idx = client->server_count;
    struct cluster_server *srv = &client->servers[idx];

    strncpy(srv->host, host, sizeof(srv->host) - 1);
    srv->host[sizeof(srv->host) - 1] = '\0';
    srv->port = port ? port : QSYSDB_TCP_PORT_DEFAULT;
    srv->fd = -1;
    srv->connected = false;
    srv->is_leader = false;
    srv->latency_us = UINT64_MAX;

    client->server_count++;

    pthread_mutex_unlock(&client->lock);

    return idx;
}

int qsysdb_async_remove_server(qsysdb_async_t *client, int server_index)
{
    if (!client || server_index < 0 || server_index >= client->server_count)
        return QSYSDB_ERR_INVALID;

    pthread_mutex_lock(&client->lock);

    struct cluster_server *srv = &client->servers[server_index];

    /* Close connection if open */
    if (srv->fd >= 0) {
        close(srv->fd);
        srv->fd = -1;
    }

    /* Shift remaining servers */
    for (int i = server_index; i < client->server_count - 1; i++) {
        client->servers[i] = client->servers[i + 1];
    }
    client->server_count--;

    /* Adjust indices */
    if (client->current_server == server_index) {
        client->current_server = 0;
    } else if (client->current_server > server_index) {
        client->current_server--;
    }

    if (client->leader_index == server_index) {
        client->leader_index = -1;
    } else if (client->leader_index > server_index) {
        client->leader_index--;
    }

    pthread_mutex_unlock(&client->lock);

    return QSYSDB_OK;
}

static int connect_to_server(qsysdb_async_t *client, struct cluster_server *srv)
{
    (void)client;  /* Reserved for future use */

    /* Create socket */
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return QSYSDB_ERR_IO;

    /* Set non-blocking */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    /* Set TCP options */
    int optval = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval));
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval));

    /* Connect */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(srv->port);

    if (inet_pton(AF_INET, srv->host, &addr.sin_addr) <= 0) {
        /* Try DNS resolution */
        struct hostent *he = gethostbyname(srv->host);
        if (!he) {
            close(fd);
            return QSYSDB_ERR_CONNECT;
        }
        memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    }

    int ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0 && errno != EINPROGRESS) {
        close(fd);
        return QSYSDB_ERR_CONNECT;
    }

    srv->fd = fd;
    srv->connected = (ret == 0);

    return QSYSDB_OK;
}

int qsysdb_async_connect_cluster(qsysdb_async_t *client, int flags)
{
    if (!client)
        return QSYSDB_ERR_INVALID;

    if (client->server_count == 0)
        return QSYSDB_ERR_INVALID;

    pthread_mutex_lock(&client->lock);

    client->cluster_mode = true;
    client->conn_flags = flags;
    int connected_count = 0;

    /* Try to connect to all servers */
    for (int i = 0; i < client->server_count; i++) {
        struct cluster_server *srv = &client->servers[i];
        if (connect_to_server(client, srv) == QSYSDB_OK) {
            connected_count++;
        }
    }

    /* Use first connected server as primary */
    for (int i = 0; i < client->server_count; i++) {
        if (client->servers[i].fd >= 0) {
            client->current_server = i;
            client->fd = client->servers[i].fd;
            client->connected = client->servers[i].connected;
            client->connecting = !client->connected;
            break;
        }
    }

    pthread_mutex_unlock(&client->lock);

    return connected_count > 0 ? QSYSDB_OK : QSYSDB_ERR_CONNECT;
}

int qsysdb_async_get_leader(qsysdb_async_t *client,
                            char *host, size_t host_len, uint16_t *port)
{
    if (!client)
        return QSYSDB_ERR_INVALID;

    pthread_mutex_lock(&client->lock);

    if (client->leader_index < 0 || client->leader_index >= client->server_count) {
        pthread_mutex_unlock(&client->lock);
        return QSYSDB_ERR_NOTFOUND;
    }

    struct cluster_server *leader = &client->servers[client->leader_index];

    if (host && host_len > 0) {
        strncpy(host, leader->host, host_len - 1);
        host[host_len - 1] = '\0';
    }

    if (port) {
        *port = leader->port;
    }

    pthread_mutex_unlock(&client->lock);

    return QSYSDB_OK;
}

int qsysdb_async_server_count(qsysdb_async_t *client)
{
    if (!client) return 0;

    pthread_mutex_lock(&client->lock);
    int connected = 0;
    for (int i = 0; i < client->server_count; i++) {
        if (client->servers[i].connected)
            connected++;
    }
    pthread_mutex_unlock(&client->lock);

    return connected;
}
