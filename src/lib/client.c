/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * client.c - Client connection management
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
#include <poll.h>
#include <pthread.h>

#include <qsysdb/types.h>
#include <qsysdb/protocol.h>
#include <qsysdb/qsysdb.h>
#include "client.h"
#include "socket_transport.h"
#include "common/shm.h"
#include "common/ringbuf.h"

#define RECV_BUF_SIZE   (128 * 1024)

/*
 * Perform connection handshake with server
 * This is shared between Unix and TCP connections
 */
static int client_handshake(struct qsysdb *db, int flags)
{
    struct qsysdb_msg_connect_req req = {0};
    qsysdb_msg_init(&req.hdr, QSYSDB_MSG_CONNECT_REQ,
                    sizeof(req), db->next_request_id++);
    req.flags = db->flags;
    req.client_version = QSYSDB_VERSION;
    snprintf(req.client_name, sizeof(req.client_name), "libqsysdb-%d", getpid());

    struct qsysdb_msg_connect_rsp rsp;
    size_t rsp_len;

    int ret = client_request(db, &req, sizeof(req), &rsp, sizeof(rsp), &rsp_len);
    if (ret != QSYSDB_OK) {
        return ret;
    }

    if (rsp.hdr.error_code != QSYSDB_OK) {
        return rsp.hdr.error_code;
    }

    db->client_id = rsp.client_id;
    db->connected = true;

    /* If SHM is available and requested, also map it */
    if ((flags & QSYSDB_CONN_SHM) && rsp.shm_name[0] != '\0') {
        ret = qsysdb_shm_open(&db->shm, rsp.shm_name,
                              (flags & QSYSDB_CONN_READONLY) != 0);
        if (ret == QSYSDB_OK) {
            ringbuf_consumer_init(db->shm.ring, &db->ring_consumer);
        }
    }

    return QSYSDB_OK;
}

/*
 * Allocate and initialize common client structure
 */
static struct qsysdb *client_alloc(int flags)
{
    struct qsysdb *db = calloc(1, sizeof(*db));
    if (!db) {
        return NULL;
    }

    db->conn_type = CONN_SOCKET;
    db->flags = (uint32_t)flags;
    db->sock_fd = -1;
    db->next_request_id = 1;

    if (pthread_mutex_init(&db->lock, NULL) != 0) {
        free(db);
        return NULL;
    }

    /* Allocate receive buffer */
    db->recv_buf = malloc(RECV_BUF_SIZE);
    if (!db->recv_buf) {
        pthread_mutex_destroy(&db->lock);
        free(db);
        return NULL;
    }
    db->recv_buf_size = RECV_BUF_SIZE;

    return db;
}

/*
 * Free client structure on connection failure
 */
static void client_free(struct qsysdb *db)
{
    if (!db) return;
    
    if (db->transport && db->sock_fd >= 0) {
        db->transport->disconnect(db);
    }
    free(db->recv_buf);
    pthread_mutex_destroy(&db->lock);
    free(db);
}

qsysdb_t *qsysdb_connect(const char *socket_path, int flags)
{
    struct qsysdb *db = client_alloc(flags);
    if (!db) {
        return NULL;
    }

    /* Set socket path */
    if (socket_path != NULL) {
        strncpy(db->socket_path, socket_path, sizeof(db->socket_path) - 1);
    }

    /* Use Unix transport */
    db->transport = &unix_transport_ops;

    /* Connect via transport */
    int ret = db->transport->connect(db);
    if (ret != QSYSDB_OK) {
        db->last_error = ret;
        client_free(db);
        return NULL;
    }

    /* Perform handshake */
    ret = client_handshake(db, flags);
    if (ret != QSYSDB_OK) {
        db->last_error = ret;
        client_free(db);
        return NULL;
    }

    return db;
}

qsysdb_t *qsysdb_connect_tcp(const char *host, uint16_t port, int flags)
{
    struct qsysdb *db = client_alloc(flags | QSYSDB_CONN_TCP);
    if (!db) {
        return NULL;
    }

    /* Set TCP host and port */
    if (host != NULL) {
        strncpy(db->tcp_host, host, sizeof(db->tcp_host) - 1);
    }
    db->tcp_port = port;

    /* Use TCP transport */
    db->transport = &tcp_transport_ops;

    /* Connect via transport */
    int ret = db->transport->connect(db);
    if (ret != QSYSDB_OK) {
        db->last_error = ret;
        client_free(db);
        return NULL;
    }

    /* Perform handshake */
    ret = client_handshake(db, flags);
    if (ret != QSYSDB_OK) {
        db->last_error = ret;
        client_free(db);
        return NULL;
    }

    return db;
}

qsysdb_t *qsysdb_connect_shm(const char *shm_name, int flags)
{
    struct qsysdb *db = calloc(1, sizeof(*db));
    if (!db) {
        return NULL;
    }

    db->conn_type = CONN_SHM;
    db->flags = (uint32_t)flags;
    db->sock_fd = -1;

    if (pthread_mutex_init(&db->lock, NULL) != 0) {
        free(db);
        return NULL;
    }

    /* Use default SHM name if not specified */
    if (shm_name == NULL) {
        shm_name = QSYSDB_SHM_NAME;
    }

    /* Open shared memory */
    int ret = qsysdb_shm_open(&db->shm, shm_name,
                              (flags & QSYSDB_CONN_READONLY) != 0);
    if (ret != QSYSDB_OK) {
        db->last_error = ret;
        pthread_mutex_destroy(&db->lock);
        free(db);
        return NULL;
    }

    /* Initialize ring buffer consumer */
    ringbuf_consumer_init(db->shm.ring, &db->ring_consumer);

    db->connected = true;
    db->client_id = -1;  /* No server-assigned ID for direct SHM */

    return db;
}

void qsysdb_disconnect(qsysdb_t *db)
{
    if (!db) {
        return;
    }

    pthread_mutex_lock(&db->lock);

    /* Abort any active transaction */
    if (db->active_txn) {
        qsysdb_txn_abort(db->active_txn);
        db->active_txn = NULL;
    }

    /* Close socket via transport */
    if (db->transport && db->sock_fd >= 0) {
        db->transport->disconnect(db);
    } else if (db->sock_fd >= 0) {
        close(db->sock_fd);
        db->sock_fd = -1;
    }

    /* Close shared memory */
    if (db->shm.base) {
        qsysdb_shm_close(&db->shm);
    }

    /* Free receive buffer */
    free(db->recv_buf);
    db->recv_buf = NULL;

    db->connected = false;

    pthread_mutex_unlock(&db->lock);
    pthread_mutex_destroy(&db->lock);

    free(db);
}

int qsysdb_error(qsysdb_t *db)
{
    return db ? db->last_error : QSYSDB_ERR_INVALID;
}

const char *qsysdb_strerror(int error_code)
{
    switch (error_code) {
    case QSYSDB_OK:            return "Success";
    case QSYSDB_ERR_NOMEM:     return "Out of memory";
    case QSYSDB_ERR_INVALID:   return "Invalid argument";
    case QSYSDB_ERR_NOTFOUND:  return "Not found";
    case QSYSDB_ERR_EXISTS:    return "Already exists";
    case QSYSDB_ERR_FULL:      return "Database full";
    case QSYSDB_ERR_TOOBIG:    return "Value too large";
    case QSYSDB_ERR_BADPATH:   return "Invalid path";
    case QSYSDB_ERR_BADJSON:   return "Invalid JSON";
    case QSYSDB_ERR_CONNECT:   return "Connection failed";
    case QSYSDB_ERR_DISCONNECTED: return "Disconnected";
    case QSYSDB_ERR_TIMEOUT:   return "Timeout";
    case QSYSDB_ERR_BUSY:      return "Resource busy";
    case QSYSDB_ERR_PERM:      return "Permission denied";
    case QSYSDB_ERR_IO:        return "I/O error";
    case QSYSDB_ERR_PROTO:     return "Protocol error";
    case QSYSDB_ERR_INTERNAL:  return "Internal error";
    case QSYSDB_ERR_AGAIN:     return "Try again";
    case QSYSDB_ERR_NOTSUP:    return "Not supported";
    case QSYSDB_ERR_TXN:       return "Transaction error";
    case QSYSDB_ERR_CONFLICT:  return "Conflict";
    default:                   return "Unknown error";
    }
}

bool qsysdb_connected(qsysdb_t *db)
{
    return db && db->connected;
}

int qsysdb_fd(qsysdb_t *db)
{
    if (!db || db->conn_type != CONN_SOCKET) {
        return -1;
    }
    return db->sock_fd;
}

/*
 * Send request and receive response
 */
int client_request(struct qsysdb *db, void *req, size_t req_len,
                   void *rsp, size_t rsp_size, size_t *rsp_len)
{
    struct qsysdb_msg_header *hdr = req;

    /* Send request via transport */
    ssize_t sent;
    if (db->transport) {
        sent = db->transport->send(db, req, req_len);
    } else {
        sent = send(db->sock_fd, req, req_len, MSG_NOSIGNAL);
    }
    if (sent < 0 || (size_t)sent != req_len) {
        return QSYSDB_ERR_IO;
    }

    /* Receive response header */
    size_t received = 0;
    while (received < sizeof(struct qsysdb_msg_header)) {
        ssize_t n;
        if (db->transport) {
            n = db->transport->recv(db, (char *)rsp + received,
                                    sizeof(struct qsysdb_msg_header) - received, 0);
            /* Transport returns negative error codes, not -1 with errno */
            if (n == QSYSDB_ERR_AGAIN) {
                continue;
            }
            if (n < 0) {
                return QSYSDB_ERR_DISCONNECTED;
            }
        } else {
            n = recv(db->sock_fd, (char *)rsp + received,
                     sizeof(struct qsysdb_msg_header) - received, 0);
            if (n <= 0) {
                if (n < 0 && (errno == EAGAIN || errno == EINTR)) {
                    continue;
                }
                return QSYSDB_ERR_DISCONNECTED;
            }
        }
        if (n == 0) {
            return QSYSDB_ERR_DISCONNECTED;
        }
        received += (size_t)n;
    }

    struct qsysdb_msg_header *rsp_hdr = rsp;

    /* Validate response */
    if (rsp_hdr->magic != QSYSDB_MSG_MAGIC) {
        return QSYSDB_ERR_PROTO;
    }

    if (rsp_hdr->request_id != hdr->request_id) {
        /* Response doesn't match - might be a notification */
        /* For now, just error out */
        return QSYSDB_ERR_PROTO;
    }

    /* Receive rest of response */
    size_t total_len = rsp_hdr->msg_len;
    if (total_len > rsp_size) {
        return QSYSDB_ERR_PROTO;
    }

    while (received < total_len) {
        ssize_t n;
        if (db->transport) {
            n = db->transport->recv(db, (char *)rsp + received,
                                    total_len - received, 0);
            if (n == QSYSDB_ERR_AGAIN) {
                continue;
            }
            if (n <= 0) {
                return QSYSDB_ERR_DISCONNECTED;
            }
        } else {
            n = recv(db->sock_fd, (char *)rsp + received,
                     total_len - received, 0);
            if (n <= 0) {
                if (n < 0 && (errno == EAGAIN || errno == EINTR)) {
                    continue;
                }
                return QSYSDB_ERR_DISCONNECTED;
            }
        }
        received += (size_t)n;
    }

    if (rsp_len) {
        *rsp_len = received;
    }

    return QSYSDB_OK;
}

struct local_subscription *client_find_subscription(struct qsysdb *db, int id)
{
    for (int i = 0; i < MAX_LOCAL_SUBS; i++) {
        if (db->subscriptions[i].active && db->subscriptions[i].id == id) {
            return &db->subscriptions[i];
        }
    }
    return NULL;
}

int client_process_notifications(struct qsysdb *db)
{
    if (db->conn_type != CONN_SOCKET) {
        return 0;  /* SHM mode doesn't have async notifications via socket */
    }

    /* Check if data available without blocking */
    struct pollfd pfd = {
        .fd = db->sock_fd,
        .events = POLLIN,
        .revents = 0
    };

    int ret = poll(&pfd, 1, 0);
    if (ret <= 0) {
        return 0;
    }

    /* Read available data */
    ssize_t n = recv(db->sock_fd, db->recv_buf + db->recv_len,
                     db->recv_buf_size - db->recv_len, MSG_DONTWAIT);
    if (n <= 0) {
        return 0;
    }
    db->recv_len += (size_t)n;

    int processed = 0;

    /* Process complete messages */
    while (db->recv_len >= sizeof(struct qsysdb_msg_header)) {
        struct qsysdb_msg_header *hdr = (struct qsysdb_msg_header *)db->recv_buf;

        if (hdr->magic != QSYSDB_MSG_MAGIC) {
            db->recv_len = 0;  /* Reset on protocol error */
            break;
        }

        if (hdr->msg_len > db->recv_len) {
            break;  /* Need more data */
        }

        /* Process notification */
        if (hdr->msg_type == QSYSDB_MSG_NOTIFICATION) {
            struct qsysdb_msg_notification *notif =
                (struct qsysdb_msg_notification *)hdr;

            struct local_subscription *sub =
                client_find_subscription(db, notif->subscription_id);

            if (sub && sub->callback) {
                char path[QSYSDB_MAX_PATH];
                size_t path_len = notif->path_len;
                if (path_len >= sizeof(path)) {
                    path_len = sizeof(path) - 1;
                }
                memcpy(path, notif->data, path_len);
                path[path_len] = '\0';

                const char *value = NULL;
                if (notif->value_len > 0) {
                    value = notif->data + notif->path_len;
                }

                sub->callback(path, value, (int)notif->event_type, sub->userdata);
            }

            processed++;
        }

        /* Remove processed message */
        size_t remaining = db->recv_len - hdr->msg_len;
        if (remaining > 0) {
            memmove(db->recv_buf, db->recv_buf + hdr->msg_len, remaining);
        }
        db->recv_len = remaining;
    }

    return processed;
}

const char *qsysdb_version(void)
{
    static char version[32];
    snprintf(version, sizeof(version), "%d.%d",
             QSYSDB_VERSION, QSYSDB_PROTOCOL_VERSION);
    return version;
}
