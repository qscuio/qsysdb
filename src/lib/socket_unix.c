/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * socket_unix.c - Unix domain socket transport implementation
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <qsysdb/types.h>
#include "client.h"
#include "socket_transport.h"

/*
 * Set socket timeouts for read/write operations
 */
static int unix_set_timeout(struct qsysdb *db, int timeout_ms)
{
    if (!db || db->sock_fd < 0) {
        return QSYSDB_ERR_INVALID;
    }

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    if (setsockopt(db->sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        return QSYSDB_ERR_IO;
    }
    if (setsockopt(db->sock_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
        return QSYSDB_ERR_IO;
    }

    return QSYSDB_OK;
}

/*
 * Connect to server via Unix domain socket
 */
static int unix_connect(struct qsysdb *db)
{
    if (!db) {
        return QSYSDB_ERR_INVALID;
    }

    const char *socket_path = db->socket_path;

    /* Use default socket path if not specified */
    if (socket_path[0] == '\0') {
        strncpy(db->socket_path, QSYSDB_SOCKET_PATH, sizeof(db->socket_path) - 1);
        socket_path = db->socket_path;
    }

    /* Create socket */
    db->sock_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (db->sock_fd < 0) {
        return QSYSDB_ERR_IO;
    }

    /* Set connection timeout */
    unix_set_timeout(db, QSYSDB_CONNECT_TIMEOUT);

    /* Prepare address */
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    size_t path_len = strlen(socket_path);
    if (path_len >= sizeof(addr.sun_path)) {
        path_len = sizeof(addr.sun_path) - 1;
    }
    memcpy(addr.sun_path, socket_path, path_len);
    addr.sun_path[path_len] = '\0';

    /* Connect */
    if (connect(db->sock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(db->sock_fd);
        db->sock_fd = -1;
        return QSYSDB_ERR_CONNECT;
    }

    /* Set normal operation timeout */
    unix_set_timeout(db, QSYSDB_READ_TIMEOUT);

    db->sock_type = SOCK_TYPE_UNIX;

    return QSYSDB_OK;
}

/*
 * Disconnect Unix socket
 */
static void unix_disconnect(struct qsysdb *db)
{
    if (!db) {
        return;
    }

    if (db->sock_fd >= 0) {
        close(db->sock_fd);
        db->sock_fd = -1;
    }
}

/*
 * Send data over Unix socket
 */
static ssize_t unix_send(struct qsysdb *db, const void *buf, size_t len)
{
    if (!db || db->sock_fd < 0) {
        return QSYSDB_ERR_INVALID;
    }

    ssize_t sent = send(db->sock_fd, buf, len, MSG_NOSIGNAL);
    if (sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return QSYSDB_ERR_AGAIN;
        }
        if (errno == EPIPE || errno == ECONNRESET) {
            return QSYSDB_ERR_DISCONNECTED;
        }
        return QSYSDB_ERR_IO;
    }

    return sent;
}

/*
 * Receive data from Unix socket
 */
static ssize_t unix_recv(struct qsysdb *db, void *buf, size_t len, int flags)
{
    if (!db || db->sock_fd < 0) {
        return QSYSDB_ERR_INVALID;
    }

    ssize_t received = recv(db->sock_fd, buf, len, flags);
    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return QSYSDB_ERR_AGAIN;
        }
        if (errno == EINTR) {
            return QSYSDB_ERR_AGAIN;
        }
        return QSYSDB_ERR_IO;
    }
    if (received == 0) {
        return QSYSDB_ERR_DISCONNECTED;
    }

    return received;
}

/*
 * Get file descriptor for poll/select
 */
static int unix_get_fd(struct qsysdb *db)
{
    if (!db) {
        return -1;
    }
    return db->sock_fd;
}

/*
 * Unix transport operations
 */
const struct transport_ops unix_transport_ops = {
    .type = TRANSPORT_UNIX,
    .connect = unix_connect,
    .disconnect = unix_disconnect,
    .send = unix_send,
    .recv = unix_recv,
    .set_timeout = unix_set_timeout,
    .get_fd = unix_get_fd,
};
