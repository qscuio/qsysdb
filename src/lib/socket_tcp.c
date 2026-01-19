/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * socket_tcp.c - TCP socket transport implementation
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
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <qsysdb/types.h>
#include "client.h"
#include "socket_transport.h"

/*
 * Set socket timeouts for read/write operations
 */
static int tcp_set_timeout(struct qsysdb *db, int timeout_ms)
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
 * Set TCP-specific socket options
 */
static int tcp_set_options(int fd)
{
    int optval = 1;

    /* Disable Nagle's algorithm for low latency */
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval)) < 0) {
        return QSYSDB_ERR_IO;
    }

    /* Enable keepalive for connection health monitoring */
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval)) < 0) {
        return QSYSDB_ERR_IO;
    }

    return QSYSDB_OK;
}

/*
 * Connect to server via TCP socket
 */
static int tcp_connect(struct qsysdb *db)
{
    if (!db) {
        return QSYSDB_ERR_INVALID;
    }

    const char *host = db->tcp_host;
    uint16_t port = db->tcp_port;

    /* Use defaults if not specified */
    if (host[0] == '\0') {
        strncpy(db->tcp_host, "127.0.0.1", sizeof(db->tcp_host) - 1);
        host = db->tcp_host;
    }
    if (port == 0) {
        port = QSYSDB_TCP_PORT_DEFAULT;
        db->tcp_port = port;
    }

    /* Resolve hostname */
    struct addrinfo hints, *result, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;      /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", port);

    int ret = getaddrinfo(host, port_str, &hints, &result);
    if (ret != 0) {
        return QSYSDB_ERR_CONNECT;
    }

    /* Try each address until we successfully connect */
    int sock_fd = -1;
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sock_fd = socket(rp->ai_family, rp->ai_socktype | SOCK_CLOEXEC, 
                         rp->ai_protocol);
        if (sock_fd < 0) {
            continue;
        }

        /* Set connection timeout before connect */
        struct timeval tv;
        tv.tv_sec = QSYSDB_CONNECT_TIMEOUT / 1000;
        tv.tv_usec = (QSYSDB_CONNECT_TIMEOUT % 1000) * 1000;
        setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (connect(sock_fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;  /* Success */
        }

        close(sock_fd);
        sock_fd = -1;
    }

    freeaddrinfo(result);

    if (sock_fd < 0) {
        return QSYSDB_ERR_CONNECT;
    }

    db->sock_fd = sock_fd;

    /* Set TCP options */
    ret = tcp_set_options(sock_fd);
    if (ret != QSYSDB_OK) {
        close(sock_fd);
        db->sock_fd = -1;
        return ret;
    }

    /* Set normal operation timeout */
    tcp_set_timeout(db, QSYSDB_READ_TIMEOUT);

    db->sock_type = SOCK_TYPE_TCP;

    return QSYSDB_OK;
}

/*
 * Disconnect TCP socket
 */
static void tcp_disconnect(struct qsysdb *db)
{
    if (!db) {
        return;
    }

    if (db->sock_fd >= 0) {
        /* Graceful shutdown */
        shutdown(db->sock_fd, SHUT_RDWR);
        close(db->sock_fd);
        db->sock_fd = -1;
    }
}

/*
 * Send data over TCP socket
 */
static ssize_t tcp_send(struct qsysdb *db, const void *buf, size_t len)
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
 * Receive data from TCP socket
 */
static ssize_t tcp_recv(struct qsysdb *db, void *buf, size_t len, int flags)
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
static int tcp_get_fd(struct qsysdb *db)
{
    if (!db) {
        return -1;
    }
    return db->sock_fd;
}

/*
 * TCP transport operations
 */
const struct transport_ops tcp_transport_ops = {
    .type = TRANSPORT_TCP,
    .connect = tcp_connect,
    .disconnect = tcp_disconnect,
    .send = tcp_send,
    .recv = tcp_recv,
    .set_timeout = tcp_set_timeout,
    .get_fd = tcp_get_fd,
};
