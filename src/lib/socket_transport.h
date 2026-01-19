/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * socket_transport.h - Abstract transport layer interface
 *
 * This provides a modular interface for different socket types (Unix, TCP)
 * allowing clean separation of transport-specific code from protocol handling.
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#ifndef QSYSDB_SOCKET_TRANSPORT_H
#define QSYSDB_SOCKET_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* Forward declaration */
struct qsysdb;

/*
 * Transport type identifiers
 */
enum transport_type {
    TRANSPORT_UNIX,     /* Unix domain socket */
    TRANSPORT_TCP       /* TCP/IP socket */
};

/*
 * Transport operations interface
 *
 * Each transport type (Unix, TCP) implements these operations.
 * The client library uses this interface for all socket I/O.
 */
struct transport_ops {
    /* Transport type identifier */
    enum transport_type type;

    /*
     * Connect to server
     *
     * @param db        Client connection structure
     * @return          0 on success, negative error code on failure
     */
    int (*connect)(struct qsysdb *db);

    /*
     * Disconnect from server
     *
     * @param db        Client connection structure
     */
    void (*disconnect)(struct qsysdb *db);

    /*
     * Send data to server
     *
     * @param db        Client connection structure
     * @param buf       Data buffer to send
     * @param len       Length of data
     * @return          Number of bytes sent, or negative error code
     */
    ssize_t (*send)(struct qsysdb *db, const void *buf, size_t len);

    /*
     * Receive data from server
     *
     * @param db        Client connection structure
     * @param buf       Buffer to receive data
     * @param len       Maximum bytes to receive
     * @param flags     recv() flags (MSG_DONTWAIT, etc.)
     * @return          Number of bytes received, or negative error code
     */
    ssize_t (*recv)(struct qsysdb *db, void *buf, size_t len, int flags);

    /*
     * Set socket timeouts
     *
     * @param db        Client connection structure
     * @param timeout_ms Timeout in milliseconds
     * @return          0 on success, negative error code on failure
     */
    int (*set_timeout)(struct qsysdb *db, int timeout_ms);

    /*
     * Get file descriptor for poll/select
     *
     * @param db        Client connection structure
     * @return          File descriptor, or -1 if not available
     */
    int (*get_fd)(struct qsysdb *db);
};

/*
 * Transport implementations
 * Defined in socket_unix.c and socket_tcp.c respectively
 */
extern const struct transport_ops unix_transport_ops;
extern const struct transport_ops tcp_transport_ops;

#endif /* QSYSDB_SOCKET_TRANSPORT_H */
