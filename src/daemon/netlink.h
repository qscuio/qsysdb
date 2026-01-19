/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * netlink.h - Generic Netlink interface for kernel communication
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#ifndef QSYSDB_NETLINK_H
#define QSYSDB_NETLINK_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <qsysdb/types.h>
#include "database.h"

/* Forward declarations */
struct qsysdb_db;
struct sub_manager;

/*
 * Netlink context
 */
struct netlink_ctx {
    int sock_fd;                    /* Netlink socket */
    uint16_t family_id;             /* Generic netlink family ID */
    uint32_t portid;                /* Our portid */

    struct qsysdb_db *db;           /* Database reference */
    struct sub_manager *sub_mgr;    /* Subscription manager */

    volatile bool running;
    pthread_t recv_thread;

    /* Statistics */
    uint64_t msgs_sent;
    uint64_t msgs_received;
    uint64_t errors;
};

/*
 * Initialize netlink communication
 */
int netlink_init(struct netlink_ctx *ctx, struct qsysdb_db *db,
                 struct sub_manager *sub_mgr);

/*
 * Start receiving netlink messages
 */
int netlink_start(struct netlink_ctx *ctx);

/*
 * Stop netlink receiver
 */
void netlink_stop(struct netlink_ctx *ctx);

/*
 * Shutdown netlink
 */
void netlink_shutdown(struct netlink_ctx *ctx);

/*
 * Send a notification to kernel
 */
int netlink_send_notification(struct netlink_ctx *ctx,
                              const struct qsysdb_notification *notif);

/*
 * Send a response to kernel
 */
int netlink_send_response(struct netlink_ctx *ctx, uint32_t portid,
                          uint32_t seq, int error_code,
                          const char *path, const char *value);

/*
 * Check if kernel module is loaded
 */
bool netlink_kernel_present(struct netlink_ctx *ctx);

/*
 * Get netlink statistics
 */
void netlink_stats(struct netlink_ctx *ctx, uint64_t *msgs_sent,
                   uint64_t *msgs_received, uint64_t *errors);

#endif /* QSYSDB_NETLINK_H */
