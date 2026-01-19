/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * netlink.c - Generic Netlink implementation
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>

#include <qsysdb/types.h>
#include <qsysdb/protocol.h>
#include "netlink.h"
#include "database.h"
#include "subscription.h"

#define NETLINK_RECV_BUF_SIZE   (64 * 1024)

struct nla_attr {
    uint16_t nla_len;
    uint16_t nla_type;
    char nla_data[];
};

static int send_nlmsg(struct netlink_ctx *ctx, void *msg, size_t len);
static int resolve_family_id(struct netlink_ctx *ctx);

/*
 * Build a netlink message with attributes
 */
static void *build_message(struct netlink_ctx *ctx, uint8_t cmd,
                           uint32_t seq, size_t *msg_len)
{
    size_t total_len = NLMSG_ALIGN(sizeof(struct nlmsghdr)) +
                       NLMSG_ALIGN(sizeof(struct genlmsghdr));

    struct nlmsghdr *nlh = calloc(1, total_len + 1024);  /* Extra space for attrs */
    if (!nlh) return NULL;

    nlh->nlmsg_len = (uint32_t)total_len;
    nlh->nlmsg_type = ctx->family_id;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = seq;
    nlh->nlmsg_pid = ctx->portid;

    struct genlmsghdr *genlh = (struct genlmsghdr *)NLMSG_DATA(nlh);
    genlh->cmd = cmd;
    genlh->version = QSYSDB_GENL_VERSION;

    *msg_len = total_len;
    return nlh;
}

/*
 * Add an attribute to a netlink message
 */
static int add_attr(void *msg, size_t *msg_len, uint16_t type,
                    const void *data, size_t data_len)
{
    struct nlmsghdr *nlh = msg;
    struct nla_attr *nla = (struct nla_attr *)((char *)msg + nlh->nlmsg_len);

    size_t attr_len = NLA_HDRLEN + data_len;
    size_t padded_len = NLA_ALIGN(attr_len);

    nla->nla_len = (uint16_t)attr_len;
    nla->nla_type = type;
    memcpy(nla->nla_data, data, data_len);

    nlh->nlmsg_len += (uint32_t)padded_len;
    *msg_len += padded_len;

    return 0;
}

/*
 * Parse attributes from a netlink message
 */
static int parse_attrs(void *msg, size_t msg_len,
                       struct nla_attr *attrs[], int max_attrs)
{
    struct nlmsghdr *nlh = msg;

    /* Clear output array */
    memset(attrs, 0, max_attrs * sizeof(struct nla_attr *));

    /* Calculate attribute start */
    size_t hdr_len = NLMSG_ALIGN(sizeof(struct nlmsghdr)) +
                     NLMSG_ALIGN(sizeof(struct genlmsghdr));

    if (msg_len < hdr_len) {
        return 0;
    }

    char *attr_start = (char *)msg + hdr_len;
    size_t attr_len = nlh->nlmsg_len - hdr_len;

    /* Parse attributes */
    size_t offset = 0;
    while (offset + NLA_HDRLEN <= attr_len) {
        struct nla_attr *nla = (struct nla_attr *)(attr_start + offset);

        if (nla->nla_len < NLA_HDRLEN) break;
        if (offset + NLA_ALIGN(nla->nla_len) > attr_len) break;

        if (nla->nla_type < max_attrs) {
            attrs[nla->nla_type] = nla;
        }

        offset += NLA_ALIGN(nla->nla_len);
    }

    return 0;
}

static int send_nlmsg(struct netlink_ctx *ctx, void *msg, size_t len)
{
    (void)len;  /* Length is encoded in nlh->nlmsg_len */
    struct nlmsghdr *nlh = msg;
    struct sockaddr_nl addr = {
        .nl_family = AF_NETLINK,
        .nl_pid = 0,  /* Kernel */
        .nl_groups = 0
    };

    ssize_t ret = sendto(ctx->sock_fd, msg, nlh->nlmsg_len, 0,
                         (struct sockaddr *)&addr, sizeof(addr));

    if (ret < 0) {
        ctx->errors++;
        return QSYSDB_ERR_IO;
    }

    ctx->msgs_sent++;
    return QSYSDB_OK;
}

/*
 * Resolve Generic Netlink family ID
 */
static int resolve_family_id(struct netlink_ctx *ctx)
{
    char buf[1024];
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    struct genlmsghdr *genlh;

    /* Build CTRL_CMD_GETFAMILY message */
    memset(buf, 0, sizeof(buf));
    nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
    nlh->nlmsg_type = GENL_ID_CTRL;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = 1;
    nlh->nlmsg_pid = ctx->portid;

    genlh = NLMSG_DATA(nlh);
    genlh->cmd = CTRL_CMD_GETFAMILY;
    genlh->version = 1;

    /* Add family name attribute */
    struct nla_attr *nla = (struct nla_attr *)((char *)buf + nlh->nlmsg_len);
    size_t name_len = strlen(QSYSDB_GENL_NAME) + 1;
    nla->nla_len = (uint16_t)(NLA_HDRLEN + name_len);
    nla->nla_type = CTRL_ATTR_FAMILY_NAME;
    memcpy(nla->nla_data, QSYSDB_GENL_NAME, name_len);
    nlh->nlmsg_len += NLA_ALIGN(nla->nla_len);

    /* Send request */
    struct sockaddr_nl addr = {
        .nl_family = AF_NETLINK,
        .nl_pid = 0,
        .nl_groups = 0
    };

    if (sendto(ctx->sock_fd, buf, nlh->nlmsg_len, 0,
               (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        return QSYSDB_ERR_IO;
    }

    /* Receive response */
    struct sockaddr_nl src_addr;
    socklen_t addr_len = sizeof(src_addr);
    ssize_t len = recvfrom(ctx->sock_fd, buf, sizeof(buf), 0,
                           (struct sockaddr *)&src_addr, &addr_len);

    if (len < 0) {
        return QSYSDB_ERR_IO;
    }

    /* Parse response */
    nlh = (struct nlmsghdr *)buf;
    if (nlh->nlmsg_type == NLMSG_ERROR) {
        /* Family not registered (kernel module not loaded) */
        return QSYSDB_ERR_NOTFOUND;
    }

    /* Find family ID attribute */
    genlh = NLMSG_DATA(nlh);
    char *attr_start = (char *)genlh + GENL_HDRLEN;
    size_t attr_len = nlh->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN;

    size_t offset = 0;
    while (offset + NLA_HDRLEN <= attr_len) {
        nla = (struct nla_attr *)(attr_start + offset);
        if (nla->nla_len < NLA_HDRLEN) break;

        if (nla->nla_type == CTRL_ATTR_FAMILY_ID) {
            ctx->family_id = *(uint16_t *)nla->nla_data;
            return QSYSDB_OK;
        }

        offset += NLA_ALIGN(nla->nla_len);
    }

    return QSYSDB_ERR_NOTFOUND;
}

/*
 * Handle incoming netlink message from kernel
 */
static void handle_kernel_message(struct netlink_ctx *ctx, void *msg,
                                  size_t msg_len, uint32_t src_portid)
{
    struct nlmsghdr *nlh = msg;
    struct genlmsghdr *genlh = NLMSG_DATA(nlh);
    struct nla_attr *attrs[__QSYSDB_NL_ATTR_MAX] = {0};

    parse_attrs(msg, msg_len, attrs, __QSYSDB_NL_ATTR_MAX);

    switch (genlh->cmd) {
    case QSYSDB_NL_CMD_SET: {
        const char *path = NULL, *value = NULL;
        if (attrs[QSYSDB_NL_ATTR_PATH]) {
            path = attrs[QSYSDB_NL_ATTR_PATH]->nla_data;
        }
        if (attrs[QSYSDB_NL_ATTR_VALUE]) {
            value = attrs[QSYSDB_NL_ATTR_VALUE]->nla_data;
        }

        if (path && value) {
            uint64_t version;
            int ret = db_set(ctx->db, path, strlen(path),
                             value, strlen(value),
                             QSYSDB_FLAG_KERNEL, &version);
            netlink_send_response(ctx, src_portid, nlh->nlmsg_seq,
                                  ret, path, NULL);
        }
        break;
    }

    case QSYSDB_NL_CMD_GET: {
        const char *path = NULL;
        if (attrs[QSYSDB_NL_ATTR_PATH]) {
            path = attrs[QSYSDB_NL_ATTR_PATH]->nla_data;
        }

        if (path) {
            char value_buf[QSYSDB_MAX_VALUE];
            size_t value_len;
            int ret = db_get(ctx->db, path, strlen(path),
                             value_buf, sizeof(value_buf), &value_len,
                             NULL, NULL);
            netlink_send_response(ctx, src_portid, nlh->nlmsg_seq,
                                  ret, path, ret == QSYSDB_OK ? value_buf : NULL);
        }
        break;
    }

    case QSYSDB_NL_CMD_DELETE: {
        const char *path = NULL;
        if (attrs[QSYSDB_NL_ATTR_PATH]) {
            path = attrs[QSYSDB_NL_ATTR_PATH]->nla_data;
        }

        if (path) {
            int ret = db_delete(ctx->db, path, strlen(path));
            netlink_send_response(ctx, src_portid, nlh->nlmsg_seq,
                                  ret, path, NULL);
        }
        break;
    }

    case QSYSDB_NL_CMD_KERN_UPDATE: {
        /* Kernel notifying us of a direct SHM update */
        const char *path = NULL;
        if (attrs[QSYSDB_NL_ATTR_PATH]) {
            path = attrs[QSYSDB_NL_ATTR_PATH]->nla_data;
        }
        /* The kernel has already written to SHM, we just need to
           propagate the notification to userspace subscribers */
        if (path) {
            struct qsysdb_notification notif = {0};
            notif.sequence = ctx->db->shm.header->sequence;
            notif.event_type = QSYSDB_EVENT_UPDATE;
            notif.path_len = (uint32_t)strlen(path);
            strncpy(notif.path, path, sizeof(notif.path) - 1);

            /* The server will handle broadcasting to clients */
            /* Note: In a full implementation, we'd have a callback here */
        }
        break;
    }

    default:
        break;
    }

    ctx->msgs_received++;
}

/*
 * Netlink receiver thread
 */
static void *netlink_recv_thread(void *arg)
{
    struct netlink_ctx *ctx = arg;
    char buf[NETLINK_RECV_BUF_SIZE];

    while (ctx->running) {
        struct sockaddr_nl src_addr;
        socklen_t addr_len = sizeof(src_addr);

        ssize_t len = recvfrom(ctx->sock_fd, buf, sizeof(buf), 0,
                               (struct sockaddr *)&src_addr, &addr_len);

        if (len < 0) {
            if (errno == EAGAIN || errno == EINTR) {
                continue;
            }
            ctx->errors++;
            continue;
        }

        if (len < (ssize_t)sizeof(struct nlmsghdr)) {
            continue;
        }

        struct nlmsghdr *nlh = (struct nlmsghdr *)buf;

        /* Process all messages in buffer */
        while (NLMSG_OK(nlh, len)) {
            if (nlh->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *err = NLMSG_DATA(nlh);
                if (err->error != 0) {
                    ctx->errors++;
                }
            } else if (nlh->nlmsg_type == ctx->family_id) {
                handle_kernel_message(ctx, nlh, nlh->nlmsg_len, src_addr.nl_pid);
            }

            nlh = NLMSG_NEXT(nlh, len);
        }
    }

    return NULL;
}

int netlink_init(struct netlink_ctx *ctx, struct qsysdb_db *db,
                 struct sub_manager *sub_mgr)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->db = db;
    ctx->sub_mgr = sub_mgr;

    /* Create netlink socket */
    ctx->sock_fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_GENERIC);
    if (ctx->sock_fd < 0) {
        return QSYSDB_ERR_IO;
    }

    /* Bind to kernel */
    struct sockaddr_nl addr = {
        .nl_family = AF_NETLINK,
        .nl_pid = 0,  /* Let kernel assign */
        .nl_groups = 0
    };

    if (bind(ctx->sock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(ctx->sock_fd);
        return QSYSDB_ERR_IO;
    }

    /* Get assigned portid */
    socklen_t addr_len = sizeof(addr);
    if (getsockname(ctx->sock_fd, (struct sockaddr *)&addr, &addr_len) < 0) {
        close(ctx->sock_fd);
        return QSYSDB_ERR_IO;
    }
    ctx->portid = addr.nl_pid;

    /* Set receive timeout */
    struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };  /* 100ms */
    setsockopt(ctx->sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Try to resolve family ID (will fail if kernel module not loaded) */
    int ret = resolve_family_id(ctx);
    if (ret != QSYSDB_OK) {
        /* Not an error - kernel module might be loaded later */
        ctx->family_id = 0;
    }

    return QSYSDB_OK;
}

int netlink_start(struct netlink_ctx *ctx)
{
    if (ctx->family_id == 0) {
        /* Try to resolve again */
        resolve_family_id(ctx);
    }

    ctx->running = true;

    if (pthread_create(&ctx->recv_thread, NULL, netlink_recv_thread, ctx) != 0) {
        ctx->running = false;
        return QSYSDB_ERR_INTERNAL;
    }

    return QSYSDB_OK;
}

void netlink_stop(struct netlink_ctx *ctx)
{
    ctx->running = false;

    if (ctx->recv_thread) {
        pthread_join(ctx->recv_thread, NULL);
        ctx->recv_thread = 0;
    }
}

void netlink_shutdown(struct netlink_ctx *ctx)
{
    netlink_stop(ctx);

    if (ctx->sock_fd >= 0) {
        close(ctx->sock_fd);
        ctx->sock_fd = -1;
    }
}

int netlink_send_notification(struct netlink_ctx *ctx,
                              const struct qsysdb_notification *notif)
{
    if (ctx->family_id == 0) {
        return QSYSDB_ERR_NOTFOUND;  /* No kernel module */
    }

    size_t msg_len;
    void *msg = build_message(ctx, QSYSDB_NL_CMD_NOTIFY, 0, &msg_len);
    if (!msg) {
        return QSYSDB_ERR_NOMEM;
    }

    /* Add attributes */
    add_attr(msg, &msg_len, QSYSDB_NL_ATTR_PATH, notif->path, notif->path_len + 1);
    add_attr(msg, &msg_len, QSYSDB_NL_ATTR_EVENT_TYPE,
             &notif->event_type, sizeof(notif->event_type));
    add_attr(msg, &msg_len, QSYSDB_NL_ATTR_SEQUENCE,
             &notif->sequence, sizeof(notif->sequence));
    add_attr(msg, &msg_len, QSYSDB_NL_ATTR_VERSION,
             &notif->entry_version, sizeof(notif->entry_version));

    int ret = send_nlmsg(ctx, msg, msg_len);
    free(msg);

    return ret;
}

int netlink_send_response(struct netlink_ctx *ctx, uint32_t portid,
                          uint32_t seq, int error_code,
                          const char *path, const char *value)
{
    if (ctx->family_id == 0) {
        return QSYSDB_ERR_NOTFOUND;
    }

    size_t msg_len;
    void *msg = build_message(ctx, QSYSDB_NL_CMD_GET, seq, &msg_len);
    if (!msg) {
        return QSYSDB_ERR_NOMEM;
    }

    /* Update portid in message */
    struct nlmsghdr *nlh = msg;
    nlh->nlmsg_pid = portid;
    nlh->nlmsg_flags = 0;  /* Response */

    int32_t err = (int32_t)error_code;
    add_attr(msg, &msg_len, QSYSDB_NL_ATTR_ERROR, &err, sizeof(err));

    if (path) {
        add_attr(msg, &msg_len, QSYSDB_NL_ATTR_PATH, path, strlen(path) + 1);
    }
    if (value) {
        add_attr(msg, &msg_len, QSYSDB_NL_ATTR_VALUE, value, strlen(value) + 1);
    }

    int ret = send_nlmsg(ctx, msg, msg_len);
    free(msg);

    return ret;
}

bool netlink_kernel_present(struct netlink_ctx *ctx)
{
    if (ctx->family_id != 0) {
        return true;
    }

    /* Try to resolve */
    return resolve_family_id(ctx) == QSYSDB_OK;
}

void netlink_stats(struct netlink_ctx *ctx, uint64_t *msgs_sent,
                   uint64_t *msgs_received, uint64_t *errors)
{
    if (msgs_sent) *msgs_sent = ctx->msgs_sent;
    if (msgs_received) *msgs_received = ctx->msgs_received;
    if (errors) *errors = ctx->errors;
}
