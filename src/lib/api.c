/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * api.c - Public API implementation
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>

#include <qsysdb/types.h>
#include <qsysdb/protocol.h>
#include <qsysdb/qsysdb.h>
#include "client.h"
#include "common/shm.h"
#include "common/radix_tree.h"
#include "common/ringbuf.h"

#define RECV_BUF_SIZE (256 * 1024)  /* 256KB receive buffer for list responses */

/* External declarations */
extern int qsysdb_json_validate(const char *json, size_t len);

int qsysdb_validate_path(const char *path)
{
    if (path == NULL) {
        return QSYSDB_ERR_INVALID;
    }

    size_t len = strlen(path);
    if (len == 0 || len >= QSYSDB_MAX_PATH) {
        return QSYSDB_ERR_BADPATH;
    }

    if (path[0] != '/') {
        return QSYSDB_ERR_BADPATH;
    }

    bool last_was_slash = false;
    for (size_t i = 0; i < len; i++) {
        char c = path[i];
        if (c == '/') {
            if (last_was_slash && i > 0) {
                return QSYSDB_ERR_BADPATH;
            }
            last_was_slash = true;
        } else {
            last_was_slash = false;
            if (!QSYSDB_PATH_CHAR_VALID(c)) {
                return QSYSDB_ERR_BADPATH;
            }
        }
    }

    if (len > 1 && path[len - 1] == '/') {
        return QSYSDB_ERR_BADPATH;
    }

    return QSYSDB_OK;
}

int qsysdb_validate_json(const char *json)
{
    if (json == NULL) {
        return QSYSDB_ERR_INVALID;
    }
    return qsysdb_json_validate(json, strlen(json));
}

int qsysdb_set(qsysdb_t *db, const char *path, const char *json_value)
{
    return qsysdb_set_ex(db, path, json_value, 0, NULL);
}

int qsysdb_set_ex(qsysdb_t *db, const char *path, const char *json_value,
                  uint32_t flags, uint64_t *out_version)
{
    if (!db || !path || !json_value) {
        return QSYSDB_ERR_INVALID;
    }

    int ret = qsysdb_validate_path(path);
    if (ret != QSYSDB_OK) {
        db->last_error = ret;
        return ret;
    }

    size_t path_len = strlen(path);
    size_t value_len = strlen(json_value);

    if (value_len > QSYSDB_MAX_VALUE) {
        db->last_error = QSYSDB_ERR_TOOBIG;
        return QSYSDB_ERR_TOOBIG;
    }

    ret = qsysdb_validate_json(json_value);
    if (ret != QSYSDB_OK) {
        db->last_error = ret;
        return ret;
    }

    pthread_mutex_lock(&db->lock);

    if (db->conn_type == CONN_SOCKET) {
        /* Socket-based request */
        size_t req_size = sizeof(struct qsysdb_msg_set_req) + path_len + value_len;
        struct qsysdb_msg_set_req *req = alloca(req_size);
        memset(req, 0, sizeof(*req));

        qsysdb_msg_init(&req->hdr, QSYSDB_MSG_SET_REQ,
                        (uint32_t)req_size, db->next_request_id++);
        req->flags = flags;
        req->path_len = (uint16_t)path_len;
        req->value_len = (uint16_t)value_len;
        memcpy(req->data, path, path_len);
        memcpy(req->data + path_len, json_value, value_len);

        struct qsysdb_msg_set_rsp rsp;
        size_t rsp_len;

        ret = client_request(db, req, req_size, &rsp, sizeof(rsp), &rsp_len);
        if (ret != QSYSDB_OK) {
            db->last_error = ret;
            pthread_mutex_unlock(&db->lock);
            return ret;
        }

        if (rsp.hdr.error_code != QSYSDB_OK) {
            db->last_error = rsp.hdr.error_code;
            pthread_mutex_unlock(&db->lock);
            return rsp.hdr.error_code;
        }

        if (out_version) {
            *out_version = rsp.version;
        }
    } else {
        /* Direct SHM access - not supported for writes from client lib */
        /* Writes should go through daemon for proper notification handling */
        db->last_error = QSYSDB_ERR_NOTSUP;
        pthread_mutex_unlock(&db->lock);
        return QSYSDB_ERR_NOTSUP;
    }

    pthread_mutex_unlock(&db->lock);
    return QSYSDB_OK;
}

int qsysdb_get(qsysdb_t *db, const char *path, char *buf, size_t buflen)
{
    return qsysdb_get_ex(db, path, buf, buflen, NULL, NULL, NULL);
}

int qsysdb_get_ex(qsysdb_t *db, const char *path, char *buf, size_t buflen,
                  size_t *out_len, uint64_t *out_version, uint64_t *out_timestamp)
{
    if (!db || !path) {
        return QSYSDB_ERR_INVALID;
    }

    int ret = qsysdb_validate_path(path);
    if (ret != QSYSDB_OK) {
        db->last_error = ret;
        return ret;
    }

    size_t path_len = strlen(path);

    pthread_mutex_lock(&db->lock);

    if (db->conn_type == CONN_SHM && db->shm.base) {
        /* Direct SHM read */
        uint64_t seq;
        do {
            seq = qsysdb_shm_read_begin(db->shm.header);

            uint32_t entry_offset = radix_tree_lookup(db->shm.index,
                                                       db->shm.index,
                                                       path, path_len);
            if (entry_offset == 0) {
                if (!qsysdb_shm_read_retry(db->shm.header, seq)) {
                    db->last_error = QSYSDB_ERR_NOTFOUND;
                    pthread_mutex_unlock(&db->lock);
                    return QSYSDB_ERR_NOTFOUND;
                }
                continue;
            }

            struct qsysdb_entry *entry = qsysdb_shm_data_ptr(&db->shm,
                                                              entry_offset);
            if (!entry || (entry->flags & QSYSDB_FLAG_DELETED)) {
                if (!qsysdb_shm_read_retry(db->shm.header, seq)) {
                    db->last_error = QSYSDB_ERR_NOTFOUND;
                    pthread_mutex_unlock(&db->lock);
                    return QSYSDB_ERR_NOTFOUND;
                }
                continue;
            }

            /* Copy value */
            size_t value_len = entry->value_len;
            if (buf && buflen > 0) {
                size_t copy_len = value_len < buflen - 1 ? value_len : buflen - 1;
                memcpy(buf, QSYSDB_ENTRY_VALUE(entry), copy_len);
                buf[copy_len] = '\0';
            }

            if (out_len) *out_len = value_len;
            if (out_version) *out_version = entry->version;
            if (out_timestamp) *out_timestamp = entry->timestamp_ns;

        } while (qsysdb_shm_read_retry(db->shm.header, seq));

        pthread_mutex_unlock(&db->lock);
        return QSYSDB_OK;
    }

    /* Socket-based request */
    size_t req_size = sizeof(struct qsysdb_msg_get_req) + path_len;
    struct qsysdb_msg_get_req *req = alloca(req_size);
    memset(req, 0, sizeof(*req));

    qsysdb_msg_init(&req->hdr, QSYSDB_MSG_GET_REQ,
                    (uint32_t)req_size, db->next_request_id++);
    req->path_len = (uint16_t)path_len;
    memcpy(req->path, path, path_len);

    /* Receive into temporary buffer */
    char rsp_buf[sizeof(struct qsysdb_msg_get_rsp) + QSYSDB_MAX_VALUE];
    struct qsysdb_msg_get_rsp *rsp = (struct qsysdb_msg_get_rsp *)rsp_buf;
    size_t rsp_len;

    ret = client_request(db, req, req_size, rsp_buf, sizeof(rsp_buf), &rsp_len);
    if (ret != QSYSDB_OK) {
        db->last_error = ret;
        pthread_mutex_unlock(&db->lock);
        return ret;
    }

    if (rsp->hdr.error_code != QSYSDB_OK) {
        db->last_error = rsp->hdr.error_code;
        pthread_mutex_unlock(&db->lock);
        return rsp->hdr.error_code;
    }

    /* Copy value to user buffer */
    if (buf && buflen > 0) {
        size_t copy_len = rsp->value_len < buflen - 1 ? rsp->value_len : buflen - 1;
        memcpy(buf, rsp->value, copy_len);
        buf[copy_len] = '\0';
    }

    if (out_len) *out_len = rsp->value_len;
    if (out_version) *out_version = rsp->version;
    if (out_timestamp) *out_timestamp = rsp->timestamp_ns;

    pthread_mutex_unlock(&db->lock);
    return QSYSDB_OK;
}

int qsysdb_delete(qsysdb_t *db, const char *path)
{
    if (!db || !path) {
        return QSYSDB_ERR_INVALID;
    }

    int ret = qsysdb_validate_path(path);
    if (ret != QSYSDB_OK) {
        db->last_error = ret;
        return ret;
    }

    size_t path_len = strlen(path);

    pthread_mutex_lock(&db->lock);

    if (db->conn_type != CONN_SOCKET) {
        db->last_error = QSYSDB_ERR_NOTSUP;
        pthread_mutex_unlock(&db->lock);
        return QSYSDB_ERR_NOTSUP;
    }

    size_t req_size = sizeof(struct qsysdb_msg_delete_req) + path_len;
    struct qsysdb_msg_delete_req *req = alloca(req_size);
    memset(req, 0, sizeof(*req));

    qsysdb_msg_init(&req->hdr, QSYSDB_MSG_DELETE_REQ,
                    (uint32_t)req_size, db->next_request_id++);
    req->path_len = (uint16_t)path_len;
    memcpy(req->path, path, path_len);

    struct qsysdb_msg_delete_rsp rsp;
    size_t rsp_len;

    ret = client_request(db, req, req_size, &rsp, sizeof(rsp), &rsp_len);
    if (ret != QSYSDB_OK) {
        db->last_error = ret;
        pthread_mutex_unlock(&db->lock);
        return ret;
    }

    pthread_mutex_unlock(&db->lock);
    return rsp.hdr.error_code;
}

int qsysdb_exists(qsysdb_t *db, const char *path)
{
    if (!db || !path) {
        return QSYSDB_ERR_INVALID;
    }

    int ret = qsysdb_validate_path(path);
    if (ret != QSYSDB_OK) {
        return ret;
    }

    size_t path_len = strlen(path);

    pthread_mutex_lock(&db->lock);

    /* Try direct SHM check first */
    if (db->shm.base) {
        uint64_t seq;
        bool exists = false;

        do {
            seq = qsysdb_shm_read_begin(db->shm.header);

            uint32_t entry_offset = radix_tree_lookup(db->shm.index,
                                                       db->shm.index,
                                                       path, path_len);
            if (entry_offset != 0) {
                struct qsysdb_entry *entry = qsysdb_shm_data_ptr(&db->shm,
                                                                  entry_offset);
                exists = entry && !(entry->flags & QSYSDB_FLAG_DELETED);
            }
        } while (qsysdb_shm_read_retry(db->shm.header, seq));

        pthread_mutex_unlock(&db->lock);
        return exists ? 1 : 0;
    }

    /* Fall back to socket request */
    size_t req_size = sizeof(struct qsysdb_msg_exists_req) + path_len;
    struct qsysdb_msg_exists_req *req = alloca(req_size);
    memset(req, 0, sizeof(*req));

    qsysdb_msg_init(&req->hdr, QSYSDB_MSG_EXISTS_REQ,
                    (uint32_t)req_size, db->next_request_id++);
    req->path_len = (uint16_t)path_len;
    memcpy(req->path, path, path_len);

    struct qsysdb_msg_exists_rsp rsp;
    size_t rsp_len;

    ret = client_request(db, req, req_size, &rsp, sizeof(rsp), &rsp_len);
    if (ret != QSYSDB_OK) {
        pthread_mutex_unlock(&db->lock);
        return ret;
    }

    pthread_mutex_unlock(&db->lock);

    if (rsp.hdr.error_code != QSYSDB_OK) {
        return rsp.hdr.error_code;
    }

    return rsp.exists ? 1 : 0;
}

int qsysdb_list(qsysdb_t *db, const char *prefix, char ***paths, size_t *count)
{
    if (!db || !paths || !count) {
        return QSYSDB_ERR_INVALID;
    }

    *paths = NULL;
    *count = 0;

    pthread_mutex_lock(&db->lock);

    if (db->conn_type != CONN_SOCKET) {
        /* TODO: Implement SHM-based listing */
        db->last_error = QSYSDB_ERR_NOTSUP;
        pthread_mutex_unlock(&db->lock);
        return QSYSDB_ERR_NOTSUP;
    }

    size_t prefix_len = prefix ? strlen(prefix) : 0;
    size_t req_size = sizeof(struct qsysdb_msg_list_req) + prefix_len;
    struct qsysdb_msg_list_req *req = alloca(req_size);
    memset(req, 0, sizeof(*req));

    qsysdb_msg_init(&req->hdr, QSYSDB_MSG_LIST_REQ,
                    (uint32_t)req_size, db->next_request_id++);
    req->max_results = 0;  /* Unlimited */
    req->prefix_len = (uint16_t)prefix_len;
    if (prefix_len > 0) {
        memcpy(req->prefix, prefix, prefix_len);
    }

    /* Use large buffer for response */
    char *rsp_buf = malloc(RECV_BUF_SIZE);
    if (!rsp_buf) {
        pthread_mutex_unlock(&db->lock);
        return QSYSDB_ERR_NOMEM;
    }

    size_t rsp_len;
    int ret = client_request(db, req, req_size, rsp_buf, RECV_BUF_SIZE, &rsp_len);
    if (ret != QSYSDB_OK) {
        free(rsp_buf);
        pthread_mutex_unlock(&db->lock);
        return ret;
    }

    struct qsysdb_msg_list_rsp *rsp = (struct qsysdb_msg_list_rsp *)rsp_buf;

    if (rsp->hdr.error_code != QSYSDB_OK) {
        ret = rsp->hdr.error_code;
        free(rsp_buf);
        pthread_mutex_unlock(&db->lock);
        return ret;
    }

    /* Allocate path array */
    char **result = malloc(rsp->count * sizeof(char *));
    if (!result) {
        free(rsp_buf);
        pthread_mutex_unlock(&db->lock);
        return QSYSDB_ERR_NOMEM;
    }

    /* Parse null-terminated paths */
    char *p = rsp->paths;
    for (uint32_t i = 0; i < rsp->count; i++) {
        result[i] = strdup(p);
        p += strlen(p) + 1;
    }

    *paths = result;
    *count = rsp->count;

    free(rsp_buf);
    pthread_mutex_unlock(&db->lock);
    return QSYSDB_OK;
}

void qsysdb_list_free(char **paths, size_t count)
{
    if (paths) {
        for (size_t i = 0; i < count; i++) {
            free(paths[i]);
        }
        free(paths);
    }
}

int qsysdb_delete_tree(qsysdb_t *db, const char *prefix, size_t *deleted)
{
    if (!db || !prefix) {
        return QSYSDB_ERR_INVALID;
    }

    pthread_mutex_lock(&db->lock);

    if (db->conn_type != CONN_SOCKET) {
        pthread_mutex_unlock(&db->lock);
        return QSYSDB_ERR_NOTSUP;
    }

    size_t prefix_len = strlen(prefix);
    size_t req_size = sizeof(struct qsysdb_msg_delete_tree_req) + prefix_len;
    struct qsysdb_msg_delete_tree_req *req = alloca(req_size);
    memset(req, 0, sizeof(*req));

    qsysdb_msg_init(&req->hdr, QSYSDB_MSG_DELETE_TREE_REQ,
                    (uint32_t)req_size, db->next_request_id++);
    req->prefix_len = (uint16_t)prefix_len;
    memcpy(req->prefix, prefix, prefix_len);

    struct qsysdb_msg_delete_tree_rsp rsp;
    size_t rsp_len;

    int ret = client_request(db, req, req_size, &rsp, sizeof(rsp), &rsp_len);
    if (ret != QSYSDB_OK) {
        pthread_mutex_unlock(&db->lock);
        return ret;
    }

    if (deleted) {
        *deleted = rsp.deleted_count;
    }

    pthread_mutex_unlock(&db->lock);
    return rsp.hdr.error_code;
}

int qsysdb_subscribe(qsysdb_t *db, const char *pattern,
                     qsysdb_callback_t callback, void *userdata)
{
    if (!db || !pattern || !callback) {
        return QSYSDB_ERR_INVALID;
    }

    pthread_mutex_lock(&db->lock);

    if (db->conn_type != CONN_SOCKET) {
        pthread_mutex_unlock(&db->lock);
        return QSYSDB_ERR_NOTSUP;
    }

    /* Find free slot */
    int slot = -1;
    for (int i = 0; i < MAX_LOCAL_SUBS; i++) {
        if (!db->subscriptions[i].active) {
            slot = i;
            break;
        }
    }

    if (slot < 0) {
        pthread_mutex_unlock(&db->lock);
        return QSYSDB_ERR_FULL;
    }

    size_t pattern_len = strlen(pattern);
    size_t req_size = sizeof(struct qsysdb_msg_subscribe_req) + pattern_len;
    struct qsysdb_msg_subscribe_req *req = alloca(req_size);
    memset(req, 0, sizeof(*req));

    qsysdb_msg_init(&req->hdr, QSYSDB_MSG_SUBSCRIBE_REQ,
                    (uint32_t)req_size, db->next_request_id++);
    req->flags = 0;
    req->pattern_len = (uint16_t)pattern_len;
    memcpy(req->pattern, pattern, pattern_len);

    struct qsysdb_msg_subscribe_rsp rsp;
    size_t rsp_len;

    int ret = client_request(db, req, req_size, &rsp, sizeof(rsp), &rsp_len);
    if (ret != QSYSDB_OK) {
        pthread_mutex_unlock(&db->lock);
        return ret;
    }

    if (rsp.hdr.error_code != QSYSDB_OK) {
        pthread_mutex_unlock(&db->lock);
        return rsp.hdr.error_code;
    }

    /* Store local subscription */
    struct local_subscription *sub = &db->subscriptions[slot];
    sub->id = rsp.subscription_id;
    strncpy(sub->pattern, pattern, sizeof(sub->pattern) - 1);
    sub->callback = callback;
    sub->userdata = userdata;
    sub->active = true;
    db->subscription_count++;

    pthread_mutex_unlock(&db->lock);
    return rsp.subscription_id;
}

int qsysdb_unsubscribe(qsysdb_t *db, int subscription_id)
{
    if (!db || subscription_id <= 0) {
        return QSYSDB_ERR_INVALID;
    }

    pthread_mutex_lock(&db->lock);

    /* Find local subscription */
    struct local_subscription *sub = client_find_subscription(db, subscription_id);
    if (!sub) {
        pthread_mutex_unlock(&db->lock);
        return QSYSDB_ERR_NOTFOUND;
    }

    if (db->conn_type == CONN_SOCKET) {
        struct qsysdb_msg_unsubscribe_req req = {0};
        qsysdb_msg_init(&req.hdr, QSYSDB_MSG_UNSUBSCRIBE_REQ,
                        sizeof(req), db->next_request_id++);
        req.subscription_id = subscription_id;

        struct qsysdb_msg_unsubscribe_rsp rsp;
        size_t rsp_len;

        client_request(db, &req, sizeof(req), &rsp, sizeof(rsp), &rsp_len);
    }

    sub->active = false;
    db->subscription_count--;

    pthread_mutex_unlock(&db->lock);
    return QSYSDB_OK;
}

int qsysdb_poll(qsysdb_t *db, int timeout_ms)
{
    if (!db) {
        return QSYSDB_ERR_INVALID;
    }

    if (db->conn_type != CONN_SOCKET) {
        return 0;  /* No socket-based notifications in SHM mode */
    }

    struct pollfd pfd = {
        .fd = db->sock_fd,
        .events = POLLIN,
        .revents = 0
    };

    int ret = poll(&pfd, 1, timeout_ms);
    if (ret < 0) {
        return QSYSDB_ERR_IO;
    }

    if (ret == 0) {
        return 0;  /* Timeout */
    }

    pthread_mutex_lock(&db->lock);
    int processed = client_process_notifications(db);
    pthread_mutex_unlock(&db->lock);

    return processed;
}

qsysdb_txn_t *qsysdb_txn_begin(qsysdb_t *db)
{
    if (!db || db->conn_type != CONN_SOCKET) {
        return NULL;
    }

    pthread_mutex_lock(&db->lock);

    if (db->active_txn) {
        pthread_mutex_unlock(&db->lock);
        return NULL;  /* Already have active transaction */
    }

    struct qsysdb_msg_txn_begin_req req = {0};
    qsysdb_msg_init(&req.hdr, QSYSDB_MSG_TXN_BEGIN_REQ,
                    sizeof(req), db->next_request_id++);

    struct qsysdb_msg_txn_begin_rsp rsp;
    size_t rsp_len;

    int ret = client_request(db, &req, sizeof(req), &rsp, sizeof(rsp), &rsp_len);
    if (ret != QSYSDB_OK || rsp.hdr.error_code != QSYSDB_OK) {
        pthread_mutex_unlock(&db->lock);
        return NULL;
    }

    struct qsysdb_txn *txn = calloc(1, sizeof(*txn));
    if (!txn) {
        pthread_mutex_unlock(&db->lock);
        return NULL;
    }

    txn->db = db;
    txn->txn_id = rsp.txn_id;
    db->active_txn = txn;

    pthread_mutex_unlock(&db->lock);
    return txn;
}

int qsysdb_txn_set(qsysdb_txn_t *txn, const char *path, const char *json_value)
{
    if (!txn || !path || !json_value || txn->committed || txn->aborted) {
        return QSYSDB_ERR_INVALID;
    }

    size_t path_len = strlen(path);
    size_t value_len = strlen(json_value);

    pthread_mutex_lock(&txn->db->lock);

    size_t req_size = sizeof(struct qsysdb_msg_txn_set_req) + path_len + value_len;
    struct qsysdb_msg_txn_set_req *req = alloca(req_size);
    memset(req, 0, sizeof(*req));

    qsysdb_msg_init(&req->hdr, QSYSDB_MSG_TXN_SET_REQ,
                    (uint32_t)req_size, txn->db->next_request_id++);
    req->txn_id = txn->txn_id;
    req->flags = 0;
    req->path_len = (uint16_t)path_len;
    req->value_len = (uint16_t)value_len;
    memcpy(req->data, path, path_len);
    memcpy(req->data + path_len, json_value, value_len);

    struct qsysdb_msg_header rsp;
    size_t rsp_len;

    int ret = client_request(txn->db, req, req_size, &rsp, sizeof(rsp), &rsp_len);

    pthread_mutex_unlock(&txn->db->lock);

    if (ret != QSYSDB_OK) {
        return ret;
    }
    return rsp.error_code;
}

int qsysdb_txn_delete(qsysdb_txn_t *txn, const char *path)
{
    if (!txn || !path || txn->committed || txn->aborted) {
        return QSYSDB_ERR_INVALID;
    }

    size_t path_len = strlen(path);

    pthread_mutex_lock(&txn->db->lock);

    size_t req_size = sizeof(struct qsysdb_msg_txn_delete_req) + path_len;
    struct qsysdb_msg_txn_delete_req *req = alloca(req_size);
    memset(req, 0, sizeof(*req));

    qsysdb_msg_init(&req->hdr, QSYSDB_MSG_TXN_DELETE_REQ,
                    (uint32_t)req_size, txn->db->next_request_id++);
    req->txn_id = txn->txn_id;
    req->path_len = (uint16_t)path_len;
    memcpy(req->path, path, path_len);

    struct qsysdb_msg_header rsp;
    size_t rsp_len;

    int ret = client_request(txn->db, req, req_size, &rsp, sizeof(rsp), &rsp_len);

    pthread_mutex_unlock(&txn->db->lock);

    if (ret != QSYSDB_OK) {
        return ret;
    }
    return rsp.error_code;
}

int qsysdb_txn_commit(qsysdb_txn_t *txn)
{
    if (!txn || txn->committed || txn->aborted) {
        return QSYSDB_ERR_INVALID;
    }

    pthread_mutex_lock(&txn->db->lock);

    struct qsysdb_msg_txn_commit_req req = {0};
    qsysdb_msg_init(&req.hdr, QSYSDB_MSG_TXN_COMMIT_REQ,
                    sizeof(req), txn->db->next_request_id++);
    req.txn_id = txn->txn_id;

    struct qsysdb_msg_txn_commit_rsp rsp;
    size_t rsp_len;

    int ret = client_request(txn->db, &req, sizeof(req), &rsp, sizeof(rsp), &rsp_len);

    if (ret == QSYSDB_OK && rsp.hdr.error_code == QSYSDB_OK) {
        txn->committed = true;
        txn->db->active_txn = NULL;
        pthread_mutex_unlock(&txn->db->lock);
        free(txn);
        return QSYSDB_OK;
    }

    pthread_mutex_unlock(&txn->db->lock);
    return ret != QSYSDB_OK ? ret : rsp.hdr.error_code;
}

void qsysdb_txn_abort(qsysdb_txn_t *txn)
{
    if (!txn || txn->committed || txn->aborted) {
        return;
    }

    pthread_mutex_lock(&txn->db->lock);

    struct qsysdb_msg_txn_abort_req req = {0};
    qsysdb_msg_init(&req.hdr, QSYSDB_MSG_TXN_ABORT_REQ,
                    sizeof(req), txn->db->next_request_id++);
    req.txn_id = txn->txn_id;

    struct qsysdb_msg_header rsp;
    size_t rsp_len;

    client_request(txn->db, &req, sizeof(req), &rsp, sizeof(rsp), &rsp_len);

    txn->aborted = true;
    txn->db->active_txn = NULL;

    pthread_mutex_unlock(&txn->db->lock);
    free(txn);
}

int qsysdb_stats(qsysdb_t *db, struct qsysdb_stats *stats)
{
    if (!db || !stats) {
        return QSYSDB_ERR_INVALID;
    }

    memset(stats, 0, sizeof(*stats));

    pthread_mutex_lock(&db->lock);

    if (db->conn_type == CONN_SOCKET) {
        struct qsysdb_msg_stats_req req = {0};
        qsysdb_msg_init(&req.hdr, QSYSDB_MSG_STATS_REQ,
                        sizeof(req), db->next_request_id++);

        struct qsysdb_msg_stats_rsp rsp;
        size_t rsp_len;

        int ret = client_request(db, &req, sizeof(req), &rsp, sizeof(rsp), &rsp_len);
        if (ret != QSYSDB_OK) {
            pthread_mutex_unlock(&db->lock);
            return ret;
        }

        if (rsp.hdr.error_code != QSYSDB_OK) {
            pthread_mutex_unlock(&db->lock);
            return rsp.hdr.error_code;
        }

        stats->entry_count = rsp.entry_count;
        stats->total_size = rsp.total_size;
        stats->used_size = rsp.used_size;
        stats->sequence = rsp.sequence;
        stats->total_sets = rsp.total_sets;
        stats->total_gets = rsp.total_gets;
        stats->total_deletes = rsp.total_deletes;
        stats->client_count = rsp.client_count;
        stats->subscription_count = rsp.subscription_count;
    } else if (db->shm.base) {
        /* Direct SHM stats */
        stats->entry_count = db->shm.header->entry_count;
        stats->total_size = db->shm.header->data_size;
        stats->used_size = db->shm.header->data_used;
        stats->sequence = db->shm.header->sequence;
        stats->total_sets = db->shm.header->total_sets;
        stats->total_gets = db->shm.header->total_gets;
        stats->total_deletes = db->shm.header->total_deletes;
    }

    pthread_mutex_unlock(&db->lock);
    return QSYSDB_OK;
}
