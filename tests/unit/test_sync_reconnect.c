/*
 * QSysDB - Sync Client Reconnect/Callback Tests
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <pthread.h>

#include <qsysdb/types.h>
#include <qsysdb/qsysdb.h>
#include "lib/client.h"
#include "framework/test_framework.h"

static const char *_current_suite_name = "sync_reconnect";

/* Callback tracking */
static int g_connect_count;
static int g_disconnect_count;
static int g_disconnect_reason;
static void *g_connect_userdata;
static void *g_disconnect_userdata;

static void reset_counters(void) {
    g_connect_count = 0;
    g_disconnect_count = 0;
    g_disconnect_reason = 0;
    g_connect_userdata = NULL;
    g_disconnect_userdata = NULL;
}

static void on_connect(qsysdb_t *db, void *userdata) {
    (void)db;
    g_connect_count++;
    g_connect_userdata = userdata;
}

static void on_disconnect(qsysdb_t *db, int reason, void *userdata) {
    (void)db;
    g_disconnect_count++;
    g_disconnect_reason = reason;
    g_disconnect_userdata = userdata;
}

/* Test: callback registration stores pointers */
TEST(callback_registration) {
    /* Allocate a minimal client struct directly */
    struct qsysdb *db = calloc(1, sizeof(*db));
    TEST_ASSERT_NOT_NULL(db);
    pthread_mutex_init(&db->lock, NULL);

    int tag1 = 42, tag2 = 99;

    qsysdb_on_connect(db, on_connect, &tag1);
    qsysdb_on_disconnect(db, on_disconnect, &tag2);

    TEST_ASSERT(db->on_connect == on_connect);
    TEST_ASSERT(db->on_connect_data == &tag1);
    TEST_ASSERT(db->on_disconnect == on_disconnect);
    TEST_ASSERT(db->on_disconnect_data == &tag2);

    /* Clear callbacks */
    qsysdb_on_connect(db, NULL, NULL);
    TEST_ASSERT_NULL(db->on_connect);

    pthread_mutex_destroy(&db->lock);
    free(db);
}

/* Test: reconnect config stores values */
TEST(reconnect_config) {
    struct qsysdb *db = calloc(1, sizeof(*db));
    TEST_ASSERT_NOT_NULL(db);
    pthread_mutex_init(&db->lock, NULL);

    qsysdb_set_reconnect(db, true, 500, 3);

    TEST_ASSERT_TRUE(db->auto_reconnect);
    TEST_ASSERT_EQ(500, db->reconnect_interval_ms);
    TEST_ASSERT_EQ(3, db->reconnect_max_retries);

    /* Default interval for invalid value */
    qsysdb_set_reconnect(db, true, 0, 0);
    TEST_ASSERT_EQ(1000, db->reconnect_interval_ms);

    pthread_mutex_destroy(&db->lock);
    free(db);
}

/* Test: client_handle_disconnect fires disconnect callback */
TEST(disconnect_callback_fires) {
    reset_counters();

    struct qsysdb *db = calloc(1, sizeof(*db));
    TEST_ASSERT_NOT_NULL(db);
    pthread_mutex_init(&db->lock, NULL);
    db->connected = true;
    db->conn_type = CONN_SOCKET;

    int tag = 77;
    qsysdb_on_disconnect(db, on_disconnect, &tag);

    pthread_mutex_lock(&db->lock);
    int ret = client_handle_disconnect(db, QSYSDB_ERR_DISCONNECTED,
                                       QSYSDB_DISCONNECT_SERVER);
    pthread_mutex_unlock(&db->lock);

    TEST_ASSERT_EQ(1, g_disconnect_count);
    TEST_ASSERT_EQ(QSYSDB_DISCONNECT_SERVER, g_disconnect_reason);
    TEST_ASSERT(g_disconnect_userdata == &tag);
    TEST_ASSERT_EQ(QSYSDB_ERR_DISCONNECTED, ret);  /* No auto-reconnect */

    pthread_mutex_destroy(&db->lock);
    free(db);
}

/* Test: non-disconnect errors pass through unchanged */
TEST(non_disconnect_passthrough) {
    reset_counters();

    struct qsysdb *db = calloc(1, sizeof(*db));
    TEST_ASSERT_NOT_NULL(db);
    pthread_mutex_init(&db->lock, NULL);
    db->connected = true;

    qsysdb_on_disconnect(db, on_disconnect, NULL);

    pthread_mutex_lock(&db->lock);
    int ret = client_handle_disconnect(db, QSYSDB_ERR_NOTFOUND,
                                       QSYSDB_DISCONNECT_SERVER);
    pthread_mutex_unlock(&db->lock);

    TEST_ASSERT_EQ(0, g_disconnect_count);  /* Not called for non-disconnect errors */
    TEST_ASSERT_EQ(QSYSDB_ERR_NOTFOUND, ret);

    pthread_mutex_destroy(&db->lock);
    free(db);
}

/* Test: NULL db is safe */
TEST(null_safety) {
    qsysdb_on_connect(NULL, on_connect, NULL);
    qsysdb_on_disconnect(NULL, on_disconnect, NULL);
    qsysdb_set_reconnect(NULL, true, 1000, 5);
    TEST_ASSERT_TRUE(1);  /* If we get here, nothing crashed */
}

/* Test: IO error also triggers disconnect callback */
TEST(io_error_triggers_disconnect) {
    reset_counters();

    struct qsysdb *db = calloc(1, sizeof(*db));
    TEST_ASSERT_NOT_NULL(db);
    pthread_mutex_init(&db->lock, NULL);
    db->connected = true;
    db->conn_type = CONN_SOCKET;

    int tag = 88;
    qsysdb_on_disconnect(db, on_disconnect, &tag);

    pthread_mutex_lock(&db->lock);
    int ret = client_handle_disconnect(db, QSYSDB_ERR_IO,
                                       QSYSDB_DISCONNECT_IO);
    pthread_mutex_unlock(&db->lock);

    TEST_ASSERT_EQ(1, g_disconnect_count);
    TEST_ASSERT_EQ(QSYSDB_DISCONNECT_IO, g_disconnect_reason);
    TEST_ASSERT_EQ(QSYSDB_ERR_IO, ret);
    TEST_ASSERT_FALSE(db->connected);

    pthread_mutex_destroy(&db->lock);
    free(db);
}

TEST_MAIN()
