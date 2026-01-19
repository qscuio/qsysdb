/*
 * QSysDB - Client-Server Connection Tests
 *
 * Tests for Unix socket, TCP, and shared memory connections.
 * These tests start an in-process server for testing connections.
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <errno.h>

#include <qsysdb/types.h>
#include <qsysdb/qsysdb.h>
#include "common/shm.h"
#include "daemon/database.h"
#include "daemon/server.h"
#include "daemon/subscription.h"

#define TEST(name) static void test_##name(void)
#define RUN_TEST(name) do { \
    printf("  " #name "... "); \
    fflush(stdout); \
    test_##name(); \
    printf("OK\n"); \
} while(0)

#define TEST_SHM_NAME     "/qsysdb_conn_test"
#define TEST_SHM_SIZE     (64 * 1024 * 1024)
#define TEST_SOCKET_PATH  "/tmp/qsysdb_test.sock"
#define TEST_TCP_PORT     15959

/* Global test state */
static struct qsysdb_db g_db;
static struct sub_manager g_sub_mgr;
static struct server g_server;
static bool g_db_inited = false;
static bool g_sub_inited = false;
static bool g_server_started = false;

/*
 * Setup and teardown helpers
 */
static void cleanup_test_files(void)
{
    unlink(TEST_SOCKET_PATH);
    qsysdb_shm_unlink(TEST_SHM_NAME);
}

static int setup_server(bool enable_tcp)
{
    cleanup_test_files();

    /* Initialize database (creates SHM internally) */
    int ret = db_init(&g_db, TEST_SHM_NAME, TEST_SHM_SIZE);
    if (ret != QSYSDB_OK) {
        fprintf(stderr, "Failed to init database: %d\n", ret);
        return -1;
    }
    g_db_inited = true;

    /* Initialize subscription manager */
    ret = sub_manager_init(&g_sub_mgr);
    if (ret != QSYSDB_OK) {
        fprintf(stderr, "Failed to init sub manager: %d\n", ret);
        db_shutdown(&g_db);
        g_db_inited = false;
        return -1;
    }
    g_sub_inited = true;

    /* Configure server */
    struct server_config config;
    server_config_init(&config);
    config.unix_enabled = true;
    snprintf(config.unix_path, sizeof(config.unix_path), "%s", TEST_SOCKET_PATH);
    config.tcp_enabled = enable_tcp;
    if (enable_tcp) {
        snprintf(config.tcp_bind, sizeof(config.tcp_bind), "127.0.0.1");
        config.tcp_port = TEST_TCP_PORT;
    }

    /* Initialize server */
    ret = server_init(&g_server, &config, &g_db, &g_sub_mgr);
    if (ret != QSYSDB_OK) {
        fprintf(stderr, "Failed to init server: %d\n", ret);
        sub_manager_shutdown(&g_sub_mgr);
        g_sub_inited = false;
        db_shutdown(&g_db);
        g_db_inited = false;
        return -1;
    }

    /* Start server */
    ret = server_start(&g_server);
    if (ret != QSYSDB_OK) {
        fprintf(stderr, "Failed to start server: %d\n", ret);
        server_shutdown(&g_server);
        sub_manager_shutdown(&g_sub_mgr);
        g_sub_inited = false;
        db_shutdown(&g_db);
        g_db_inited = false;
        return -1;
    }

    g_server_started = true;

    /* Give server time to start */
    usleep(50000);

    return 0;
}

static void teardown_server(void)
{
    if (g_server_started) {
        server_shutdown(&g_server);
        g_server_started = false;
    }
    if (g_sub_inited) {
        sub_manager_shutdown(&g_sub_mgr);
        g_sub_inited = false;
    }
    if (g_db_inited) {
        db_shutdown(&g_db);
        g_db_inited = false;
    }
    cleanup_test_files();
}

/*
 * Unix Socket Connection Tests
 */

TEST(unix_connect_disconnect)
{
    assert(setup_server(false) == 0);

    qsysdb_t *db = qsysdb_connect(TEST_SOCKET_PATH, 0);
    assert(db != NULL);
    assert(qsysdb_connected(db) == true);

    qsysdb_disconnect(db);

    teardown_server();
}

TEST(unix_set_get)
{
    assert(setup_server(false) == 0);

    qsysdb_t *db = qsysdb_connect(TEST_SOCKET_PATH, 0);
    assert(db != NULL);

    /* Set a value */
    int ret = qsysdb_set(db, "/test/key", "{\"value\":42}");
    assert(ret == QSYSDB_OK);

    /* Get it back */
    char buf[256];
    ret = qsysdb_get(db, "/test/key", buf, sizeof(buf));
    assert(ret == QSYSDB_OK);
    assert(strcmp(buf, "{\"value\":42}") == 0);

    qsysdb_disconnect(db);
    teardown_server();
}

TEST(unix_exists_delete)
{
    assert(setup_server(false) == 0);

    qsysdb_t *db = qsysdb_connect(TEST_SOCKET_PATH, 0);
    assert(db != NULL);

    /* Set a value */
    assert(qsysdb_set(db, "/exists/key", "true") == QSYSDB_OK);

    /* Check exists */
    assert(qsysdb_exists(db, "/exists/key") == 1);
    assert(qsysdb_exists(db, "/exists/nonexistent") == 0);

    /* Delete */
    assert(qsysdb_delete(db, "/exists/key") == QSYSDB_OK);
    assert(qsysdb_exists(db, "/exists/key") == 0);

    qsysdb_disconnect(db);
    teardown_server();
}

TEST(unix_multiple_clients)
{
    assert(setup_server(false) == 0);

    /* Connect multiple clients */
    qsysdb_t *db1 = qsysdb_connect(TEST_SOCKET_PATH, 0);
    qsysdb_t *db2 = qsysdb_connect(TEST_SOCKET_PATH, 0);
    qsysdb_t *db3 = qsysdb_connect(TEST_SOCKET_PATH, 0);

    assert(db1 != NULL);
    assert(db2 != NULL);
    assert(db3 != NULL);

    /* Each client writes to different keys */
    assert(qsysdb_set(db1, "/client/1", "{\"id\":1}") == QSYSDB_OK);
    assert(qsysdb_set(db2, "/client/2", "{\"id\":2}") == QSYSDB_OK);
    assert(qsysdb_set(db3, "/client/3", "{\"id\":3}") == QSYSDB_OK);

    /* All clients can see all keys */
    char buf[256];
    assert(qsysdb_get(db1, "/client/2", buf, sizeof(buf)) == QSYSDB_OK);
    assert(strcmp(buf, "{\"id\":2}") == 0);

    assert(qsysdb_get(db2, "/client/3", buf, sizeof(buf)) == QSYSDB_OK);
    assert(strcmp(buf, "{\"id\":3}") == 0);

    assert(qsysdb_get(db3, "/client/1", buf, sizeof(buf)) == QSYSDB_OK);
    assert(strcmp(buf, "{\"id\":1}") == 0);

    qsysdb_disconnect(db1);
    qsysdb_disconnect(db2);
    qsysdb_disconnect(db3);

    teardown_server();
}

TEST(unix_large_value)
{
    assert(setup_server(false) == 0);

    qsysdb_t *db = qsysdb_connect(TEST_SOCKET_PATH, 0);
    assert(db != NULL);

    /* Create a large JSON value */
    char *large = malloc(32 * 1024);
    assert(large != NULL);

    strcpy(large, "{\"data\":\"");
    size_t pos = strlen(large);
    for (int i = 0; i < 30000; i++) {
        large[pos++] = 'a' + (i % 26);
    }
    strcpy(large + pos, "\"}");

    /* Set and get */
    assert(qsysdb_set(db, "/large", large) == QSYSDB_OK);

    char *buf = malloc(64 * 1024);
    assert(buf != NULL);
    assert(qsysdb_get(db, "/large", buf, 64 * 1024) == QSYSDB_OK);
    assert(strcmp(buf, large) == 0);

    free(large);
    free(buf);
    qsysdb_disconnect(db);
    teardown_server();
}

/*
 * TCP Connection Tests
 */

TEST(tcp_connect_disconnect)
{
    assert(setup_server(true) == 0);

    qsysdb_t *db = qsysdb_connect_tcp("127.0.0.1", TEST_TCP_PORT, 0);
    assert(db != NULL);
    assert(qsysdb_connected(db) == true);

    qsysdb_disconnect(db);

    teardown_server();
}

TEST(tcp_set_get)
{
    assert(setup_server(true) == 0);

    qsysdb_t *db = qsysdb_connect_tcp("127.0.0.1", TEST_TCP_PORT, 0);
    assert(db != NULL);

    /* Set a value */
    int ret = qsysdb_set(db, "/tcp/key", "{\"tcp\":true}");
    assert(ret == QSYSDB_OK);

    /* Get it back */
    char buf[256];
    ret = qsysdb_get(db, "/tcp/key", buf, sizeof(buf));
    assert(ret == QSYSDB_OK);
    assert(strcmp(buf, "{\"tcp\":true}") == 0);

    qsysdb_disconnect(db);
    teardown_server();
}

TEST(tcp_localhost_default)
{
    assert(setup_server(true) == 0);

    /* Connect with NULL host (should default to localhost) */
    qsysdb_t *db = qsysdb_connect_tcp(NULL, TEST_TCP_PORT, 0);
    assert(db != NULL);

    assert(qsysdb_set(db, "/tcp/default", "1") == QSYSDB_OK);

    qsysdb_disconnect(db);
    teardown_server();
}

TEST(tcp_multiple_clients)
{
    assert(setup_server(true) == 0);

    qsysdb_t *db1 = qsysdb_connect_tcp("127.0.0.1", TEST_TCP_PORT, 0);
    qsysdb_t *db2 = qsysdb_connect_tcp("127.0.0.1", TEST_TCP_PORT, 0);

    assert(db1 != NULL);
    assert(db2 != NULL);

    /* Both can write and read */
    assert(qsysdb_set(db1, "/tcp/client1", "true") == QSYSDB_OK);
    assert(qsysdb_set(db2, "/tcp/client2", "true") == QSYSDB_OK);

    char buf[64];
    assert(qsysdb_get(db1, "/tcp/client2", buf, sizeof(buf)) == QSYSDB_OK);
    assert(qsysdb_get(db2, "/tcp/client1", buf, sizeof(buf)) == QSYSDB_OK);

    qsysdb_disconnect(db1);
    qsysdb_disconnect(db2);

    teardown_server();
}

/*
 * Mixed Connection Tests
 */

TEST(mixed_unix_tcp)
{
    assert(setup_server(true) == 0);

    /* Connect via both Unix and TCP */
    qsysdb_t *unix_db = qsysdb_connect(TEST_SOCKET_PATH, 0);
    qsysdb_t *tcp_db = qsysdb_connect_tcp("127.0.0.1", TEST_TCP_PORT, 0);

    assert(unix_db != NULL);
    assert(tcp_db != NULL);

    /* Unix client writes */
    assert(qsysdb_set(unix_db, "/mixed/from_unix", "{\"source\":\"unix\"}") == QSYSDB_OK);

    /* TCP client writes */
    assert(qsysdb_set(tcp_db, "/mixed/from_tcp", "{\"source\":\"tcp\"}") == QSYSDB_OK);

    /* Both can read each other's data */
    char buf[256];
    assert(qsysdb_get(unix_db, "/mixed/from_tcp", buf, sizeof(buf)) == QSYSDB_OK);
    assert(strcmp(buf, "{\"source\":\"tcp\"}") == 0);

    assert(qsysdb_get(tcp_db, "/mixed/from_unix", buf, sizeof(buf)) == QSYSDB_OK);
    assert(strcmp(buf, "{\"source\":\"unix\"}") == 0);

    qsysdb_disconnect(unix_db);
    qsysdb_disconnect(tcp_db);

    teardown_server();
}

/*
 * Shared Memory Direct Access Tests
 */

TEST(shm_direct_open)
{
    assert(setup_server(false) == 0);

    /* Write via socket */
    qsysdb_t *sock_db = qsysdb_connect(TEST_SOCKET_PATH, 0);
    assert(sock_db != NULL);
    assert(qsysdb_set(sock_db, "/shm/test", "{\"from\":\"socket\"}") == QSYSDB_OK);

    /* Open SHM directly */
    qsysdb_t *shm_db = qsysdb_connect_shm(TEST_SHM_NAME, QSYSDB_CONN_READONLY);
    assert(shm_db != NULL);

    /* Read via SHM (direct read, bypassing socket) */
    char buf[256];
    int ret = qsysdb_get(shm_db, "/shm/test", buf, sizeof(buf));
    assert(ret == QSYSDB_OK);
    assert(strcmp(buf, "{\"from\":\"socket\"}") == 0);

    qsysdb_disconnect(shm_db);
    qsysdb_disconnect(sock_db);

    teardown_server();
}

TEST(shm_with_socket)
{
    assert(setup_server(false) == 0);

    /* Connect with SHM flag - should get both socket and SHM access */
    qsysdb_t *db = qsysdb_connect(TEST_SOCKET_PATH, QSYSDB_CONN_SHM);
    assert(db != NULL);

    /* Write via socket */
    assert(qsysdb_set(db, "/hybrid/key", "{\"hybrid\":true}") == QSYSDB_OK);

    /* Read - may use SHM fast path if available */
    char buf[256];
    assert(qsysdb_get(db, "/hybrid/key", buf, sizeof(buf)) == QSYSDB_OK);
    assert(strcmp(buf, "{\"hybrid\":true}") == 0);

    qsysdb_disconnect(db);

    teardown_server();
}

/*
 * Error Handling Tests
 */

TEST(connect_failure)
{
    /* Try to connect to non-existent socket */
    qsysdb_t *db = qsysdb_connect("/nonexistent/socket.sock", 0);
    assert(db == NULL);

    /* Try TCP to localhost with no server */
    db = qsysdb_connect_tcp("127.0.0.1", 59599, 0);
    assert(db == NULL);
}

TEST(invalid_path)
{
    assert(setup_server(false) == 0);

    qsysdb_t *db = qsysdb_connect(TEST_SOCKET_PATH, 0);
    assert(db != NULL);

    /* Path without leading slash */
    int ret = qsysdb_set(db, "no/leading/slash", "1");
    assert(ret == QSYSDB_ERR_BADPATH);

    /* Empty path is invalid */
    ret = qsysdb_set(db, "", "1");
    assert(ret == QSYSDB_ERR_BADPATH);

    qsysdb_disconnect(db);
    teardown_server();
}

TEST(invalid_json)
{
    assert(setup_server(false) == 0);

    qsysdb_t *db = qsysdb_connect(TEST_SOCKET_PATH, 0);
    assert(db != NULL);

    /* Invalid JSON */
    int ret = qsysdb_set(db, "/bad", "not json");
    assert(ret == QSYSDB_ERR_BADJSON);

    ret = qsysdb_set(db, "/bad", "{broken");
    assert(ret == QSYSDB_ERR_BADJSON);

    qsysdb_disconnect(db);
    teardown_server();
}

TEST(get_nonexistent)
{
    assert(setup_server(false) == 0);

    qsysdb_t *db = qsysdb_connect(TEST_SOCKET_PATH, 0);
    assert(db != NULL);

    char buf[256];
    int ret = qsysdb_get(db, "/does/not/exist", buf, sizeof(buf));
    assert(ret == QSYSDB_ERR_NOTFOUND);

    qsysdb_disconnect(db);
    teardown_server();
}

/*
 * Statistics Tests
 */

TEST(stats)
{
    assert(setup_server(false) == 0);

    qsysdb_t *db = qsysdb_connect(TEST_SOCKET_PATH, 0);
    assert(db != NULL);

    /* Perform some operations */
    assert(qsysdb_set(db, "/stats/a", "1") == QSYSDB_OK);
    assert(qsysdb_set(db, "/stats/b", "2") == QSYSDB_OK);

    char buf[64];
    assert(qsysdb_get(db, "/stats/a", buf, sizeof(buf)) == QSYSDB_OK);

    /* Get stats */
    struct qsysdb_stats stats;
    int ret = qsysdb_stats(db, &stats);
    assert(ret == QSYSDB_OK);
    assert(stats.entry_count >= 2);
    assert(stats.total_sets >= 2);
    assert(stats.total_gets >= 1);

    qsysdb_disconnect(db);
    teardown_server();
}

int main(void)
{
    printf("Running connection tests...\n\n");

    printf("Unix Socket Tests:\n");
    RUN_TEST(unix_connect_disconnect);
    RUN_TEST(unix_set_get);
    RUN_TEST(unix_exists_delete);
    RUN_TEST(unix_multiple_clients);
    RUN_TEST(unix_large_value);

    printf("\nTCP Tests:\n");
    RUN_TEST(tcp_connect_disconnect);
    RUN_TEST(tcp_set_get);
    RUN_TEST(tcp_localhost_default);
    RUN_TEST(tcp_multiple_clients);

    printf("\nMixed Connection Tests:\n");
    RUN_TEST(mixed_unix_tcp);

    printf("\nShared Memory Tests:\n");
    RUN_TEST(shm_direct_open);
    RUN_TEST(shm_with_socket);

    printf("\nError Handling Tests:\n");
    RUN_TEST(connect_failure);
    RUN_TEST(invalid_path);
    RUN_TEST(invalid_json);
    RUN_TEST(get_nonexistent);

    printf("\nStatistics Tests:\n");
    RUN_TEST(stats);

    printf("\nAll connection tests passed!\n");
    return 0;
}
