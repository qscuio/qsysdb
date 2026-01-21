/*
 * QSysDB - Async Client API Unit Tests
 *
 * Tests the async client API functionality including:
 *   - Client creation and destruction
 *   - Configuration and state management
 *   - Watch builder pattern
 *   - Batch operations builder
 *   - Error handling
 *
 * Note: These tests focus on the API surface and local operations.
 * Integration tests with a running server are in separate files.
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <qsysdb/types.h>
#include <qsysdb/async.h>
#include "framework/test_framework.h"

static const char *_current_suite_name = "async_client";

/* ============================================
 * Client Creation Tests
 * ============================================ */

TEST(client_new_returns_valid_handle)
{
    qsysdb_async_t *client = qsysdb_async_new();
    TEST_ASSERT_NOT_NULL(client);
    qsysdb_async_free(client);
}

TEST(client_free_null_safe)
{
    /* Should not crash when freeing NULL */
    qsysdb_async_free(NULL);
    TEST_ASSERT_TRUE(1);  /* If we get here, it didn't crash */
}

TEST(client_multiple_create_free)
{
    /* Test creating and freeing multiple clients */
    qsysdb_async_t *clients[10];

    for (int i = 0; i < 10; i++) {
        clients[i] = qsysdb_async_new();
        TEST_ASSERT_NOT_NULL(clients[i]);
    }

    for (int i = 0; i < 10; i++) {
        qsysdb_async_free(clients[i]);
    }
}

/* ============================================
 * Client State Tests
 * ============================================ */

TEST(client_not_connected_initially)
{
    qsysdb_async_t *client = qsysdb_async_new();
    TEST_ASSERT_NOT_NULL(client);

    TEST_ASSERT_FALSE(qsysdb_async_is_connected(client));

    qsysdb_async_free(client);
}

TEST(client_fd_invalid_when_not_connected)
{
    qsysdb_async_t *client = qsysdb_async_new();
    TEST_ASSERT_NOT_NULL(client);

    int fd = qsysdb_async_fd(client);
    TEST_ASSERT_EQ(-1, fd);

    qsysdb_async_free(client);
}

TEST(client_pending_count_zero_initially)
{
    qsysdb_async_t *client = qsysdb_async_new();
    TEST_ASSERT_NOT_NULL(client);

    int count = qsysdb_async_pending_count(client);
    TEST_ASSERT_EQ(0, count);

    qsysdb_async_free(client);
}

TEST(client_watch_count_zero_initially)
{
    qsysdb_async_t *client = qsysdb_async_new();
    TEST_ASSERT_NOT_NULL(client);

    int count = qsysdb_async_watch_count(client);
    TEST_ASSERT_EQ(0, count);

    qsysdb_async_free(client);
}

/* ============================================
 * Client Configuration Tests
 * ============================================ */

static bool state_handler_called = false;
static bool error_handler_called = false;

static void test_state_handler(qsysdb_async_t *client, bool connected, void *userdata)
{
    (void)client;
    (void)connected;
    (void)userdata;
    state_handler_called = true;
}

static void test_error_handler(qsysdb_async_t *client, int error,
                                const char *message, void *userdata)
{
    (void)client;
    (void)error;
    (void)message;
    (void)userdata;
    error_handler_called = true;
}

TEST(client_set_state_handler)
{
    qsysdb_async_t *client = qsysdb_async_new();
    TEST_ASSERT_NOT_NULL(client);

    /* Should not crash */
    qsysdb_async_on_state(client, test_state_handler, NULL);

    qsysdb_async_free(client);
}

TEST(client_set_error_handler)
{
    qsysdb_async_t *client = qsysdb_async_new();
    TEST_ASSERT_NOT_NULL(client);

    /* Should not crash */
    qsysdb_async_on_error(client, test_error_handler, NULL);

    qsysdb_async_free(client);
}

TEST(client_set_reconnect)
{
    qsysdb_async_t *client = qsysdb_async_new();
    TEST_ASSERT_NOT_NULL(client);

    /* Should not crash */
    qsysdb_async_set_reconnect(client, true, 1000);
    qsysdb_async_set_reconnect(client, false, 0);

    qsysdb_async_free(client);
}

/* ============================================
 * Connection Error Tests
 * ============================================ */

TEST(connect_to_invalid_path_fails)
{
    qsysdb_async_t *client = qsysdb_async_new();
    TEST_ASSERT_NOT_NULL(client);

    int ret = qsysdb_async_connect(client, "/nonexistent/path/to/socket.sock", 0);
    TEST_ASSERT_NE(QSYSDB_OK, ret);

    qsysdb_async_free(client);
}

TEST(connect_tcp_to_invalid_host_fails)
{
    qsysdb_async_t *client = qsysdb_async_new();
    TEST_ASSERT_NOT_NULL(client);

    /* Port 1 is unlikely to have anything listening */
    int ret = qsysdb_async_connect_tcp(client, "127.0.0.1", 1, 0);
    /* May fail immediately or return would-block depending on implementation */
    TEST_ASSERT_TRUE(ret != QSYSDB_OK || !qsysdb_async_is_connected(client));

    qsysdb_async_free(client);
}

TEST(disconnect_when_not_connected)
{
    qsysdb_async_t *client = qsysdb_async_new();
    TEST_ASSERT_NOT_NULL(client);

    /* Should not crash when disconnecting while not connected */
    qsysdb_async_disconnect(client);

    TEST_ASSERT_FALSE(qsysdb_async_is_connected(client));

    qsysdb_async_free(client);
}

/* ============================================
 * Watch Builder Tests
 * ============================================ */

TEST(watch_create_returns_handle)
{
    qsysdb_async_t *client = qsysdb_async_new();
    TEST_ASSERT_NOT_NULL(client);

    qsysdb_watch_t *watch = qsysdb_watch_create(client);
    TEST_ASSERT_NOT_NULL(watch);

    qsysdb_watch_stop(watch);
    qsysdb_async_free(client);
}

TEST(watch_create_null_client)
{
    qsysdb_watch_t *watch = qsysdb_watch_create(NULL);
    TEST_ASSERT_NULL(watch);
}

static void dummy_event_handler(qsysdb_event_t *event, void *userdata)
{
    (void)event;
    (void)userdata;
}

TEST(watch_builder_chaining)
{
    qsysdb_async_t *client = qsysdb_async_new();
    TEST_ASSERT_NOT_NULL(client);

    qsysdb_watch_t *watch = qsysdb_watch_create(client);
    TEST_ASSERT_NOT_NULL(watch);

    /* Test chaining - each function should return the same watch */
    qsysdb_watch_t *w1 = qsysdb_watch_pattern(watch, "/test/path");
    TEST_ASSERT_EQ(watch, w1);

    qsysdb_watch_t *w2 = qsysdb_watch_on_event(watch, dummy_event_handler, NULL);
    TEST_ASSERT_EQ(watch, w2);

    qsysdb_watch_t *w3 = qsysdb_watch_get_initial(watch, true);
    TEST_ASSERT_EQ(watch, w3);

    qsysdb_watch_t *w4 = qsysdb_watch_queue_size(watch, 100);
    TEST_ASSERT_EQ(watch, w4);

    qsysdb_watch_stop(watch);
    qsysdb_async_free(client);
}

TEST(watch_pattern_null_safe)
{
    qsysdb_async_t *client = qsysdb_async_new();
    TEST_ASSERT_NOT_NULL(client);

    qsysdb_watch_t *watch = qsysdb_watch_create(client);
    TEST_ASSERT_NOT_NULL(watch);

    /* Should handle NULL pattern gracefully */
    qsysdb_watch_t *w = qsysdb_watch_pattern(watch, NULL);
    TEST_ASSERT_EQ(watch, w);  /* Should return same watch even on error */

    qsysdb_watch_stop(watch);
    qsysdb_async_free(client);
}

TEST(watch_on_create_handler)
{
    qsysdb_async_t *client = qsysdb_async_new();
    TEST_ASSERT_NOT_NULL(client);

    qsysdb_watch_t *watch = qsysdb_watch_create(client);
    TEST_ASSERT_NOT_NULL(watch);

    qsysdb_watch_t *w = qsysdb_watch_on_create(watch, dummy_event_handler, NULL);
    TEST_ASSERT_EQ(watch, w);

    qsysdb_watch_stop(watch);
    qsysdb_async_free(client);
}

TEST(watch_on_update_handler)
{
    qsysdb_async_t *client = qsysdb_async_new();
    TEST_ASSERT_NOT_NULL(client);

    qsysdb_watch_t *watch = qsysdb_watch_create(client);
    TEST_ASSERT_NOT_NULL(watch);

    qsysdb_watch_t *w = qsysdb_watch_on_update(watch, dummy_event_handler, NULL);
    TEST_ASSERT_EQ(watch, w);

    qsysdb_watch_stop(watch);
    qsysdb_async_free(client);
}

TEST(watch_on_delete_handler)
{
    qsysdb_async_t *client = qsysdb_async_new();
    TEST_ASSERT_NOT_NULL(client);

    qsysdb_watch_t *watch = qsysdb_watch_create(client);
    TEST_ASSERT_NOT_NULL(watch);

    qsysdb_watch_t *w = qsysdb_watch_on_delete(watch, dummy_event_handler, NULL);
    TEST_ASSERT_EQ(watch, w);

    qsysdb_watch_stop(watch);
    qsysdb_async_free(client);
}

TEST(watch_start_without_connection_fails)
{
    qsysdb_async_t *client = qsysdb_async_new();
    TEST_ASSERT_NOT_NULL(client);

    qsysdb_watch_t *watch = qsysdb_watch_create(client);
    TEST_ASSERT_NOT_NULL(watch);

    qsysdb_watch_pattern(watch, "/test/path");
    qsysdb_watch_on_event(watch, dummy_event_handler, NULL);

    /* Should fail because client is not connected */
    int id = qsysdb_watch_start(watch);
    TEST_ASSERT_LT(id, 0);

    qsysdb_watch_stop(watch);
    qsysdb_async_free(client);
}

TEST(watch_pause_resume)
{
    qsysdb_async_t *client = qsysdb_async_new();
    TEST_ASSERT_NOT_NULL(client);

    qsysdb_watch_t *watch = qsysdb_watch_create(client);
    TEST_ASSERT_NOT_NULL(watch);

    /* Should not crash even when not started */
    qsysdb_watch_pause(watch);
    qsysdb_watch_resume(watch);

    qsysdb_watch_stop(watch);
    qsysdb_async_free(client);
}

TEST(watch_stop_null_safe)
{
    /* Should not crash */
    qsysdb_watch_stop(NULL);
    TEST_ASSERT_TRUE(1);
}

/* ============================================
 * Batch Operations Tests
 * ============================================ */

TEST(batch_create_returns_handle)
{
    qsysdb_async_t *client = qsysdb_async_new();
    TEST_ASSERT_NOT_NULL(client);

    qsysdb_batch_t *batch = qsysdb_batch_create(client);
    TEST_ASSERT_NOT_NULL(batch);

    qsysdb_batch_cancel(batch);
    qsysdb_async_free(client);
}

TEST(batch_create_null_client)
{
    qsysdb_batch_t *batch = qsysdb_batch_create(NULL);
    TEST_ASSERT_NULL(batch);
}

TEST(batch_count_initially_zero)
{
    qsysdb_async_t *client = qsysdb_async_new();
    TEST_ASSERT_NOT_NULL(client);

    qsysdb_batch_t *batch = qsysdb_batch_create(client);
    TEST_ASSERT_NOT_NULL(batch);

    TEST_ASSERT_EQ(0, qsysdb_batch_count(batch));

    qsysdb_batch_cancel(batch);
    qsysdb_async_free(client);
}

TEST(batch_set_increments_count)
{
    qsysdb_async_t *client = qsysdb_async_new();
    TEST_ASSERT_NOT_NULL(client);

    qsysdb_batch_t *batch = qsysdb_batch_create(client);
    TEST_ASSERT_NOT_NULL(batch);

    qsysdb_batch_set(batch, "/test/key1", "value1");
    TEST_ASSERT_EQ(1, qsysdb_batch_count(batch));

    qsysdb_batch_set(batch, "/test/key2", "value2");
    TEST_ASSERT_EQ(2, qsysdb_batch_count(batch));

    qsysdb_batch_set(batch, "/test/key3", "value3");
    TEST_ASSERT_EQ(3, qsysdb_batch_count(batch));

    qsysdb_batch_cancel(batch);
    qsysdb_async_free(client);
}

TEST(batch_delete_increments_count)
{
    qsysdb_async_t *client = qsysdb_async_new();
    TEST_ASSERT_NOT_NULL(client);

    qsysdb_batch_t *batch = qsysdb_batch_create(client);
    TEST_ASSERT_NOT_NULL(batch);

    qsysdb_batch_delete(batch, "/test/key1");
    TEST_ASSERT_EQ(1, qsysdb_batch_count(batch));

    qsysdb_batch_delete(batch, "/test/key2");
    TEST_ASSERT_EQ(2, qsysdb_batch_count(batch));

    qsysdb_batch_cancel(batch);
    qsysdb_async_free(client);
}

TEST(batch_mixed_operations)
{
    qsysdb_async_t *client = qsysdb_async_new();
    TEST_ASSERT_NOT_NULL(client);

    qsysdb_batch_t *batch = qsysdb_batch_create(client);
    TEST_ASSERT_NOT_NULL(batch);

    qsysdb_batch_set(batch, "/test/key1", "value1");
    qsysdb_batch_delete(batch, "/test/key2");
    qsysdb_batch_set(batch, "/test/key3", "value3");

    TEST_ASSERT_EQ(3, qsysdb_batch_count(batch));

    qsysdb_batch_cancel(batch);
    qsysdb_async_free(client);
}

TEST(batch_chaining)
{
    qsysdb_async_t *client = qsysdb_async_new();
    TEST_ASSERT_NOT_NULL(client);

    qsysdb_batch_t *batch = qsysdb_batch_create(client);
    TEST_ASSERT_NOT_NULL(batch);

    /* Test chaining - each function should return the same batch */
    qsysdb_batch_t *b1 = qsysdb_batch_set(batch, "/key1", "val1");
    TEST_ASSERT_EQ(batch, b1);

    qsysdb_batch_t *b2 = qsysdb_batch_delete(batch, "/key2");
    TEST_ASSERT_EQ(batch, b2);

    qsysdb_batch_cancel(batch);
    qsysdb_async_free(client);
}

TEST(batch_cancel_null_safe)
{
    /* Should not crash */
    qsysdb_batch_cancel(NULL);
    TEST_ASSERT_TRUE(1);
}

TEST(batch_execute_without_connection_fails)
{
    qsysdb_async_t *client = qsysdb_async_new();
    TEST_ASSERT_NOT_NULL(client);

    qsysdb_batch_t *batch = qsysdb_batch_create(client);
    TEST_ASSERT_NOT_NULL(batch);

    qsysdb_batch_set(batch, "/test/key", "value");

    /* Should fail because client is not connected */
    qsysdb_op_t *op = qsysdb_batch_execute(batch, NULL, NULL);
    TEST_ASSERT_NULL(op);

    /* batch is consumed by execute, don't cancel */
    qsysdb_async_free(client);
}

/* ============================================
 * Statistics Tests
 * ============================================ */

TEST(client_stats_initially_zero)
{
    qsysdb_async_t *client = qsysdb_async_new();
    TEST_ASSERT_NOT_NULL(client);

    qsysdb_client_stats_t stats;
    qsysdb_async_get_stats(client, &stats);

    TEST_ASSERT_EQ(0, stats.ops_sent);
    TEST_ASSERT_EQ(0, stats.ops_completed);
    TEST_ASSERT_EQ(0, stats.ops_failed);
    TEST_ASSERT_EQ(0, stats.events_received);
    TEST_ASSERT_EQ(0, stats.bytes_sent);
    TEST_ASSERT_EQ(0, stats.bytes_received);
    TEST_ASSERT_EQ(0, stats.pending_ops);
    TEST_ASSERT_EQ(0, stats.active_watches);

    qsysdb_async_free(client);
}

/* ============================================
 * Event Loop Integration Tests
 * ============================================ */

TEST(process_when_not_connected)
{
    qsysdb_async_t *client = qsysdb_async_new();
    TEST_ASSERT_NOT_NULL(client);

    /* Should handle gracefully when not connected */
    int ret = qsysdb_async_process(client);
    TEST_ASSERT_LE(ret, 0);  /* Should return error or 0 */

    qsysdb_async_free(client);
}

TEST(poll_when_not_connected)
{
    qsysdb_async_t *client = qsysdb_async_new();
    TEST_ASSERT_NOT_NULL(client);

    /* Should return immediately with error when not connected */
    int ret = qsysdb_async_poll(client, 0);
    TEST_ASSERT_LE(ret, 0);

    qsysdb_async_free(client);
}

TEST(events_when_not_connected)
{
    qsysdb_async_t *client = qsysdb_async_new();
    TEST_ASSERT_NOT_NULL(client);

    int events = qsysdb_async_events(client);
    /* When not connected, should return 0 or minimal events */
    TEST_ASSERT_GE(events, 0);

    qsysdb_async_free(client);
}

/* ============================================
 * Async Operations Tests (without connection)
 * ============================================ */

static void dummy_complete_handler(qsysdb_result_t *result, void *userdata)
{
    (void)result;
    (void)userdata;
}

static void dummy_get_handler(qsysdb_get_result_t *result, void *userdata)
{
    (void)result;
    (void)userdata;
}

TEST(async_set_without_connection)
{
    qsysdb_async_t *client = qsysdb_async_new();
    TEST_ASSERT_NOT_NULL(client);

    /* Should fail because not connected */
    qsysdb_op_t *op = qsysdb_async_set(client, "/test/key", "value",
                                        dummy_complete_handler, NULL);
    TEST_ASSERT_NULL(op);

    qsysdb_async_free(client);
}

TEST(async_get_without_connection)
{
    qsysdb_async_t *client = qsysdb_async_new();
    TEST_ASSERT_NOT_NULL(client);

    /* Should fail because not connected */
    qsysdb_op_t *op = qsysdb_async_get(client, "/test/key",
                                        dummy_get_handler, NULL);
    TEST_ASSERT_NULL(op);

    qsysdb_async_free(client);
}

TEST(async_delete_without_connection)
{
    qsysdb_async_t *client = qsysdb_async_new();
    TEST_ASSERT_NOT_NULL(client);

    /* Should fail because not connected */
    qsysdb_op_t *op = qsysdb_async_delete(client, "/test/key",
                                           dummy_complete_handler, NULL);
    TEST_ASSERT_NULL(op);

    qsysdb_async_free(client);
}

TEST(async_exists_without_connection)
{
    qsysdb_async_t *client = qsysdb_async_new();
    TEST_ASSERT_NOT_NULL(client);

    /* Should fail because not connected */
    qsysdb_op_t *op = qsysdb_async_exists(client, "/test/key",
                                           dummy_complete_handler, NULL);
    TEST_ASSERT_NULL(op);

    qsysdb_async_free(client);
}

/* ============================================
 * Operation Cancellation Tests
 * ============================================ */

TEST(op_cancel_null_safe)
{
    /* Should not crash */
    qsysdb_op_cancel(NULL);
    TEST_ASSERT_TRUE(1);
}

/* ============================================
 * Sync Convenience Functions Tests
 * ============================================ */

TEST(sync_set_without_connection)
{
    qsysdb_async_t *client = qsysdb_async_new();
    TEST_ASSERT_NOT_NULL(client);

    int ret = qsysdb_async_set_sync(client, "/test/key", "value");
    TEST_ASSERT_NE(QSYSDB_OK, ret);

    qsysdb_async_free(client);
}

TEST(sync_get_without_connection)
{
    qsysdb_async_t *client = qsysdb_async_new();
    TEST_ASSERT_NOT_NULL(client);

    char buf[256];
    int ret = qsysdb_async_get_sync(client, "/test/key", buf, sizeof(buf));
    TEST_ASSERT_NE(QSYSDB_OK, ret);

    qsysdb_async_free(client);
}

TEST(sync_delete_without_connection)
{
    qsysdb_async_t *client = qsysdb_async_new();
    TEST_ASSERT_NOT_NULL(client);

    int ret = qsysdb_async_delete_sync(client, "/test/key");
    TEST_ASSERT_NE(QSYSDB_OK, ret);

    qsysdb_async_free(client);
}

/* ============================================
 * Test Main
 * ============================================ */

TEST_MAIN()
