/*
 * QSysDB - Async Client API Benchmarks
 *
 * Benchmarks for the async client API including:
 *   - Client creation/destruction overhead
 *   - Watch builder operations
 *   - Batch builder operations
 *   - Memory allocation patterns
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <qsysdb/types.h>
#include <qsysdb/async.h>
#include "framework/benchmark.h"

/* ============================================
 * Client Lifecycle Benchmarks
 * ============================================ */

BENCHMARK(async_client, create_free)
{
    qsysdb_async_t *client = qsysdb_async_new();
    BENCH_DO_NOT_OPTIMIZE(client);
    qsysdb_async_free(client);
}

BENCHMARK(async_client, create_free_100x)
{
    BENCH_ITER(100) {
        qsysdb_async_t *client = qsysdb_async_new();
        BENCH_DO_NOT_OPTIMIZE(client);
        qsysdb_async_free(client);
    }
}

/* ============================================
 * Client Configuration Benchmarks
 * ============================================ */

static qsysdb_async_t *g_client = NULL;

static void setup_client(void *userdata)
{
    (void)userdata;
    g_client = qsysdb_async_new();
}

static void teardown_client(void *userdata)
{
    (void)userdata;
    if (g_client) {
        qsysdb_async_free(g_client);
        g_client = NULL;
    }
}

static void dummy_state_handler(qsysdb_async_t *client, bool connected, void *userdata)
{
    (void)client;
    (void)connected;
    (void)userdata;
}

static void dummy_error_handler(qsysdb_async_t *client, int error,
                                 const char *message, void *userdata)
{
    (void)client;
    (void)error;
    (void)message;
    (void)userdata;
}

BENCHMARK_F(async_client, set_state_handler, setup_client, teardown_client, NULL)
{
    qsysdb_async_on_state(g_client, dummy_state_handler, NULL);
    BENCH_CLOBBER();
}

BENCHMARK_F(async_client, set_error_handler, setup_client, teardown_client, NULL)
{
    qsysdb_async_on_error(g_client, dummy_error_handler, NULL);
    BENCH_CLOBBER();
}

BENCHMARK_F(async_client, set_reconnect, setup_client, teardown_client, NULL)
{
    qsysdb_async_set_reconnect(g_client, true, 1000);
    BENCH_CLOBBER();
}

BENCHMARK_F(async_client, is_connected_check, setup_client, teardown_client, NULL)
{
    bool connected = qsysdb_async_is_connected(g_client);
    BENCH_DO_NOT_OPTIMIZE(connected);
}

BENCHMARK_F(async_client, get_fd, setup_client, teardown_client, NULL)
{
    int fd = qsysdb_async_fd(g_client);
    BENCH_DO_NOT_OPTIMIZE(fd);
}

BENCHMARK_F(async_client, get_pending_count, setup_client, teardown_client, NULL)
{
    int count = qsysdb_async_pending_count(g_client);
    BENCH_DO_NOT_OPTIMIZE(count);
}

BENCHMARK_F(async_client, get_watch_count, setup_client, teardown_client, NULL)
{
    int count = qsysdb_async_watch_count(g_client);
    BENCH_DO_NOT_OPTIMIZE(count);
}

BENCHMARK_F(async_client, get_stats, setup_client, teardown_client, NULL)
{
    qsysdb_client_stats_t stats;
    qsysdb_async_get_stats(g_client, &stats);
    BENCH_DO_NOT_OPTIMIZE(stats.ops_sent);
}

/* ============================================
 * Watch Builder Benchmarks
 * ============================================ */

BENCHMARK_F(async_watch, create_stop, setup_client, teardown_client, NULL)
{
    qsysdb_watch_t *watch = qsysdb_watch_create(g_client);
    BENCH_DO_NOT_OPTIMIZE(watch);
    qsysdb_watch_stop(watch);
}

static void dummy_event_handler(qsysdb_event_t *event, void *userdata)
{
    (void)event;
    (void)userdata;
}

BENCHMARK_F(async_watch, full_builder_chain, setup_client, teardown_client, NULL)
{
    qsysdb_watch_t *watch = qsysdb_watch_create(g_client);

    qsysdb_watch_pattern(watch, "/test/path/*");
    qsysdb_watch_on_event(watch, dummy_event_handler, NULL);
    qsysdb_watch_on_create(watch, dummy_event_handler, NULL);
    qsysdb_watch_on_update(watch, dummy_event_handler, NULL);
    qsysdb_watch_on_delete(watch, dummy_event_handler, NULL);
    qsysdb_watch_get_initial(watch, true);
    qsysdb_watch_queue_size(watch, 1000);

    BENCH_DO_NOT_OPTIMIZE(watch);
    qsysdb_watch_stop(watch);
}

BENCHMARK_F(async_watch, pattern_only, setup_client, teardown_client, NULL)
{
    qsysdb_watch_t *watch = qsysdb_watch_create(g_client);
    qsysdb_watch_pattern(watch, "/test/path/*");
    BENCH_DO_NOT_OPTIMIZE(watch);
    qsysdb_watch_stop(watch);
}

BENCHMARK_F(async_watch, create_100_watches, setup_client, teardown_client, NULL)
{
    qsysdb_watch_t *watches[100];

    BENCH_ITER(100) {
        watches[_bench_i] = qsysdb_watch_create(g_client);
    }

    BENCH_DO_NOT_OPTIMIZE(watches[0]);

    BENCH_ITER(100) {
        qsysdb_watch_stop(watches[_bench_i]);
    }
}

/* ============================================
 * Batch Builder Benchmarks
 * ============================================ */

BENCHMARK_F(async_batch, create_cancel, setup_client, teardown_client, NULL)
{
    qsysdb_batch_t *batch = qsysdb_batch_create(g_client);
    BENCH_DO_NOT_OPTIMIZE(batch);
    qsysdb_batch_cancel(batch);
}

BENCHMARK_F(async_batch, add_10_sets, setup_client, teardown_client, NULL)
{
    qsysdb_batch_t *batch = qsysdb_batch_create(g_client);

    BENCH_ITER(10) {
        char key[64];
        snprintf(key, sizeof(key), "/test/key%d", _bench_i);
        qsysdb_batch_set(batch, key, "test_value");
    }

    int count = qsysdb_batch_count(batch);
    BENCH_DO_NOT_OPTIMIZE(count);
    qsysdb_batch_cancel(batch);
}

BENCHMARK_F(async_batch, add_100_sets, setup_client, teardown_client, NULL)
{
    qsysdb_batch_t *batch = qsysdb_batch_create(g_client);

    BENCH_ITER(100) {
        char key[64];
        snprintf(key, sizeof(key), "/test/key%d", _bench_i);
        qsysdb_batch_set(batch, key, "test_value");
    }

    int count = qsysdb_batch_count(batch);
    BENCH_DO_NOT_OPTIMIZE(count);
    qsysdb_batch_cancel(batch);
}

BENCHMARK_F(async_batch, add_10_deletes, setup_client, teardown_client, NULL)
{
    qsysdb_batch_t *batch = qsysdb_batch_create(g_client);

    BENCH_ITER(10) {
        char key[64];
        snprintf(key, sizeof(key), "/test/key%d", _bench_i);
        qsysdb_batch_delete(batch, key);
    }

    int count = qsysdb_batch_count(batch);
    BENCH_DO_NOT_OPTIMIZE(count);
    qsysdb_batch_cancel(batch);
}

BENCHMARK_F(async_batch, mixed_operations, setup_client, teardown_client, NULL)
{
    qsysdb_batch_t *batch = qsysdb_batch_create(g_client);

    BENCH_ITER(50) {
        char key[64];
        snprintf(key, sizeof(key), "/test/key%d", _bench_i);
        if (_bench_i % 2 == 0) {
            qsysdb_batch_set(batch, key, "test_value");
        } else {
            qsysdb_batch_delete(batch, key);
        }
    }

    int count = qsysdb_batch_count(batch);
    BENCH_DO_NOT_OPTIMIZE(count);
    qsysdb_batch_cancel(batch);
}

BENCHMARK_F(async_batch, chained_operations, setup_client, teardown_client, NULL)
{
    qsysdb_batch_t *batch = qsysdb_batch_create(g_client);

    /* Chain operations fluently */
    qsysdb_batch_set(
        qsysdb_batch_set(
            qsysdb_batch_set(
                qsysdb_batch_delete(
                    qsysdb_batch_set(batch, "/key1", "val1"),
                    "/key2"),
                "/key3", "val3"),
            "/key4", "val4"),
        "/key5", "val5");

    int count = qsysdb_batch_count(batch);
    BENCH_DO_NOT_OPTIMIZE(count);
    qsysdb_batch_cancel(batch);
}

/* ============================================
 * Memory Allocation Pattern Benchmarks
 * ============================================ */

BENCHMARK(async_memory, rapid_client_cycling)
{
    /* Simulate rapid connect/disconnect patterns */
    BENCH_ITER(10) {
        qsysdb_async_t *client = qsysdb_async_new();

        /* Configure the client */
        qsysdb_async_set_reconnect(client, true, 1000);
        qsysdb_async_on_state(client, dummy_state_handler, NULL);
        qsysdb_async_on_error(client, dummy_error_handler, NULL);

        /* Create some watches */
        qsysdb_watch_t *w1 = qsysdb_watch_create(client);
        qsysdb_watch_t *w2 = qsysdb_watch_create(client);

        qsysdb_watch_pattern(w1, "/path1/*");
        qsysdb_watch_pattern(w2, "/path2/*");

        /* Create a batch */
        qsysdb_batch_t *batch = qsysdb_batch_create(client);
        qsysdb_batch_set(batch, "/key", "value");

        /* Cleanup */
        qsysdb_batch_cancel(batch);
        qsysdb_watch_stop(w1);
        qsysdb_watch_stop(w2);
        qsysdb_async_free(client);
    }
}

BENCHMARK(async_memory, heavy_batch_usage)
{
    qsysdb_async_t *client = qsysdb_async_new();

    /* Create multiple batches with many operations */
    BENCH_ITER(10) {
        qsysdb_batch_t *batch = qsysdb_batch_create(client);

        for (int j = 0; j < 100; j++) {
            char key[64], value[128];
            snprintf(key, sizeof(key), "/test/batch%d/key%d", _bench_i, j);
            snprintf(value, sizeof(value), "value_%d_%d", _bench_i, j);
            qsysdb_batch_set(batch, key, value);
        }

        qsysdb_batch_cancel(batch);
    }

    qsysdb_async_free(client);
}

BENCHMARK(async_memory, heavy_watch_usage)
{
    qsysdb_async_t *client = qsysdb_async_new();

    /* Create many watches */
    qsysdb_watch_t *watches[100];

    for (int i = 0; i < 100; i++) {
        watches[i] = qsysdb_watch_create(client);
        char pattern[64];
        snprintf(pattern, sizeof(pattern), "/test/watch%d/*", i);
        qsysdb_watch_pattern(watches[i], pattern);
        qsysdb_watch_on_event(watches[i], dummy_event_handler, NULL);
    }

    BENCH_CLOBBER();

    for (int i = 0; i < 100; i++) {
        qsysdb_watch_stop(watches[i]);
    }

    qsysdb_async_free(client);
}

/* ============================================
 * Benchmark Main
 * ============================================ */

BENCHMARK_MAIN()
