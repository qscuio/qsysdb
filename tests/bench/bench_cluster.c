/*
 * QSysDB - Cluster Benchmark Suite
 *
 * Benchmarks for cluster functionality including:
 *   - Client cluster mode operations
 *   - Cluster creation and configuration
 *   - Node management (add/remove)
 *   - Election operations
 *   - Replication performance
 *   - Database synchronization
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include <qsysdb/types.h>
#include <qsysdb/async.h>
#include <qsysdb/cluster.h>
#include <qsysdb/election.h>
#include <qsysdb/replication.h>
#include <qsysdb/cluster_protocol.h>
#include "framework/benchmark.h"

/* ============================================
 * Cluster Client Benchmarks
 * ============================================ */

static qsysdb_async_t *g_async_client = NULL;

static void async_client_setup(void *userdata)
{
    (void)userdata;
    g_async_client = qsysdb_async_new();
}

static void async_client_teardown(void *userdata)
{
    (void)userdata;
    if (g_async_client) {
        qsysdb_async_free(g_async_client);
        g_async_client = NULL;
    }
}

BENCHMARK_F(cluster_client, enable_cluster_mode, async_client_setup, async_client_teardown, NULL)
{
    qsysdb_async_set_cluster_mode(g_async_client, true);
    BENCH_CLOBBER();
}

BENCHMARK_F(cluster_client, disable_cluster_mode, async_client_setup, async_client_teardown, NULL)
{
    qsysdb_async_set_cluster_mode(g_async_client, true);
    qsysdb_async_set_cluster_mode(g_async_client, false);
    BENCH_CLOBBER();
}

BENCHMARK_F(cluster_client, add_single_server, async_client_setup, async_client_teardown, NULL)
{
    qsysdb_async_set_cluster_mode(g_async_client, true);
    int ret = qsysdb_async_add_server(g_async_client, "192.168.1.10", 5959);
    BENCH_DO_NOT_OPTIMIZE(ret);
}

BENCHMARK_F(cluster_client, add_3_servers, async_client_setup, async_client_teardown, NULL)
{
    qsysdb_async_set_cluster_mode(g_async_client, true);
    qsysdb_async_add_server(g_async_client, "192.168.1.10", 5959);
    qsysdb_async_add_server(g_async_client, "192.168.1.11", 5959);
    int ret = qsysdb_async_add_server(g_async_client, "192.168.1.12", 5959);
    BENCH_DO_NOT_OPTIMIZE(ret);
}

BENCHMARK_F(cluster_client, add_10_servers, async_client_setup, async_client_teardown, NULL)
{
    qsysdb_async_set_cluster_mode(g_async_client, true);
    for (int i = 0; i < 10; i++) {
        char addr[32];
        snprintf(addr, sizeof(addr), "192.168.1.%d", 10 + i);
        qsysdb_async_add_server(g_async_client, addr, 5959);
    }
    BENCH_CLOBBER();
}

static qsysdb_async_t *g_populated_client = NULL;

static void populated_client_setup(void *userdata)
{
    (void)userdata;
    g_populated_client = qsysdb_async_new();
    qsysdb_async_set_cluster_mode(g_populated_client, true);
    for (int i = 0; i < 5; i++) {
        char addr[32];
        snprintf(addr, sizeof(addr), "192.168.1.%d", 10 + i);
        qsysdb_async_add_server(g_populated_client, addr, 5959);
    }
}

static void populated_client_teardown(void *userdata)
{
    (void)userdata;
    if (g_populated_client) {
        qsysdb_async_free(g_populated_client);
        g_populated_client = NULL;
    }
}

BENCHMARK_F(cluster_client, remove_server, populated_client_setup, populated_client_teardown, NULL)
{
    int ret = qsysdb_async_remove_server(g_populated_client, 2);  /* Remove server at index 2 */
    BENCH_DO_NOT_OPTIMIZE(ret);
}

BENCHMARK_F(cluster_client, get_server_count, populated_client_setup, populated_client_teardown, NULL)
{
    int count = qsysdb_async_server_count(g_populated_client);
    BENCH_DO_NOT_OPTIMIZE(count);
}

/* ============================================
 * Cluster Manager Benchmarks
 * ============================================ */

static qsysdb_cluster_t *g_cluster = NULL;

static void cluster_setup(void *userdata)
{
    (void)userdata;
    qsysdb_cluster_config_t config;
    qsysdb_cluster_config_init(&config);
    config.node_id = 1;
    strcpy(config.bind_address, "127.0.0.1");
    g_cluster = qsysdb_cluster_create(&config);
}

static void cluster_teardown(void *userdata)
{
    (void)userdata;
    if (g_cluster) {
        qsysdb_cluster_destroy(g_cluster);
        g_cluster = NULL;
    }
}

BENCHMARK(cluster_manager, config_init)
{
    qsysdb_cluster_config_t config;
    qsysdb_cluster_config_init(&config);
    BENCH_DO_NOT_OPTIMIZE(config.node_id);
}

BENCHMARK(cluster_manager, create_destroy)
{
    qsysdb_cluster_config_t config;
    qsysdb_cluster_config_init(&config);
    config.node_id = 1;
    strcpy(config.bind_address, "127.0.0.1");

    qsysdb_cluster_t *cluster = qsysdb_cluster_create(&config);
    BENCH_DO_NOT_OPTIMIZE(cluster);
    qsysdb_cluster_destroy(cluster);
}

BENCHMARK_F(cluster_manager, add_node, cluster_setup, cluster_teardown, NULL)
{
    static int idx = 0;
    char addr[32];
    snprintf(addr, sizeof(addr), "192.168.1.%d", (idx++ % 200) + 10);
    uint32_t node_id = qsysdb_cluster_add_node(g_cluster, addr, 5959, 5960);
    BENCH_DO_NOT_OPTIMIZE(node_id);
}

BENCHMARK_F(cluster_manager, is_leader_check, cluster_setup, cluster_teardown, NULL)
{
    bool is_leader = qsysdb_cluster_is_leader(g_cluster);
    BENCH_DO_NOT_OPTIMIZE(is_leader);
}

BENCHMARK_F(cluster_manager, get_state, cluster_setup, cluster_teardown, NULL)
{
    qsysdb_node_state_t state = qsysdb_cluster_get_state(g_cluster);
    BENCH_DO_NOT_OPTIMIZE(state);
}

BENCHMARK_F(cluster_manager, get_node_id, cluster_setup, cluster_teardown, NULL)
{
    uint32_t id = qsysdb_cluster_get_node_id(g_cluster);
    BENCH_DO_NOT_OPTIMIZE(id);
}

BENCHMARK_F(cluster_manager, get_term, cluster_setup, cluster_teardown, NULL)
{
    uint64_t term = qsysdb_cluster_get_term(g_cluster);
    BENCH_DO_NOT_OPTIMIZE(term);
}

BENCHMARK_F(cluster_manager, time_ms, cluster_setup, cluster_teardown, NULL)
{
    uint64_t time = qsysdb_cluster_time_ms();
    BENCH_DO_NOT_OPTIMIZE(time);
}

/* Multi-node cluster benchmarks */
static qsysdb_cluster_t *g_multi_cluster = NULL;

static void multi_cluster_setup(void *userdata)
{
    (void)userdata;
    qsysdb_cluster_config_t config;
    qsysdb_cluster_config_init(&config);
    config.node_id = 1;
    strcpy(config.bind_address, "127.0.0.1");
    g_multi_cluster = qsysdb_cluster_create(&config);

    /* Add 9 more nodes (total 10) */
    for (int i = 0; i < 9; i++) {
        char addr[32];
        snprintf(addr, sizeof(addr), "192.168.1.%d", 10 + i);
        qsysdb_cluster_add_node(g_multi_cluster, addr, 5959, 5960);
    }
}

static void multi_cluster_teardown(void *userdata)
{
    (void)userdata;
    if (g_multi_cluster) {
        qsysdb_cluster_destroy(g_multi_cluster);
        g_multi_cluster = NULL;
    }
}

BENCHMARK_F(cluster_manager, get_nodes_10, multi_cluster_setup, multi_cluster_teardown, NULL)
{
    qsysdb_node_t *nodes = NULL;
    int count = 0;
    int ret = qsysdb_cluster_get_nodes(g_multi_cluster, &nodes, &count);
    BENCH_DO_NOT_OPTIMIZE(ret);
    if (nodes) free(nodes);
}

BENCHMARK_F(cluster_manager, remove_node, multi_cluster_setup, multi_cluster_teardown, NULL)
{
    /* Remove a specific node (will be re-added on next setup) */
    int ret = qsysdb_cluster_remove_node(g_multi_cluster, g_multi_cluster->nodes[5].node_id);
    BENCH_DO_NOT_OPTIMIZE(ret);
}

/* ============================================
 * Protocol Message Benchmarks
 * ============================================ */

BENCHMARK(cluster_protocol, msg_init_heartbeat)
{
    qsysdb_cluster_header_t hdr;
    qsysdb_cluster_msg_init(&hdr, CLUSTER_MSG_HEARTBEAT, 1, 5, 0);
    BENCH_DO_NOT_OPTIMIZE(hdr.magic);
}

BENCHMARK(cluster_protocol, msg_init_request_vote)
{
    qsysdb_cluster_header_t hdr;
    qsysdb_cluster_msg_init(&hdr, CLUSTER_MSG_REQUEST_VOTE, 1, 5,
                            sizeof(qsysdb_msg_request_vote_t) - sizeof(qsysdb_cluster_header_t));
    BENCH_DO_NOT_OPTIMIZE(hdr.magic);
}

BENCHMARK(cluster_protocol, msg_validate)
{
    qsysdb_cluster_header_t hdr;
    qsysdb_cluster_msg_init(&hdr, CLUSTER_MSG_HEARTBEAT, 1, 0, 0);
    int ret = qsysdb_cluster_msg_validate(&hdr, sizeof(hdr));
    BENCH_DO_NOT_OPTIMIZE(ret);
}

BENCHMARK(cluster_protocol, msg_type_name)
{
    const char *name = qsysdb_cluster_msg_type_name(CLUSTER_MSG_HEARTBEAT);
    BENCH_DO_NOT_OPTIMIZE(name);
}

BENCHMARK(cluster_protocol, build_heartbeat_msg)
{
    qsysdb_msg_heartbeat_t msg;
    qsysdb_cluster_msg_init(&msg.header, CLUSTER_MSG_HEARTBEAT, 1, 5,
                            sizeof(qsysdb_msg_heartbeat_t) - sizeof(qsysdb_cluster_header_t));
    msg.commit_index = 100;
    BENCH_DO_NOT_OPTIMIZE(msg.header.magic);
}

BENCHMARK(cluster_protocol, build_request_vote_msg)
{
    qsysdb_msg_request_vote_t msg;
    qsysdb_cluster_msg_init(&msg.header, CLUSTER_MSG_REQUEST_VOTE, 1, 5,
                            sizeof(qsysdb_msg_request_vote_t) - sizeof(qsysdb_cluster_header_t));
    msg.last_log_index = 100;
    msg.last_log_term = 4;
    BENCH_DO_NOT_OPTIMIZE(msg.header.magic);
}

BENCHMARK(cluster_protocol, build_append_entries_msg)
{
    qsysdb_msg_append_entries_t msg;
    qsysdb_cluster_msg_init(&msg.header, CLUSTER_MSG_APPEND_ENTRIES, 1, 5,
                            sizeof(qsysdb_msg_append_entries_t) - sizeof(qsysdb_cluster_header_t));
    msg.prev_log_index = 99;
    msg.prev_log_term = 4;
    msg.leader_commit = 100;
    msg.entry_count = 10;
    BENCH_DO_NOT_OPTIMIZE(msg.header.magic);
}

/* ============================================
 * Election Benchmarks
 * ============================================ */

static qsysdb_cluster_t *g_election_cluster = NULL;

static void election_setup(void *userdata)
{
    (void)userdata;
    qsysdb_cluster_config_t config;
    qsysdb_cluster_config_init(&config);
    config.node_id = 1;
    strcpy(config.bind_address, "127.0.0.1");
    config.election_timeout_min = 150;
    config.election_timeout_max = 300;
    g_election_cluster = qsysdb_cluster_create(&config);
    if (g_election_cluster) {
        qsysdb_election_init(g_election_cluster);
    }
}

static void election_teardown(void *userdata)
{
    (void)userdata;
    if (g_election_cluster) {
        qsysdb_election_cleanup(g_election_cluster);
        qsysdb_cluster_destroy(g_election_cluster);
        g_election_cluster = NULL;
    }
}

BENCHMARK(cluster_election, init_cleanup)
{
    qsysdb_cluster_config_t config;
    qsysdb_cluster_config_init(&config);
    config.node_id = 1;
    strcpy(config.bind_address, "127.0.0.1");

    qsysdb_cluster_t *cluster = qsysdb_cluster_create(&config);
    qsysdb_election_init(cluster);
    BENCH_DO_NOT_OPTIMIZE(cluster->election);
    qsysdb_election_cleanup(cluster);
    qsysdb_cluster_destroy(cluster);
}

BENCHMARK_F(cluster_election, get_term, election_setup, election_teardown, NULL)
{
    uint64_t term = qsysdb_election_get_term(g_election_cluster);
    BENCH_DO_NOT_OPTIMIZE(term);
}

BENCHMARK_F(cluster_election, get_voted_for, election_setup, election_teardown, NULL)
{
    uint32_t voted_for = qsysdb_election_get_voted_for(g_election_cluster);
    BENCH_DO_NOT_OPTIMIZE(voted_for);
}

BENCHMARK_F(cluster_election, random_timeout, election_setup, election_teardown, NULL)
{
    int timeout = qsysdb_election_random_timeout(g_election_cluster);
    BENCH_DO_NOT_OPTIMIZE(timeout);
}

BENCHMARK_F(cluster_election, reset_timeout, election_setup, election_teardown, NULL)
{
    qsysdb_election_reset_timeout(g_election_cluster);
    BENCH_CLOBBER();
}

BENCHMARK_F(cluster_election, tick_follower, election_setup, election_teardown, NULL)
{
    /* Set deadline far in future so tick doesn't trigger election */
    g_election_cluster->election->election_deadline = qsysdb_cluster_time_ms() + 10000;
    int ret = qsysdb_election_tick(g_election_cluster);
    BENCH_DO_NOT_OPTIMIZE(ret);
}

BENCHMARK_F(cluster_election, handle_vote_request, election_setup, election_teardown, NULL)
{
    g_election_cluster->election->current_term = 1;
    g_election_cluster->election->voted_for = 0;
    bool vote_granted;
    int ret = qsysdb_election_handle_vote_request(g_election_cluster, 2, 2, 0, 0, &vote_granted);
    BENCH_DO_NOT_OPTIMIZE(ret);
}

BENCHMARK_F(cluster_election, handle_heartbeat, election_setup, election_teardown, NULL)
{
    g_election_cluster->election->current_term = 1;
    int ret = qsysdb_election_handle_heartbeat(g_election_cluster, 2, 1);
    BENCH_DO_NOT_OPTIMIZE(ret);
}

BENCHMARK_F(cluster_election, step_down, election_setup, election_teardown, NULL)
{
    g_election_cluster->election->state = QSYSDB_NODE_CANDIDATE;
    g_election_cluster->election->current_term = 1;
    qsysdb_election_step_down(g_election_cluster, 5);
    BENCH_CLOBBER();
}

/* ============================================
 * Replication Benchmarks
 * ============================================ */

/* Replication state benchmarks */
static qsysdb_cluster_t *g_repl_cluster = NULL;

static void repl_setup(void *userdata)
{
    (void)userdata;
    qsysdb_cluster_config_t config;
    qsysdb_cluster_config_init(&config);
    config.node_id = 1;
    strcpy(config.bind_address, "127.0.0.1");
    g_repl_cluster = qsysdb_cluster_create(&config);
    if (g_repl_cluster) {
        qsysdb_replication_init(g_repl_cluster);
        /* Make this node the leader for replication tests */
        g_repl_cluster->state = QSYSDB_NODE_LEADER;
        g_repl_cluster->current_term = 1;
    }
}

static void repl_teardown(void *userdata)
{
    (void)userdata;
    if (g_repl_cluster) {
        qsysdb_replication_cleanup(g_repl_cluster);
        qsysdb_cluster_destroy(g_repl_cluster);
        g_repl_cluster = NULL;
    }
}

BENCHMARK(cluster_replication, init_cleanup)
{
    qsysdb_cluster_config_t config;
    qsysdb_cluster_config_init(&config);
    config.node_id = 1;
    strcpy(config.bind_address, "127.0.0.1");

    qsysdb_cluster_t *cluster = qsysdb_cluster_create(&config);
    qsysdb_replication_init(cluster);
    BENCH_DO_NOT_OPTIMIZE(cluster->replication);
    qsysdb_replication_cleanup(cluster);
    qsysdb_cluster_destroy(cluster);
}

BENCHMARK_F(cluster_replication, append_entry, repl_setup, repl_teardown, NULL)
{
    int64_t ret = qsysdb_replication_append(g_repl_cluster, QSYSDB_REPL_OP_SET,
                                            "/test/key", "{\"v\":1}", 7, 0);
    BENCH_DO_NOT_OPTIMIZE(ret);
}

BENCHMARK_F(cluster_replication, get_last_index, repl_setup, repl_teardown, NULL)
{
    uint64_t idx = qsysdb_replication_last_index(g_repl_cluster);
    BENCH_DO_NOT_OPTIMIZE(idx);
}

BENCHMARK_F(cluster_replication, get_commit_index, repl_setup, repl_teardown, NULL)
{
    uint64_t idx = qsysdb_replication_commit_index(g_repl_cluster);
    BENCH_DO_NOT_OPTIMIZE(idx);
}

/* Batch replication entry benchmarks */
BENCHMARK_F(cluster_replication, append_10_entries, repl_setup, repl_teardown, NULL)
{
    for (int i = 0; i < 10; i++) {
        qsysdb_replication_append(g_repl_cluster, QSYSDB_REPL_OP_SET,
                                  "/test/key", "{\"v\":1}", 7, 0);
    }
    BENCH_CLOBBER();
}

BENCHMARK_F(cluster_replication, append_100_entries, repl_setup, repl_teardown, NULL)
{
    for (int i = 0; i < 100; i++) {
        qsysdb_replication_append(g_repl_cluster, QSYSDB_REPL_OP_SET,
                                  "/test/key", "{\"v\":1}", 7, 0);
    }
    BENCH_CLOBBER();
}

/* ============================================
 * Database Sync Simulation Benchmarks
 * ============================================ */

/* Simulate replication log serialization for network transfer using wire format */
BENCHMARK(cluster_sync, serialize_wire_entry_small)
{
    char buf[256];
    qsysdb_wire_entry_t *wire = (qsysdb_wire_entry_t *)buf;

    const char *path = "/test/key";
    const char *value = "{\"v\":1}";
    size_t path_len = 9;
    size_t value_len = 7;

    wire->index = 12345;
    wire->term = 10;
    wire->op_type = QSYSDB_REPL_OP_SET;
    wire->flags = 0;
    wire->path_len = path_len;
    wire->value_len = value_len;
    memcpy(wire->data, path, path_len);
    memcpy(wire->data + path_len, value, value_len);

    BENCH_DO_NOT_OPTIMIZE(wire->index);
}

BENCHMARK(cluster_sync, serialize_wire_entry_medium)
{
    char buf[512];
    qsysdb_wire_entry_t *wire = (qsysdb_wire_entry_t *)buf;

    char path[64] = "/benchmark/test/path/entry/12345";
    char value[256] = "{\"id\":12345,\"name\":\"benchmark_item\",\"data\":\"some_value_here\"}";
    size_t path_len = strlen(path);
    size_t value_len = strlen(value);

    wire->index = 12345;
    wire->term = 10;
    wire->op_type = QSYSDB_REPL_OP_SET;
    wire->flags = 0;
    wire->path_len = path_len;
    wire->value_len = value_len;
    memcpy(wire->data, path, path_len);
    memcpy(wire->data + path_len, value, value_len);

    BENCH_DO_NOT_OPTIMIZE(wire->index);
}

BENCHMARK(cluster_sync, serialize_10_wire_entries)
{
    char buf[8192];
    size_t offset = 0;

    for (int i = 0; i < 10; i++) {
        char path[64];
        char value[128];
        snprintf(path, sizeof(path), "/sync/batch/entry/%d", i);
        snprintf(value, sizeof(value), "{\"id\":%d,\"data\":\"batch_item\"}", i);
        size_t path_len = strlen(path);
        size_t value_len = strlen(value);

        qsysdb_wire_entry_t *wire = (qsysdb_wire_entry_t *)(buf + offset);
        wire->index = i;
        wire->term = 1;
        wire->op_type = QSYSDB_REPL_OP_SET;
        wire->flags = 0;
        wire->path_len = path_len;
        wire->value_len = value_len;
        memcpy(wire->data, path, path_len);
        memcpy(wire->data + path_len, value, value_len);

        offset += sizeof(qsysdb_wire_entry_t) + path_len + value_len;
    }

    BENCH_DO_NOT_OPTIMIZE(offset);
}

BENCHMARK(cluster_sync, deserialize_wire_entry)
{
    /* Pre-serialized entry buffer */
    char buf[256];
    qsysdb_wire_entry_t *wire = (qsysdb_wire_entry_t *)buf;

    const char *path = "/test/key";
    const char *value = "{\"v\":1}";
    size_t path_len = 9;
    size_t value_len = 7;

    /* Serialize */
    wire->index = 12345;
    wire->term = 10;
    wire->op_type = QSYSDB_REPL_OP_SET;
    wire->flags = 0;
    wire->path_len = path_len;
    wire->value_len = value_len;
    memcpy(wire->data, path, path_len);
    memcpy(wire->data + path_len, value, value_len);

    /* Now deserialize (read the wire format) */
    uint64_t read_index = wire->index;
    uint64_t read_term = wire->term;
    uint8_t read_op = wire->op_type;
    const char *read_path = wire->data;
    const char *read_value = wire->data + wire->path_len;

    BENCH_DO_NOT_OPTIMIZE(read_index);
    BENCH_DO_NOT_OPTIMIZE(read_term);
    BENCH_DO_NOT_OPTIMIZE(read_op);
    BENCH_DO_NOT_OPTIMIZE(read_path);
    BENCH_DO_NOT_OPTIMIZE(read_value);
}

/* Replication entry creation benchmark */
BENCHMARK(cluster_sync, entry_create_free)
{
    qsysdb_repl_entry_t *entry = qsysdb_repl_entry_create(QSYSDB_REPL_OP_SET,
                                                          "/test/key",
                                                          "{\"v\":1}", 7);
    BENCH_DO_NOT_OPTIMIZE(entry);
    if (entry) qsysdb_repl_entry_free(entry);
}

BENCHMARK(cluster_sync, entry_create_medium)
{
    char path[64] = "/benchmark/test/path/entry/12345";
    char value[256] = "{\"id\":12345,\"name\":\"benchmark_item\",\"data\":\"some_value_here\"}";

    qsysdb_repl_entry_t *entry = qsysdb_repl_entry_create(QSYSDB_REPL_OP_SET,
                                                          path, value, strlen(value));
    BENCH_DO_NOT_OPTIMIZE(entry);
    if (entry) qsysdb_repl_entry_free(entry);
}

/* ============================================
 * Throughput Benchmarks
 * ============================================ */

BENCHMARK(cluster_throughput, cluster_create_destroy_cycle)
{
    BENCH_ITER(10) {
        qsysdb_cluster_config_t config;
        qsysdb_cluster_config_init(&config);
        config.node_id = _bench_i + 1;
        strcpy(config.bind_address, "127.0.0.1");

        qsysdb_cluster_t *cluster = qsysdb_cluster_create(&config);
        BENCH_DO_NOT_OPTIMIZE(cluster);
        qsysdb_cluster_destroy(cluster);
    }
}

BENCHMARK(cluster_throughput, client_create_configure_destroy_cycle)
{
    BENCH_ITER(10) {
        qsysdb_async_t *client = qsysdb_async_new();
        qsysdb_async_set_cluster_mode(client, true);

        for (int j = 0; j < 3; j++) {
            char addr[32];
            snprintf(addr, sizeof(addr), "192.168.%d.%d", _bench_i, j + 10);
            qsysdb_async_add_server(client, addr, 5959);
        }

        qsysdb_async_free(client);
    }
    BENCH_CLOBBER();
}

BENCHMARK(cluster_throughput, protocol_message_cycle)
{
    BENCH_ITER(100) {
        qsysdb_cluster_header_t hdr;
        qsysdb_cluster_msg_init(&hdr, CLUSTER_MSG_HEARTBEAT, _bench_i, _bench_i, 0);
        int ret = qsysdb_cluster_msg_validate(&hdr, sizeof(hdr));
        BENCH_DO_NOT_OPTIMIZE(ret);
    }
}

/* ============================================
 * Scalability Benchmarks
 * ============================================ */

BENCHMARK(cluster_scalability, add_100_nodes)
{
    qsysdb_cluster_config_t config;
    qsysdb_cluster_config_init(&config);
    config.node_id = 1;
    strcpy(config.bind_address, "127.0.0.1");

    qsysdb_cluster_t *cluster = qsysdb_cluster_create(&config);

    for (int i = 0; i < 100; i++) {
        char addr[32];
        snprintf(addr, sizeof(addr), "10.0.%d.%d", i / 256, i % 256);
        qsysdb_cluster_add_node(cluster, addr, 5959, 5960);
    }

    BENCH_DO_NOT_OPTIMIZE(cluster->node_count);
    qsysdb_cluster_destroy(cluster);
}

BENCHMARK(cluster_scalability, client_add_100_servers)
{
    qsysdb_async_t *client = qsysdb_async_new();
    qsysdb_async_set_cluster_mode(client, true);

    for (int i = 0; i < 100; i++) {
        char addr[32];
        snprintf(addr, sizeof(addr), "10.0.%d.%d", i / 256, i % 256);
        qsysdb_async_add_server(client, addr, 5959);
    }

    int count = qsysdb_async_server_count(client);
    BENCH_DO_NOT_OPTIMIZE(count);
    qsysdb_async_free(client);
}

/* ============================================
 * Memory Usage Benchmarks
 * ============================================ */

BENCHMARK(cluster_memory, rapid_cluster_cycling)
{
    BENCH_ITER(10) {
        qsysdb_cluster_config_t config;
        qsysdb_cluster_config_init(&config);
        config.node_id = _bench_i + 1;
        strcpy(config.bind_address, "127.0.0.1");

        qsysdb_cluster_t *cluster = qsysdb_cluster_create(&config);

        /* Add nodes */
        for (int j = 0; j < 5; j++) {
            char addr[32];
            snprintf(addr, sizeof(addr), "192.168.%d.%d", _bench_i, j + 10);
            qsysdb_cluster_add_node(cluster, addr, 5959, 5960);
        }

        /* Init election */
        qsysdb_election_init(cluster);

        /* Init replication */
        qsysdb_replication_init(cluster);

        /* Cleanup */
        qsysdb_replication_cleanup(cluster);
        qsysdb_election_cleanup(cluster);
        qsysdb_cluster_destroy(cluster);
    }
    BENCH_CLOBBER();
}

BENCHMARK(cluster_memory, rapid_client_cycling)
{
    BENCH_ITER(20) {
        qsysdb_async_t *client = qsysdb_async_new();
        qsysdb_async_set_cluster_mode(client, true);

        for (int j = 0; j < 10; j++) {
            char addr[32];
            snprintf(addr, sizeof(addr), "192.168.%d.%d", _bench_i, j + 10);
            qsysdb_async_add_server(client, addr, 5959);
        }

        qsysdb_async_free(client);
    }
    BENCH_CLOBBER();
}

/* ============================================
 * Benchmark Main
 * ============================================ */

BENCHMARK_MAIN()
