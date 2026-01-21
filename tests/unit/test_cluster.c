/*
 * QSysDB - Cluster Unit Tests
 *
 * Tests cluster management functionality including:
 *   - Cluster configuration
 *   - Node management
 *   - State transitions
 *   - Message protocol
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <qsysdb/types.h>
#include <qsysdb/cluster.h>
#include <qsysdb/cluster_protocol.h>
#include "framework/test_framework.h"

static const char *_current_suite_name = "cluster";

/* ============================================
 * Configuration Tests
 * ============================================ */

TEST(config_init_defaults)
{
    qsysdb_cluster_config_t config;
    qsysdb_cluster_config_init(&config);

    TEST_ASSERT_EQ(0, config.node_id);  /* Auto-generate */
    TEST_ASSERT_EQ(QSYSDB_TCP_PORT_DEFAULT, config.client_port);
    TEST_ASSERT_EQ(QSYSDB_CLUSTER_PORT_DEFAULT, config.cluster_port);
    TEST_ASSERT_EQ(QSYSDB_DISCOVERY_STATIC, config.discovery);
    TEST_ASSERT_EQ(QSYSDB_ELECTION_TIMEOUT_MIN, config.election_timeout_min);
    TEST_ASSERT_EQ(QSYSDB_ELECTION_TIMEOUT_MAX, config.election_timeout_max);
    TEST_ASSERT_EQ(QSYSDB_HEARTBEAT_INTERVAL, config.heartbeat_interval);
}

TEST(config_custom_values)
{
    qsysdb_cluster_config_t config;
    qsysdb_cluster_config_init(&config);

    config.node_id = 42;
    config.client_port = 9000;
    config.cluster_port = 9001;
    config.election_timeout_min = 200;
    config.election_timeout_max = 400;

    TEST_ASSERT_EQ(42, config.node_id);
    TEST_ASSERT_EQ(9000, config.client_port);
    TEST_ASSERT_EQ(9001, config.cluster_port);
    TEST_ASSERT_EQ(200, config.election_timeout_min);
    TEST_ASSERT_EQ(400, config.election_timeout_max);
}

/* ============================================
 * Cluster Creation Tests
 * ============================================ */

TEST(cluster_create_success)
{
    qsysdb_cluster_config_t config;
    qsysdb_cluster_config_init(&config);
    config.node_id = 1;
    strcpy(config.bind_address, "127.0.0.1");

    qsysdb_cluster_t *cluster = qsysdb_cluster_create(&config);
    TEST_ASSERT_NOT_NULL(cluster);

    TEST_ASSERT_EQ(1, cluster->config.node_id);
    TEST_ASSERT_EQ(QSYSDB_NODE_FOLLOWER, cluster->state);
    TEST_ASSERT_EQ(1, cluster->node_count);  /* Self node */

    qsysdb_cluster_destroy(cluster);
}

TEST(cluster_create_auto_node_id)
{
    qsysdb_cluster_config_t config;
    qsysdb_cluster_config_init(&config);
    config.node_id = 0;  /* Auto-generate */
    strcpy(config.bind_address, "127.0.0.1");

    qsysdb_cluster_t *cluster = qsysdb_cluster_create(&config);
    TEST_ASSERT_NOT_NULL(cluster);

    /* Should have generated a non-zero node ID */
    TEST_ASSERT_TRUE(cluster->config.node_id != 0);

    qsysdb_cluster_destroy(cluster);
}

TEST(cluster_create_null_config)
{
    qsysdb_cluster_t *cluster = qsysdb_cluster_create(NULL);
    TEST_ASSERT_NULL(cluster);
}

/* ============================================
 * State Query Tests
 * ============================================ */

TEST(cluster_initial_state_follower)
{
    qsysdb_cluster_config_t config;
    qsysdb_cluster_config_init(&config);
    config.node_id = 1;
    strcpy(config.bind_address, "127.0.0.1");

    qsysdb_cluster_t *cluster = qsysdb_cluster_create(&config);
    TEST_ASSERT_NOT_NULL(cluster);

    TEST_ASSERT_FALSE(qsysdb_cluster_is_leader(cluster));
    TEST_ASSERT_EQ(QSYSDB_NODE_FOLLOWER, qsysdb_cluster_get_state(cluster));

    qsysdb_cluster_destroy(cluster);
}

TEST(cluster_get_node_id)
{
    qsysdb_cluster_config_t config;
    qsysdb_cluster_config_init(&config);
    config.node_id = 42;
    strcpy(config.bind_address, "127.0.0.1");

    qsysdb_cluster_t *cluster = qsysdb_cluster_create(&config);
    TEST_ASSERT_NOT_NULL(cluster);

    TEST_ASSERT_EQ(42, qsysdb_cluster_get_node_id(cluster));

    qsysdb_cluster_destroy(cluster);
}

TEST(cluster_initial_term_zero)
{
    qsysdb_cluster_config_t config;
    qsysdb_cluster_config_init(&config);
    config.node_id = 1;
    strcpy(config.bind_address, "127.0.0.1");

    qsysdb_cluster_t *cluster = qsysdb_cluster_create(&config);
    TEST_ASSERT_NOT_NULL(cluster);

    TEST_ASSERT_EQ(0, qsysdb_cluster_get_term(cluster));

    qsysdb_cluster_destroy(cluster);
}

/* ============================================
 * Node Management Tests
 * ============================================ */

TEST(cluster_add_node_success)
{
    qsysdb_cluster_config_t config;
    qsysdb_cluster_config_init(&config);
    config.node_id = 1;
    strcpy(config.bind_address, "127.0.0.1");

    qsysdb_cluster_t *cluster = qsysdb_cluster_create(&config);
    TEST_ASSERT_NOT_NULL(cluster);

    uint32_t node_id = qsysdb_cluster_add_node(cluster, "192.168.1.10", 5959, 5960);
    TEST_ASSERT_TRUE(node_id != 0);  /* Non-zero indicates success */
    TEST_ASSERT_EQ(2, cluster->node_count);

    qsysdb_cluster_destroy(cluster);
}

TEST(cluster_add_multiple_nodes)
{
    qsysdb_cluster_config_t config;
    qsysdb_cluster_config_init(&config);
    config.node_id = 1;
    strcpy(config.bind_address, "127.0.0.1");

    qsysdb_cluster_t *cluster = qsysdb_cluster_create(&config);
    TEST_ASSERT_NOT_NULL(cluster);

    qsysdb_cluster_add_node(cluster, "192.168.1.10", 5959, 5960);
    qsysdb_cluster_add_node(cluster, "192.168.1.11", 5959, 5960);
    qsysdb_cluster_add_node(cluster, "192.168.1.12", 5959, 5960);

    TEST_ASSERT_EQ(4, cluster->node_count);  /* Self + 3 nodes */

    qsysdb_cluster_destroy(cluster);
}

TEST(cluster_get_nodes)
{
    qsysdb_cluster_config_t config;
    qsysdb_cluster_config_init(&config);
    config.node_id = 1;
    strcpy(config.bind_address, "127.0.0.1");

    qsysdb_cluster_t *cluster = qsysdb_cluster_create(&config);
    TEST_ASSERT_NOT_NULL(cluster);

    qsysdb_cluster_add_node(cluster, "192.168.1.10", 5959, 5960);

    qsysdb_node_t *nodes = NULL;
    int count = 0;
    int ret = qsysdb_cluster_get_nodes(cluster, &nodes, &count);

    TEST_ASSERT_OK(ret);
    TEST_ASSERT_NOT_NULL(nodes);
    TEST_ASSERT_EQ(2, count);

    free(nodes);
    qsysdb_cluster_destroy(cluster);
}

TEST(cluster_remove_node)
{
    qsysdb_cluster_config_t config;
    qsysdb_cluster_config_init(&config);
    config.node_id = 1;
    strcpy(config.bind_address, "127.0.0.1");

    qsysdb_cluster_t *cluster = qsysdb_cluster_create(&config);
    TEST_ASSERT_NOT_NULL(cluster);

    int node_id = qsysdb_cluster_add_node(cluster, "192.168.1.10", 5959, 5960);
    TEST_ASSERT_EQ(2, cluster->node_count);

    int ret = qsysdb_cluster_remove_node(cluster, node_id);
    TEST_ASSERT_OK(ret);
    TEST_ASSERT_EQ(1, cluster->node_count);

    qsysdb_cluster_destroy(cluster);
}

/* ============================================
 * Protocol Message Tests
 * ============================================ */

TEST(protocol_header_init)
{
    qsysdb_cluster_header_t hdr;
    qsysdb_cluster_msg_init(&hdr, CLUSTER_MSG_HEARTBEAT, 42, 5, 100);

    TEST_ASSERT_EQ(QSYSDB_CLUSTER_MAGIC, hdr.magic);
    TEST_ASSERT_EQ(QSYSDB_CLUSTER_PROTOCOL_VERSION, hdr.version);
    TEST_ASSERT_EQ(CLUSTER_MSG_HEARTBEAT, hdr.msg_type);
    TEST_ASSERT_EQ(42, hdr.sender_id);
    TEST_ASSERT_EQ(5, hdr.term);
    TEST_ASSERT_EQ(100, hdr.payload_len);
}

TEST(protocol_header_validate_success)
{
    qsysdb_cluster_header_t hdr;
    qsysdb_cluster_msg_init(&hdr, CLUSTER_MSG_HEARTBEAT, 1, 0, 0);

    int ret = qsysdb_cluster_msg_validate(&hdr, sizeof(hdr));
    TEST_ASSERT_OK(ret);
}

TEST(protocol_header_validate_bad_magic)
{
    qsysdb_cluster_header_t hdr;
    qsysdb_cluster_msg_init(&hdr, CLUSTER_MSG_HEARTBEAT, 1, 0, 0);
    hdr.magic = 0xDEADBEEF;

    int ret = qsysdb_cluster_msg_validate(&hdr, sizeof(hdr));
    TEST_ASSERT_EQ(QSYSDB_ERR_PROTO, ret);
}

TEST(protocol_header_validate_short_message)
{
    qsysdb_cluster_header_t hdr;
    qsysdb_cluster_msg_init(&hdr, CLUSTER_MSG_HEARTBEAT, 1, 0, 0);

    int ret = qsysdb_cluster_msg_validate(&hdr, sizeof(hdr) - 1);
    TEST_ASSERT_EQ(QSYSDB_ERR_PROTO, ret);
}

TEST(protocol_msg_type_names)
{
    TEST_ASSERT_STR_EQ("HEARTBEAT", qsysdb_cluster_msg_type_name(CLUSTER_MSG_HEARTBEAT));
    TEST_ASSERT_STR_EQ("REQUEST_VOTE", qsysdb_cluster_msg_type_name(CLUSTER_MSG_REQUEST_VOTE));
    TEST_ASSERT_STR_EQ("APPEND_ENTRIES", qsysdb_cluster_msg_type_name(CLUSTER_MSG_APPEND_ENTRIES));
    TEST_ASSERT_STR_EQ("DISCOVER", qsysdb_cluster_msg_type_name(CLUSTER_MSG_DISCOVER));
}

/* ============================================
 * Time Utilities Tests
 * ============================================ */

TEST(cluster_time_ms_monotonic)
{
    uint64_t t1 = qsysdb_cluster_time_ms();
    usleep(10000);  /* 10ms */
    uint64_t t2 = qsysdb_cluster_time_ms();

    TEST_ASSERT_TRUE(t2 > t1);
    TEST_ASSERT_TRUE(t2 - t1 >= 9);  /* Allow some tolerance */
    TEST_ASSERT_TRUE(t2 - t1 < 50);  /* But not too much */
}

/* ============================================
 * Callback Tests
 * ============================================ */

static int g_leader_change_count = 0;
static uint32_t g_last_leader_id = 0;

static void test_leader_change_callback(qsysdb_cluster_t *cluster,
                                        uint32_t new_leader_id, void *userdata)
{
    (void)cluster;
    (void)userdata;
    g_leader_change_count++;
    g_last_leader_id = new_leader_id;
}

TEST(cluster_leader_change_callback)
{
    qsysdb_cluster_config_t config;
    qsysdb_cluster_config_init(&config);
    config.node_id = 1;
    strcpy(config.bind_address, "127.0.0.1");

    qsysdb_cluster_t *cluster = qsysdb_cluster_create(&config);
    TEST_ASSERT_NOT_NULL(cluster);

    g_leader_change_count = 0;
    g_last_leader_id = 0;

    qsysdb_cluster_on_leader_change(cluster, test_leader_change_callback, NULL);

    /* Simulate becoming leader */
    cluster->state = QSYSDB_NODE_LEADER;
    cluster->current_leader = cluster->config.node_id;
    if (cluster->on_leader_change) {
        cluster->on_leader_change(cluster, cluster->config.node_id,
                                  cluster->leader_change_userdata);
    }

    TEST_ASSERT_EQ(1, g_leader_change_count);
    TEST_ASSERT_EQ(1, g_last_leader_id);

    qsysdb_cluster_destroy(cluster);
}

/* ============================================
 * Main Test Runner
 * ============================================ */

TEST_MAIN()
