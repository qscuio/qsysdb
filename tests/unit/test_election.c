/*
 * QSysDB - Election Unit Tests
 *
 * Tests Raft-inspired leader election functionality including:
 *   - Election initialization
 *   - Vote request/response handling
 *   - Term management
 *   - State transitions
 *   - Timeout handling
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
#include <qsysdb/election.h>
#include "framework/test_framework.h"

static const char *_current_suite_name = "election";

/* Test fixture */
static qsysdb_cluster_t *g_cluster = NULL;

static void setup_cluster(void)
{
    qsysdb_cluster_config_t config;
    qsysdb_cluster_config_init(&config);
    config.node_id = 1;
    strcpy(config.bind_address, "127.0.0.1");
    config.election_timeout_min = 150;
    config.election_timeout_max = 300;

    g_cluster = qsysdb_cluster_create(&config);
    if (g_cluster) {
        qsysdb_election_init(g_cluster);
    }
}

static void teardown_cluster(void)
{
    if (g_cluster) {
        qsysdb_election_cleanup(g_cluster);
        qsysdb_cluster_destroy(g_cluster);
        g_cluster = NULL;
    }
}

/* ============================================
 * Initialization Tests
 * ============================================ */

TEST(election_init_success)
{
    setup_cluster();
    TEST_ASSERT_NOT_NULL(g_cluster);
    TEST_ASSERT_NOT_NULL(g_cluster->election);
    teardown_cluster();
}

TEST(election_init_state_follower)
{
    setup_cluster();
    TEST_ASSERT_NOT_NULL(g_cluster);

    TEST_ASSERT_EQ(QSYSDB_NODE_FOLLOWER, g_cluster->election->state);

    teardown_cluster();
}

TEST(election_init_term_zero)
{
    setup_cluster();
    TEST_ASSERT_NOT_NULL(g_cluster);

    TEST_ASSERT_EQ(0, qsysdb_election_get_term(g_cluster));

    teardown_cluster();
}

TEST(election_init_no_vote)
{
    setup_cluster();
    TEST_ASSERT_NOT_NULL(g_cluster);

    TEST_ASSERT_EQ(0, qsysdb_election_get_voted_for(g_cluster));

    teardown_cluster();
}

/* ============================================
 * Random Timeout Tests
 * ============================================ */

TEST(election_random_timeout_in_range)
{
    setup_cluster();
    TEST_ASSERT_NOT_NULL(g_cluster);

    for (int i = 0; i < 100; i++) {
        int timeout = qsysdb_election_random_timeout(g_cluster);
        TEST_ASSERT_TRUE(timeout >= g_cluster->config.election_timeout_min);
        TEST_ASSERT_TRUE(timeout <= g_cluster->config.election_timeout_max);
    }

    teardown_cluster();
}

/* ============================================
 * Timeout Reset Tests
 * ============================================ */

TEST(election_reset_timeout)
{
    setup_cluster();
    TEST_ASSERT_NOT_NULL(g_cluster);

    uint64_t deadline1 = g_cluster->election->election_deadline;
    usleep(10000);  /* 10ms */
    qsysdb_election_reset_timeout(g_cluster);
    uint64_t deadline2 = g_cluster->election->election_deadline;

    TEST_ASSERT_TRUE(deadline2 > deadline1);

    teardown_cluster();
}

/* ============================================
 * Step Down Tests
 * ============================================ */

TEST(election_step_down_higher_term)
{
    setup_cluster();
    TEST_ASSERT_NOT_NULL(g_cluster);

    /* Simulate being a candidate */
    g_cluster->election->state = QSYSDB_NODE_CANDIDATE;
    g_cluster->election->current_term = 1;
    g_cluster->state = QSYSDB_NODE_CANDIDATE;

    /* Step down due to higher term */
    qsysdb_election_step_down(g_cluster, 5);

    TEST_ASSERT_EQ(QSYSDB_NODE_FOLLOWER, g_cluster->election->state);
    TEST_ASSERT_EQ(5, g_cluster->election->current_term);
    TEST_ASSERT_EQ(0, g_cluster->election->voted_for);

    teardown_cluster();
}

TEST(election_step_down_same_term_no_change)
{
    setup_cluster();
    TEST_ASSERT_NOT_NULL(g_cluster);

    g_cluster->election->current_term = 5;
    uint64_t old_voted_for = g_cluster->election->voted_for = 42;

    /* Same term should not change anything */
    qsysdb_election_step_down(g_cluster, 5);

    TEST_ASSERT_EQ(5, g_cluster->election->current_term);
    TEST_ASSERT_EQ(old_voted_for, g_cluster->election->voted_for);

    teardown_cluster();
}

/* ============================================
 * Vote Request Tests
 * ============================================ */

TEST(election_vote_request_grant_higher_term)
{
    setup_cluster();
    TEST_ASSERT_NOT_NULL(g_cluster);

    g_cluster->election->current_term = 1;
    g_cluster->election->voted_for = 0;

    bool vote_granted = false;
    int ret = qsysdb_election_handle_vote_request(g_cluster,
                                                   2,   /* candidate_id */
                                                   2,   /* term (higher) */
                                                   0,   /* last_log_index */
                                                   0,   /* last_log_term */
                                                   &vote_granted);

    TEST_ASSERT_OK(ret);
    TEST_ASSERT_TRUE(vote_granted);
    TEST_ASSERT_EQ(2, g_cluster->election->voted_for);

    teardown_cluster();
}

TEST(election_vote_request_deny_lower_term)
{
    setup_cluster();
    TEST_ASSERT_NOT_NULL(g_cluster);

    g_cluster->election->current_term = 5;

    bool vote_granted = false;
    int ret = qsysdb_election_handle_vote_request(g_cluster,
                                                   2,   /* candidate_id */
                                                   3,   /* term (lower) */
                                                   0, 0,
                                                   &vote_granted);

    TEST_ASSERT_OK(ret);
    TEST_ASSERT_FALSE(vote_granted);

    teardown_cluster();
}

TEST(election_vote_request_deny_already_voted)
{
    setup_cluster();
    TEST_ASSERT_NOT_NULL(g_cluster);

    g_cluster->election->current_term = 2;
    g_cluster->election->voted_for = 99;  /* Already voted for node 99 */

    bool vote_granted = false;
    int ret = qsysdb_election_handle_vote_request(g_cluster,
                                                   2,   /* candidate_id (different) */
                                                   2,   /* same term */
                                                   0, 0,
                                                   &vote_granted);

    TEST_ASSERT_OK(ret);
    TEST_ASSERT_FALSE(vote_granted);
    TEST_ASSERT_EQ(99, g_cluster->election->voted_for);

    teardown_cluster();
}

TEST(election_vote_request_grant_same_candidate)
{
    setup_cluster();
    TEST_ASSERT_NOT_NULL(g_cluster);

    g_cluster->election->current_term = 2;
    g_cluster->election->voted_for = 42;

    bool vote_granted = false;
    int ret = qsysdb_election_handle_vote_request(g_cluster,
                                                   42,  /* same candidate we voted for */
                                                   2,   /* same term */
                                                   0, 0,
                                                   &vote_granted);

    TEST_ASSERT_OK(ret);
    TEST_ASSERT_TRUE(vote_granted);

    teardown_cluster();
}

/* ============================================
 * Vote Response Tests
 * ============================================ */

TEST(election_vote_response_not_candidate)
{
    setup_cluster();
    TEST_ASSERT_NOT_NULL(g_cluster);

    /* As follower, vote responses should be ignored */
    g_cluster->election->state = QSYSDB_NODE_FOLLOWER;
    g_cluster->election->votes_received = 0;

    int ret = qsysdb_election_handle_vote_response(g_cluster, 2, 1, true);

    TEST_ASSERT_OK(ret);
    TEST_ASSERT_EQ(0, g_cluster->election->votes_received);

    teardown_cluster();
}

TEST(election_vote_response_count_votes)
{
    setup_cluster();
    TEST_ASSERT_NOT_NULL(g_cluster);

    /* As candidate, count votes */
    g_cluster->election->state = QSYSDB_NODE_CANDIDATE;
    g_cluster->election->current_term = 1;
    g_cluster->election->votes_received = 1;  /* Self vote */
    g_cluster->election->votes_needed = 2;
    g_cluster->state = QSYSDB_NODE_CANDIDATE;
    g_cluster->current_term = 1;

    int ret = qsysdb_election_handle_vote_response(g_cluster, 2, 1, true);

    TEST_ASSERT_OK(ret);
    TEST_ASSERT_EQ(2, g_cluster->election->votes_received);

    teardown_cluster();
}

TEST(election_vote_response_higher_term_step_down)
{
    setup_cluster();
    TEST_ASSERT_NOT_NULL(g_cluster);

    g_cluster->election->state = QSYSDB_NODE_CANDIDATE;
    g_cluster->election->current_term = 1;
    g_cluster->state = QSYSDB_NODE_CANDIDATE;
    g_cluster->current_term = 1;

    /* Higher term in response should cause step down */
    int ret = qsysdb_election_handle_vote_response(g_cluster, 2, 5, false);

    TEST_ASSERT_OK(ret);
    TEST_ASSERT_EQ(QSYSDB_NODE_FOLLOWER, g_cluster->election->state);

    teardown_cluster();
}

/* ============================================
 * Heartbeat Tests
 * ============================================ */

TEST(election_heartbeat_updates_leader)
{
    setup_cluster();
    TEST_ASSERT_NOT_NULL(g_cluster);

    g_cluster->election->current_term = 1;
    g_cluster->current_term = 1;
    g_cluster->current_leader = 0;

    int ret = qsysdb_election_handle_heartbeat(g_cluster, 42, 1);

    TEST_ASSERT_OK(ret);
    TEST_ASSERT_EQ(42, g_cluster->current_leader);

    teardown_cluster();
}

TEST(election_heartbeat_candidate_steps_down)
{
    setup_cluster();
    TEST_ASSERT_NOT_NULL(g_cluster);

    g_cluster->election->state = QSYSDB_NODE_CANDIDATE;
    g_cluster->election->current_term = 1;
    g_cluster->state = QSYSDB_NODE_CANDIDATE;
    g_cluster->current_term = 1;

    int ret = qsysdb_election_handle_heartbeat(g_cluster, 42, 1);

    TEST_ASSERT_OK(ret);
    TEST_ASSERT_EQ(QSYSDB_NODE_FOLLOWER, g_cluster->election->state);
    TEST_ASSERT_EQ(42, g_cluster->current_leader);

    teardown_cluster();
}

TEST(election_heartbeat_ignore_old_term)
{
    setup_cluster();
    TEST_ASSERT_NOT_NULL(g_cluster);

    g_cluster->election->current_term = 5;
    g_cluster->current_term = 5;
    g_cluster->current_leader = 10;

    /* Old term heartbeat should be ignored */
    int ret = qsysdb_election_handle_heartbeat(g_cluster, 42, 3);

    TEST_ASSERT_OK(ret);
    TEST_ASSERT_EQ(10, g_cluster->current_leader);  /* Unchanged */

    teardown_cluster();
}

/* ============================================
 * Election Start Tests
 * ============================================ */

TEST(election_start_increments_term)
{
    setup_cluster();
    TEST_ASSERT_NOT_NULL(g_cluster);

    g_cluster->election->current_term = 0;

    int ret = qsysdb_election_start(g_cluster);

    TEST_ASSERT_OK(ret);
    TEST_ASSERT_EQ(1, g_cluster->election->current_term);

    teardown_cluster();
}

TEST(election_start_becomes_candidate)
{
    setup_cluster();
    TEST_ASSERT_NOT_NULL(g_cluster);

    /* Add another node so election doesn't immediately win */
    qsysdb_cluster_add_node(g_cluster, "192.168.1.10", 5959, 5960);
    TEST_ASSERT_EQ(2, g_cluster->node_count);

    int ret = qsysdb_election_start(g_cluster);

    TEST_ASSERT_OK(ret);
    /* With 2 nodes, we need 2 votes, so we should remain candidate */
    TEST_ASSERT_EQ(QSYSDB_NODE_CANDIDATE, g_cluster->election->state);

    teardown_cluster();
}

TEST(election_start_votes_for_self)
{
    setup_cluster();
    TEST_ASSERT_NOT_NULL(g_cluster);

    int ret = qsysdb_election_start(g_cluster);

    TEST_ASSERT_OK(ret);
    TEST_ASSERT_EQ(g_cluster->config.node_id, g_cluster->election->voted_for);
    TEST_ASSERT_EQ(1, g_cluster->election->votes_received);

    teardown_cluster();
}

/* ============================================
 * Tick Tests
 * ============================================ */

TEST(election_tick_leader_no_timeout)
{
    setup_cluster();
    TEST_ASSERT_NOT_NULL(g_cluster);

    g_cluster->election->state = QSYSDB_NODE_LEADER;
    g_cluster->election->election_deadline = 0;  /* Would timeout */

    int ret = qsysdb_election_tick(g_cluster);

    TEST_ASSERT_OK(ret);
    /* Leader should not start election */
    TEST_ASSERT_EQ(QSYSDB_NODE_LEADER, g_cluster->election->state);

    teardown_cluster();
}

/* ============================================
 * Main Test Runner
 * ============================================ */

TEST_MAIN()
