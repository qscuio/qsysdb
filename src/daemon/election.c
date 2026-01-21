/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * election.c - Raft-inspired leader election implementation
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#include <qsysdb/election.h>
#include <qsysdb/replication.h>
#include <qsysdb/cluster_protocol.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*
 * Logging macros
 */
#define ELECTION_LOG(fmt, ...) \
    fprintf(stderr, "[ELECTION] " fmt "\n", ##__VA_ARGS__)
#define ELECTION_DEBUG(fmt, ...) \
    fprintf(stderr, "[ELECTION DEBUG] " fmt "\n", ##__VA_ARGS__)

/*
 * Get state name for logging
 */
static const char *state_name(qsysdb_node_state_t state) __attribute__((unused));
static const char *state_name(qsysdb_node_state_t state)
{
    switch (state) {
    case QSYSDB_NODE_FOLLOWER:  return "FOLLOWER";
    case QSYSDB_NODE_CANDIDATE: return "CANDIDATE";
    case QSYSDB_NODE_LEADER:    return "LEADER";
    default:                    return "UNKNOWN";
    }
}

/*
 * Initialize election manager
 */
int qsysdb_election_init(qsysdb_cluster_t *cluster)
{
    if (!cluster)
        return QSYSDB_ERR_INVALID;

    qsysdb_election_t *election = calloc(1, sizeof(*election));
    if (!election)
        return QSYSDB_ERR_NOMEM;

    election->current_term = 0;
    election->voted_for = 0;
    election->votes_received = 0;
    election->votes_needed = 0;
    election->state = QSYSDB_NODE_FOLLOWER;
    election->cluster = cluster;

    pthread_mutex_init(&election->lock, NULL);

    /* Set initial election deadline */
    election->election_deadline = qsysdb_cluster_time_ms() +
        qsysdb_election_random_timeout(cluster);
    election->last_heartbeat = qsysdb_cluster_time_ms();

    cluster->election = election;
    cluster->state = QSYSDB_NODE_FOLLOWER;

    ELECTION_LOG("Election manager initialized, initial timeout at %lu ms",
                 election->election_deadline);

    return QSYSDB_OK;
}

/*
 * Cleanup election manager
 */
void qsysdb_election_cleanup(qsysdb_cluster_t *cluster)
{
    if (!cluster || !cluster->election)
        return;

    qsysdb_election_t *election = cluster->election;

    free(election->next_index);
    free(election->match_index);
    pthread_mutex_destroy(&election->lock);
    free(election);

    cluster->election = NULL;
}

/*
 * Get random election timeout
 */
int qsysdb_election_random_timeout(qsysdb_cluster_t *cluster)
{
    int min = cluster->config.election_timeout_min;
    int max = cluster->config.election_timeout_max;
    return min + (rand() % (max - min + 1));
}

/*
 * Reset election timeout
 */
void qsysdb_election_reset_timeout(qsysdb_cluster_t *cluster)
{
    if (!cluster || !cluster->election)
        return;

    qsysdb_election_t *election = cluster->election;
    pthread_mutex_lock(&election->lock);

    election->last_heartbeat = qsysdb_cluster_time_ms();
    election->election_deadline = election->last_heartbeat +
        qsysdb_election_random_timeout(cluster);

    pthread_mutex_unlock(&election->lock);
}

/*
 * Check if election timeout has expired
 */
bool qsysdb_election_timeout_expired(qsysdb_cluster_t *cluster)
{
    if (!cluster || !cluster->election)
        return false;

    qsysdb_election_t *election = cluster->election;
    pthread_mutex_lock(&election->lock);

    bool expired = qsysdb_cluster_time_ms() >= election->election_deadline;

    pthread_mutex_unlock(&election->lock);
    return expired;
}

/*
 * Step down to follower state
 */
void qsysdb_election_step_down(qsysdb_cluster_t *cluster, uint64_t new_term)
{
    if (!cluster || !cluster->election)
        return;

    qsysdb_election_t *election = cluster->election;
    pthread_mutex_lock(&election->lock);

    if (new_term > election->current_term) {
        ELECTION_LOG("Stepping down: term %lu -> %lu",
                     election->current_term, new_term);

        election->current_term = new_term;
        election->voted_for = 0;
        election->votes_received = 0;

        if (election->state != QSYSDB_NODE_FOLLOWER) {
            election->state = QSYSDB_NODE_FOLLOWER;
            cluster->state = QSYSDB_NODE_FOLLOWER;
            ELECTION_LOG("State changed to FOLLOWER");
        }

        cluster->current_term = new_term;
    }

    /* Reset election timeout */
    election->election_deadline = qsysdb_cluster_time_ms() +
        qsysdb_election_random_timeout(cluster);

    pthread_mutex_unlock(&election->lock);
}

/*
 * Start a new election
 */
int qsysdb_election_start(qsysdb_cluster_t *cluster)
{
    if (!cluster || !cluster->election)
        return QSYSDB_ERR_INVALID;

    qsysdb_election_t *election = cluster->election;
    pthread_mutex_lock(&election->lock);

    /* Increment term */
    election->current_term++;
    cluster->current_term = election->current_term;

    /* Become candidate */
    election->state = QSYSDB_NODE_CANDIDATE;
    cluster->state = QSYSDB_NODE_CANDIDATE;

    /* Vote for self */
    election->voted_for = cluster->config.node_id;
    election->votes_received = 1;

    /* Calculate votes needed (majority) */
    pthread_rwlock_rdlock(&cluster->nodes_lock);
    int alive_nodes = 0;
    for (int i = 0; i < cluster->node_count; i++) {
        if (cluster->nodes[i].is_alive)
            alive_nodes++;
    }
    pthread_rwlock_unlock(&cluster->nodes_lock);

    election->votes_needed = (alive_nodes / 2) + 1;

    /* Reset election deadline */
    election->election_deadline = qsysdb_cluster_time_ms() +
        qsysdb_election_random_timeout(cluster);

    cluster->elections_started++;

    ELECTION_LOG("Starting election: term=%lu, votes_needed=%u/%d",
                 election->current_term, election->votes_needed, alive_nodes);

    pthread_mutex_unlock(&election->lock);

    /* Send RequestVote to all nodes */
    qsysdb_msg_request_vote_t msg;
    qsysdb_cluster_msg_init(&msg.header, CLUSTER_MSG_REQUEST_VOTE,
                            cluster->config.node_id,
                            cluster->current_term,
                            sizeof(msg) - sizeof(msg.header));

    /* Get last log info */
    if (cluster->replication) {
        msg.last_log_index = qsysdb_replication_last_index(cluster);
        msg.last_log_term = qsysdb_replication_last_term(cluster);
    } else {
        msg.last_log_index = 0;
        msg.last_log_term = 0;
    }
    msg.header.timestamp = qsysdb_cluster_time_ms();

    qsysdb_cluster_broadcast(cluster, &msg, sizeof(msg));

    /* Check if we already won (single-node cluster) */
    pthread_mutex_lock(&election->lock);
    if (election->votes_received >= election->votes_needed &&
        election->state == QSYSDB_NODE_CANDIDATE) {
        ELECTION_LOG("Won election with %u votes (single node)",
                     election->votes_received);
        election->state = QSYSDB_NODE_LEADER;
        cluster->state = QSYSDB_NODE_LEADER;
        cluster->current_leader = cluster->config.node_id;
        cluster->elections_won++;

        /* Notify callback */
        if (cluster->on_leader_change) {
            cluster->on_leader_change(cluster, cluster->config.node_id,
                                      cluster->leader_change_userdata);
        }
    }
    pthread_mutex_unlock(&election->lock);

    return QSYSDB_OK;
}

/*
 * Handle vote request from another candidate
 */
int qsysdb_election_handle_vote_request(qsysdb_cluster_t *cluster,
                                        uint32_t candidate_id,
                                        uint64_t term,
                                        uint64_t last_log_index,
                                        uint64_t last_log_term,
                                        bool *vote_granted)
{
    if (!cluster || !cluster->election || !vote_granted)
        return QSYSDB_ERR_INVALID;

    qsysdb_election_t *election = cluster->election;
    *vote_granted = false;

    pthread_mutex_lock(&election->lock);

    /* If request term is less than our term, reject */
    if (term < election->current_term) {
        ELECTION_DEBUG("Rejecting vote for %u: term %lu < %lu",
                       candidate_id, term, election->current_term);
        pthread_mutex_unlock(&election->lock);
        return QSYSDB_OK;
    }

    /* If request term is greater, step down */
    if (term > election->current_term) {
        pthread_mutex_unlock(&election->lock);
        qsysdb_election_step_down(cluster, term);
        pthread_mutex_lock(&election->lock);
    }

    /* Check if we already voted for someone else this term */
    if (election->voted_for != 0 && election->voted_for != candidate_id) {
        ELECTION_DEBUG("Rejecting vote for %u: already voted for %u",
                       candidate_id, election->voted_for);
        pthread_mutex_unlock(&election->lock);
        return QSYSDB_OK;
    }

    /* Check if candidate's log is at least as up-to-date as ours */
    uint64_t our_last_index = 0, our_last_term = 0;
    if (cluster->replication) {
        our_last_index = qsysdb_replication_last_index(cluster);
        our_last_term = qsysdb_replication_last_term(cluster);
    }

    bool log_ok = (last_log_term > our_last_term) ||
                  (last_log_term == our_last_term && last_log_index >= our_last_index);

    if (!log_ok) {
        ELECTION_DEBUG("Rejecting vote for %u: log not up-to-date "
                       "(their: %lu/%lu, ours: %lu/%lu)",
                       candidate_id, last_log_index, last_log_term,
                       our_last_index, our_last_term);
        pthread_mutex_unlock(&election->lock);
        return QSYSDB_OK;
    }

    /* Grant vote */
    election->voted_for = candidate_id;
    *vote_granted = true;

    /* Reset election timeout since we granted a vote */
    election->election_deadline = qsysdb_cluster_time_ms() +
        qsysdb_election_random_timeout(cluster);

    ELECTION_LOG("Granted vote to %u for term %lu", candidate_id, term);

    pthread_mutex_unlock(&election->lock);
    return QSYSDB_OK;
}

/*
 * Handle vote response from another node
 */
int qsysdb_election_handle_vote_response(qsysdb_cluster_t *cluster,
                                         uint32_t voter_id,
                                         uint64_t term,
                                         bool vote_granted)
{
    if (!cluster || !cluster->election)
        return QSYSDB_ERR_INVALID;

    qsysdb_election_t *election = cluster->election;

    pthread_mutex_lock(&election->lock);

    /* Ignore if we're not a candidate */
    if (election->state != QSYSDB_NODE_CANDIDATE) {
        pthread_mutex_unlock(&election->lock);
        return QSYSDB_OK;
    }

    /* If response term is greater, step down */
    if (term > election->current_term) {
        pthread_mutex_unlock(&election->lock);
        qsysdb_election_step_down(cluster, term);
        return QSYSDB_OK;
    }

    /* Ignore if term doesn't match */
    if (term != election->current_term) {
        pthread_mutex_unlock(&election->lock);
        return QSYSDB_OK;
    }

    if (vote_granted) {
        election->votes_received++;
        ELECTION_DEBUG("Received vote from %u: %u/%u votes",
                       voter_id, election->votes_received, election->votes_needed);

        /* Check if we won */
        if (election->votes_received >= election->votes_needed) {
            ELECTION_LOG("Won election with %u votes!", election->votes_received);

            election->state = QSYSDB_NODE_LEADER;
            cluster->state = QSYSDB_NODE_LEADER;
            cluster->current_leader = cluster->config.node_id;
            cluster->elections_won++;

            /* Initialize leader state for replication */
            if (cluster->replication) {
                uint64_t last_index = qsysdb_replication_last_index(cluster);
                pthread_rwlock_rdlock(&cluster->nodes_lock);
                for (int i = 0; i < cluster->node_count; i++) {
                    if (!cluster->nodes[i].is_self) {
                        /* Initialize next_index to last log index + 1 */
                        cluster->nodes[i].last_log_index = last_index + 1;
                    }
                }
                pthread_rwlock_unlock(&cluster->nodes_lock);
            }

            /* Notify callback */
            if (cluster->on_leader_change) {
                pthread_mutex_unlock(&election->lock);
                cluster->on_leader_change(cluster, cluster->config.node_id,
                                          cluster->leader_change_userdata);
                return QSYSDB_OK;
            }
        }
    } else {
        ELECTION_DEBUG("Vote denied by %u", voter_id);
    }

    pthread_mutex_unlock(&election->lock);
    return QSYSDB_OK;
}

/*
 * Handle heartbeat from leader
 */
int qsysdb_election_handle_heartbeat(qsysdb_cluster_t *cluster,
                                     uint32_t leader_id,
                                     uint64_t term)
{
    if (!cluster || !cluster->election)
        return QSYSDB_ERR_INVALID;

    qsysdb_election_t *election = cluster->election;

    pthread_mutex_lock(&election->lock);

    /* If term is greater, step down */
    if (term > election->current_term) {
        pthread_mutex_unlock(&election->lock);
        qsysdb_election_step_down(cluster, term);
        pthread_mutex_lock(&election->lock);
    }

    /* Ignore old-term heartbeats */
    if (term < election->current_term) {
        pthread_mutex_unlock(&election->lock);
        return QSYSDB_OK;
    }

    /* Accept heartbeat from valid leader */
    if (election->state == QSYSDB_NODE_CANDIDATE) {
        /* Another node won the election, step down */
        ELECTION_LOG("Received heartbeat from leader %u, stepping down", leader_id);
        election->state = QSYSDB_NODE_FOLLOWER;
        cluster->state = QSYSDB_NODE_FOLLOWER;
        cluster->elections_lost++;
    }

    /* Update leader tracking */
    if (cluster->current_leader != leader_id) {
        uint32_t old_leader = cluster->current_leader;
        cluster->current_leader = leader_id;
        ELECTION_LOG("New leader: %u (was %u)", leader_id, old_leader);

        /* Notify callback */
        if (cluster->on_leader_change) {
            pthread_mutex_unlock(&election->lock);
            cluster->on_leader_change(cluster, leader_id,
                                      cluster->leader_change_userdata);
            pthread_mutex_lock(&election->lock);
        }
    }

    /* Reset election timeout */
    election->last_heartbeat = qsysdb_cluster_time_ms();
    election->election_deadline = election->last_heartbeat +
        qsysdb_election_random_timeout(cluster);

    pthread_mutex_unlock(&election->lock);
    return QSYSDB_OK;
}

/*
 * Election timer tick - called periodically
 */
int qsysdb_election_tick(qsysdb_cluster_t *cluster)
{
    if (!cluster || !cluster->election)
        return QSYSDB_ERR_INVALID;

    qsysdb_election_t *election = cluster->election;

    pthread_mutex_lock(&election->lock);

    /* Leaders don't time out */
    if (election->state == QSYSDB_NODE_LEADER) {
        pthread_mutex_unlock(&election->lock);
        return QSYSDB_OK;
    }

    /* Check if election timeout expired */
    uint64_t now = qsysdb_cluster_time_ms();
    if (now >= election->election_deadline) {
        pthread_mutex_unlock(&election->lock);

        if (election->state == QSYSDB_NODE_CANDIDATE) {
            /* Election timed out, start new election */
            ELECTION_LOG("Election timed out, starting new election");
        } else {
            /* No heartbeat from leader, start election */
            ELECTION_LOG("Leader heartbeat timeout, starting election");
        }

        qsysdb_election_start(cluster);
        return 1;  /* Election started */
    }

    pthread_mutex_unlock(&election->lock);
    return QSYSDB_OK;
}

/*
 * State query functions
 */

uint64_t qsysdb_election_get_term(qsysdb_cluster_t *cluster)
{
    if (!cluster || !cluster->election)
        return 0;

    pthread_mutex_lock(&cluster->election->lock);
    uint64_t term = cluster->election->current_term;
    pthread_mutex_unlock(&cluster->election->lock);

    return term;
}

uint32_t qsysdb_election_get_voted_for(qsysdb_cluster_t *cluster)
{
    if (!cluster || !cluster->election)
        return 0;

    pthread_mutex_lock(&cluster->election->lock);
    uint32_t voted_for = cluster->election->voted_for;
    pthread_mutex_unlock(&cluster->election->lock);

    return voted_for;
}
