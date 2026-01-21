/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * election.h - Raft-inspired leader election API
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#ifndef QSYSDB_ELECTION_H
#define QSYSDB_ELECTION_H

#include <qsysdb/cluster.h>
#include <pthread.h>

/*
 * Election state structure
 * Tracks Raft-style election state for this node
 */
struct qsysdb_election {
    /* Persistent state (would be persisted to disk in production) */
    uint64_t current_term;          /* Current election term */
    uint32_t voted_for;             /* Node we voted for this term (0 = none) */

    /* Volatile state */
    uint32_t votes_received;        /* Votes received in current election */
    uint32_t votes_needed;          /* Votes needed to win (majority) */
    uint64_t election_deadline;     /* When current election times out (ms) */
    uint64_t last_heartbeat;        /* Last time we heard from leader (ms) */
    qsysdb_node_state_t state;      /* Current state */

    /* Leader state (only valid if leader) */
    uint32_t *next_index;           /* For each server, index of next log entry to send */
    uint32_t *match_index;          /* For each server, index of highest log entry known to be replicated */

    /* Synchronization */
    pthread_mutex_t lock;

    /* Back-reference to cluster */
    qsysdb_cluster_t *cluster;
};

/*
 * Election lifecycle functions
 */

/**
 * Initialize election manager
 * @param cluster Cluster handle
 * @return 0 on success, negative error code on failure
 */
int qsysdb_election_init(qsysdb_cluster_t *cluster);

/**
 * Cleanup election manager
 * @param cluster Cluster handle
 */
void qsysdb_election_cleanup(qsysdb_cluster_t *cluster);

/*
 * Election operations
 */

/**
 * Start a new election (become candidate)
 * Called when election timeout expires without hearing from leader
 * @param cluster Cluster handle
 * @return 0 on success, negative error code on failure
 */
int qsysdb_election_start(qsysdb_cluster_t *cluster);

/**
 * Process a vote request from another candidate
 * @param cluster Cluster handle
 * @param candidate_id ID of the candidate requesting vote
 * @param term Candidate's term
 * @param last_log_index Index of candidate's last log entry
 * @param last_log_term Term of candidate's last log entry
 * @param vote_granted Output: whether vote was granted
 * @return 0 on success, negative error code on failure
 */
int qsysdb_election_handle_vote_request(qsysdb_cluster_t *cluster,
                                        uint32_t candidate_id,
                                        uint64_t term,
                                        uint64_t last_log_index,
                                        uint64_t last_log_term,
                                        bool *vote_granted);

/**
 * Process a vote response from another node
 * @param cluster Cluster handle
 * @param voter_id ID of the node that voted
 * @param term Voter's term
 * @param vote_granted Whether vote was granted
 * @return 0 on success, negative error code on failure
 */
int qsysdb_election_handle_vote_response(qsysdb_cluster_t *cluster,
                                         uint32_t voter_id,
                                         uint64_t term,
                                         bool vote_granted);

/**
 * Process a heartbeat from the leader
 * @param cluster Cluster handle
 * @param leader_id ID of the leader
 * @param term Leader's term
 * @return 0 on success, negative error code on failure
 */
int qsysdb_election_handle_heartbeat(qsysdb_cluster_t *cluster,
                                     uint32_t leader_id,
                                     uint64_t term);

/**
 * Step down from leader/candidate to follower
 * Called when we discover a higher term
 * @param cluster Cluster handle
 * @param new_term The higher term that caused step-down
 */
void qsysdb_election_step_down(qsysdb_cluster_t *cluster, uint64_t new_term);

/**
 * Election timer tick - called periodically to check timeouts
 * @param cluster Cluster handle
 * @return 0 on success, 1 if election started, negative error code on failure
 */
int qsysdb_election_tick(qsysdb_cluster_t *cluster);

/**
 * Reset election timeout (called when hearing from leader)
 * @param cluster Cluster handle
 */
void qsysdb_election_reset_timeout(qsysdb_cluster_t *cluster);

/**
 * Get random election timeout between min and max
 * @param cluster Cluster handle
 * @return Timeout in milliseconds
 */
int qsysdb_election_random_timeout(qsysdb_cluster_t *cluster);

/*
 * State query functions
 */

/**
 * Get current election term
 * @param cluster Cluster handle
 * @return Current term
 */
uint64_t qsysdb_election_get_term(qsysdb_cluster_t *cluster);

/**
 * Get node we voted for this term
 * @param cluster Cluster handle
 * @return Node ID we voted for, or 0 if none
 */
uint32_t qsysdb_election_get_voted_for(qsysdb_cluster_t *cluster);

/**
 * Check if election timeout has expired
 * @param cluster Cluster handle
 * @return true if timeout expired
 */
bool qsysdb_election_timeout_expired(qsysdb_cluster_t *cluster);

#endif /* QSYSDB_ELECTION_H */
