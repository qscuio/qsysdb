/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * cluster_protocol.h - Inter-node communication protocol definitions
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#ifndef QSYSDB_CLUSTER_PROTOCOL_H
#define QSYSDB_CLUSTER_PROTOCOL_H

#include <qsysdb/types.h>

/*
 * Cluster protocol constants
 */
#define QSYSDB_CLUSTER_MAGIC            0x51434C55  /* "QCLU" */
#define QSYSDB_CLUSTER_PROTOCOL_VERSION 1
#define QSYSDB_CLUSTER_MAX_MSG_SIZE     (1024 * 1024)  /* 1MB max message */

/*
 * Cluster message types
 */
typedef enum qsysdb_cluster_msg_type {
    /* Election messages (1-19) */
    CLUSTER_MSG_REQUEST_VOTE = 1,       /* Candidate requesting votes */
    CLUSTER_MSG_VOTE_RESPONSE,          /* Response to vote request */

    /* Heartbeat/leadership messages (20-39) */
    CLUSTER_MSG_HEARTBEAT = 20,         /* Leader heartbeat */
    CLUSTER_MSG_HEARTBEAT_ACK,          /* Heartbeat acknowledgment */

    /* Replication messages (40-59) */
    CLUSTER_MSG_APPEND_ENTRIES = 40,    /* Log replication from leader */
    CLUSTER_MSG_APPEND_RESPONSE,        /* Response to append entries */
    CLUSTER_MSG_INSTALL_SNAPSHOT,       /* Full snapshot transfer */
    CLUSTER_MSG_SNAPSHOT_RESPONSE,      /* Response to snapshot */

    /* Discovery messages (60-79) */
    CLUSTER_MSG_DISCOVER = 60,          /* Discovery request (multicast) */
    CLUSTER_MSG_ANNOUNCE,               /* Node announcement */
    CLUSTER_MSG_JOIN_REQUEST,           /* Request to join cluster */
    CLUSTER_MSG_JOIN_RESPONSE,          /* Response to join request */
    CLUSTER_MSG_LEAVE,                  /* Node leaving cluster */

    /* Write forwarding messages (80-99) */
    CLUSTER_MSG_FORWARD_WRITE = 80,     /* Forward write to leader */
    CLUSTER_MSG_FORWARD_RESPONSE,       /* Response from leader */

    /* Administrative messages (100-119) */
    CLUSTER_MSG_GET_STATE = 100,        /* Get cluster state */
    CLUSTER_MSG_STATE_RESPONSE,         /* Cluster state response */
    CLUSTER_MSG_PING,                   /* Cluster ping */
    CLUSTER_MSG_PONG                    /* Cluster pong */
} qsysdb_cluster_msg_type_t;

/*
 * Base message header for all cluster messages
 */
typedef struct qsysdb_cluster_header {
    uint32_t magic;                     /* QSYSDB_CLUSTER_MAGIC */
    uint8_t version;                    /* Protocol version */
    uint8_t msg_type;                   /* Message type */
    uint16_t flags;                     /* Message flags */
    uint32_t payload_len;               /* Payload length (after header) */
    uint32_t sender_id;                 /* Sender node ID */
    uint64_t term;                      /* Current term of sender */
    uint64_t timestamp;                 /* Message timestamp (ms) */
} __attribute__((packed)) qsysdb_cluster_header_t;

/*
 * RequestVote message (candidate -> all nodes)
 */
typedef struct qsysdb_msg_request_vote {
    qsysdb_cluster_header_t header;
    uint64_t last_log_index;            /* Index of candidate's last log entry */
    uint64_t last_log_term;             /* Term of candidate's last log entry */
} __attribute__((packed)) qsysdb_msg_request_vote_t;

/*
 * VoteResponse message (node -> candidate)
 */
typedef struct qsysdb_msg_vote_response {
    qsysdb_cluster_header_t header;
    uint8_t vote_granted;               /* 1 if vote granted, 0 otherwise */
    uint8_t reserved[7];
} __attribute__((packed)) qsysdb_msg_vote_response_t;

/*
 * Heartbeat message (leader -> all followers)
 */
typedef struct qsysdb_msg_heartbeat {
    qsysdb_cluster_header_t header;
    uint32_t leader_id;                 /* Leader's node ID */
    uint32_t node_count;                /* Number of nodes in cluster */
    uint64_t commit_index;              /* Leader's commit index */
    uint16_t leader_client_port;        /* Leader's client port */
    uint16_t leader_cluster_port;       /* Leader's cluster port */
    char leader_address[256];           /* Leader's address */
} __attribute__((packed)) qsysdb_msg_heartbeat_t;

/*
 * HeartbeatAck message (follower -> leader)
 */
typedef struct qsysdb_msg_heartbeat_ack {
    qsysdb_cluster_header_t header;
    uint64_t last_log_index;            /* Follower's last log index */
    uint64_t last_applied;              /* Follower's last applied index */
} __attribute__((packed)) qsysdb_msg_heartbeat_ack_t;

/*
 * AppendEntries header (entries follow the header)
 */
typedef struct qsysdb_msg_append_entries {
    qsysdb_cluster_header_t header;
    uint32_t leader_id;                 /* Leader's node ID */
    uint32_t entry_count;               /* Number of entries following */
    uint64_t prev_log_index;            /* Index of log entry before new ones */
    uint64_t prev_log_term;             /* Term of prev_log_index entry */
    uint64_t leader_commit;             /* Leader's commit index */
    /* Followed by entry_count serialized entries */
} __attribute__((packed)) qsysdb_msg_append_entries_t;

/*
 * Serialized replication entry (for wire transfer)
 */
typedef struct qsysdb_wire_entry {
    uint64_t index;                     /* Log index */
    uint64_t term;                      /* Entry term */
    uint8_t op_type;                    /* Operation type */
    uint8_t reserved[3];
    uint32_t flags;                     /* Entry flags */
    uint16_t path_len;                  /* Path length */
    uint16_t value_len;                 /* Value length */
    /* Followed by path (path_len bytes) and value (value_len bytes) */
    char data[];
} __attribute__((packed)) qsysdb_wire_entry_t;

/*
 * AppendResponse message (follower -> leader)
 */
typedef struct qsysdb_msg_append_response {
    qsysdb_cluster_header_t header;
    uint8_t success;                    /* 1 if successful, 0 otherwise */
    uint8_t reserved[7];
    uint64_t match_index;               /* Last matching log index */
    uint64_t last_log_index;            /* Follower's last log index */
} __attribute__((packed)) qsysdb_msg_append_response_t;

/*
 * Discovery message (multicast)
 */
typedef struct qsysdb_msg_discover {
    qsysdb_cluster_header_t header;
    uint16_t client_port;               /* Discoverer's client port */
    uint16_t cluster_port;              /* Discoverer's cluster port */
    char address[256];                  /* Discoverer's address */
} __attribute__((packed)) qsysdb_msg_discover_t;

/*
 * Announce message (response to discovery or periodic)
 */
typedef struct qsysdb_msg_announce {
    qsysdb_cluster_header_t header;
    uint32_t node_id;                   /* Announcing node's ID */
    uint32_t leader_id;                 /* Current leader ID (0 if unknown) */
    uint16_t client_port;               /* Client port */
    uint16_t cluster_port;              /* Cluster port */
    uint8_t node_state;                 /* Node state (follower/candidate/leader) */
    uint8_t reserved[3];
    uint64_t last_log_index;            /* Node's last log index */
    char address[256];                  /* Node's address */
} __attribute__((packed)) qsysdb_msg_announce_t;

/*
 * JoinRequest message (new node -> existing node)
 */
typedef struct qsysdb_msg_join_request {
    qsysdb_cluster_header_t header;
    uint16_t client_port;               /* New node's client port */
    uint16_t cluster_port;              /* New node's cluster port */
    char address[256];                  /* New node's address */
} __attribute__((packed)) qsysdb_msg_join_request_t;

/*
 * JoinResponse message (leader -> new node)
 */
typedef struct qsysdb_msg_join_response {
    qsysdb_cluster_header_t header;
    uint8_t accepted;                   /* 1 if accepted, 0 otherwise */
    uint8_t reserved[3];
    uint32_t assigned_node_id;          /* Assigned node ID */
    uint32_t node_count;                /* Number of existing nodes */
    /* Followed by node_count announce messages for each node */
} __attribute__((packed)) qsysdb_msg_join_response_t;

/*
 * ForwardWrite message (follower -> leader)
 */
typedef struct qsysdb_msg_forward_write {
    qsysdb_cluster_header_t header;
    uint32_t client_request_id;         /* Original client request ID */
    uint32_t original_msg_type;         /* Original message type */
    uint32_t payload_size;              /* Size of original request payload */
    uint32_t reserved;
    /* Followed by original request payload */
    char payload[];
} __attribute__((packed)) qsysdb_msg_forward_write_t;

/*
 * ForwardResponse message (leader -> follower)
 */
typedef struct qsysdb_msg_forward_response {
    qsysdb_cluster_header_t header;
    uint32_t client_request_id;         /* Original client request ID */
    int32_t error_code;                 /* Error code (0 = success) */
    uint32_t response_size;             /* Size of response payload */
    uint32_t reserved;
    /* Followed by response payload */
    char payload[];
} __attribute__((packed)) qsysdb_msg_forward_response_t;

/*
 * GetState message (any node -> any node)
 */
typedef struct qsysdb_msg_get_state {
    qsysdb_cluster_header_t header;
} __attribute__((packed)) qsysdb_msg_get_state_t;

/*
 * StateResponse message
 */
typedef struct qsysdb_msg_state_response {
    qsysdb_cluster_header_t header;
    uint32_t node_id;
    uint32_t leader_id;
    uint8_t node_state;
    uint8_t reserved[3];
    uint32_t node_count;
    uint64_t commit_index;
    uint64_t last_log_index;
    uint64_t last_applied;
} __attribute__((packed)) qsysdb_msg_state_response_t;

/*
 * Helper functions for message handling
 */

/**
 * Initialize a cluster message header
 */
static inline void qsysdb_cluster_msg_init(qsysdb_cluster_header_t *hdr,
                                           qsysdb_cluster_msg_type_t type,
                                           uint32_t sender_id,
                                           uint64_t term,
                                           uint32_t payload_len)
{
    hdr->magic = QSYSDB_CLUSTER_MAGIC;
    hdr->version = QSYSDB_CLUSTER_PROTOCOL_VERSION;
    hdr->msg_type = (uint8_t)type;
    hdr->flags = 0;
    hdr->payload_len = payload_len;
    hdr->sender_id = sender_id;
    hdr->term = term;
    hdr->timestamp = 0;  /* Set by sender */
}

/**
 * Validate a cluster message header
 * @return 0 if valid, negative error code otherwise
 */
static inline int qsysdb_cluster_msg_validate(const qsysdb_cluster_header_t *hdr,
                                              size_t received_len)
{
    if (received_len < sizeof(qsysdb_cluster_header_t))
        return QSYSDB_ERR_PROTO;
    if (hdr->magic != QSYSDB_CLUSTER_MAGIC)
        return QSYSDB_ERR_PROTO;
    if (hdr->version != QSYSDB_CLUSTER_PROTOCOL_VERSION)
        return QSYSDB_ERR_PROTO;
    if (sizeof(qsysdb_cluster_header_t) + hdr->payload_len > received_len)
        return QSYSDB_ERR_PROTO;
    return QSYSDB_OK;
}

/**
 * Get total message size
 */
static inline size_t qsysdb_cluster_msg_size(const qsysdb_cluster_header_t *hdr)
{
    return sizeof(qsysdb_cluster_header_t) + hdr->payload_len;
}

/**
 * Get message type name for logging
 */
static inline const char *qsysdb_cluster_msg_type_name(qsysdb_cluster_msg_type_t type)
{
    switch (type) {
    case CLUSTER_MSG_REQUEST_VOTE:      return "REQUEST_VOTE";
    case CLUSTER_MSG_VOTE_RESPONSE:     return "VOTE_RESPONSE";
    case CLUSTER_MSG_HEARTBEAT:         return "HEARTBEAT";
    case CLUSTER_MSG_HEARTBEAT_ACK:     return "HEARTBEAT_ACK";
    case CLUSTER_MSG_APPEND_ENTRIES:    return "APPEND_ENTRIES";
    case CLUSTER_MSG_APPEND_RESPONSE:   return "APPEND_RESPONSE";
    case CLUSTER_MSG_INSTALL_SNAPSHOT:  return "INSTALL_SNAPSHOT";
    case CLUSTER_MSG_SNAPSHOT_RESPONSE: return "SNAPSHOT_RESPONSE";
    case CLUSTER_MSG_DISCOVER:          return "DISCOVER";
    case CLUSTER_MSG_ANNOUNCE:          return "ANNOUNCE";
    case CLUSTER_MSG_JOIN_REQUEST:      return "JOIN_REQUEST";
    case CLUSTER_MSG_JOIN_RESPONSE:     return "JOIN_RESPONSE";
    case CLUSTER_MSG_LEAVE:             return "LEAVE";
    case CLUSTER_MSG_FORWARD_WRITE:     return "FORWARD_WRITE";
    case CLUSTER_MSG_FORWARD_RESPONSE:  return "FORWARD_RESPONSE";
    case CLUSTER_MSG_GET_STATE:         return "GET_STATE";
    case CLUSTER_MSG_STATE_RESPONSE:    return "STATE_RESPONSE";
    case CLUSTER_MSG_PING:              return "PING";
    case CLUSTER_MSG_PONG:              return "PONG";
    default:                            return "UNKNOWN";
    }
}

#endif /* QSYSDB_CLUSTER_PROTOCOL_H */
