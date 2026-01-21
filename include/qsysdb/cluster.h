/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * cluster.h - Cluster management API for multi-node deployments
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#ifndef QSYSDB_CLUSTER_H
#define QSYSDB_CLUSTER_H

#include <qsysdb/types.h>
#include <pthread.h>

/*
 * Cluster configuration constants
 */
#define QSYSDB_CLUSTER_MAGIC            0x51434C55  /* "QCLU" */
#define QSYSDB_CLUSTER_VERSION          1
#define QSYSDB_CLUSTER_MAX_NODES        16
#define QSYSDB_CLUSTER_PORT_DEFAULT     5960
#define QSYSDB_CLUSTER_MULTICAST_GROUP  "239.255.42.42"
#define QSYSDB_CLUSTER_MULTICAST_PORT   5961

/*
 * Default election timeouts (milliseconds)
 */
#define QSYSDB_ELECTION_TIMEOUT_MIN     150
#define QSYSDB_ELECTION_TIMEOUT_MAX     300
#define QSYSDB_HEARTBEAT_INTERVAL       50
#define QSYSDB_NODE_TIMEOUT             1000

/*
 * Cluster node states (Raft-inspired)
 */
typedef enum qsysdb_node_state {
    QSYSDB_NODE_FOLLOWER = 0,   /* Slave node - accepts reads, forwards writes */
    QSYSDB_NODE_CANDIDATE,      /* Election in progress */
    QSYSDB_NODE_LEADER          /* Master node - accepts reads and writes */
} qsysdb_node_state_t;

/*
 * Service discovery methods
 */
typedef enum qsysdb_discovery_method {
    QSYSDB_DISCOVERY_STATIC = 0,    /* Static list of seed nodes */
    QSYSDB_DISCOVERY_MULTICAST,     /* UDP multicast discovery */
    QSYSDB_DISCOVERY_DNS            /* DNS-based discovery */
} qsysdb_discovery_method_t;

/*
 * Cluster node information
 */
typedef struct qsysdb_node {
    uint32_t node_id;               /* Unique node identifier */
    char address[256];              /* Node IP address or hostname */
    uint16_t client_port;           /* Port for client connections */
    uint16_t cluster_port;          /* Port for inter-node communication */
    qsysdb_node_state_t state;      /* Current node state */
    uint64_t last_heartbeat;        /* Timestamp of last heartbeat (ms) */
    uint64_t last_log_index;        /* Last log entry index */
    uint64_t last_log_term;         /* Term of last log entry */
    bool is_self;                   /* True if this is the local node */
    bool is_alive;                  /* True if node is reachable */
} qsysdb_node_t;

/*
 * Cluster configuration
 */
typedef struct qsysdb_cluster_config {
    /* Node identity */
    uint32_t node_id;               /* Unique ID for this node (0 = auto-generate) */
    char bind_address[256];         /* Address to bind cluster socket */
    uint16_t client_port;           /* Port for client connections */
    uint16_t cluster_port;          /* Port for inter-node communication */

    /* Discovery method */
    qsysdb_discovery_method_t discovery;

    /* Static node list (for DISCOVERY_STATIC) */
    char **seed_nodes;              /* Array of "host:port" strings */
    int seed_node_count;

    /* Multicast settings (for DISCOVERY_MULTICAST) */
    char multicast_group[64];       /* Multicast group address */
    uint16_t multicast_port;        /* Multicast port */

    /* DNS settings (for DISCOVERY_DNS) */
    char dns_name[256];             /* DNS name for SRV lookup */

    /* Election timeouts (milliseconds) */
    int election_timeout_min;       /* Minimum election timeout (default: 150ms) */
    int election_timeout_max;       /* Maximum election timeout (default: 300ms) */
    int heartbeat_interval;         /* Leader heartbeat interval (default: 50ms) */
    int node_timeout;               /* Node considered dead after this (default: 1000ms) */

    /* Replication settings */
    int max_entries_per_append;     /* Max entries per AppendEntries RPC (default: 100) */
    int snapshot_threshold;         /* Entries before snapshot (default: 10000) */
} qsysdb_cluster_config_t;

/*
 * Forward declarations
 */
typedef struct qsysdb_cluster qsysdb_cluster_t;
typedef struct qsysdb_election qsysdb_election_t;
typedef struct qsysdb_replication qsysdb_replication_t;

/*
 * Callback function types
 */
typedef void (*qsysdb_leader_change_fn)(qsysdb_cluster_t *cluster,
                                        uint32_t new_leader_id,
                                        void *userdata);
typedef void (*qsysdb_node_change_fn)(qsysdb_cluster_t *cluster,
                                      qsysdb_node_t *node,
                                      bool joined,
                                      void *userdata);

/*
 * Cluster handle structure
 */
struct qsysdb_cluster {
    qsysdb_cluster_config_t config;

    /* Node management */
    qsysdb_node_t *nodes;
    int node_count;
    int node_capacity;
    pthread_rwlock_t nodes_lock;

    /* Current state */
    qsysdb_node_state_t state;
    uint32_t current_leader;
    uint64_t current_term;

    /* Election state */
    qsysdb_election_t *election;

    /* Replication state */
    qsysdb_replication_t *replication;

    /* Networking */
    int cluster_socket;             /* UDP socket for cluster communication */
    int cluster_tcp_socket;         /* TCP socket for replication */
    int epoll_fd;
    struct epoll_event *events;
    int max_events;

    /* Threading */
    pthread_t cluster_thread;
    pthread_t heartbeat_thread;
    bool running;
    pthread_mutex_t state_lock;
    pthread_cond_t state_cond;

    /* Callbacks */
    qsysdb_leader_change_fn on_leader_change;
    void *leader_change_userdata;
    qsysdb_node_change_fn on_node_change;
    void *node_change_userdata;

    /* Reference to database */
    void *db;                       /* qsysdb_t* - opaque to avoid circular deps */
    void *server;                   /* server_t* - for write forwarding */

    /* Statistics */
    uint64_t elections_started;
    uint64_t elections_won;
    uint64_t elections_lost;
    uint64_t heartbeats_sent;
    uint64_t heartbeats_received;
    uint64_t entries_replicated;
};

/*
 * Cluster lifecycle functions
 */

/**
 * Create a new cluster instance
 * @param config Cluster configuration
 * @return New cluster handle, or NULL on error
 */
qsysdb_cluster_t *qsysdb_cluster_create(qsysdb_cluster_config_t *config);

/**
 * Destroy a cluster instance
 * @param cluster Cluster handle
 */
void qsysdb_cluster_destroy(qsysdb_cluster_t *cluster);

/**
 * Start cluster operations (discovery, election, replication)
 * @param cluster Cluster handle
 * @return 0 on success, negative error code on failure
 */
int qsysdb_cluster_start(qsysdb_cluster_t *cluster);

/**
 * Stop cluster operations
 * @param cluster Cluster handle
 * @return 0 on success, negative error code on failure
 */
int qsysdb_cluster_stop(qsysdb_cluster_t *cluster);

/*
 * Cluster state query functions
 */

/**
 * Check if this node is the leader
 * @param cluster Cluster handle
 * @return true if leader, false otherwise
 */
bool qsysdb_cluster_is_leader(qsysdb_cluster_t *cluster);

/**
 * Get current leader node
 * @param cluster Cluster handle
 * @return Pointer to leader node info, or NULL if no leader
 */
qsysdb_node_t *qsysdb_cluster_get_leader(qsysdb_cluster_t *cluster);

/**
 * Get all known nodes in the cluster
 * @param cluster Cluster handle
 * @param nodes Output array of nodes (caller must free)
 * @param count Output number of nodes
 * @return 0 on success, negative error code on failure
 */
int qsysdb_cluster_get_nodes(qsysdb_cluster_t *cluster,
                             qsysdb_node_t **nodes, int *count);

/**
 * Get this node's ID
 * @param cluster Cluster handle
 * @return Node ID
 */
uint32_t qsysdb_cluster_get_node_id(qsysdb_cluster_t *cluster);

/**
 * Get current term
 * @param cluster Cluster handle
 * @return Current election term
 */
uint64_t qsysdb_cluster_get_term(qsysdb_cluster_t *cluster);

/**
 * Get cluster state
 * @param cluster Cluster handle
 * @return Current node state (follower/candidate/leader)
 */
qsysdb_node_state_t qsysdb_cluster_get_state(qsysdb_cluster_t *cluster);

/*
 * Cluster callback registration
 */

/**
 * Register callback for leader changes
 * @param cluster Cluster handle
 * @param callback Function to call on leader change
 * @param userdata User data passed to callback
 */
void qsysdb_cluster_on_leader_change(qsysdb_cluster_t *cluster,
                                     qsysdb_leader_change_fn callback,
                                     void *userdata);

/**
 * Register callback for node membership changes
 * @param cluster Cluster handle
 * @param callback Function to call on node join/leave
 * @param userdata User data passed to callback
 */
void qsysdb_cluster_on_node_change(qsysdb_cluster_t *cluster,
                                   qsysdb_node_change_fn callback,
                                   void *userdata);

/*
 * Cluster operations
 */

/**
 * Forward a write operation to the leader
 * @param cluster Cluster handle
 * @param msg_type Message type (SET, DELETE, etc.)
 * @param data Request data
 * @param data_len Request data length
 * @param response Output response buffer
 * @param response_len Output response length
 * @return 0 on success, negative error code on failure
 */
int qsysdb_cluster_forward_write(qsysdb_cluster_t *cluster,
                                 uint32_t msg_type,
                                 const void *data, size_t data_len,
                                 void **response, size_t *response_len);

/**
 * Add a node to the cluster
 * @param cluster Cluster handle
 * @param address Node address
 * @param client_port Client port
 * @param cluster_port Cluster port
 * @return Node ID on success, negative error code on failure
 */
int qsysdb_cluster_add_node(qsysdb_cluster_t *cluster,
                            const char *address,
                            uint16_t client_port,
                            uint16_t cluster_port);

/**
 * Remove a node from the cluster
 * @param cluster Cluster handle
 * @param node_id Node ID to remove
 * @return 0 on success, negative error code on failure
 */
int qsysdb_cluster_remove_node(qsysdb_cluster_t *cluster, uint32_t node_id);

/*
 * Internal functions (used by election and replication)
 */

/**
 * Send a cluster message to a specific node
 */
int qsysdb_cluster_send(qsysdb_cluster_t *cluster, uint32_t node_id,
                        const void *data, size_t len);

/**
 * Broadcast a message to all nodes
 */
int qsysdb_cluster_broadcast(qsysdb_cluster_t *cluster,
                             const void *data, size_t len);

/**
 * Get current time in milliseconds
 */
uint64_t qsysdb_cluster_time_ms(void);

/**
 * Initialize cluster configuration with defaults
 */
void qsysdb_cluster_config_init(qsysdb_cluster_config_t *config);

#endif /* QSYSDB_CLUSTER_H */
