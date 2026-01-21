/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * cluster.c - Cluster manager implementation
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#include <qsysdb/cluster.h>
#include <qsysdb/election.h>
#include <qsysdb/replication.h>
#include <qsysdb/cluster_protocol.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

/*
 * Internal constants
 */
#define CLUSTER_MAX_EVENTS      64
#define CLUSTER_RECV_BUFFER     65536
#define CLUSTER_TICK_INTERVAL   10  /* ms */

/*
 * Logging macros
 */
#define CLUSTER_LOG(fmt, ...) \
    fprintf(stderr, "[CLUSTER] " fmt "\n", ##__VA_ARGS__)
#define CLUSTER_DEBUG(fmt, ...) \
    fprintf(stderr, "[CLUSTER DEBUG] " fmt "\n", ##__VA_ARGS__)
#define CLUSTER_ERROR(fmt, ...) \
    fprintf(stderr, "[CLUSTER ERROR] " fmt "\n", ##__VA_ARGS__)

/*
 * Forward declarations
 */
static void *cluster_thread_main(void *arg);
static void *heartbeat_thread_main(void *arg);
static int cluster_setup_socket(qsysdb_cluster_t *cluster);
static int cluster_handle_message(qsysdb_cluster_t *cluster,
                                  const void *data, size_t len,
                                  struct sockaddr_in *from);
static int cluster_discover_nodes(qsysdb_cluster_t *cluster);
static qsysdb_node_t *cluster_find_node(qsysdb_cluster_t *cluster, uint32_t node_id);
static qsysdb_node_t *cluster_find_node_by_addr(qsysdb_cluster_t *cluster,
                                                const char *address, uint16_t port);

/*
 * Get current time in milliseconds
 */
uint64_t qsysdb_cluster_time_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/*
 * Initialize cluster configuration with defaults
 */
void qsysdb_cluster_config_init(qsysdb_cluster_config_t *config)
{
    memset(config, 0, sizeof(*config));
    config->node_id = 0;  /* Auto-generate */
    strcpy(config->bind_address, "0.0.0.0");
    config->client_port = QSYSDB_TCP_PORT_DEFAULT;
    config->cluster_port = QSYSDB_CLUSTER_PORT_DEFAULT;
    config->discovery = QSYSDB_DISCOVERY_STATIC;
    strcpy(config->multicast_group, QSYSDB_CLUSTER_MULTICAST_GROUP);
    config->multicast_port = QSYSDB_CLUSTER_MULTICAST_PORT;
    config->election_timeout_min = QSYSDB_ELECTION_TIMEOUT_MIN;
    config->election_timeout_max = QSYSDB_ELECTION_TIMEOUT_MAX;
    config->heartbeat_interval = QSYSDB_HEARTBEAT_INTERVAL;
    config->node_timeout = QSYSDB_NODE_TIMEOUT;
    config->max_entries_per_append = QSYSDB_REPL_MAX_ENTRIES;
    config->snapshot_threshold = 10000;
}

/*
 * Generate a node ID based on address and port
 */
static uint32_t cluster_generate_node_id(const char *address, uint16_t port)
{
    uint32_t hash = 5381;
    const char *p = address;
    while (*p) {
        hash = ((hash << 5) + hash) + *p++;
    }
    hash = ((hash << 5) + hash) + port;
    /* Ensure non-zero */
    return hash ? hash : 1;
}

/*
 * Create a new cluster instance
 */
qsysdb_cluster_t *qsysdb_cluster_create(qsysdb_cluster_config_t *config)
{
    qsysdb_cluster_t *cluster;

    if (!config) {
        CLUSTER_ERROR("NULL config");
        return NULL;
    }

    cluster = calloc(1, sizeof(*cluster));
    if (!cluster) {
        CLUSTER_ERROR("Failed to allocate cluster");
        return NULL;
    }

    /* Copy configuration */
    memcpy(&cluster->config, config, sizeof(*config));

    /* Generate node ID if not provided */
    if (cluster->config.node_id == 0) {
        cluster->config.node_id = cluster_generate_node_id(
            cluster->config.bind_address, cluster->config.cluster_port);
    }

    /* Initialize node list */
    cluster->node_capacity = QSYSDB_CLUSTER_MAX_NODES;
    cluster->nodes = calloc(cluster->node_capacity, sizeof(qsysdb_node_t));
    if (!cluster->nodes) {
        CLUSTER_ERROR("Failed to allocate nodes array");
        free(cluster);
        return NULL;
    }

    /* Add self as first node */
    qsysdb_node_t *self = &cluster->nodes[0];
    self->node_id = cluster->config.node_id;
    snprintf(self->address, sizeof(self->address), "%s", cluster->config.bind_address);
    self->client_port = cluster->config.client_port;
    self->cluster_port = cluster->config.cluster_port;
    self->state = QSYSDB_NODE_FOLLOWER;
    self->is_self = true;
    self->is_alive = true;
    self->last_heartbeat = qsysdb_cluster_time_ms();
    cluster->node_count = 1;

    /* Initialize locks */
    pthread_rwlock_init(&cluster->nodes_lock, NULL);
    pthread_mutex_init(&cluster->state_lock, NULL);
    pthread_cond_init(&cluster->state_cond, NULL);

    /* Initialize state */
    cluster->state = QSYSDB_NODE_FOLLOWER;
    cluster->current_leader = 0;
    cluster->current_term = 0;
    cluster->running = false;

    /* Initialize sockets */
    cluster->cluster_socket = -1;
    cluster->cluster_tcp_socket = -1;
    cluster->epoll_fd = -1;

    /* Allocate epoll events */
    cluster->max_events = CLUSTER_MAX_EVENTS;
    cluster->events = calloc(cluster->max_events, sizeof(struct epoll_event));
    if (!cluster->events) {
        CLUSTER_ERROR("Failed to allocate epoll events");
        pthread_rwlock_destroy(&cluster->nodes_lock);
        pthread_mutex_destroy(&cluster->state_lock);
        pthread_cond_destroy(&cluster->state_cond);
        free(cluster->nodes);
        free(cluster);
        return NULL;
    }

    CLUSTER_LOG("Cluster created: node_id=%u, address=%s:%u",
                cluster->config.node_id,
                cluster->config.bind_address,
                cluster->config.cluster_port);

    return cluster;
}

/*
 * Destroy a cluster instance
 */
void qsysdb_cluster_destroy(qsysdb_cluster_t *cluster)
{
    if (!cluster)
        return;

    /* Stop if running */
    if (cluster->running) {
        qsysdb_cluster_stop(cluster);
    }

    /* Cleanup election */
    if (cluster->election) {
        qsysdb_election_cleanup(cluster);
    }

    /* Cleanup replication */
    if (cluster->replication) {
        qsysdb_replication_cleanup(cluster);
    }

    /* Close sockets */
    if (cluster->cluster_socket >= 0)
        close(cluster->cluster_socket);
    if (cluster->cluster_tcp_socket >= 0)
        close(cluster->cluster_tcp_socket);
    if (cluster->epoll_fd >= 0)
        close(cluster->epoll_fd);

    /* Free resources */
    pthread_rwlock_destroy(&cluster->nodes_lock);
    pthread_mutex_destroy(&cluster->state_lock);
    pthread_cond_destroy(&cluster->state_cond);
    free(cluster->events);
    free(cluster->nodes);
    free(cluster);

    CLUSTER_LOG("Cluster destroyed");
}

/*
 * Setup cluster UDP socket
 */
static int cluster_setup_socket(qsysdb_cluster_t *cluster)
{
    struct sockaddr_in addr;
    int opt = 1;

    /* Create UDP socket for cluster communication */
    cluster->cluster_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (cluster->cluster_socket < 0) {
        CLUSTER_ERROR("Failed to create cluster socket: %s", strerror(errno));
        return QSYSDB_ERR_IO;
    }

    /* Set socket options */
    setsockopt(cluster->cluster_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(cluster->cluster_socket, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    /* Make non-blocking */
    int flags = fcntl(cluster->cluster_socket, F_GETFL, 0);
    fcntl(cluster->cluster_socket, F_SETFL, flags | O_NONBLOCK);

    /* Bind to cluster port */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(cluster->config.cluster_port);
    if (inet_pton(AF_INET, cluster->config.bind_address, &addr.sin_addr) <= 0) {
        addr.sin_addr.s_addr = INADDR_ANY;
    }

    if (bind(cluster->cluster_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        CLUSTER_ERROR("Failed to bind cluster socket: %s", strerror(errno));
        close(cluster->cluster_socket);
        cluster->cluster_socket = -1;
        return QSYSDB_ERR_IO;
    }

    /* Setup multicast if using multicast discovery */
    if (cluster->config.discovery == QSYSDB_DISCOVERY_MULTICAST) {
        struct ip_mreq mreq;
        inet_pton(AF_INET, cluster->config.multicast_group, &mreq.imr_multiaddr);
        mreq.imr_interface.s_addr = INADDR_ANY;
        if (setsockopt(cluster->cluster_socket, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                       &mreq, sizeof(mreq)) < 0) {
            CLUSTER_ERROR("Failed to join multicast group: %s", strerror(errno));
        }
    }

    /* Create epoll instance */
    cluster->epoll_fd = epoll_create1(0);
    if (cluster->epoll_fd < 0) {
        CLUSTER_ERROR("Failed to create epoll: %s", strerror(errno));
        close(cluster->cluster_socket);
        cluster->cluster_socket = -1;
        return QSYSDB_ERR_IO;
    }

    /* Add cluster socket to epoll */
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = cluster->cluster_socket;
    if (epoll_ctl(cluster->epoll_fd, EPOLL_CTL_ADD, cluster->cluster_socket, &ev) < 0) {
        CLUSTER_ERROR("Failed to add socket to epoll: %s", strerror(errno));
        close(cluster->epoll_fd);
        close(cluster->cluster_socket);
        cluster->epoll_fd = -1;
        cluster->cluster_socket = -1;
        return QSYSDB_ERR_IO;
    }

    CLUSTER_LOG("Cluster socket bound to port %u", cluster->config.cluster_port);
    return QSYSDB_OK;
}

/*
 * Start cluster operations
 */
int qsysdb_cluster_start(qsysdb_cluster_t *cluster)
{
    int ret;

    if (!cluster)
        return QSYSDB_ERR_INVALID;

    if (cluster->running) {
        CLUSTER_LOG("Cluster already running");
        return QSYSDB_OK;
    }

    /* Setup sockets */
    ret = cluster_setup_socket(cluster);
    if (ret != QSYSDB_OK)
        return ret;

    /* Initialize election manager */
    ret = qsysdb_election_init(cluster);
    if (ret != QSYSDB_OK) {
        CLUSTER_ERROR("Failed to initialize election manager");
        return ret;
    }

    /* Initialize replication manager */
    ret = qsysdb_replication_init(cluster);
    if (ret != QSYSDB_OK) {
        CLUSTER_ERROR("Failed to initialize replication manager");
        qsysdb_election_cleanup(cluster);
        return ret;
    }

    /* Discover initial nodes */
    cluster_discover_nodes(cluster);

    /* Start cluster thread */
    cluster->running = true;
    ret = pthread_create(&cluster->cluster_thread, NULL, cluster_thread_main, cluster);
    if (ret != 0) {
        CLUSTER_ERROR("Failed to create cluster thread: %s", strerror(ret));
        cluster->running = false;
        qsysdb_replication_cleanup(cluster);
        qsysdb_election_cleanup(cluster);
        return QSYSDB_ERR_INTERNAL;
    }

    /* Start heartbeat thread */
    ret = pthread_create(&cluster->heartbeat_thread, NULL, heartbeat_thread_main, cluster);
    if (ret != 0) {
        CLUSTER_ERROR("Failed to create heartbeat thread: %s", strerror(ret));
        cluster->running = false;
        pthread_join(cluster->cluster_thread, NULL);
        qsysdb_replication_cleanup(cluster);
        qsysdb_election_cleanup(cluster);
        return QSYSDB_ERR_INTERNAL;
    }

    /* Start replication */
    ret = qsysdb_replication_start(cluster);
    if (ret != QSYSDB_OK) {
        CLUSTER_ERROR("Failed to start replication");
        cluster->running = false;
        pthread_join(cluster->cluster_thread, NULL);
        pthread_join(cluster->heartbeat_thread, NULL);
        qsysdb_replication_cleanup(cluster);
        qsysdb_election_cleanup(cluster);
        return ret;
    }

    CLUSTER_LOG("Cluster started");
    return QSYSDB_OK;
}

/*
 * Stop cluster operations
 */
int qsysdb_cluster_stop(qsysdb_cluster_t *cluster)
{
    if (!cluster || !cluster->running)
        return QSYSDB_OK;

    CLUSTER_LOG("Stopping cluster...");

    /* Signal threads to stop */
    cluster->running = false;
    pthread_cond_broadcast(&cluster->state_cond);

    /* Stop replication */
    qsysdb_replication_stop(cluster);

    /* Wait for threads */
    pthread_join(cluster->cluster_thread, NULL);
    pthread_join(cluster->heartbeat_thread, NULL);

    CLUSTER_LOG("Cluster stopped");
    return QSYSDB_OK;
}

/*
 * Discover nodes based on configured discovery method
 */
static int cluster_discover_nodes(qsysdb_cluster_t *cluster)
{
    switch (cluster->config.discovery) {
    case QSYSDB_DISCOVERY_STATIC:
        /* Add seed nodes */
        for (int i = 0; i < cluster->config.seed_node_count; i++) {
            char *node_spec = cluster->config.seed_nodes[i];
            char address[256];
            uint16_t port = QSYSDB_CLUSTER_PORT_DEFAULT;

            /* Parse host:port */
            char *colon = strchr(node_spec, ':');
            if (colon) {
                size_t addr_len = colon - node_spec;
                if (addr_len >= sizeof(address))
                    addr_len = sizeof(address) - 1;
                strncpy(address, node_spec, addr_len);
                address[addr_len] = '\0';
                port = atoi(colon + 1);
            } else {
                strncpy(address, node_spec, sizeof(address) - 1);
                address[sizeof(address) - 1] = '\0';
            }

            qsysdb_cluster_add_node(cluster, address,
                                    cluster->config.client_port, port);
        }
        break;

    case QSYSDB_DISCOVERY_MULTICAST:
        /* Send discovery message */
        {
            qsysdb_msg_discover_t msg;
            qsysdb_cluster_msg_init(&msg.header, CLUSTER_MSG_DISCOVER,
                                    cluster->config.node_id,
                                    cluster->current_term,
                                    sizeof(msg) - sizeof(msg.header));
            msg.client_port = cluster->config.client_port;
            msg.cluster_port = cluster->config.cluster_port;
            snprintf(msg.address, sizeof(msg.address), "%s", cluster->config.bind_address);
            msg.header.timestamp = qsysdb_cluster_time_ms();

            struct sockaddr_in mcast_addr;
            memset(&mcast_addr, 0, sizeof(mcast_addr));
            mcast_addr.sin_family = AF_INET;
            mcast_addr.sin_port = htons(cluster->config.multicast_port);
            inet_pton(AF_INET, cluster->config.multicast_group, &mcast_addr.sin_addr);

            sendto(cluster->cluster_socket, &msg, sizeof(msg), 0,
                   (struct sockaddr *)&mcast_addr, sizeof(mcast_addr));

            CLUSTER_LOG("Sent discovery message to multicast group");
        }
        break;

    case QSYSDB_DISCOVERY_DNS:
        /* DNS SRV lookup - not implemented in this version */
        CLUSTER_LOG("DNS discovery not yet implemented");
        break;
    }

    return QSYSDB_OK;
}

/*
 * Main cluster thread
 */
static void *cluster_thread_main(void *arg)
{
    qsysdb_cluster_t *cluster = arg;
    char recv_buf[CLUSTER_RECV_BUFFER];

    CLUSTER_LOG("Cluster thread started");

    while (cluster->running) {
        int nfds = epoll_wait(cluster->epoll_fd, cluster->events,
                              cluster->max_events, CLUSTER_TICK_INTERVAL);

        if (nfds < 0) {
            if (errno == EINTR)
                continue;
            CLUSTER_ERROR("epoll_wait failed: %s", strerror(errno));
            break;
        }

        /* Process incoming messages */
        for (int i = 0; i < nfds; i++) {
            if (cluster->events[i].data.fd == cluster->cluster_socket) {
                struct sockaddr_in from;
                socklen_t from_len = sizeof(from);

                ssize_t len = recvfrom(cluster->cluster_socket, recv_buf,
                                       sizeof(recv_buf), 0,
                                       (struct sockaddr *)&from, &from_len);

                if (len > 0) {
                    cluster_handle_message(cluster, recv_buf, len, &from);
                }
            }
        }

        /* Run election tick */
        qsysdb_election_tick(cluster);

        /* Check node health */
        uint64_t now = qsysdb_cluster_time_ms();
        pthread_rwlock_wrlock(&cluster->nodes_lock);
        for (int i = 0; i < cluster->node_count; i++) {
            qsysdb_node_t *node = &cluster->nodes[i];
            if (!node->is_self && node->is_alive) {
                if (now - node->last_heartbeat > (uint64_t)cluster->config.node_timeout) {
                    CLUSTER_LOG("Node %u timed out", node->node_id);
                    node->is_alive = false;
                    if (cluster->on_node_change) {
                        cluster->on_node_change(cluster, node, false,
                                                cluster->node_change_userdata);
                    }
                }
            }
        }
        pthread_rwlock_unlock(&cluster->nodes_lock);
    }

    CLUSTER_LOG("Cluster thread exiting");
    return NULL;
}

/*
 * Heartbeat thread - sends periodic heartbeats when leader
 */
static void *heartbeat_thread_main(void *arg)
{
    qsysdb_cluster_t *cluster = arg;

    CLUSTER_LOG("Heartbeat thread started");

    while (cluster->running) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += cluster->config.heartbeat_interval * 1000000;
        if (ts.tv_nsec >= 1000000000) {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000;
        }

        pthread_mutex_lock(&cluster->state_lock);
        pthread_cond_timedwait(&cluster->state_cond, &cluster->state_lock, &ts);
        pthread_mutex_unlock(&cluster->state_lock);

        if (!cluster->running)
            break;

        /* Send heartbeats if we are the leader */
        if (cluster->state == QSYSDB_NODE_LEADER) {
            qsysdb_msg_heartbeat_t msg;
            qsysdb_cluster_msg_init(&msg.header, CLUSTER_MSG_HEARTBEAT,
                                    cluster->config.node_id,
                                    cluster->current_term,
                                    sizeof(msg) - sizeof(msg.header));
            msg.leader_id = cluster->config.node_id;
            msg.commit_index = cluster->replication ?
                qsysdb_replication_commit_index(cluster) : 0;
            msg.leader_client_port = cluster->config.client_port;
            msg.leader_cluster_port = cluster->config.cluster_port;
            snprintf(msg.leader_address, sizeof(msg.leader_address), "%s",
                     cluster->config.bind_address);
            msg.header.timestamp = qsysdb_cluster_time_ms();

            /* Count active nodes */
            pthread_rwlock_rdlock(&cluster->nodes_lock);
            msg.node_count = 0;
            for (int i = 0; i < cluster->node_count; i++) {
                if (cluster->nodes[i].is_alive)
                    msg.node_count++;
            }
            pthread_rwlock_unlock(&cluster->nodes_lock);

            qsysdb_cluster_broadcast(cluster, &msg, sizeof(msg));
            cluster->heartbeats_sent++;
        }
    }

    CLUSTER_LOG("Heartbeat thread exiting");
    return NULL;
}

/*
 * Handle incoming cluster message
 */
static int cluster_handle_message(qsysdb_cluster_t *cluster,
                                  const void *data, size_t len,
                                  struct sockaddr_in *from)
{
    const qsysdb_cluster_header_t *hdr = data;

    /* Validate header */
    if (qsysdb_cluster_msg_validate(hdr, len) != QSYSDB_OK) {
        CLUSTER_DEBUG("Invalid message from %s:%u",
                      inet_ntoa(from->sin_addr), ntohs(from->sin_port));
        return QSYSDB_ERR_PROTO;
    }

    /* Ignore messages from self */
    if (hdr->sender_id == cluster->config.node_id)
        return QSYSDB_OK;

    /* Update node's last heartbeat time */
    pthread_rwlock_wrlock(&cluster->nodes_lock);
    qsysdb_node_t *sender = cluster_find_node(cluster, hdr->sender_id);
    if (sender) {
        sender->last_heartbeat = qsysdb_cluster_time_ms();
        if (!sender->is_alive) {
            sender->is_alive = true;
            CLUSTER_LOG("Node %u is back online", sender->node_id);
            if (cluster->on_node_change) {
                cluster->on_node_change(cluster, sender, true,
                                        cluster->node_change_userdata);
            }
        }
    }
    pthread_rwlock_unlock(&cluster->nodes_lock);

    /* Handle message based on type */
    switch (hdr->msg_type) {
    case CLUSTER_MSG_REQUEST_VOTE:
        {
            const qsysdb_msg_request_vote_t *req = data;
            bool vote_granted = false;
            qsysdb_election_handle_vote_request(cluster, hdr->sender_id, hdr->term,
                                                req->last_log_index, req->last_log_term,
                                                &vote_granted);

            /* Send response */
            qsysdb_msg_vote_response_t resp;
            qsysdb_cluster_msg_init(&resp.header, CLUSTER_MSG_VOTE_RESPONSE,
                                    cluster->config.node_id,
                                    cluster->current_term,
                                    sizeof(resp) - sizeof(resp.header));
            resp.vote_granted = vote_granted ? 1 : 0;
            resp.header.timestamp = qsysdb_cluster_time_ms();
            qsysdb_cluster_send(cluster, hdr->sender_id, &resp, sizeof(resp));
        }
        break;

    case CLUSTER_MSG_VOTE_RESPONSE:
        {
            const qsysdb_msg_vote_response_t *resp = data;
            qsysdb_election_handle_vote_response(cluster, hdr->sender_id, hdr->term,
                                                 resp->vote_granted != 0);
        }
        break;

    case CLUSTER_MSG_HEARTBEAT:
        {
            const qsysdb_msg_heartbeat_t *hb = data;
            qsysdb_election_handle_heartbeat(cluster, hb->leader_id, hdr->term);
            cluster->heartbeats_received++;

            /* Send acknowledgment */
            qsysdb_msg_heartbeat_ack_t ack;
            qsysdb_cluster_msg_init(&ack.header, CLUSTER_MSG_HEARTBEAT_ACK,
                                    cluster->config.node_id,
                                    cluster->current_term,
                                    sizeof(ack) - sizeof(ack.header));
            ack.last_log_index = cluster->replication ?
                qsysdb_replication_last_index(cluster) : 0;
            ack.last_applied = cluster->replication ?
                cluster->replication->last_applied : 0;
            ack.header.timestamp = qsysdb_cluster_time_ms();
            qsysdb_cluster_send(cluster, hdr->sender_id, &ack, sizeof(ack));
        }
        break;

    case CLUSTER_MSG_HEARTBEAT_ACK:
        /* Leader processes acks for tracking follower state */
        break;

    case CLUSTER_MSG_APPEND_ENTRIES:
        {
            const qsysdb_msg_append_entries_t *ae = data;
            bool success = false;
            uint64_t match_index = 0;

            /* Parse entries from message */
            qsysdb_repl_entry_t *entries = NULL;
            int entry_count = ae->entry_count;

            if (entry_count > 0) {
                entries = calloc(entry_count, sizeof(qsysdb_repl_entry_t));
                if (entries) {
                    const char *entry_data = (const char *)(ae + 1);
                    for (int i = 0; i < entry_count; i++) {
                        const qsysdb_wire_entry_t *we = (const qsysdb_wire_entry_t *)entry_data;
                        entries[i].index = we->index;
                        entries[i].term = we->term;
                        entries[i].op_type = we->op_type;
                        entries[i].flags = we->flags;
                        entries[i].path_len = we->path_len;
                        entries[i].value_len = we->value_len;
                        entries[i].path = strndup(we->data, we->path_len);
                        if (we->value_len > 0) {
                            entries[i].value = strndup(we->data + we->path_len, we->value_len);
                        }
                        entry_data += sizeof(qsysdb_wire_entry_t) + we->path_len + we->value_len;
                    }
                }
            }

            qsysdb_replication_handle_append(cluster, ae->leader_id, hdr->term,
                                             ae->prev_log_index, ae->prev_log_term,
                                             entries, entry_count,
                                             ae->leader_commit,
                                             &success, &match_index);

            /* Free entries */
            if (entries) {
                for (int i = 0; i < entry_count; i++) {
                    free(entries[i].path);
                    free(entries[i].value);
                }
                free(entries);
            }

            /* Send response */
            qsysdb_msg_append_response_t resp;
            qsysdb_cluster_msg_init(&resp.header, CLUSTER_MSG_APPEND_RESPONSE,
                                    cluster->config.node_id,
                                    cluster->current_term,
                                    sizeof(resp) - sizeof(resp.header));
            resp.success = success ? 1 : 0;
            resp.match_index = match_index;
            resp.last_log_index = qsysdb_replication_last_index(cluster);
            resp.header.timestamp = qsysdb_cluster_time_ms();
            qsysdb_cluster_send(cluster, hdr->sender_id, &resp, sizeof(resp));
        }
        break;

    case CLUSTER_MSG_APPEND_RESPONSE:
        {
            const qsysdb_msg_append_response_t *resp = data;
            qsysdb_replication_handle_append_response(cluster, hdr->sender_id, hdr->term,
                                                      resp->success != 0, resp->match_index);
        }
        break;

    case CLUSTER_MSG_DISCOVER:
        {
            const qsysdb_msg_discover_t *disc = data;
            /* Add discovered node */
            qsysdb_cluster_add_node(cluster, disc->address,
                                    disc->client_port, disc->cluster_port);

            /* Send announcement back */
            qsysdb_msg_announce_t ann;
            qsysdb_cluster_msg_init(&ann.header, CLUSTER_MSG_ANNOUNCE,
                                    cluster->config.node_id,
                                    cluster->current_term,
                                    sizeof(ann) - sizeof(ann.header));
            ann.node_id = cluster->config.node_id;
            ann.leader_id = cluster->current_leader;
            ann.client_port = cluster->config.client_port;
            ann.cluster_port = cluster->config.cluster_port;
            ann.node_state = cluster->state;
            ann.last_log_index = cluster->replication ?
                qsysdb_replication_last_index(cluster) : 0;
            snprintf(ann.address, sizeof(ann.address), "%s", cluster->config.bind_address);
            ann.header.timestamp = qsysdb_cluster_time_ms();
            qsysdb_cluster_send(cluster, hdr->sender_id, &ann, sizeof(ann));
        }
        break;

    case CLUSTER_MSG_ANNOUNCE:
        {
            const qsysdb_msg_announce_t *ann = data;
            qsysdb_cluster_add_node(cluster, ann->address,
                                    ann->client_port, ann->cluster_port);
        }
        break;

    case CLUSTER_MSG_FORWARD_WRITE:
        /* Handle forwarded write from follower - only leader processes these */
        if (cluster->state == QSYSDB_NODE_LEADER) {
            /* Forward to server for processing */
            /* The server will call back with the result */
        }
        break;

    default:
        CLUSTER_DEBUG("Unknown message type: %d", hdr->msg_type);
        break;
    }

    return QSYSDB_OK;
}

/*
 * Find a node by ID
 */
static qsysdb_node_t *cluster_find_node(qsysdb_cluster_t *cluster, uint32_t node_id)
{
    for (int i = 0; i < cluster->node_count; i++) {
        if (cluster->nodes[i].node_id == node_id)
            return &cluster->nodes[i];
    }
    return NULL;
}

/*
 * Find a node by address and port
 */
static qsysdb_node_t *cluster_find_node_by_addr(qsysdb_cluster_t *cluster,
                                                const char *address, uint16_t port)
{
    for (int i = 0; i < cluster->node_count; i++) {
        if (strcmp(cluster->nodes[i].address, address) == 0 &&
            cluster->nodes[i].cluster_port == port)
            return &cluster->nodes[i];
    }
    return NULL;
}

/*
 * Send a message to a specific node
 */
int qsysdb_cluster_send(qsysdb_cluster_t *cluster, uint32_t node_id,
                        const void *data, size_t len)
{
    pthread_rwlock_rdlock(&cluster->nodes_lock);
    qsysdb_node_t *node = cluster_find_node(cluster, node_id);
    if (!node) {
        pthread_rwlock_unlock(&cluster->nodes_lock);
        return QSYSDB_ERR_NOTFOUND;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(node->cluster_port);
    inet_pton(AF_INET, node->address, &addr.sin_addr);

    pthread_rwlock_unlock(&cluster->nodes_lock);

    ssize_t sent = sendto(cluster->cluster_socket, data, len, 0,
                          (struct sockaddr *)&addr, sizeof(addr));

    if (sent < 0) {
        CLUSTER_DEBUG("Failed to send to node %u: %s", node_id, strerror(errno));
        return QSYSDB_ERR_IO;
    }

    return QSYSDB_OK;
}

/*
 * Broadcast a message to all nodes
 */
int qsysdb_cluster_broadcast(qsysdb_cluster_t *cluster, const void *data, size_t len)
{
    pthread_rwlock_rdlock(&cluster->nodes_lock);

    for (int i = 0; i < cluster->node_count; i++) {
        qsysdb_node_t *node = &cluster->nodes[i];
        if (node->is_self || !node->is_alive)
            continue;

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(node->cluster_port);
        inet_pton(AF_INET, node->address, &addr.sin_addr);

        sendto(cluster->cluster_socket, data, len, 0,
               (struct sockaddr *)&addr, sizeof(addr));
    }

    pthread_rwlock_unlock(&cluster->nodes_lock);
    return QSYSDB_OK;
}

/*
 * State query functions
 */

bool qsysdb_cluster_is_leader(qsysdb_cluster_t *cluster)
{
    if (!cluster)
        return false;
    return cluster->state == QSYSDB_NODE_LEADER;
}

qsysdb_node_t *qsysdb_cluster_get_leader(qsysdb_cluster_t *cluster)
{
    if (!cluster || cluster->current_leader == 0)
        return NULL;

    pthread_rwlock_rdlock(&cluster->nodes_lock);
    qsysdb_node_t *leader = cluster_find_node(cluster, cluster->current_leader);
    pthread_rwlock_unlock(&cluster->nodes_lock);

    return leader;
}

int qsysdb_cluster_get_nodes(qsysdb_cluster_t *cluster,
                             qsysdb_node_t **nodes, int *count)
{
    if (!cluster || !nodes || !count)
        return QSYSDB_ERR_INVALID;

    pthread_rwlock_rdlock(&cluster->nodes_lock);

    *count = cluster->node_count;
    *nodes = calloc(cluster->node_count, sizeof(qsysdb_node_t));
    if (!*nodes) {
        pthread_rwlock_unlock(&cluster->nodes_lock);
        return QSYSDB_ERR_NOMEM;
    }

    memcpy(*nodes, cluster->nodes, cluster->node_count * sizeof(qsysdb_node_t));
    pthread_rwlock_unlock(&cluster->nodes_lock);

    return QSYSDB_OK;
}

uint32_t qsysdb_cluster_get_node_id(qsysdb_cluster_t *cluster)
{
    return cluster ? cluster->config.node_id : 0;
}

uint64_t qsysdb_cluster_get_term(qsysdb_cluster_t *cluster)
{
    return cluster ? cluster->current_term : 0;
}

qsysdb_node_state_t qsysdb_cluster_get_state(qsysdb_cluster_t *cluster)
{
    return cluster ? cluster->state : QSYSDB_NODE_FOLLOWER;
}

/*
 * Callback registration
 */

void qsysdb_cluster_on_leader_change(qsysdb_cluster_t *cluster,
                                     qsysdb_leader_change_fn callback,
                                     void *userdata)
{
    if (!cluster)
        return;
    cluster->on_leader_change = callback;
    cluster->leader_change_userdata = userdata;
}

void qsysdb_cluster_on_node_change(qsysdb_cluster_t *cluster,
                                   qsysdb_node_change_fn callback,
                                   void *userdata)
{
    if (!cluster)
        return;
    cluster->on_node_change = callback;
    cluster->node_change_userdata = userdata;
}

/*
 * Add a node to the cluster
 */
int qsysdb_cluster_add_node(qsysdb_cluster_t *cluster,
                            const char *address,
                            uint16_t client_port,
                            uint16_t cluster_port)
{
    if (!cluster || !address)
        return QSYSDB_ERR_INVALID;

    pthread_rwlock_wrlock(&cluster->nodes_lock);

    /* Check if node already exists */
    qsysdb_node_t *existing = cluster_find_node_by_addr(cluster, address, cluster_port);
    if (existing) {
        pthread_rwlock_unlock(&cluster->nodes_lock);
        return existing->node_id;
    }

    /* Check capacity */
    if (cluster->node_count >= cluster->node_capacity) {
        pthread_rwlock_unlock(&cluster->nodes_lock);
        CLUSTER_ERROR("Node capacity reached");
        return QSYSDB_ERR_FULL;
    }

    /* Add new node */
    qsysdb_node_t *node = &cluster->nodes[cluster->node_count];
    node->node_id = cluster_generate_node_id(address, cluster_port);
    strncpy(node->address, address, sizeof(node->address) - 1);
    node->client_port = client_port;
    node->cluster_port = cluster_port;
    node->state = QSYSDB_NODE_FOLLOWER;
    node->last_heartbeat = qsysdb_cluster_time_ms();
    node->is_self = false;
    node->is_alive = true;
    cluster->node_count++;

    CLUSTER_LOG("Added node %u at %s:%u", node->node_id, address, cluster_port);

    pthread_rwlock_unlock(&cluster->nodes_lock);

    /* Notify callback */
    if (cluster->on_node_change) {
        cluster->on_node_change(cluster, node, true, cluster->node_change_userdata);
    }

    return node->node_id;
}

/*
 * Remove a node from the cluster
 */
int qsysdb_cluster_remove_node(qsysdb_cluster_t *cluster, uint32_t node_id)
{
    if (!cluster)
        return QSYSDB_ERR_INVALID;

    pthread_rwlock_wrlock(&cluster->nodes_lock);

    int idx = -1;
    for (int i = 0; i < cluster->node_count; i++) {
        if (cluster->nodes[i].node_id == node_id) {
            idx = i;
            break;
        }
    }

    if (idx < 0) {
        pthread_rwlock_unlock(&cluster->nodes_lock);
        return QSYSDB_ERR_NOTFOUND;
    }

    /* Don't allow removing self */
    if (cluster->nodes[idx].is_self) {
        pthread_rwlock_unlock(&cluster->nodes_lock);
        return QSYSDB_ERR_INVALID;
    }

    qsysdb_node_t removed = cluster->nodes[idx];

    /* Shift remaining nodes */
    for (int i = idx; i < cluster->node_count - 1; i++) {
        cluster->nodes[i] = cluster->nodes[i + 1];
    }
    cluster->node_count--;

    CLUSTER_LOG("Removed node %u", node_id);

    pthread_rwlock_unlock(&cluster->nodes_lock);

    /* Notify callback */
    if (cluster->on_node_change) {
        cluster->on_node_change(cluster, &removed, false, cluster->node_change_userdata);
    }

    return QSYSDB_OK;
}

/*
 * Forward a write operation to the leader
 */
int qsysdb_cluster_forward_write(qsysdb_cluster_t *cluster,
                                 uint32_t msg_type,
                                 const void *data, size_t data_len,
                                 void **response, size_t *response_len)
{
    if (!cluster || !data)
        return QSYSDB_ERR_INVALID;

    if (cluster->state == QSYSDB_NODE_LEADER) {
        /* We are the leader, no forwarding needed */
        return QSYSDB_ERR_INVALID;
    }

    if (cluster->current_leader == 0) {
        /* No leader known */
        return QSYSDB_ERR_BUSY;
    }

    /* Build forward message */
    size_t msg_size = sizeof(qsysdb_msg_forward_write_t) + data_len;
    qsysdb_msg_forward_write_t *msg = malloc(msg_size);
    if (!msg)
        return QSYSDB_ERR_NOMEM;

    qsysdb_cluster_msg_init(&msg->header, CLUSTER_MSG_FORWARD_WRITE,
                            cluster->config.node_id,
                            cluster->current_term,
                            msg_size - sizeof(msg->header));
    msg->client_request_id = 0;  /* Will be set by caller */
    msg->original_msg_type = msg_type;
    msg->payload_size = data_len;
    memcpy(msg->payload, data, data_len);
    msg->header.timestamp = qsysdb_cluster_time_ms();

    /* Send to leader */
    int ret = qsysdb_cluster_send(cluster, cluster->current_leader, msg, msg_size);
    free(msg);

    if (ret != QSYSDB_OK)
        return ret;

    /* For now, return immediately - response will come asynchronously */
    /* A production implementation would wait for the response */
    *response = NULL;
    *response_len = 0;

    return QSYSDB_OK;
}
