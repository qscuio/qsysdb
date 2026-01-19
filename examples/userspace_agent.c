/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * userspace_agent.c - Example userspace agent
 *
 * This example demonstrates how to build an agent that:
 * - Connects to QSysDB
 * - Publishes its own state
 * - Subscribes to changes from other agents
 * - Reacts to state changes
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

#include <qsysdb/qsysdb.h>

#define AGENT_NAME "example-agent"
#define AGENT_BASE_PATH "/agents/" AGENT_NAME

static volatile int g_running = 1;
static qsysdb_t *g_db = NULL;

static void signal_handler(int sig)
{
    (void)sig;
    g_running = 0;
}

/*
 * Callback for configuration changes
 */
static void on_config_change(const char *path, const char *value,
                             int event_type, void *userdata)
{
    (void)userdata;

    const char *event_name;
    switch (event_type) {
    case QSYSDB_EVENT_CREATE: event_name = "created"; break;
    case QSYSDB_EVENT_UPDATE: event_name = "updated"; break;
    case QSYSDB_EVENT_DELETE: event_name = "deleted"; break;
    default: event_name = "changed"; break;
    }

    printf("[CONFIG] %s %s", path, event_name);
    if (value) {
        printf(": %s", value);
    }
    printf("\n");

    /* React to configuration changes */
    if (strstr(path, "/config/log_level") && value) {
        printf("  -> Log level changed, would update logging here\n");
    }
}

/*
 * Callback for watching other agents
 */
static void on_agent_change(const char *path, const char *value,
                            int event_type, void *userdata)
{
    (void)userdata;

    if (event_type == QSYSDB_EVENT_CREATE) {
        printf("[AGENTS] New agent appeared: %s\n", path);
    } else if (event_type == QSYSDB_EVENT_DELETE) {
        printf("[AGENTS] Agent disappeared: %s\n", path);
    } else if (strstr(path, "/status")) {
        printf("[AGENTS] Agent status update: %s = %s\n", path, value ? value : "(deleted)");
    }
}

/*
 * Publish agent status
 */
static int publish_status(qsysdb_t *db, const char *status)
{
    char path[256];
    char value[512];

    snprintf(path, sizeof(path), "%s/status", AGENT_BASE_PATH);
    snprintf(value, sizeof(value),
             "{\"state\":\"%s\",\"pid\":%d,\"timestamp\":%ld}",
             status, getpid(), time(NULL));

    int ret = qsysdb_set(db, path, value);
    if (ret != QSYSDB_OK) {
        fprintf(stderr, "Failed to publish status: %s\n", qsysdb_strerror(ret));
    }
    return ret;
}

/*
 * Publish agent metrics
 */
static int publish_metrics(qsysdb_t *db, int requests, int errors)
{
    char path[256];
    char value[512];

    snprintf(path, sizeof(path), "%s/metrics", AGENT_BASE_PATH);
    snprintf(value, sizeof(value),
             "{\"requests\":%d,\"errors\":%d,\"uptime\":%ld}",
             requests, errors, time(NULL));

    return qsysdb_set(db, path, value);
}

/*
 * Register agent in the database
 */
static int register_agent(qsysdb_t *db)
{
    char path[256];
    char value[512];

    /* Publish agent info */
    snprintf(path, sizeof(path), "%s/info", AGENT_BASE_PATH);
    snprintf(value, sizeof(value),
             "{\"name\":\"%s\",\"version\":\"1.0.0\",\"started\":%ld}",
             AGENT_NAME, time(NULL));

    int ret = qsysdb_set(db, path, value);
    if (ret != QSYSDB_OK) {
        return ret;
    }

    /* Publish initial status */
    ret = publish_status(db, "starting");
    if (ret != QSYSDB_OK) {
        return ret;
    }

    return QSYSDB_OK;
}

/*
 * Unregister agent (cleanup)
 */
static void unregister_agent(qsysdb_t *db)
{
    publish_status(db, "stopping");

    /* Optionally delete our entire subtree */
    /* qsysdb_delete_tree(db, AGENT_BASE_PATH, NULL); */
}

int main(int argc, char *argv[])
{
    int ret;
    int sub_config, sub_agents;
    int requests = 0, errors = 0;

    (void)argc;
    (void)argv;

    printf("QSysDB Example Agent\n");
    printf("====================\n\n");

    /* Setup signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Connect to QSysDB */
    printf("Connecting to QSysDB...\n");
    g_db = qsysdb_connect(NULL, QSYSDB_CONN_SHM);
    if (!g_db) {
        fprintf(stderr, "Failed to connect to QSysDB\n");
        return 1;
    }
    printf("Connected!\n\n");

    /* Register this agent */
    printf("Registering agent...\n");
    ret = register_agent(g_db);
    if (ret != QSYSDB_OK) {
        fprintf(stderr, "Failed to register: %s\n", qsysdb_strerror(ret));
        qsysdb_disconnect(g_db);
        return 1;
    }

    /* Subscribe to configuration changes */
    printf("Subscribing to /config/*...\n");
    sub_config = qsysdb_subscribe(g_db, "/config/*", on_config_change, NULL);
    if (sub_config < 0) {
        fprintf(stderr, "Warning: failed to subscribe to config: %s\n",
                qsysdb_strerror(sub_config));
    }

    /* Subscribe to other agents' status */
    printf("Subscribing to /agents/*...\n");
    sub_agents = qsysdb_subscribe(g_db, "/agents/*", on_agent_change, NULL);
    if (sub_agents < 0) {
        fprintf(stderr, "Warning: failed to subscribe to agents: %s\n",
                qsysdb_strerror(sub_agents));
    }

    /* Mark as running */
    publish_status(g_db, "running");

    printf("\nAgent running. Press Ctrl+C to stop.\n");
    printf("Try: qsysdb-cli set /config/log_level '\"debug\"'\n\n");

    /* Main loop */
    while (g_running) {
        /* Poll for notifications */
        ret = qsysdb_poll(g_db, 1000);  /* 1 second timeout */
        if (ret < 0 && ret != QSYSDB_ERR_AGAIN) {
            fprintf(stderr, "Poll error: %s\n", qsysdb_strerror(ret));
            errors++;
        }

        /* Simulate some work */
        requests++;

        /* Periodically publish metrics */
        if (requests % 10 == 0) {
            publish_metrics(g_db, requests, errors);
        }
    }

    printf("\nShutting down...\n");

    /* Cleanup */
    if (sub_config > 0) {
        qsysdb_unsubscribe(g_db, sub_config);
    }
    if (sub_agents > 0) {
        qsysdb_unsubscribe(g_db, sub_agents);
    }

    unregister_agent(g_db);
    qsysdb_disconnect(g_db);

    printf("Agent stopped.\n");
    return 0;
}
