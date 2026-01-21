/*
 * QSysDB - Async Client Integration Example
 *
 * This example demonstrates how to integrate qsysdb async client
 * with your own event loop using epoll.
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>

#include <qsysdb/async.h>

static volatile int running = 1;

static void signal_handler(int sig)
{
    (void)sig;
    running = 0;
}

/*
 * Callback for async get operations
 */
static void on_get_result(qsysdb_get_result_t *result, void *userdata)
{
    const char *key = (const char *)userdata;

    if (result->base.error == QSYSDB_OK) {
        printf("[GET] %s = %.*s\n", key, (int)result->value_len, result->value);
    } else if (result->base.error == QSYSDB_ERR_NOTFOUND) {
        printf("[GET] %s: not found\n", key);
    } else {
        printf("[GET] %s: error %d\n", key, result->base.error);
    }
}

/*
 * Callback for async set operations
 */
static void on_set_complete(qsysdb_result_t *result, void *userdata)
{
    const char *key = (const char *)userdata;

    if (result->error == QSYSDB_OK) {
        printf("[SET] %s: success\n", key);
    } else {
        printf("[SET] %s: error %d\n", key, result->error);
    }
}

/*
 * Callback for watch notifications - called when subscribed keys change
 */
static void on_watch_event(qsysdb_event_t *event, void *userdata)
{
    const char *watch_name = (const char *)userdata;
    const char *type_str;

    switch (event->type) {
    case QSYSDB_EVENT_CREATE:  type_str = "CREATE"; break;
    case QSYSDB_EVENT_UPDATE:  type_str = "UPDATE"; break;
    case QSYSDB_EVENT_DELETE:  type_str = "DELETE"; break;
    default:                   type_str = "UNKNOWN"; break;
    }

    printf("[WATCH:%s] %s on %s", watch_name, type_str, event->path);
    if (event->value && event->value_len > 0) {
        printf(" = %.*s", (int)event->value_len, event->value);
    }
    printf("\n");
}

/*
 * Callback for batch operations
 */
static void on_batch_complete(qsysdb_batch_result_t *result, void *userdata)
{
    (void)userdata;
    printf("[BATCH] completed: status=%d, succeeded=%d, failed=%d\n",
           result->base.error, result->succeeded, result->failed);
}

/*
 * Demo: Periodic timer to generate some activity
 */
static void do_periodic_work(qsysdb_async_t *client, int counter)
{
    char key[64];
    char value[128];

    /* Update a counter entry */
    snprintf(key, sizeof(key), "/app/metrics/counter");
    snprintf(value, sizeof(value), "%d", counter);

    qsysdb_async_set(client, key, value,
                     on_set_complete, (void *)"metrics/counter");

    /* Every 5 iterations, do a batch update */
    if (counter % 5 == 0) {
        qsysdb_batch_t *batch = qsysdb_batch_create(client);
        if (batch) {
            for (int i = 0; i < 3; i++) {
                snprintf(key, sizeof(key), "/app/batch/item%d", i);
                snprintf(value, sizeof(value), "batch_value_%d_%d", counter, i);
                qsysdb_batch_set(batch, key, value);
            }
            qsysdb_batch_execute(batch, on_batch_complete, NULL);
        }
    }

    /* Every 10 iterations, read back some values */
    if (counter % 10 == 0) {
        qsysdb_async_get(client, "/app/metrics/counter",
                         on_get_result, (void *)"/app/metrics/counter");
        qsysdb_async_get(client, "/app/batch/item0",
                         on_get_result, (void *)"/app/batch/item0");
    }
}

int main(int argc, char *argv[])
{
    const char *socket_path = "/tmp/qsysdb.sock";
    int epoll_fd = -1;
    int timer_fd = -1;
    qsysdb_async_t *client = NULL;
    int ret = 1;

    if (argc > 1) {
        socket_path = argv[1];
    }

    /* Set up signal handler for clean shutdown */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("QSysDB Async Client Integration Example\n");
    printf("Socket: %s\n\n", socket_path);

    /* Create epoll instance for our event loop */
    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0) {
        perror("epoll_create1");
        goto cleanup;
    }

    /* Create a timer for periodic work (every 1 second) */
    timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (timer_fd < 0) {
        perror("timerfd_create");
        goto cleanup;
    }

    struct itimerspec ts = {
        .it_interval = { .tv_sec = 1, .tv_nsec = 0 },
        .it_value = { .tv_sec = 1, .tv_nsec = 0 }
    };
    if (timerfd_settime(timer_fd, 0, &ts, NULL) < 0) {
        perror("timerfd_settime");
        goto cleanup;
    }

    /* Create async client */
    client = qsysdb_async_new();
    if (!client) {
        fprintf(stderr, "Failed to create async client\n");
        goto cleanup;
    }

    /* Connect to server (non-blocking) */
    int status = qsysdb_async_connect(client, socket_path, 0);
    if (status != QSYSDB_OK) {
        fprintf(stderr, "Failed to connect: %d\n", status);
        goto cleanup;
    }

    printf("Connected to qsysdb server\n");

    /* Get the client's file descriptor for event loop integration */
    int client_fd = qsysdb_async_fd(client);
    if (client_fd < 0) {
        fprintf(stderr, "Failed to get client fd\n");
        goto cleanup;
    }

    /* Add client fd to epoll */
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLOUT | EPOLLET;  /* Edge-triggered */
    ev.data.fd = client_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev) < 0) {
        perror("epoll_ctl(client_fd)");
        goto cleanup;
    }

    /* Add timer fd to epoll */
    ev.events = EPOLLIN;
    ev.data.fd = timer_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, timer_fd, &ev) < 0) {
        perror("epoll_ctl(timer_fd)");
        goto cleanup;
    }

    /* Set up watches using the builder pattern */
    printf("\nSetting up watches...\n");

    /* Watch 1: Monitor all metrics (prefix match with wildcard) */
    qsysdb_watch_t *watch1 = qsysdb_watch_create(client);
    if (watch1) {
        qsysdb_watch_pattern(watch1, "/app/metrics/*");
        qsysdb_watch_on_event(watch1, on_watch_event, (void *)"metrics");
        int watch_id = qsysdb_watch_start(watch1);
        if (watch_id > 0) {
            printf("[WATCH:metrics] subscribed with id=%d\n", watch_id);
        } else {
            printf("[WATCH:metrics] subscribe failed: %d\n", watch_id);
        }
    }

    /* Watch 2: Monitor batch items (prefix match with wildcard) */
    qsysdb_watch_t *watch2 = qsysdb_watch_create(client);
    if (watch2) {
        qsysdb_watch_pattern(watch2, "/app/batch/*");
        qsysdb_watch_on_event(watch2, on_watch_event, (void *)"batch");
        int watch_id = qsysdb_watch_start(watch2);
        if (watch_id > 0) {
            printf("[WATCH:batch] subscribed with id=%d\n", watch_id);
        } else {
            printf("[WATCH:batch] subscribe failed: %d\n", watch_id);
        }
    }

    /* Watch 3: Monitor a specific key (exact match) */
    qsysdb_watch_t *watch3 = qsysdb_watch_create(client);
    if (watch3) {
        qsysdb_watch_pattern(watch3, "/app/config/setting");
        qsysdb_watch_on_event(watch3, on_watch_event, (void *)"config");
        int watch_id = qsysdb_watch_start(watch3);
        if (watch_id > 0) {
            printf("[WATCH:config] subscribed with id=%d\n", watch_id);
        } else {
            printf("[WATCH:config] subscribe failed: %d\n", watch_id);
        }
    }

    /* Initial data setup */
    printf("\nSetting initial data...\n");
    qsysdb_async_set(client, "/app/config/setting", "initial",
                     on_set_complete, (void *)"/app/config/setting");

    /* Main event loop */
    printf("\nEntering event loop (press Ctrl+C to stop)...\n\n");

    struct epoll_event events[16];
    int counter = 0;

    while (running) {
        int nfds = epoll_wait(epoll_fd, events, 16, 1000);
        if (nfds < 0) {
            if (running) perror("epoll_wait");
            break;
        }

        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == client_fd) {
                /* Client socket is ready - process events */
                int result = qsysdb_async_process(client);
                if (result < 0) {
                    fprintf(stderr, "Client error: %d\n", result);
                    running = 0;
                    break;
                }
            } else if (events[i].data.fd == timer_fd) {
                /* Timer fired - do periodic work */
                uint64_t exp;
                if (read(timer_fd, &exp, sizeof(exp)) == sizeof(exp)) {
                    counter++;
                    do_periodic_work(client, counter);
                }
            }
        }

        /* Process any pending client operations */
        qsysdb_async_process(client);
    }

    printf("\nShutting down...\n");
    ret = 0;

cleanup:
    if (client) {
        qsysdb_async_disconnect(client);
        qsysdb_async_free(client);
    }
    if (timer_fd >= 0) close(timer_fd);
    if (epoll_fd >= 0) close(epoll_fd);

    return ret;
}
