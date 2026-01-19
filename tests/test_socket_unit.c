/*
 * QSysDB - Socket Transport Unit Tests
 *
 * Unit tests for the transport layer abstraction (Unix and TCP).
 * These tests verify the transport ops interface without requiring
 * a full server.
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <pthread.h>

#include <qsysdb/types.h>
#include "lib/client.h"
#include "lib/socket_transport.h"

#define TEST(name) static void test_##name(void)
#define RUN_TEST(name) do { \
    printf("  " #name "... "); \
    fflush(stdout); \
    test_##name(); \
    printf("OK\n"); \
} while(0)

#define TEST_UNIX_PATH "/tmp/qsysdb_transport_test.sock"
#define TEST_TCP_PORT  15960

/*
 * Simple echo server for testing transport layer
 */
struct test_server {
    int listen_fd;
    int client_fd;
    pthread_t thread;
    volatile int running;
    int port;
    char *socket_path;
};

static void *unix_echo_server(void *arg)
{
    struct test_server *srv = arg;

    while (srv->running) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(srv->listen_fd, &fds);

        struct timeval tv = {0, 100000};  /* 100ms timeout */
        int ret = select(srv->listen_fd + 1, &fds, NULL, NULL, &tv);
        if (ret <= 0) continue;

        struct sockaddr_un addr;
        socklen_t addr_len = sizeof(addr);
        int fd = accept(srv->listen_fd, (struct sockaddr *)&addr, &addr_len);
        if (fd < 0) continue;

        srv->client_fd = fd;

        /* Echo loop */
        char buf[1024];
        while (srv->running) {
            ssize_t n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
            if (n > 0) {
                send(fd, buf, n, 0);
            } else if (n == 0) {
                break;
            }
            usleep(1000);
        }

        close(fd);
        srv->client_fd = -1;
    }

    return NULL;
}

static void *tcp_echo_server(void *arg)
{
    struct test_server *srv = arg;

    while (srv->running) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(srv->listen_fd, &fds);

        struct timeval tv = {0, 100000};
        int ret = select(srv->listen_fd + 1, &fds, NULL, NULL, &tv);
        if (ret <= 0) continue;

        struct sockaddr_in addr;
        socklen_t addr_len = sizeof(addr);
        int fd = accept(srv->listen_fd, (struct sockaddr *)&addr, &addr_len);
        if (fd < 0) continue;

        srv->client_fd = fd;

        /* Echo loop */
        char buf[1024];
        while (srv->running) {
            ssize_t n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
            if (n > 0) {
                send(fd, buf, n, 0);
            } else if (n == 0) {
                break;
            }
            usleep(1000);
        }

        close(fd);
        srv->client_fd = -1;
    }

    return NULL;
}

static int start_unix_server(struct test_server *srv, const char *path)
{
    memset(srv, 0, sizeof(*srv));
    srv->client_fd = -1;
    srv->socket_path = strdup(path);

    unlink(path);

    srv->listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv->listen_fd < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (bind(srv->listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(srv->listen_fd);
        return -1;
    }

    listen(srv->listen_fd, 5);
    srv->running = 1;
    pthread_create(&srv->thread, NULL, unix_echo_server, srv);

    usleep(10000);  /* Let server start */
    return 0;
}

static int start_tcp_server(struct test_server *srv, int port)
{
    memset(srv, 0, sizeof(*srv));
    srv->client_fd = -1;
    srv->port = port;

    srv->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (srv->listen_fd < 0) return -1;

    int opt = 1;
    setsockopt(srv->listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    if (bind(srv->listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(srv->listen_fd);
        return -1;
    }

    listen(srv->listen_fd, 5);
    srv->running = 1;
    pthread_create(&srv->thread, NULL, tcp_echo_server, srv);

    usleep(10000);
    return 0;
}

static void stop_server(struct test_server *srv)
{
    srv->running = 0;
    pthread_join(srv->thread, NULL);
    if (srv->client_fd >= 0) close(srv->client_fd);
    close(srv->listen_fd);
    if (srv->socket_path) {
        unlink(srv->socket_path);
        free(srv->socket_path);
    }
}

/*
 * Transport Interface Tests
 */

TEST(transport_ops_exist)
{
    /* Verify transport operations structures exist */
    assert(unix_transport_ops.type == TRANSPORT_UNIX);
    assert(unix_transport_ops.connect != NULL);
    assert(unix_transport_ops.disconnect != NULL);
    assert(unix_transport_ops.send != NULL);
    assert(unix_transport_ops.recv != NULL);
    assert(unix_transport_ops.set_timeout != NULL);
    assert(unix_transport_ops.get_fd != NULL);

    assert(tcp_transport_ops.type == TRANSPORT_TCP);
    assert(tcp_transport_ops.connect != NULL);
    assert(tcp_transport_ops.disconnect != NULL);
    assert(tcp_transport_ops.send != NULL);
    assert(tcp_transport_ops.recv != NULL);
    assert(tcp_transport_ops.set_timeout != NULL);
    assert(tcp_transport_ops.get_fd != NULL);
}

TEST(unix_transport_connect)
{
    struct test_server srv;
    assert(start_unix_server(&srv, TEST_UNIX_PATH) == 0);

    /* Create a minimal client structure */
    struct qsysdb db;
    memset(&db, 0, sizeof(db));
    db.sock_fd = -1;
    strncpy(db.socket_path, TEST_UNIX_PATH, sizeof(db.socket_path) - 1);

    /* Connect */
    int ret = unix_transport_ops.connect(&db);
    assert(ret == QSYSDB_OK);
    assert(db.sock_fd >= 0);
    assert(db.sock_type == SOCK_TYPE_UNIX);

    /* Get FD */
    int fd = unix_transport_ops.get_fd(&db);
    assert(fd == db.sock_fd);

    /* Disconnect */
    unix_transport_ops.disconnect(&db);
    assert(db.sock_fd == -1);

    stop_server(&srv);
}

TEST(unix_transport_send_recv)
{
    struct test_server srv;
    assert(start_unix_server(&srv, TEST_UNIX_PATH) == 0);

    struct qsysdb db;
    memset(&db, 0, sizeof(db));
    db.sock_fd = -1;
    strncpy(db.socket_path, TEST_UNIX_PATH, sizeof(db.socket_path) - 1);

    assert(unix_transport_ops.connect(&db) == QSYSDB_OK);

    /* Send data */
    const char *msg = "Hello, Unix transport!";
    ssize_t sent = unix_transport_ops.send(&db, msg, strlen(msg));
    assert(sent == (ssize_t)strlen(msg));

    /* Wait for echo */
    usleep(10000);

    /* Receive data */
    char buf[256];
    ssize_t received = unix_transport_ops.recv(&db, buf, sizeof(buf), 0);
    assert(received == (ssize_t)strlen(msg));
    assert(memcmp(buf, msg, strlen(msg)) == 0);

    unix_transport_ops.disconnect(&db);
    stop_server(&srv);
}

TEST(unix_transport_timeout)
{
    struct test_server srv;
    assert(start_unix_server(&srv, TEST_UNIX_PATH) == 0);

    struct qsysdb db;
    memset(&db, 0, sizeof(db));
    db.sock_fd = -1;
    strncpy(db.socket_path, TEST_UNIX_PATH, sizeof(db.socket_path) - 1);

    assert(unix_transport_ops.connect(&db) == QSYSDB_OK);

    /* Set timeout */
    int ret = unix_transport_ops.set_timeout(&db, 100);
    assert(ret == QSYSDB_OK);

    unix_transport_ops.disconnect(&db);
    stop_server(&srv);
}

TEST(tcp_transport_connect)
{
    struct test_server srv;
    assert(start_tcp_server(&srv, TEST_TCP_PORT) == 0);

    struct qsysdb db;
    memset(&db, 0, sizeof(db));
    db.sock_fd = -1;
    strncpy(db.tcp_host, "127.0.0.1", sizeof(db.tcp_host) - 1);
    db.tcp_port = TEST_TCP_PORT;

    /* Connect */
    int ret = tcp_transport_ops.connect(&db);
    assert(ret == QSYSDB_OK);
    assert(db.sock_fd >= 0);
    assert(db.sock_type == SOCK_TYPE_TCP);

    /* Get FD */
    int fd = tcp_transport_ops.get_fd(&db);
    assert(fd == db.sock_fd);

    /* Disconnect */
    tcp_transport_ops.disconnect(&db);
    assert(db.sock_fd == -1);

    stop_server(&srv);
}

TEST(tcp_transport_send_recv)
{
    struct test_server srv;
    assert(start_tcp_server(&srv, TEST_TCP_PORT) == 0);

    struct qsysdb db;
    memset(&db, 0, sizeof(db));
    db.sock_fd = -1;
    strncpy(db.tcp_host, "127.0.0.1", sizeof(db.tcp_host) - 1);
    db.tcp_port = TEST_TCP_PORT;

    assert(tcp_transport_ops.connect(&db) == QSYSDB_OK);

    /* Send data */
    const char *msg = "Hello, TCP transport!";
    ssize_t sent = tcp_transport_ops.send(&db, msg, strlen(msg));
    assert(sent == (ssize_t)strlen(msg));

    /* Wait for echo */
    usleep(10000);

    /* Receive data */
    char buf[256];
    ssize_t received = tcp_transport_ops.recv(&db, buf, sizeof(buf), 0);
    assert(received == (ssize_t)strlen(msg));
    assert(memcmp(buf, msg, strlen(msg)) == 0);

    tcp_transport_ops.disconnect(&db);
    stop_server(&srv);
}

TEST(tcp_transport_localhost_default)
{
    struct test_server srv;
    assert(start_tcp_server(&srv, TEST_TCP_PORT) == 0);

    struct qsysdb db;
    memset(&db, 0, sizeof(db));
    db.sock_fd = -1;
    /* Leave tcp_host empty to test default */
    db.tcp_port = TEST_TCP_PORT;

    int ret = tcp_transport_ops.connect(&db);
    assert(ret == QSYSDB_OK);
    assert(db.sock_fd >= 0);

    /* Verify default was applied */
    assert(db.tcp_host[0] != '\0');

    tcp_transport_ops.disconnect(&db);
    stop_server(&srv);
}

TEST(transport_connect_failure)
{
    struct qsysdb db;
    memset(&db, 0, sizeof(db));
    db.sock_fd = -1;

    /* Unix: non-existent socket */
    strncpy(db.socket_path, "/nonexistent/path.sock", sizeof(db.socket_path) - 1);
    int ret = unix_transport_ops.connect(&db);
    assert(ret != QSYSDB_OK);
    assert(db.sock_fd == -1);

    /* TCP: non-existent server */
    memset(&db, 0, sizeof(db));
    db.sock_fd = -1;
    strncpy(db.tcp_host, "127.0.0.1", sizeof(db.tcp_host) - 1);
    db.tcp_port = 59999;  /* Unlikely to be in use */
    ret = tcp_transport_ops.connect(&db);
    assert(ret != QSYSDB_OK);
    assert(db.sock_fd == -1);
}

TEST(transport_null_safety)
{
    /* These should not crash */
    unix_transport_ops.disconnect(NULL);
    tcp_transport_ops.disconnect(NULL);

    assert(unix_transport_ops.get_fd(NULL) == -1);
    assert(tcp_transport_ops.get_fd(NULL) == -1);

    assert(unix_transport_ops.send(NULL, "test", 4) < 0);
    assert(tcp_transport_ops.send(NULL, "test", 4) < 0);
}

int main(void)
{
    printf("Running socket transport unit tests...\n\n");

    printf("Interface Tests:\n");
    RUN_TEST(transport_ops_exist);

    printf("\nUnix Transport Tests:\n");
    RUN_TEST(unix_transport_connect);
    RUN_TEST(unix_transport_send_recv);
    RUN_TEST(unix_transport_timeout);

    printf("\nTCP Transport Tests:\n");
    RUN_TEST(tcp_transport_connect);
    RUN_TEST(tcp_transport_send_recv);
    RUN_TEST(tcp_transport_localhost_default);

    printf("\nError Handling Tests:\n");
    RUN_TEST(transport_connect_failure);
    RUN_TEST(transport_null_safety);

    printf("\nAll socket transport tests passed!\n");
    return 0;
}
