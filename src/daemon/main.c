/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * main.c - Daemon entry point
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <errno.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <pwd.h>

#include <qsysdb/types.h>
#include "database.h"
#include "subscription.h"
#include "server.h"
#include "netlink.h"
#include "snapshot.h"
#include "common/shm.h"
#include "common/ringbuf.h"

/* Global state */
static struct qsysdb_db g_db;
static struct sub_manager g_sub_mgr;
static struct server g_server;
static struct netlink_ctx g_netlink;
static volatile sig_atomic_t g_running = 1;
static volatile sig_atomic_t g_reload = 0;
static int g_pidfile_fd = -1;

/* Configuration */
static struct {
    char socket_path[256];
    char shm_name[64];
    char snapshot_path[256];
    char pidfile_path[256];
    size_t shm_size;
    int foreground;
    int verbose;
    int load_snapshot;
    /* TCP configuration */
    int tcp_enabled;
    char tcp_bind[64];
    uint16_t tcp_port;
} g_config = {
    .socket_path = QSYSDB_SOCKET_PATH,
    .shm_name = QSYSDB_SHM_NAME,
    .snapshot_path = "",
    .pidfile_path = "/var/run/qsysdb/qsysdbd.pid",
    .shm_size = QSYSDB_SHM_SIZE_DEFAULT,
    .foreground = 0,
    .verbose = 0,
    .load_snapshot = 0,
    .tcp_enabled = 0,
    .tcp_bind = QSYSDB_TCP_BIND_DEFAULT,
    .tcp_port = QSYSDB_TCP_PORT_DEFAULT
};

static void signal_handler(int sig)
{
    switch (sig) {
    case SIGINT:
    case SIGTERM:
        g_running = 0;
        break;
    case SIGHUP:
        g_reload = 1;
        break;
    default:
        break;
    }
}

static void setup_signals(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);

    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    /* Ignore SIGPIPE */
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);
}

static int create_pidfile(void)
{
    /* Ensure directory exists */
    char dir[256];
    snprintf(dir, sizeof(dir), "%s", g_config.pidfile_path);
    char *last_slash = strrchr(dir, '/');
    if (last_slash) {
        *last_slash = '\0';
        mkdir(dir, 0755);
    }

    g_pidfile_fd = open(g_config.pidfile_path, O_RDWR | O_CREAT, 0644);
    if (g_pidfile_fd < 0) {
        fprintf(stderr, "Cannot open pidfile: %s\n", strerror(errno));
        return -1;
    }

    if (flock(g_pidfile_fd, LOCK_EX | LOCK_NB) < 0) {
        fprintf(stderr, "Cannot lock pidfile: daemon already running?\n");
        close(g_pidfile_fd);
        g_pidfile_fd = -1;
        return -1;
    }

    if (ftruncate(g_pidfile_fd, 0) < 0) {
        /* Ignore truncate errors */
    }
    char buf[32];
    snprintf(buf, sizeof(buf), "%d\n", getpid());
    if (write(g_pidfile_fd, buf, strlen(buf)) < 0) {
        /* Ignore write errors */
    }

    return 0;
}

static void remove_pidfile(void)
{
    if (g_pidfile_fd >= 0) {
        close(g_pidfile_fd);
        unlink(g_config.pidfile_path);
        g_pidfile_fd = -1;
    }
}

static int daemonize(void)
{
    pid_t pid = fork();
    if (pid < 0) {
        return -1;
    }
    if (pid > 0) {
        exit(0);  /* Parent exits */
    }

    /* Create new session */
    if (setsid() < 0) {
        return -1;
    }

    /* Fork again to prevent acquiring a terminal */
    pid = fork();
    if (pid < 0) {
        return -1;
    }
    if (pid > 0) {
        exit(0);
    }

    /* Change working directory */
    if (chdir("/") < 0) {
        /* Ignore */
    }

    /* Close standard file descriptors */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    /* Redirect to /dev/null */
    int null_fd = open("/dev/null", O_RDWR);
    if (null_fd >= 0) {
        dup2(null_fd, STDIN_FILENO);
        dup2(null_fd, STDOUT_FILENO);
        dup2(null_fd, STDERR_FILENO);
        if (null_fd > 2) {
            close(null_fd);
        }
    }

    return 0;
}

static void print_usage(const char *prog)
{
    printf("Usage: %s [options]\n", prog);
    printf("\n");
    printf("Options:\n");
    printf("  -f, --foreground      Run in foreground (don't daemonize)\n");
    printf("  -s, --socket PATH     Unix socket path (default: %s)\n", QSYSDB_SOCKET_PATH);
    printf("  -m, --shm NAME        Shared memory name (default: %s)\n", QSYSDB_SHM_NAME);
    printf("  -S, --size SIZE       Shared memory size in MB (default: 64)\n");
    printf("  -p, --pidfile PATH    PID file path\n");
    printf("  -l, --load PATH       Load snapshot on startup\n");
    printf("  -t, --tcp             Enable TCP server\n");
    printf("  -b, --bind ADDR       TCP bind address (default: %s)\n", QSYSDB_TCP_BIND_DEFAULT);
    printf("  -P, --port PORT       TCP port (default: %d)\n", QSYSDB_TCP_PORT_DEFAULT);
    printf("  -v, --verbose         Increase verbosity\n");
    printf("  -h, --help            Show this help\n");
    printf("  -V, --version         Show version\n");
    printf("\n");
}

static int parse_args(int argc, char *argv[])
{
    static struct option long_options[] = {
        {"foreground", no_argument,       0, 'f'},
        {"socket",     required_argument, 0, 's'},
        {"shm",        required_argument, 0, 'm'},
        {"size",       required_argument, 0, 'S'},
        {"pidfile",    required_argument, 0, 'p'},
        {"load",       required_argument, 0, 'l'},
        {"tcp",        no_argument,       0, 't'},
        {"bind",       required_argument, 0, 'b'},
        {"port",       required_argument, 0, 'P'},
        {"verbose",    no_argument,       0, 'v'},
        {"help",       no_argument,       0, 'h'},
        {"version",    no_argument,       0, 'V'},
        {0, 0, 0, 0}
    };

    int c;
    while ((c = getopt_long(argc, argv, "fs:m:S:p:l:tb:P:vhV", long_options, NULL)) != -1) {
        switch (c) {
        case 'f':
            g_config.foreground = 1;
            break;
        case 's':
            snprintf(g_config.socket_path, sizeof(g_config.socket_path), "%s", optarg);
            break;
        case 'm':
            snprintf(g_config.shm_name, sizeof(g_config.shm_name), "%s", optarg);
            break;
        case 'S':
            g_config.shm_size = (size_t)atoi(optarg) * 1024 * 1024;
            break;
        case 'p':
            snprintf(g_config.pidfile_path, sizeof(g_config.pidfile_path), "%s", optarg);
            break;
        case 'l':
            snprintf(g_config.snapshot_path, sizeof(g_config.snapshot_path), "%s", optarg);
            g_config.load_snapshot = 1;
            break;
        case 't':
            g_config.tcp_enabled = 1;
            break;
        case 'b':
            snprintf(g_config.tcp_bind, sizeof(g_config.tcp_bind), "%s", optarg);
            break;
        case 'P':
            g_config.tcp_port = (uint16_t)atoi(optarg);
            break;
        case 'v':
            g_config.verbose++;
            break;
        case 'h':
            print_usage(argv[0]);
            exit(0);
        case 'V':
            printf("qsysdbd version %d.%d\n", QSYSDB_VERSION, QSYSDB_PROTOCOL_VERSION);
            exit(0);
        default:
            return -1;
        }
    }

    return 0;
}

static void log_msg(int level, const char *fmt, ...)
{
    if (level > g_config.verbose && !g_config.foreground) {
        return;
    }

    va_list ap;
    va_start(ap, fmt);

    if (g_config.foreground) {
        vfprintf(stderr, fmt, ap);
        fprintf(stderr, "\n");
    } else {
        /* Could use syslog here */
        vsyslog(LOG_INFO, fmt, ap);
    }

    va_end(ap);
}

static void notification_loop(void)
{
    struct ringbuf_consumer consumer;
    ringbuf_consumer_init(g_db.shm.ring, &consumer);

    while (g_running) {
        struct qsysdb_notification notif;

        /* Poll for notifications */
        int ret = ringbuf_consume(g_db.shm.ring, &consumer, &notif);
        if (ret == QSYSDB_OK) {
            /* Broadcast to matching clients */
            server_broadcast_notification(&g_server, &notif);

            /* Send to kernel if present */
            if (netlink_kernel_present(&g_netlink)) {
                netlink_send_notification(&g_netlink, &notif);
            }
        } else {
            /* No notification, sleep briefly */
            usleep(1000);  /* 1ms */
        }

        /* Handle reload signal */
        if (g_reload) {
            g_reload = 0;
            log_msg(0, "Received SIGHUP, could reload config here");
        }
    }
}

int main(int argc, char *argv[])
{
    int ret;

    /* Parse command line */
    if (parse_args(argc, argv) < 0) {
        print_usage(argv[0]);
        return 1;
    }

    /* Check for root (needed for socket in /var/run) */
    if (geteuid() != 0) {
        fprintf(stderr, "Warning: not running as root, "
                "may not be able to create socket/shm\n");
    }

    /* Daemonize if not foreground */
    if (!g_config.foreground) {
        if (daemonize() < 0) {
            fprintf(stderr, "Failed to daemonize\n");
            return 1;
        }
    }

    /* Setup signal handlers */
    setup_signals();

    /* Create PID file */
    if (create_pidfile() < 0) {
        return 1;
    }

    log_msg(0, "QSysDB daemon starting...");

    /* Initialize database */
    log_msg(1, "Initializing database (shm=%s, size=%zu MB)",
            g_config.shm_name, g_config.shm_size / (1024 * 1024));

    ret = db_init(&g_db, g_config.shm_name, g_config.shm_size);
    if (ret != QSYSDB_OK) {
        log_msg(0, "Failed to initialize database: %d", ret);
        remove_pidfile();
        return 1;
    }

    /* Load snapshot if requested */
    if (g_config.load_snapshot) {
        const char *path = g_config.snapshot_path[0] ?
                           g_config.snapshot_path : snapshot_default_path();
        log_msg(1, "Loading snapshot from %s", path);

        ret = snapshot_load(&g_db, path);
        if (ret == QSYSDB_ERR_NOTFOUND) {
            log_msg(1, "No snapshot found, starting fresh");
        } else if (ret != QSYSDB_OK) {
            log_msg(0, "Warning: failed to load snapshot: %d", ret);
        } else {
            log_msg(0, "Snapshot loaded successfully");
        }
    }

    /* Initialize subscription manager */
    log_msg(1, "Initializing subscription manager");
    ret = sub_manager_init(&g_sub_mgr);
    if (ret != QSYSDB_OK) {
        log_msg(0, "Failed to initialize subscription manager: %d", ret);
        db_shutdown(&g_db);
        remove_pidfile();
        return 1;
    }

    /* Initialize server */
    log_msg(1, "Initializing server (socket=%s)", g_config.socket_path);

    /* Ensure socket directory exists */
    char sock_dir[256];
    snprintf(sock_dir, sizeof(sock_dir), "%s", g_config.socket_path);
    char *last_slash = strrchr(sock_dir, '/');
    if (last_slash) {
        *last_slash = '\0';
        mkdir(sock_dir, 0755);
    }

    /* Setup server configuration */
    struct server_config srv_config;
    server_config_init(&srv_config);
    snprintf(srv_config.unix_path, sizeof(srv_config.unix_path), "%s",
             g_config.socket_path);
    srv_config.tcp_enabled = g_config.tcp_enabled;
    if (g_config.tcp_enabled) {
        snprintf(srv_config.tcp_bind, sizeof(srv_config.tcp_bind), "%s",
                 g_config.tcp_bind);
        srv_config.tcp_port = g_config.tcp_port;
        log_msg(1, "TCP server enabled on %s:%d",
                g_config.tcp_bind, g_config.tcp_port);
    }

    ret = server_init(&g_server, &srv_config, &g_db, &g_sub_mgr);
    if (ret != QSYSDB_OK) {
        log_msg(0, "Failed to initialize server: %d", ret);
        sub_manager_shutdown(&g_sub_mgr);
        db_shutdown(&g_db);
        remove_pidfile();
        return 1;
    }

    /* Initialize netlink (optional - kernel module may not be loaded) */
    log_msg(1, "Initializing netlink interface");
    ret = netlink_init(&g_netlink, &g_db, &g_sub_mgr);
    if (ret != QSYSDB_OK) {
        log_msg(1, "Warning: netlink init failed (kernel module not loaded?)");
    }

    /* Start server */
    log_msg(1, "Starting server");
    ret = server_start(&g_server);
    if (ret != QSYSDB_OK) {
        log_msg(0, "Failed to start server: %d", ret);
        netlink_shutdown(&g_netlink);
        server_shutdown(&g_server);
        sub_manager_shutdown(&g_sub_mgr);
        db_shutdown(&g_db);
        remove_pidfile();
        return 1;
    }

    /* Start netlink receiver */
    netlink_start(&g_netlink);

    log_msg(0, "QSysDB daemon running (pid=%d)", getpid());

    /* Main notification dispatch loop */
    notification_loop();

    /* Shutdown sequence */
    log_msg(0, "QSysDB daemon shutting down...");

    /* Save snapshot before exit */
    log_msg(1, "Saving snapshot");
    ret = snapshot_save(&g_db, g_config.snapshot_path[0] ?
                        g_config.snapshot_path : NULL);
    if (ret != QSYSDB_OK) {
        log_msg(0, "Warning: failed to save snapshot: %d", ret);
    }

    /* Stop and cleanup */
    netlink_stop(&g_netlink);
    server_stop(&g_server);

    netlink_shutdown(&g_netlink);
    server_shutdown(&g_server);
    sub_manager_shutdown(&g_sub_mgr);

    /* Unlink shared memory */
    qsysdb_shm_unlink(g_config.shm_name);
    db_shutdown(&g_db);

    remove_pidfile();

    log_msg(0, "QSysDB daemon stopped");

    return 0;
}
