/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * qsysdb-cli.c - Command-line interface tool
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>

#include <qsysdb/qsysdb.h>

static volatile int g_running = 1;

static void signal_handler(int sig)
{
    (void)sig;
    g_running = 0;
}

static void print_usage(const char *prog)
{
    printf("Usage: %s [options] <command> [args...]\n", prog);
    printf("\n");
    printf("Commands:\n");
    printf("  get <path>               Get value at path\n");
    printf("  set <path> <json>        Set value at path\n");
    printf("  delete <path>            Delete path\n");
    printf("  exists <path>            Check if path exists\n");
    printf("  list [prefix]            List paths (optionally with prefix)\n");
    printf("  watch <pattern>          Watch for changes matching pattern\n");
    printf("  stats                    Show database statistics\n");
    printf("\n");
    printf("Options:\n");
    printf("  -s, --socket PATH        Socket path (default: %s)\n", QSYSDB_SOCKET_PATH);
    printf("  -S, --shm                Use shared memory direct access\n");
    printf("  -m, --shm-name NAME      Shared memory name (default: %s)\n", QSYSDB_SHM_NAME);
    printf("  -j, --json               Output in JSON format\n");
    printf("  -v, --verbose            Verbose output\n");
    printf("  -h, --help               Show this help\n");
    printf("  -V, --version            Show version\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s set /config/server '{\"host\":\"localhost\",\"port\":8080}'\n", prog);
    printf("  %s get /config/server\n", prog);
    printf("  %s watch '/config/*'\n", prog);
    printf("  %s list /config\n", prog);
    printf("\n");
}

static int cmd_get(qsysdb_t *db, const char *path, int json_output)
{
    char buf[QSYSDB_MAX_VALUE];
    uint64_t version, timestamp;
    size_t len;

    int ret = qsysdb_get_ex(db, path, buf, sizeof(buf), &len, &version, &timestamp);
    if (ret != QSYSDB_OK) {
        if (json_output) {
            printf("{\"error\":\"%s\",\"code\":%d}\n", qsysdb_strerror(ret), ret);
        } else {
            fprintf(stderr, "Error: %s\n", qsysdb_strerror(ret));
        }
        return 1;
    }

    if (json_output) {
        printf("{\"path\":\"%s\",\"value\":%s,\"version\":%lu,\"timestamp\":%lu}\n",
               path, buf, version, timestamp);
    } else {
        printf("%s\n", buf);
    }

    return 0;
}

static int cmd_set(qsysdb_t *db, const char *path, const char *value, int json_output)
{
    uint64_t version;

    int ret = qsysdb_set_ex(db, path, value, 0, &version);
    if (ret != QSYSDB_OK) {
        if (json_output) {
            printf("{\"error\":\"%s\",\"code\":%d}\n", qsysdb_strerror(ret), ret);
        } else {
            fprintf(stderr, "Error: %s\n", qsysdb_strerror(ret));
        }
        return 1;
    }

    if (json_output) {
        printf("{\"ok\":true,\"version\":%lu}\n", version);
    } else {
        printf("OK (version %lu)\n", version);
    }

    return 0;
}

static int cmd_delete(qsysdb_t *db, const char *path, int json_output)
{
    int ret = qsysdb_delete(db, path);
    if (ret != QSYSDB_OK) {
        if (json_output) {
            printf("{\"error\":\"%s\",\"code\":%d}\n", qsysdb_strerror(ret), ret);
        } else {
            fprintf(stderr, "Error: %s\n", qsysdb_strerror(ret));
        }
        return 1;
    }

    if (json_output) {
        printf("{\"ok\":true}\n");
    } else {
        printf("Deleted\n");
    }

    return 0;
}

static int cmd_exists(qsysdb_t *db, const char *path, int json_output)
{
    int ret = qsysdb_exists(db, path);
    if (ret < 0) {
        if (json_output) {
            printf("{\"error\":\"%s\",\"code\":%d}\n", qsysdb_strerror(ret), ret);
        } else {
            fprintf(stderr, "Error: %s\n", qsysdb_strerror(ret));
        }
        return 1;
    }

    if (json_output) {
        printf("{\"exists\":%s}\n", ret ? "true" : "false");
    } else {
        printf("%s\n", ret ? "yes" : "no");
    }

    return ret ? 0 : 1;
}

static int cmd_list(qsysdb_t *db, const char *prefix, int json_output)
{
    char **paths;
    size_t count;

    int ret = qsysdb_list(db, prefix, &paths, &count);
    if (ret != QSYSDB_OK) {
        if (json_output) {
            printf("{\"error\":\"%s\",\"code\":%d}\n", qsysdb_strerror(ret), ret);
        } else {
            fprintf(stderr, "Error: %s\n", qsysdb_strerror(ret));
        }
        return 1;
    }

    if (json_output) {
        printf("{\"count\":%zu,\"paths\":[", count);
        for (size_t i = 0; i < count; i++) {
            printf("\"%s\"%s", paths[i], i < count - 1 ? "," : "");
        }
        printf("]}\n");
    } else {
        for (size_t i = 0; i < count; i++) {
            printf("%s\n", paths[i]);
        }
        if (count == 0) {
            printf("(no entries)\n");
        }
    }

    qsysdb_list_free(paths, count);
    return 0;
}

static void watch_callback(const char *path, const char *value,
                           int event_type, void *userdata)
{
    int json_output = *(int *)userdata;
    const char *event_name;

    switch (event_type) {
    case QSYSDB_EVENT_CREATE:
        event_name = "CREATE";
        break;
    case QSYSDB_EVENT_UPDATE:
        event_name = "UPDATE";
        break;
    case QSYSDB_EVENT_DELETE:
        event_name = "DELETE";
        break;
    case QSYSDB_EVENT_DELETE_TREE:
        event_name = "DELETE_TREE";
        break;
    default:
        event_name = "UNKNOWN";
        break;
    }

    if (json_output) {
        printf("{\"event\":\"%s\",\"path\":\"%s\"", event_name, path);
        if (value) {
            printf(",\"value\":%s", value);
        }
        printf("}\n");
    } else {
        printf("[%s] %s", event_name, path);
        if (value) {
            printf(" = %s", value);
        }
        printf("\n");
    }

    fflush(stdout);
}

static int cmd_watch(qsysdb_t *db, const char *pattern, int json_output)
{
    int sub_id;

    sub_id = qsysdb_subscribe(db, pattern, watch_callback, &json_output);
    if (sub_id < 0) {
        if (json_output) {
            printf("{\"error\":\"%s\",\"code\":%d}\n",
                   qsysdb_strerror(sub_id), sub_id);
        } else {
            fprintf(stderr, "Error: %s\n", qsysdb_strerror(sub_id));
        }
        return 1;
    }

    if (!json_output) {
        printf("Watching %s (subscription %d)...\n", pattern, sub_id);
        printf("Press Ctrl+C to stop\n\n");
    }

    /* Poll for notifications */
    while (g_running) {
        int count = qsysdb_poll(db, 1000);
        if (count < 0 && count != QSYSDB_ERR_AGAIN) {
            break;
        }
    }

    qsysdb_unsubscribe(db, sub_id);

    if (!json_output) {
        printf("\nStopped watching\n");
    }

    return 0;
}

static int cmd_stats(qsysdb_t *db, int json_output)
{
    struct qsysdb_stats stats;

    int ret = qsysdb_stats(db, &stats);
    if (ret != QSYSDB_OK) {
        if (json_output) {
            printf("{\"error\":\"%s\",\"code\":%d}\n", qsysdb_strerror(ret), ret);
        } else {
            fprintf(stderr, "Error: %s\n", qsysdb_strerror(ret));
        }
        return 1;
    }

    if (json_output) {
        printf("{");
        printf("\"entry_count\":%lu,", stats.entry_count);
        printf("\"total_size\":%lu,", stats.total_size);
        printf("\"used_size\":%lu,", stats.used_size);
        printf("\"sequence\":%lu,", stats.sequence);
        printf("\"total_sets\":%lu,", stats.total_sets);
        printf("\"total_gets\":%lu,", stats.total_gets);
        printf("\"total_deletes\":%lu,", stats.total_deletes);
        printf("\"client_count\":%u,", stats.client_count);
        printf("\"subscription_count\":%u", stats.subscription_count);
        printf("}\n");
    } else {
        printf("Database Statistics:\n");
        printf("  Entries:       %lu\n", stats.entry_count);
        printf("  Size:          %lu / %lu bytes (%.1f%%)\n",
               stats.used_size, stats.total_size,
               stats.total_size ? 100.0 * stats.used_size / stats.total_size : 0);
        printf("  Sequence:      %lu\n", stats.sequence);
        printf("  Total sets:    %lu\n", stats.total_sets);
        printf("  Total gets:    %lu\n", stats.total_gets);
        printf("  Total deletes: %lu\n", stats.total_deletes);
        printf("  Clients:       %u\n", stats.client_count);
        printf("  Subscriptions: %u\n", stats.subscription_count);
    }

    return 0;
}

int main(int argc, char *argv[])
{
    const char *socket_path = NULL;
    const char *shm_name = NULL;
    int use_shm = 0;
    int json_output = 0;
    int verbose = 0;

    static struct option long_options[] = {
        {"socket",  required_argument, 0, 's'},
        {"shm",     no_argument,       0, 'S'},
        {"shm-name", required_argument, 0, 'm'},
        {"json",    no_argument,       0, 'j'},
        {"verbose", no_argument,       0, 'v'},
        {"help",    no_argument,       0, 'h'},
        {"version", no_argument,       0, 'V'},
        {0, 0, 0, 0}
    };

    int c;
    while ((c = getopt_long(argc, argv, "s:Sm:jvhV", long_options, NULL)) != -1) {
        switch (c) {
        case 's':
            socket_path = optarg;
            break;
        case 'S':
            use_shm = 1;
            break;
        case 'm':
            shm_name = optarg;
            break;
        case 'j':
            json_output = 1;
            break;
        case 'v':
            verbose = 1;
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        case 'V':
            printf("qsysdb-cli version %s\n", qsysdb_version());
            return 0;
        default:
            return 1;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Error: no command specified\n");
        print_usage(argv[0]);
        return 1;
    }

    const char *command = argv[optind];

    /* Setup signal handler for watch command */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Connect to database */
    qsysdb_t *db;
    int flags = use_shm ? QSYSDB_CONN_SHM : 0;

    if (use_shm) {
        db = qsysdb_connect_shm(shm_name, flags);
    } else {
        db = qsysdb_connect(socket_path, flags);
    }

    if (!db) {
        if (json_output) {
            printf("{\"error\":\"connection failed\"}\n");
        } else {
            fprintf(stderr, "Error: failed to connect to qsysdb\n");
        }
        return 1;
    }

    if (verbose && !json_output) {
        printf("Connected to qsysdb%s\n",
               use_shm ? " (direct SHM)" : " (via socket)");
    }

    int result = 0;

    if (strcmp(command, "get") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: get requires a path\n");
            result = 1;
        } else {
            result = cmd_get(db, argv[optind + 1], json_output);
        }
    } else if (strcmp(command, "set") == 0) {
        if (optind + 2 >= argc) {
            fprintf(stderr, "Error: set requires path and value\n");
            result = 1;
        } else {
            result = cmd_set(db, argv[optind + 1], argv[optind + 2], json_output);
        }
    } else if (strcmp(command, "delete") == 0 || strcmp(command, "del") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: delete requires a path\n");
            result = 1;
        } else {
            result = cmd_delete(db, argv[optind + 1], json_output);
        }
    } else if (strcmp(command, "exists") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: exists requires a path\n");
            result = 1;
        } else {
            result = cmd_exists(db, argv[optind + 1], json_output);
        }
    } else if (strcmp(command, "list") == 0 || strcmp(command, "ls") == 0) {
        const char *prefix = optind + 1 < argc ? argv[optind + 1] : "/";
        result = cmd_list(db, prefix, json_output);
    } else if (strcmp(command, "watch") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: watch requires a pattern\n");
            result = 1;
        } else {
            result = cmd_watch(db, argv[optind + 1], json_output);
        }
    } else if (strcmp(command, "stats") == 0) {
        result = cmd_stats(db, json_output);
    } else {
        fprintf(stderr, "Error: unknown command '%s'\n", command);
        result = 1;
    }

    qsysdb_disconnect(db);

    return result;
}
