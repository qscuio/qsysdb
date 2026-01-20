/*
 * QSysDB - Network Tables Tests
 *
 * Tests for structured network data including:
 *   - IP Routing Tables (IPv4/IPv6)
 *   - ECMP (Equal-Cost Multi-Path) routing
 *   - Network Interface Tables
 *   - ARP/Neighbor Tables
 *   - Route lookup and prefix matching
 *   - Interface state management
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <qsysdb/types.h>
#include "common/shm.h"
#include "common/radix_tree.h"
#include "daemon/database.h"
#include "daemon/subscription.h"
#include "framework/test_framework.h"

static const char *_current_suite_name = "network_tables";

/* Test fixture data */
#define TEST_SHM_NAME "/qsysdb_network_test"
#define TEST_SHM_SIZE (64 * 1024 * 1024)

static struct qsysdb_db g_db;
static bool g_db_inited = false;

/* Setup/teardown */
static void net_setup(void) {
    qsysdb_shm_unlink(TEST_SHM_NAME);
    int ret = db_init(&g_db, TEST_SHM_NAME, TEST_SHM_SIZE);
    TEST_ASSERT_OK(ret);
    g_db_inited = true;
}

static void net_teardown(void) {
    if (g_db_inited) {
        db_shutdown(&g_db);
        g_db_inited = false;
    }
    qsysdb_shm_unlink(TEST_SHM_NAME);
}

/* ============================================
 * Helper functions for creating JSON
 * ============================================ */

/* Create a route entry JSON */
static void create_route_json(char *buf, size_t buflen,
                               const char *prefix, int prefix_len,
                               const char *nexthop, const char *interface,
                               int metric, int protocol)
{
    snprintf(buf, buflen,
             "{"
             "\"prefix\":\"%s\","
             "\"prefix_len\":%d,"
             "\"nexthop\":\"%s\","
             "\"interface\":\"%s\","
             "\"metric\":%d,"
             "\"protocol\":%d,"
             "\"flags\":[\"up\",\"gateway\"]"
             "}",
             prefix, prefix_len, nexthop, interface, metric, protocol);
}

/* Create an ECMP route entry JSON with multiple nexthops */
static void create_ecmp_route_json(char *buf, size_t buflen,
                                    const char *prefix, int prefix_len,
                                    const char *nexthops[], const char *interfaces[],
                                    const int weights[], int num_paths,
                                    int metric)
{
    int pos = 0;
    pos += snprintf(buf + pos, buflen - pos,
                    "{"
                    "\"prefix\":\"%s\","
                    "\"prefix_len\":%d,"
                    "\"type\":\"ecmp\","
                    "\"metric\":%d,"
                    "\"paths\":[",
                    prefix, prefix_len, metric);

    for (int i = 0; i < num_paths; i++) {
        pos += snprintf(buf + pos, buflen - pos,
                        "{\"nexthop\":\"%s\",\"interface\":\"%s\",\"weight\":%d}%s",
                        nexthops[i], interfaces[i], weights[i],
                        i < num_paths - 1 ? "," : "");
    }

    pos += snprintf(buf + pos, buflen - pos, "]}");
}

/* Create an interface entry JSON */
static void create_interface_json(char *buf, size_t buflen,
                                   const char *name, const char *mac,
                                   const char *ipv4, const char *ipv6,
                                   int mtu, const char *state,
                                   uint64_t rx_bytes, uint64_t tx_bytes)
{
    snprintf(buf, buflen,
             "{"
             "\"name\":\"%s\","
             "\"mac\":\"%s\","
             "\"ipv4\":\"%s\","
             "\"ipv6\":\"%s\","
             "\"mtu\":%d,"
             "\"state\":\"%s\","
             "\"stats\":{"
             "\"rx_bytes\":%lu,"
             "\"tx_bytes\":%lu,"
             "\"rx_packets\":0,"
             "\"tx_packets\":0,"
             "\"rx_errors\":0,"
             "\"tx_errors\":0"
             "},"
             "\"flags\":[\"up\",\"broadcast\",\"multicast\"]"
             "}",
             name, mac, ipv4, ipv6, mtu, state,
             (unsigned long)rx_bytes, (unsigned long)tx_bytes);
}

/* Create an ARP entry JSON */
static void create_arp_json(char *buf, size_t buflen,
                            const char *ip, const char *mac,
                            const char *interface, const char *state,
                            int age_seconds)
{
    snprintf(buf, buflen,
             "{"
             "\"ip\":\"%s\","
             "\"mac\":\"%s\","
             "\"interface\":\"%s\","
             "\"state\":\"%s\","
             "\"age\":%d,"
             "\"flags\":[\"complete\"]"
             "}",
             ip, mac, interface, state, age_seconds);
}

/* ============================================
 * IPv4 Routing Table Tests
 * ============================================ */

TEST(routing_add_default_route)
{
    net_setup();

    char value[512];
    create_route_json(value, sizeof(value),
                      "0.0.0.0", 0,
                      "192.168.1.1", "eth0",
                      100, 4 /* RTPROT_STATIC */);

    const char *path = "/routing/ipv4/default";
    TEST_ASSERT_OK(db_set(&g_db, path, strlen(path), value, strlen(value), 0, NULL));

    /* Verify */
    char buf[1024];
    size_t out_len;
    TEST_ASSERT_OK(db_get(&g_db, path, strlen(path), buf, sizeof(buf), &out_len, NULL, NULL));
    buf[out_len] = '\0';
    TEST_ASSERT_STR_CONTAINS(buf, "\"prefix\":\"0.0.0.0\"");
    TEST_ASSERT_STR_CONTAINS(buf, "\"nexthop\":\"192.168.1.1\"");

    net_teardown();
}

TEST(routing_add_network_routes)
{
    net_setup();

    char value[512];

    /* Add several network routes */
    struct {
        const char *path;
        const char *prefix;
        int prefix_len;
        const char *nexthop;
        const char *iface;
    } routes[] = {
        { "/routing/ipv4/10.0.0.0_8",     "10.0.0.0",    8,  "192.168.1.1", "eth0" },
        { "/routing/ipv4/172.16.0.0_12",  "172.16.0.0",  12, "192.168.1.1", "eth0" },
        { "/routing/ipv4/192.168.0.0_16", "192.168.0.0", 16, "192.168.1.1", "eth0" },
        { "/routing/ipv4/192.168.1.0_24", "192.168.1.0", 24, NULL,          "eth0" },
    };

    for (size_t i = 0; i < sizeof(routes) / sizeof(routes[0]); i++) {
        const char *nh = routes[i].nexthop ? routes[i].nexthop : "0.0.0.0";
        create_route_json(value, sizeof(value),
                          routes[i].prefix, routes[i].prefix_len,
                          nh, routes[i].iface,
                          100, 4);
        TEST_ASSERT_OK(db_set(&g_db, routes[i].path, strlen(routes[i].path),
                              value, strlen(value), 0, NULL));
    }

    /* List all IPv4 routes */
    char **paths = NULL;
    size_t count = 0;
    TEST_ASSERT_OK(db_list(&g_db, "/routing/ipv4", 13, &paths, &count, 100));
    TEST_ASSERT_EQ(4, count);
    db_list_free(paths, count);

    net_teardown();
}

TEST(routing_add_host_route)
{
    net_setup();

    char value[512];
    create_route_json(value, sizeof(value),
                      "8.8.8.8", 32,
                      "192.168.1.1", "eth0",
                      50, 4);

    const char *path = "/routing/ipv4/8.8.8.8_32";
    TEST_ASSERT_OK(db_set(&g_db, path, strlen(path), value, strlen(value), 0, NULL));

    /* Verify host route */
    char buf[1024];
    size_t out_len;
    TEST_ASSERT_OK(db_get(&g_db, path, strlen(path), buf, sizeof(buf), &out_len, NULL, NULL));
    buf[out_len] = '\0';
    TEST_ASSERT_STR_CONTAINS(buf, "\"prefix_len\":32");

    net_teardown();
}

TEST(routing_delete_route)
{
    net_setup();

    char value[512];
    create_route_json(value, sizeof(value),
                      "10.0.0.0", 8,
                      "192.168.1.1", "eth0",
                      100, 4);

    const char *path = "/routing/ipv4/10.0.0.0_8";
    TEST_ASSERT_OK(db_set(&g_db, path, strlen(path), value, strlen(value), 0, NULL));

    bool exists;
    TEST_ASSERT_OK(db_exists(&g_db, path, strlen(path), &exists));
    TEST_ASSERT_TRUE(exists);

    TEST_ASSERT_OK(db_delete(&g_db, path, strlen(path)));

    TEST_ASSERT_OK(db_exists(&g_db, path, strlen(path), &exists));
    TEST_ASSERT_FALSE(exists);

    net_teardown();
}

TEST(routing_update_route_metric)
{
    net_setup();

    char value[512];
    const char *path = "/routing/ipv4/10.0.0.0_8";

    /* Add route with metric 100 */
    create_route_json(value, sizeof(value),
                      "10.0.0.0", 8,
                      "192.168.1.1", "eth0",
                      100, 4);
    TEST_ASSERT_OK(db_set(&g_db, path, strlen(path), value, strlen(value), 0, NULL));

    /* Update with metric 200 */
    create_route_json(value, sizeof(value),
                      "10.0.0.0", 8,
                      "192.168.1.1", "eth0",
                      200, 4);
    TEST_ASSERT_OK(db_set(&g_db, path, strlen(path), value, strlen(value), 0, NULL));

    /* Verify updated metric */
    char buf[1024];
    size_t out_len;
    TEST_ASSERT_OK(db_get(&g_db, path, strlen(path), buf, sizeof(buf), &out_len, NULL, NULL));
    buf[out_len] = '\0';
    TEST_ASSERT_STR_CONTAINS(buf, "\"metric\":200");

    net_teardown();
}

/* ============================================
 * ECMP (Equal-Cost Multi-Path) Tests
 * ============================================ */

TEST(ecmp_two_path_route)
{
    net_setup();

    const char *nexthops[] = { "192.168.1.1", "192.168.2.1" };
    const char *interfaces[] = { "eth0", "eth1" };
    const int weights[] = { 1, 1 };

    char value[1024];
    create_ecmp_route_json(value, sizeof(value),
                           "10.0.0.0", 8,
                           nexthops, interfaces, weights, 2,
                           100);

    const char *path = "/routing/ipv4/10.0.0.0_8";
    TEST_ASSERT_OK(db_set(&g_db, path, strlen(path), value, strlen(value), 0, NULL));

    /* Verify ECMP route */
    char buf[2048];
    size_t out_len;
    TEST_ASSERT_OK(db_get(&g_db, path, strlen(path), buf, sizeof(buf), &out_len, NULL, NULL));
    buf[out_len] = '\0';
    TEST_ASSERT_STR_CONTAINS(buf, "\"type\":\"ecmp\"");
    TEST_ASSERT_STR_CONTAINS(buf, "\"nexthop\":\"192.168.1.1\"");
    TEST_ASSERT_STR_CONTAINS(buf, "\"nexthop\":\"192.168.2.1\"");

    net_teardown();
}

TEST(ecmp_four_path_route)
{
    net_setup();

    const char *nexthops[] = { "10.1.1.1", "10.2.2.1", "10.3.3.1", "10.4.4.1" };
    const char *interfaces[] = { "eth0", "eth1", "eth2", "eth3" };
    const int weights[] = { 1, 1, 1, 1 };

    char value[2048];
    create_ecmp_route_json(value, sizeof(value),
                           "0.0.0.0", 0,
                           nexthops, interfaces, weights, 4,
                           100);

    const char *path = "/routing/ipv4/default_ecmp";
    TEST_ASSERT_OK(db_set(&g_db, path, strlen(path), value, strlen(value), 0, NULL));

    /* Verify 4-way ECMP */
    char buf[4096];
    size_t out_len;
    TEST_ASSERT_OK(db_get(&g_db, path, strlen(path), buf, sizeof(buf), &out_len, NULL, NULL));
    buf[out_len] = '\0';
    TEST_ASSERT_STR_CONTAINS(buf, "\"nexthop\":\"10.1.1.1\"");
    TEST_ASSERT_STR_CONTAINS(buf, "\"nexthop\":\"10.4.4.1\"");

    net_teardown();
}

TEST(ecmp_weighted_paths)
{
    net_setup();

    const char *nexthops[] = { "192.168.1.1", "192.168.2.1", "192.168.3.1" };
    const char *interfaces[] = { "eth0", "eth1", "eth2" };
    const int weights[] = { 2, 1, 1 };  /* 50%, 25%, 25% distribution */

    char value[2048];
    create_ecmp_route_json(value, sizeof(value),
                           "10.0.0.0", 8,
                           nexthops, interfaces, weights, 3,
                           100);

    const char *path = "/routing/ipv4/10.0.0.0_8_weighted";
    TEST_ASSERT_OK(db_set(&g_db, path, strlen(path), value, strlen(value), 0, NULL));

    /* Verify weighted ECMP */
    char buf[2048];
    size_t out_len;
    TEST_ASSERT_OK(db_get(&g_db, path, strlen(path), buf, sizeof(buf), &out_len, NULL, NULL));
    buf[out_len] = '\0';
    TEST_ASSERT_STR_CONTAINS(buf, "\"weight\":2");
    TEST_ASSERT_STR_CONTAINS(buf, "\"weight\":1");

    net_teardown();
}

TEST(ecmp_add_remove_path)
{
    net_setup();

    const char *path = "/routing/ipv4/10.0.0.0_8";

    /* Start with 2 paths */
    const char *nexthops2[] = { "192.168.1.1", "192.168.2.1" };
    const char *interfaces2[] = { "eth0", "eth1" };
    const int weights2[] = { 1, 1 };

    char value[2048];
    create_ecmp_route_json(value, sizeof(value),
                           "10.0.0.0", 8,
                           nexthops2, interfaces2, weights2, 2,
                           100);
    TEST_ASSERT_OK(db_set(&g_db, path, strlen(path), value, strlen(value), 0, NULL));

    /* Upgrade to 3 paths */
    const char *nexthops3[] = { "192.168.1.1", "192.168.2.1", "192.168.3.1" };
    const char *interfaces3[] = { "eth0", "eth1", "eth2" };
    const int weights3[] = { 1, 1, 1 };

    create_ecmp_route_json(value, sizeof(value),
                           "10.0.0.0", 8,
                           nexthops3, interfaces3, weights3, 3,
                           100);
    TEST_ASSERT_OK(db_set(&g_db, path, strlen(path), value, strlen(value), 0, NULL));

    /* Verify 3 paths now */
    char buf[2048];
    size_t out_len;
    TEST_ASSERT_OK(db_get(&g_db, path, strlen(path), buf, sizeof(buf), &out_len, NULL, NULL));
    buf[out_len] = '\0';
    TEST_ASSERT_STR_CONTAINS(buf, "\"nexthop\":\"192.168.3.1\"");

    /* Downgrade to 1 path (no longer ECMP) */
    create_route_json(value, sizeof(value),
                      "10.0.0.0", 8,
                      "192.168.1.1", "eth0",
                      100, 4);
    TEST_ASSERT_OK(db_set(&g_db, path, strlen(path), value, strlen(value), 0, NULL));

    TEST_ASSERT_OK(db_get(&g_db, path, strlen(path), buf, sizeof(buf), &out_len, NULL, NULL));
    buf[out_len] = '\0';
    /* Should no longer have "ecmp" type */
    TEST_ASSERT_TRUE(strstr(buf, "\"type\":\"ecmp\"") == NULL);

    net_teardown();
}

/* ============================================
 * IPv6 Routing Tests
 * ============================================ */

TEST(routing_ipv6_default_route)
{
    net_setup();

    char value[512];
    snprintf(value, sizeof(value),
             "{"
             "\"prefix\":\"::\","
             "\"prefix_len\":0,"
             "\"nexthop\":\"fe80::1\","
             "\"interface\":\"eth0\","
             "\"metric\":1024,"
             "\"protocol\":9"
             "}");

    const char *path = "/routing/ipv6/default";
    TEST_ASSERT_OK(db_set(&g_db, path, strlen(path), value, strlen(value), 0, NULL));

    char buf[1024];
    size_t out_len;
    TEST_ASSERT_OK(db_get(&g_db, path, strlen(path), buf, sizeof(buf), &out_len, NULL, NULL));
    buf[out_len] = '\0';
    TEST_ASSERT_STR_CONTAINS(buf, "\"prefix\":\"::\"");
    TEST_ASSERT_STR_CONTAINS(buf, "\"nexthop\":\"fe80::1\"");

    net_teardown();
}

TEST(routing_ipv6_network_routes)
{
    net_setup();

    /* Use dashes instead of colons in paths (colons are invalid in paths) */
    struct {
        const char *path;
        const char *prefix;
        int prefix_len;
    } routes[] = {
        { "/routing/ipv6/2001-db8--_32",  "2001:db8::",  32 },
        { "/routing/ipv6/fd00--_8",       "fd00::",      8 },
        { "/routing/ipv6/fe80--_10",      "fe80::",      10 },
    };

    for (size_t i = 0; i < sizeof(routes) / sizeof(routes[0]); i++) {
        char value[512];
        snprintf(value, sizeof(value),
                 "{\"prefix\":\"%s\",\"prefix_len\":%d,\"interface\":\"eth0\",\"metric\":256}",
                 routes[i].prefix, routes[i].prefix_len);
        TEST_ASSERT_OK(db_set(&g_db, routes[i].path, strlen(routes[i].path),
                              value, strlen(value), 0, NULL));
    }

    char **paths = NULL;
    size_t count = 0;
    TEST_ASSERT_OK(db_list(&g_db, "/routing/ipv6", 13, &paths, &count, 100));
    TEST_ASSERT_EQ(3, count);
    db_list_free(paths, count);

    net_teardown();
}

/* ============================================
 * Network Interface Table Tests
 * ============================================ */

TEST(interface_add_loopback)
{
    net_setup();

    char value[1024];
    create_interface_json(value, sizeof(value),
                          "lo", "00:00:00:00:00:00",
                          "127.0.0.1", "::1",
                          65536, "up",
                          0, 0);

    const char *path = "/interfaces/lo";
    TEST_ASSERT_OK(db_set(&g_db, path, strlen(path), value, strlen(value), 0, NULL));

    char buf[2048];
    size_t out_len;
    TEST_ASSERT_OK(db_get(&g_db, path, strlen(path), buf, sizeof(buf), &out_len, NULL, NULL));
    buf[out_len] = '\0';
    TEST_ASSERT_STR_CONTAINS(buf, "\"name\":\"lo\"");
    TEST_ASSERT_STR_CONTAINS(buf, "\"mtu\":65536");

    net_teardown();
}

TEST(interface_add_ethernet)
{
    net_setup();

    char value[1024];
    create_interface_json(value, sizeof(value),
                          "eth0", "00:11:22:33:44:55",
                          "192.168.1.100", "fe80::211:22ff:fe33:4455",
                          1500, "up",
                          1234567890, 987654321);

    const char *path = "/interfaces/eth0";
    TEST_ASSERT_OK(db_set(&g_db, path, strlen(path), value, strlen(value), 0, NULL));

    char buf[2048];
    size_t out_len;
    TEST_ASSERT_OK(db_get(&g_db, path, strlen(path), buf, sizeof(buf), &out_len, NULL, NULL));
    buf[out_len] = '\0';
    TEST_ASSERT_STR_CONTAINS(buf, "\"mac\":\"00:11:22:33:44:55\"");
    TEST_ASSERT_STR_CONTAINS(buf, "\"ipv4\":\"192.168.1.100\"");

    net_teardown();
}

TEST(interface_multiple_interfaces)
{
    net_setup();

    const char *ifaces[] = { "lo", "eth0", "eth1", "eth2", "wlan0", "docker0" };
    const char *macs[] = {
        "00:00:00:00:00:00",
        "00:11:22:33:44:55",
        "00:11:22:33:44:56",
        "00:11:22:33:44:57",
        "aa:bb:cc:dd:ee:ff",
        "02:42:ac:11:00:01"
    };

    for (size_t i = 0; i < sizeof(ifaces) / sizeof(ifaces[0]); i++) {
        char path[64], value[1024];
        snprintf(path, sizeof(path), "/interfaces/%s", ifaces[i]);
        create_interface_json(value, sizeof(value),
                              ifaces[i], macs[i],
                              "0.0.0.0", "::",
                              1500, "up",
                              0, 0);
        TEST_ASSERT_OK(db_set(&g_db, path, strlen(path), value, strlen(value), 0, NULL));
    }

    char **paths = NULL;
    size_t count = 0;
    TEST_ASSERT_OK(db_list(&g_db, "/interfaces", 11, &paths, &count, 100));
    TEST_ASSERT_EQ(6, count);
    db_list_free(paths, count);

    net_teardown();
}

TEST(interface_state_change)
{
    net_setup();

    char value[1024];
    const char *path = "/interfaces/eth0";

    /* Interface up */
    create_interface_json(value, sizeof(value),
                          "eth0", "00:11:22:33:44:55",
                          "192.168.1.100", "fe80::1",
                          1500, "up",
                          0, 0);
    TEST_ASSERT_OK(db_set(&g_db, path, strlen(path), value, strlen(value), 0, NULL));

    /* Interface down */
    create_interface_json(value, sizeof(value),
                          "eth0", "00:11:22:33:44:55",
                          "192.168.1.100", "fe80::1",
                          1500, "down",
                          0, 0);
    TEST_ASSERT_OK(db_set(&g_db, path, strlen(path), value, strlen(value), 0, NULL));

    char buf[2048];
    size_t out_len;
    TEST_ASSERT_OK(db_get(&g_db, path, strlen(path), buf, sizeof(buf), &out_len, NULL, NULL));
    buf[out_len] = '\0';
    TEST_ASSERT_STR_CONTAINS(buf, "\"state\":\"down\"");

    net_teardown();
}

TEST(interface_update_stats)
{
    net_setup();

    char value[1024];
    const char *path = "/interfaces/eth0";

    /* Initial stats */
    create_interface_json(value, sizeof(value),
                          "eth0", "00:11:22:33:44:55",
                          "192.168.1.100", "fe80::1",
                          1500, "up",
                          1000, 500);
    TEST_ASSERT_OK(db_set(&g_db, path, strlen(path), value, strlen(value), 0, NULL));

    /* Updated stats */
    create_interface_json(value, sizeof(value),
                          "eth0", "00:11:22:33:44:55",
                          "192.168.1.100", "fe80::1",
                          1500, "up",
                          2000, 1000);
    TEST_ASSERT_OK(db_set(&g_db, path, strlen(path), value, strlen(value), 0, NULL));

    char buf[2048];
    size_t out_len;
    TEST_ASSERT_OK(db_get(&g_db, path, strlen(path), buf, sizeof(buf), &out_len, NULL, NULL));
    buf[out_len] = '\0';
    TEST_ASSERT_STR_CONTAINS(buf, "\"rx_bytes\":2000");
    TEST_ASSERT_STR_CONTAINS(buf, "\"tx_bytes\":1000");

    net_teardown();
}

TEST(interface_vlan_subinterfaces)
{
    net_setup();

    /* Add parent interface */
    char value[1024];
    create_interface_json(value, sizeof(value),
                          "eth0", "00:11:22:33:44:55",
                          "0.0.0.0", "::",
                          1500, "up",
                          0, 0);
    TEST_ASSERT_OK(db_set(&g_db, "/interfaces/eth0", 16, value, strlen(value), 0, NULL));

    /* Add VLAN sub-interfaces */
    struct {
        const char *name;
        int vlan_id;
        const char *ip;
    } vlans[] = {
        { "eth0.10",  10,  "10.10.10.1" },
        { "eth0.20",  20,  "10.20.20.1" },
        { "eth0.100", 100, "10.100.100.1" },
    };

    for (size_t i = 0; i < sizeof(vlans) / sizeof(vlans[0]); i++) {
        char path[64];
        snprintf(path, sizeof(path), "/interfaces/%s", vlans[i].name);

        snprintf(value, sizeof(value),
                 "{"
                 "\"name\":\"%s\","
                 "\"parent\":\"eth0\","
                 "\"vlan_id\":%d,"
                 "\"mac\":\"00:11:22:33:44:55\","
                 "\"ipv4\":\"%s\","
                 "\"mtu\":1500,"
                 "\"state\":\"up\""
                 "}",
                 vlans[i].name, vlans[i].vlan_id, vlans[i].ip);

        TEST_ASSERT_OK(db_set(&g_db, path, strlen(path), value, strlen(value), 0, NULL));
    }

    /* Verify VLAN interfaces */
    char buf[1024];
    size_t out_len;
    TEST_ASSERT_OK(db_get(&g_db, "/interfaces/eth0.100", 20, buf, sizeof(buf), &out_len, NULL, NULL));
    buf[out_len] = '\0';
    TEST_ASSERT_STR_CONTAINS(buf, "\"vlan_id\":100");
    TEST_ASSERT_STR_CONTAINS(buf, "\"parent\":\"eth0\"");

    net_teardown();
}

/* ============================================
 * ARP Table Tests
 * ============================================ */

TEST(arp_add_entry)
{
    net_setup();

    char value[512];
    create_arp_json(value, sizeof(value),
                    "192.168.1.1", "00:11:22:33:44:55",
                    "eth0", "reachable",
                    30);

    const char *path = "/arp/192.168.1.1";
    TEST_ASSERT_OK(db_set(&g_db, path, strlen(path), value, strlen(value), 0, NULL));

    char buf[1024];
    size_t out_len;
    TEST_ASSERT_OK(db_get(&g_db, path, strlen(path), buf, sizeof(buf), &out_len, NULL, NULL));
    buf[out_len] = '\0';
    TEST_ASSERT_STR_CONTAINS(buf, "\"ip\":\"192.168.1.1\"");
    TEST_ASSERT_STR_CONTAINS(buf, "\"mac\":\"00:11:22:33:44:55\"");

    net_teardown();
}

TEST(arp_multiple_entries)
{
    net_setup();

    struct {
        const char *ip;
        const char *mac;
        const char *state;
    } entries[] = {
        { "192.168.1.1",   "00:11:22:33:44:01", "reachable" },
        { "192.168.1.2",   "00:11:22:33:44:02", "reachable" },
        { "192.168.1.100", "00:11:22:33:44:64", "reachable" },
        { "192.168.1.254", "00:11:22:33:44:fe", "stale" },
        { "10.0.0.1",      "aa:bb:cc:dd:ee:01", "reachable" },
    };

    for (size_t i = 0; i < sizeof(entries) / sizeof(entries[0]); i++) {
        char path[64], value[512];
        snprintf(path, sizeof(path), "/arp/%s", entries[i].ip);
        create_arp_json(value, sizeof(value),
                        entries[i].ip, entries[i].mac,
                        "eth0", entries[i].state,
                        60);
        TEST_ASSERT_OK(db_set(&g_db, path, strlen(path), value, strlen(value), 0, NULL));
    }

    char **paths = NULL;
    size_t count = 0;
    TEST_ASSERT_OK(db_list(&g_db, "/arp", 4, &paths, &count, 100));
    TEST_ASSERT_EQ(5, count);
    db_list_free(paths, count);

    net_teardown();
}

TEST(arp_state_transition)
{
    net_setup();

    char value[512];
    const char *path = "/arp/192.168.1.1";

    /* Initial: incomplete */
    snprintf(value, sizeof(value),
             "{\"ip\":\"192.168.1.1\",\"mac\":\"\",\"interface\":\"eth0\","
             "\"state\":\"incomplete\",\"age\":0}");
    TEST_ASSERT_OK(db_set(&g_db, path, strlen(path), value, strlen(value), 0, NULL));

    /* Transition to reachable */
    create_arp_json(value, sizeof(value),
                    "192.168.1.1", "00:11:22:33:44:55",
                    "eth0", "reachable",
                    0);
    TEST_ASSERT_OK(db_set(&g_db, path, strlen(path), value, strlen(value), 0, NULL));

    char buf[1024];
    size_t out_len;
    TEST_ASSERT_OK(db_get(&g_db, path, strlen(path), buf, sizeof(buf), &out_len, NULL, NULL));
    buf[out_len] = '\0';
    TEST_ASSERT_STR_CONTAINS(buf, "\"state\":\"reachable\"");
    TEST_ASSERT_STR_CONTAINS(buf, "\"mac\":\"00:11:22:33:44:55\"");

    /* Transition to stale */
    create_arp_json(value, sizeof(value),
                    "192.168.1.1", "00:11:22:33:44:55",
                    "eth0", "stale",
                    300);
    TEST_ASSERT_OK(db_set(&g_db, path, strlen(path), value, strlen(value), 0, NULL));

    TEST_ASSERT_OK(db_get(&g_db, path, strlen(path), buf, sizeof(buf), &out_len, NULL, NULL));
    buf[out_len] = '\0';
    TEST_ASSERT_STR_CONTAINS(buf, "\"state\":\"stale\"");

    net_teardown();
}

TEST(arp_delete_entry)
{
    net_setup();

    char value[512];
    const char *path = "/arp/192.168.1.1";

    create_arp_json(value, sizeof(value),
                    "192.168.1.1", "00:11:22:33:44:55",
                    "eth0", "reachable",
                    30);
    TEST_ASSERT_OK(db_set(&g_db, path, strlen(path), value, strlen(value), 0, NULL));

    bool exists;
    TEST_ASSERT_OK(db_exists(&g_db, path, strlen(path), &exists));
    TEST_ASSERT_TRUE(exists);

    TEST_ASSERT_OK(db_delete(&g_db, path, strlen(path)));

    TEST_ASSERT_OK(db_exists(&g_db, path, strlen(path), &exists));
    TEST_ASSERT_FALSE(exists);

    net_teardown();
}

TEST(arp_flush_interface)
{
    net_setup();

    /* Add ARP entries for multiple interfaces */
    struct {
        const char *ip;
        const char *iface;
    } entries[] = {
        { "192.168.1.1", "eth0" },
        { "192.168.1.2", "eth0" },
        { "192.168.1.3", "eth0" },
        { "10.0.0.1",    "eth1" },
        { "10.0.0.2",    "eth1" },
    };

    for (size_t i = 0; i < sizeof(entries) / sizeof(entries[0]); i++) {
        char path[64], value[512];
        snprintf(path, sizeof(path), "/arp/%s/%s", entries[i].iface, entries[i].ip);
        create_arp_json(value, sizeof(value),
                        entries[i].ip, "00:11:22:33:44:55",
                        entries[i].iface, "reachable",
                        30);
        TEST_ASSERT_OK(db_set(&g_db, path, strlen(path), value, strlen(value), 0, NULL));
    }

    /* Verify all entries exist before deletion */
    char **all_paths = NULL;
    size_t all_count = 0;
    TEST_ASSERT_OK(db_list(&g_db, "/arp", 4, &all_paths, &all_count, 100));
    TEST_ASSERT_TRUE(all_count >= 5);  /* At least our 5 entries */
    db_list_free(all_paths, all_count);

    /* Delete all ARP entries for eth0 using individual deletes */
    const char *eth0_paths[] = {
        "/arp/eth0/192.168.1.1",
        "/arp/eth0/192.168.1.2",
        "/arp/eth0/192.168.1.3",
    };
    for (size_t i = 0; i < 3; i++) {
        TEST_ASSERT_OK(db_delete(&g_db, eth0_paths[i], strlen(eth0_paths[i])));
    }

    /* Verify eth0 entries are gone */
    bool exists = false;
    TEST_ASSERT_OK(db_exists(&g_db, "/arp/eth0/192.168.1.1",
                              strlen("/arp/eth0/192.168.1.1"), &exists));
    TEST_ASSERT_FALSE(exists);

    /* Verify eth1 entries still exist */
    exists = false;
    TEST_ASSERT_OK(db_exists(&g_db, "/arp/eth1/10.0.0.1",
                              strlen("/arp/eth1/10.0.0.1"), &exists));
    TEST_ASSERT_TRUE(exists);

    TEST_ASSERT_OK(db_exists(&g_db, "/arp/eth1/10.0.0.2",
                              strlen("/arp/eth1/10.0.0.2"), &exists));
    TEST_ASSERT_TRUE(exists);

    net_teardown();
}

/* ============================================
 * IPv6 Neighbor Table Tests
 * ============================================ */

TEST(neighbor_ipv6_entries)
{
    net_setup();

    struct {
        const char *ip;
        const char *mac;
    } neighbors[] = {
        { "fe80::1",            "00:11:22:33:44:01" },
        { "fe80::2",            "00:11:22:33:44:02" },
        { "2001:db8::1",        "00:11:22:33:44:03" },
        { "2001:db8:1:2:3:4:5:6", "00:11:22:33:44:04" },
    };

    for (size_t i = 0; i < sizeof(neighbors) / sizeof(neighbors[0]); i++) {
        char path[128], value[512];
        /* Use URL-safe encoding for IPv6 addresses in paths */
        char safe_ip[64];
        strncpy(safe_ip, neighbors[i].ip, sizeof(safe_ip) - 1);
        safe_ip[sizeof(safe_ip) - 1] = '\0';
        for (char *p = safe_ip; *p; p++) {
            if (*p == ':') *p = '_';
        }

        snprintf(path, sizeof(path), "/neighbor/ipv6/%s", safe_ip);
        snprintf(value, sizeof(value),
                 "{\"ip\":\"%s\",\"mac\":\"%s\",\"interface\":\"eth0\","
                 "\"state\":\"reachable\",\"router\":false}",
                 neighbors[i].ip, neighbors[i].mac);
        TEST_ASSERT_OK(db_set(&g_db, path, strlen(path), value, strlen(value), 0, NULL));
    }

    char **paths = NULL;
    size_t count = 0;
    TEST_ASSERT_OK(db_list(&g_db, "/neighbor/ipv6", 14, &paths, &count, 100));
    TEST_ASSERT_EQ(4, count);
    db_list_free(paths, count);

    net_teardown();
}

/* ============================================
 * Transaction Tests for Atomic Updates
 * ============================================ */

TEST(transaction_route_failover)
{
    net_setup();

    int txn_id;
    TEST_ASSERT_OK(db_txn_begin(&g_db, 1, &txn_id));

    /* Atomic route failover: delete old route, add new route */
    char old_route[512], new_route[512];

    create_route_json(old_route, sizeof(old_route),
                      "10.0.0.0", 8, "192.168.1.1", "eth0", 100, 4);
    create_route_json(new_route, sizeof(new_route),
                      "10.0.0.0", 8, "192.168.2.1", "eth1", 100, 4);

    /* First set up the old route outside transaction */
    db_set(&g_db, "/routing/ipv4/10.0.0.0_8", 23, old_route, strlen(old_route), 0, NULL);

    /* Now do atomic failover in transaction */
    TEST_ASSERT_OK(db_txn_set(&g_db, txn_id, "/routing/ipv4/10.0.0.0_8", 23,
                              new_route, strlen(new_route), 0));

    /* Add backup route notification */
    const char *notify = "{\"event\":\"route_failover\",\"prefix\":\"10.0.0.0/8\"}";
    TEST_ASSERT_OK(db_txn_set(&g_db, txn_id, "/events/route_change", 20,
                              notify, strlen(notify), 0));

    uint64_t seq;
    int ops;
    TEST_ASSERT_OK(db_txn_commit(&g_db, txn_id, &seq, &ops));
    TEST_ASSERT_EQ(2, ops);

    /* Verify new route is in place */
    char buf[1024];
    size_t out_len;
    TEST_ASSERT_OK(db_get(&g_db, "/routing/ipv4/10.0.0.0_8", 23, buf, sizeof(buf), &out_len, NULL, NULL));
    buf[out_len] = '\0';
    TEST_ASSERT_STR_CONTAINS(buf, "\"nexthop\":\"192.168.2.1\"");

    net_teardown();
}

TEST(transaction_interface_config)
{
    net_setup();

    int txn_id;
    TEST_ASSERT_OK(db_txn_begin(&g_db, 1, &txn_id));

    /* Atomic interface configuration: interface + route + arp */
    char iface_json[1024], route_json[512], arp_json[512];

    create_interface_json(iface_json, sizeof(iface_json),
                          "eth2", "00:11:22:33:44:77",
                          "10.10.10.1", "fe80::1",
                          1500, "up",
                          0, 0);

    create_route_json(route_json, sizeof(route_json),
                      "10.10.10.0", 24, "0.0.0.0", "eth2", 100, 4);

    create_arp_json(arp_json, sizeof(arp_json),
                    "10.10.10.254", "00:aa:bb:cc:dd:ee",
                    "eth2", "permanent",
                    0);

    TEST_ASSERT_OK(db_txn_set(&g_db, txn_id, "/interfaces/eth2", 16,
                              iface_json, strlen(iface_json), 0));
    TEST_ASSERT_OK(db_txn_set(&g_db, txn_id, "/routing/ipv4/10.10.10.0_24", 25,
                              route_json, strlen(route_json), 0));
    TEST_ASSERT_OK(db_txn_set(&g_db, txn_id, "/arp/10.10.10.254", 17,
                              arp_json, strlen(arp_json), 0));

    uint64_t seq;
    int ops;
    TEST_ASSERT_OK(db_txn_commit(&g_db, txn_id, &seq, &ops));
    TEST_ASSERT_EQ(3, ops);

    /* Verify all three entries exist */
    bool exists;
    TEST_ASSERT_OK(db_exists(&g_db, "/interfaces/eth2", 16, &exists));
    TEST_ASSERT_TRUE(exists);
    TEST_ASSERT_OK(db_exists(&g_db, "/routing/ipv4/10.10.10.0_24", 25, &exists));
    TEST_ASSERT_TRUE(exists);
    TEST_ASSERT_OK(db_exists(&g_db, "/arp/10.10.10.254", 17, &exists));
    TEST_ASSERT_TRUE(exists);

    net_teardown();
}

/* ============================================
 * Subscription Tests for Network Events
 * ============================================ */

TEST(subscription_route_changes)
{
    struct sub_manager mgr;
    TEST_ASSERT_OK(sub_manager_init(&mgr));

    /* Multiple clients subscribe to different route prefixes */
    int sub1, sub2, sub3;
    TEST_ASSERT_OK(sub_add(&mgr, 1, "/routing/ipv4/*", 15, &sub1));
    TEST_ASSERT_OK(sub_add(&mgr, 2, "/routing/ipv6/*", 15, &sub2));
    TEST_ASSERT_OK(sub_add(&mgr, 3, "/routing/*", 10, &sub3));

    int client_ids[10], sub_ids[10];

    /* IPv4 route change should notify clients 1 and 3 */
    int matches = sub_match(&mgr, "/routing/ipv4/10.0.0.0_8", 23, client_ids, sub_ids, 10);
    TEST_ASSERT_GE(matches, 1);

    /* IPv6 route change should notify clients 2 and 3 */
    matches = sub_match(&mgr, "/routing/ipv6/2001_db8", 21, client_ids, sub_ids, 10);
    TEST_ASSERT_GE(matches, 1);

    sub_manager_shutdown(&mgr);
}

TEST(subscription_interface_events)
{
    struct sub_manager mgr;
    TEST_ASSERT_OK(sub_manager_init(&mgr));

    int sub1, sub2;
    TEST_ASSERT_OK(sub_add(&mgr, 1, "/interfaces/eth0", 16, &sub1));  /* Exact match */
    TEST_ASSERT_OK(sub_add(&mgr, 2, "/interfaces/*", 13, &sub2));     /* All interfaces */

    int client_ids[10], sub_ids[10];

    /* eth0 change should notify both */
    int matches = sub_match(&mgr, "/interfaces/eth0", 16, client_ids, sub_ids, 10);
    TEST_ASSERT_GE(matches, 1);

    /* eth1 change should only notify client 2 */
    matches = sub_match(&mgr, "/interfaces/eth1", 16, client_ids, sub_ids, 10);
    TEST_ASSERT_EQ(1, matches);
    TEST_ASSERT_EQ(2, client_ids[0]);

    sub_manager_shutdown(&mgr);
}

TEST_MAIN()
