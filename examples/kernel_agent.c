/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * kernel_agent.c - Example kernel module that uses kqsysdb
 *
 * This example demonstrates how kernel modules can:
 * - Read and write to the database
 * - Subscribe to changes
 * - React to state changes from userspace
 *
 * Build: Add to kernel tree or use out-of-tree build
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: GPL-2.0
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/workqueue.h>

/* Include the kqsysdb header */
#include "../kernel/kqsysdb.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("QSysDB Project");
MODULE_DESCRIPTION("Example kernel module using QSysDB");
MODULE_VERSION("1.0");

#define AGENT_NAME "kernel-example"
#define AGENT_PATH "/agents/" AGENT_NAME

/* State */
static struct timer_list update_timer;
static struct workqueue_struct *work_queue;
static struct work_struct update_work;
static int subscription_id = -1;
static atomic_t counter = ATOMIC_INIT(0);
static bool initialized = false;

/*
 * Subscription callback - called when watched paths change
 * Note: Called in softirq context, must be fast and non-blocking
 */
static void on_config_change(const char *path, const char *value,
                              int event_type, void *data)
{
    pr_info("kqsysdb_example: config change: %s (event=%d)\n", path, event_type);

    if (value) {
        pr_info("kqsysdb_example: new value: %.64s%s\n",
                value, strlen(value) > 64 ? "..." : "");
    }

    /* Could trigger work here to react to changes */
}

/*
 * Work function to publish updates
 */
static void publish_update(struct work_struct *work)
{
    char value[256];
    int count;
    int ret;

    if (!kqsysdb_ready()) {
        pr_debug("kqsysdb_example: database not ready\n");
        return;
    }

    count = atomic_inc_return(&counter);

    /* Publish our status */
    snprintf(value, sizeof(value),
             "{\"state\":\"running\",\"counter\":%d,\"jiffies\":%lu}",
             count, jiffies);

    ret = kqsysdb_set(AGENT_PATH "/status", value);
    if (ret != 0) {
        pr_warn("kqsysdb_example: failed to publish status: %d\n", ret);
    }
}

/*
 * Timer callback - schedules work to publish updates
 */
static void timer_callback(struct timer_list *t)
{
    if (initialized && work_queue) {
        queue_work(work_queue, &update_work);
    }

    /* Reschedule timer for 5 seconds */
    mod_timer(&update_timer, jiffies + 5 * HZ);
}

/*
 * Register this agent in the database
 */
static int register_agent(void)
{
    char value[256];
    int ret;

    if (!kqsysdb_ready()) {
        pr_info("kqsysdb_example: waiting for database...\n");
        return -EAGAIN;
    }

    /* Publish agent info */
    snprintf(value, sizeof(value),
             "{\"name\":\"%s\",\"type\":\"kernel\",\"version\":\"1.0.0\"}",
             AGENT_NAME);

    ret = kqsysdb_set(AGENT_PATH "/info", value);
    if (ret != 0) {
        pr_err("kqsysdb_example: failed to set info: %d\n", ret);
        return ret;
    }

    /* Subscribe to configuration changes */
    subscription_id = kqsysdb_subscribe("/config/*", on_config_change, NULL);
    if (subscription_id < 0) {
        pr_warn("kqsysdb_example: failed to subscribe: %d\n", subscription_id);
        /* Continue anyway - subscription is optional */
    } else {
        pr_info("kqsysdb_example: subscribed with id %d\n", subscription_id);
    }

    /* Initial status publish */
    publish_update(&update_work);

    return 0;
}

/*
 * Unregister this agent
 */
static void unregister_agent(void)
{
    char value[128];

    if (subscription_id >= 0) {
        kqsysdb_unsubscribe(subscription_id);
        subscription_id = -1;
    }

    if (kqsysdb_ready()) {
        /* Mark as stopping */
        snprintf(value, sizeof(value),
                 "{\"state\":\"stopped\",\"counter\":%d}",
                 atomic_read(&counter));
        kqsysdb_set(AGENT_PATH "/status", value);
    }
}

/*
 * Module initialization
 */
static int __init kqsysdb_example_init(void)
{
    int ret;

    pr_info("kqsysdb_example: initializing\n");

    /* Create workqueue for async updates */
    work_queue = create_singlethread_workqueue("kqsysdb_example");
    if (!work_queue) {
        pr_err("kqsysdb_example: failed to create workqueue\n");
        return -ENOMEM;
    }

    INIT_WORK(&update_work, publish_update);

    /* Setup timer */
    timer_setup(&update_timer, timer_callback, 0);

    /* Try to register (may fail if daemon not ready) */
    ret = register_agent();
    if (ret == -EAGAIN) {
        pr_info("kqsysdb_example: will retry registration via timer\n");
    } else if (ret != 0) {
        pr_err("kqsysdb_example: registration failed: %d\n", ret);
        destroy_workqueue(work_queue);
        return ret;
    }

    initialized = true;

    /* Start periodic timer */
    mod_timer(&update_timer, jiffies + HZ);

    pr_info("kqsysdb_example: initialized\n");
    return 0;
}

/*
 * Module cleanup
 */
static void __exit kqsysdb_example_exit(void)
{
    pr_info("kqsysdb_example: exiting\n");

    initialized = false;

    /* Stop timer */
    del_timer_sync(&update_timer);

    /* Flush and destroy workqueue */
    if (work_queue) {
        flush_workqueue(work_queue);
        destroy_workqueue(work_queue);
    }

    /* Unregister from database */
    unregister_agent();

    pr_info("kqsysdb_example: exited\n");
}

module_init(kqsysdb_example_init);
module_exit(kqsysdb_example_exit);
