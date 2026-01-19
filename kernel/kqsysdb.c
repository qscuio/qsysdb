/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * kqsysdb.c - Main kernel module implementation
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: GPL-2.0
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/workqueue.h>
#include <net/genetlink.h>

#include "kqsysdb.h"

#define DEVICE_NAME     "qsysdb"
#define CLASS_NAME      "qsysdb"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("QSysDB Project");
MODULE_DESCRIPTION("QSysDB Kernel Module - Hierarchical State Database");
MODULE_VERSION("1.0");

/*
 * Global state
 */
static struct {
    /* Character device */
    int major;
    struct class *class;
    struct device *device;
    struct cdev cdev;

    /* Shared memory mapping */
    void __iomem *shm_base;
    size_t shm_size;
    struct page **shm_pages;
    int shm_npages;
    bool shm_mapped;

    /* Synchronization */
    spinlock_t lock;
    struct mutex shm_mutex;

    /* Subscriptions */
    struct list_head subscriptions;
    int next_sub_id;
    spinlock_t sub_lock;

    /* Netlink */
    bool netlink_ready;

    /* Statistics */
    atomic64_t total_reads;
    atomic64_t total_writes;

    /* Ready state */
    atomic_t ready;
} kqsysdb_state;

/*
 * Shared memory header (must match userspace)
 */
struct kqsysdb_shm_header {
    u32 magic;
    u32 version;
    u64 size;
    u64 sequence;
    u32 index_offset;
    u32 index_size;
    u32 data_offset;
    u32 data_size;
    u32 ring_offset;
    u32 ring_size;
    u32 data_used;
    u32 entry_count;
    u32 node_count;
    u32 lock_state;
    u32 writer_pid;
    u64 write_sequence;
    u64 total_sets;
    u64 total_gets;
    u64 total_deletes;
    u64 total_notifications;
    u8 reserved[64];
    u8 pthread_lock[64];
};

/*
 * Database entry (must match userspace)
 */
struct kqsysdb_entry {
    u32 path_hash;
    u16 path_len;
    u16 value_len;
    u64 version;
    u64 timestamp_ns;
    u32 flags;
    u32 next_offset;
    char data[];
};

#define KQSYSDB_FLAG_DELETED    0x00000001

/*
 * Forward declarations
 */
static int kqsysdb_genl_init(void);
static void kqsysdb_genl_exit(void);
static int kqsysdb_notify_userspace(const char *path, int event_type);

/*
 * Simple FNV-1a hash
 */
static u32 hash_path(const char *path, size_t len)
{
    u32 hash = 2166136261u;
    while (len--) {
        hash ^= (u8)*path++;
        hash *= 16777619u;
    }
    return hash;
}

/*
 * Spinlock operations for SHM
 */
static void shm_lock(struct kqsysdb_shm_header *hdr)
{
    while (xchg(&hdr->lock_state, 1) != 0) {
        cpu_relax();
    }
    smp_mb();
}

static void shm_unlock(struct kqsysdb_shm_header *hdr)
{
    smp_mb();
    WRITE_ONCE(hdr->lock_state, 0);
}

/*
 * Seqlock helpers
 */
static u64 shm_read_begin(struct kqsysdb_shm_header *hdr)
{
    u64 seq;
    do {
        seq = READ_ONCE(hdr->write_sequence);
    } while (seq & 1);
    smp_rmb();
    return seq;
}

static bool shm_read_retry(struct kqsysdb_shm_header *hdr, u64 start_seq)
{
    smp_rmb();
    return READ_ONCE(hdr->write_sequence) != start_seq;
}

static void shm_write_begin(struct kqsysdb_shm_header *hdr)
{
    WRITE_ONCE(hdr->write_sequence, hdr->write_sequence + 1);
    smp_wmb();
}

static void shm_write_end(struct kqsysdb_shm_header *hdr)
{
    smp_wmb();
    WRITE_ONCE(hdr->write_sequence, hdr->write_sequence + 1);
}

/*
 * Simple radix tree lookup (simplified version)
 * In a full implementation, this would be more complete
 */
static struct kqsysdb_entry *shm_lookup(const char *path, size_t path_len)
{
    struct kqsysdb_shm_header *hdr;
    void *data_base;
    u32 hash;
    u32 offset;

    if (!kqsysdb_state.shm_mapped || !kqsysdb_state.shm_base)
        return NULL;

    hdr = (struct kqsysdb_shm_header *)kqsysdb_state.shm_base;
    if (hdr->magic != QSYSDB_MAGIC)
        return NULL;

    data_base = kqsysdb_state.shm_base + hdr->data_offset;
    hash = hash_path(path, path_len);

    /* Linear scan through entries (simplified - real impl uses radix tree) */
    offset = 0;
    while (offset < hdr->data_used) {
        struct kqsysdb_entry *entry = data_base + offset;

        if (entry->path_len == 0)
            break;

        if (!(entry->flags & KQSYSDB_FLAG_DELETED) &&
            entry->path_hash == hash &&
            entry->path_len == path_len &&
            memcmp(entry->data, path, path_len) == 0) {
            return entry;
        }

        /* Move to next entry */
        offset += sizeof(*entry) + entry->path_len + 1 + entry->value_len + 1;
        offset = ALIGN(offset, 8);
    }

    return NULL;
}

/*
 * Public API: kqsysdb_get
 */
int kqsysdb_get(const char *path, char *buf, size_t buflen)
{
    struct kqsysdb_shm_header *hdr;
    struct kqsysdb_entry *entry;
    size_t path_len;
    size_t copy_len;
    u64 seq;
    int ret = KQSYSDB_ERR_NOTFOUND;

    if (!path || !buf || buflen == 0)
        return KQSYSDB_ERR_INVALID;

    if (!atomic_read(&kqsysdb_state.ready))
        return KQSYSDB_ERR_NOTREADY;

    path_len = strlen(path);
    if (path_len == 0 || path_len >= QSYSDB_MAX_PATH)
        return KQSYSDB_ERR_BADPATH;

    hdr = (struct kqsysdb_shm_header *)kqsysdb_state.shm_base;

    /* Use seqlock for consistent read */
    do {
        seq = shm_read_begin(hdr);

        entry = shm_lookup(path, path_len);
        if (!entry) {
            ret = KQSYSDB_ERR_NOTFOUND;
            continue;
        }

        /* Copy value */
        copy_len = entry->value_len;
        if (copy_len >= buflen)
            copy_len = buflen - 1;

        memcpy(buf, entry->data + entry->path_len + 1, copy_len);
        buf[copy_len] = '\0';

        ret = (int)copy_len;

    } while (shm_read_retry(hdr, seq));

    if (ret >= 0)
        atomic64_inc(&kqsysdb_state.total_reads);

    return ret;
}
EXPORT_SYMBOL(kqsysdb_get);

/*
 * Public API: kqsysdb_set
 */
int kqsysdb_set(const char *path, const char *json_value)
{
    struct kqsysdb_shm_header *hdr;
    struct kqsysdb_entry *entry;
    void *data_base;
    size_t path_len, value_len;
    size_t entry_size;
    u32 offset;
    int ret = KQSYSDB_OK;

    if (!path || !json_value)
        return KQSYSDB_ERR_INVALID;

    if (!atomic_read(&kqsysdb_state.ready))
        return KQSYSDB_ERR_NOTREADY;

    path_len = strlen(path);
    value_len = strlen(json_value);

    if (path_len == 0 || path_len >= QSYSDB_MAX_PATH)
        return KQSYSDB_ERR_BADPATH;

    if (value_len >= QSYSDB_MAX_VALUE)
        return KQSYSDB_ERR_TOOBIG;

    hdr = (struct kqsysdb_shm_header *)kqsysdb_state.shm_base;
    data_base = kqsysdb_state.shm_base + hdr->data_offset;

    mutex_lock(&kqsysdb_state.shm_mutex);
    shm_lock(hdr);
    shm_write_begin(hdr);

    /* Check if entry exists */
    entry = shm_lookup(path, path_len);
    if (entry) {
        /* Update existing entry if value fits */
        if (value_len <= entry->value_len) {
            memcpy(entry->data + entry->path_len + 1, json_value, value_len);
            entry->data[entry->path_len + 1 + value_len] = '\0';
            entry->value_len = value_len;
            entry->version++;
            entry->timestamp_ns = ktime_get_ns();
            hdr->total_sets++;
            ret = KQSYSDB_OK;
        } else {
            /* Mark old entry as deleted and create new one */
            entry->flags |= KQSYSDB_FLAG_DELETED;
            entry = NULL;
        }
    }

    if (!entry) {
        /* Create new entry */
        entry_size = sizeof(struct kqsysdb_entry) + path_len + 1 + value_len + 1;
        entry_size = ALIGN(entry_size, 8);

        offset = hdr->data_used;
        if (offset + entry_size > hdr->data_size) {
            ret = KQSYSDB_ERR_FULL;
        } else {
            entry = data_base + offset;
            memset(entry, 0, sizeof(*entry));

            entry->path_hash = hash_path(path, path_len);
            entry->path_len = path_len;
            entry->value_len = value_len;
            entry->version = 1;
            entry->timestamp_ns = ktime_get_ns();
            entry->flags = 0;

            memcpy(entry->data, path, path_len);
            entry->data[path_len] = '\0';
            memcpy(entry->data + path_len + 1, json_value, value_len);
            entry->data[path_len + 1 + value_len] = '\0';

            hdr->data_used = offset + entry_size;
            hdr->entry_count++;
            hdr->total_sets++;
            hdr->sequence++;

            ret = KQSYSDB_OK;
        }
    }

    shm_write_end(hdr);
    shm_unlock(hdr);
    mutex_unlock(&kqsysdb_state.shm_mutex);

    if (ret == KQSYSDB_OK) {
        atomic64_inc(&kqsysdb_state.total_writes);
        /* Notify userspace daemon of the change */
        kqsysdb_notify_userspace(path, entry ? KQSYSDB_EVENT_UPDATE : KQSYSDB_EVENT_CREATE);
    }

    return ret;
}
EXPORT_SYMBOL(kqsysdb_set);

/*
 * Public API: kqsysdb_delete
 */
int kqsysdb_delete(const char *path)
{
    struct kqsysdb_shm_header *hdr;
    struct kqsysdb_entry *entry;
    size_t path_len;
    int ret = KQSYSDB_ERR_NOTFOUND;

    if (!path)
        return KQSYSDB_ERR_INVALID;

    if (!atomic_read(&kqsysdb_state.ready))
        return KQSYSDB_ERR_NOTREADY;

    path_len = strlen(path);
    if (path_len == 0 || path_len >= QSYSDB_MAX_PATH)
        return KQSYSDB_ERR_BADPATH;

    hdr = (struct kqsysdb_shm_header *)kqsysdb_state.shm_base;

    mutex_lock(&kqsysdb_state.shm_mutex);
    shm_lock(hdr);
    shm_write_begin(hdr);

    entry = shm_lookup(path, path_len);
    if (entry && !(entry->flags & KQSYSDB_FLAG_DELETED)) {
        entry->flags |= KQSYSDB_FLAG_DELETED;
        hdr->entry_count--;
        hdr->total_deletes++;
        hdr->sequence++;
        ret = KQSYSDB_OK;
    }

    shm_write_end(hdr);
    shm_unlock(hdr);
    mutex_unlock(&kqsysdb_state.shm_mutex);

    if (ret == KQSYSDB_OK) {
        kqsysdb_notify_userspace(path, KQSYSDB_EVENT_DELETE);
    }

    return ret;
}
EXPORT_SYMBOL(kqsysdb_delete);

/*
 * Public API: kqsysdb_exists
 */
int kqsysdb_exists(const char *path)
{
    struct kqsysdb_shm_header *hdr;
    struct kqsysdb_entry *entry;
    size_t path_len;
    u64 seq;
    int exists = 0;

    if (!path)
        return KQSYSDB_ERR_INVALID;

    if (!atomic_read(&kqsysdb_state.ready))
        return 0;

    path_len = strlen(path);
    if (path_len == 0 || path_len >= QSYSDB_MAX_PATH)
        return 0;

    hdr = (struct kqsysdb_shm_header *)kqsysdb_state.shm_base;

    do {
        seq = shm_read_begin(hdr);
        entry = shm_lookup(path, path_len);
        exists = (entry && !(entry->flags & KQSYSDB_FLAG_DELETED)) ? 1 : 0;
    } while (shm_read_retry(hdr, seq));

    return exists;
}
EXPORT_SYMBOL(kqsysdb_exists);

/*
 * Public API: kqsysdb_subscribe
 */
int kqsysdb_subscribe(const char *pattern, kqsysdb_notify_fn callback, void *data)
{
    struct kqsysdb_subscription *sub;
    size_t pattern_len;
    unsigned long flags;

    if (!pattern || !callback)
        return KQSYSDB_ERR_INVALID;

    pattern_len = strlen(pattern);
    if (pattern_len == 0 || pattern_len >= QSYSDB_MAX_PATH)
        return KQSYSDB_ERR_BADPATH;

    sub = kzalloc(sizeof(*sub), GFP_KERNEL);
    if (!sub)
        return KQSYSDB_ERR_NOMEM;

    spin_lock_irqsave(&kqsysdb_state.sub_lock, flags);
    sub->id = ++kqsysdb_state.next_sub_id;
    spin_unlock_irqrestore(&kqsysdb_state.sub_lock, flags);

    memcpy(sub->pattern, pattern, pattern_len);
    sub->pattern[pattern_len] = '\0';
    sub->pattern_len = pattern_len;
    sub->prefix_match = (pattern[pattern_len - 1] == '*');
    if (sub->prefix_match)
        sub->pattern_len--;
    sub->callback = callback;
    sub->data = data;

    spin_lock_irqsave(&kqsysdb_state.sub_lock, flags);
    list_add(&sub->list, &kqsysdb_state.subscriptions);
    spin_unlock_irqrestore(&kqsysdb_state.sub_lock, flags);

    return sub->id;
}
EXPORT_SYMBOL(kqsysdb_subscribe);

/*
 * Public API: kqsysdb_unsubscribe
 */
void kqsysdb_unsubscribe(int sub_id)
{
    struct kqsysdb_subscription *sub, *tmp;
    unsigned long flags;

    spin_lock_irqsave(&kqsysdb_state.sub_lock, flags);
    list_for_each_entry_safe(sub, tmp, &kqsysdb_state.subscriptions, list) {
        if (sub->id == sub_id) {
            list_del(&sub->list);
            spin_unlock_irqrestore(&kqsysdb_state.sub_lock, flags);
            kfree(sub);
            return;
        }
    }
    spin_unlock_irqrestore(&kqsysdb_state.sub_lock, flags);
}
EXPORT_SYMBOL(kqsysdb_unsubscribe);

/*
 * Public API: kqsysdb_ready
 */
int kqsysdb_ready(void)
{
    return atomic_read(&kqsysdb_state.ready);
}
EXPORT_SYMBOL(kqsysdb_ready);

/*
 * Notify local kernel subscribers
 */
static void kqsysdb_notify_subscribers(const char *path, const char *value,
                                       int event_type)
{
    struct kqsysdb_subscription *sub;
    size_t path_len = strlen(path);
    unsigned long flags;

    spin_lock_irqsave(&kqsysdb_state.sub_lock, flags);
    list_for_each_entry(sub, &kqsysdb_state.subscriptions, list) {
        bool match = false;

        if (sub->prefix_match) {
            if (path_len >= sub->pattern_len &&
                memcmp(sub->pattern, path, sub->pattern_len) == 0)
                match = true;
        } else {
            if (path_len == sub->pattern_len &&
                memcmp(sub->pattern, path, path_len) == 0)
                match = true;
        }

        if (match && sub->callback) {
            /* Call callback - note: still holding spinlock, callback should be fast */
            sub->callback(path, value, event_type, sub->data);
        }
    }
    spin_unlock_irqrestore(&kqsysdb_state.sub_lock, flags);
}

/*
 * Character device operations
 */
static int kqsysdb_dev_open(struct inode *inode, struct file *filp)
{
    return 0;
}

static int kqsysdb_dev_release(struct inode *inode, struct file *filp)
{
    return 0;
}

static int kqsysdb_dev_mmap(struct file *filp, struct vm_area_struct *vma)
{
    size_t size = vma->vm_end - vma->vm_start;
    unsigned long pfn;

    if (!kqsysdb_state.shm_mapped || !kqsysdb_state.shm_base)
        return -ENODEV;

    if (size > kqsysdb_state.shm_size)
        return -EINVAL;

    /* Map the shared memory pages */
    pfn = virt_to_phys(kqsysdb_state.shm_base) >> PAGE_SHIFT;

    if (remap_pfn_range(vma, vma->vm_start, pfn, size, vma->vm_page_prot))
        return -EAGAIN;

    return 0;
}

static const struct file_operations kqsysdb_fops = {
    .owner = THIS_MODULE,
    .open = kqsysdb_dev_open,
    .release = kqsysdb_dev_release,
    .mmap = kqsysdb_dev_mmap,
};

/*
 * Module initialization
 */
static int __init kqsysdb_init(void)
{
    int ret;
    dev_t dev;

    pr_info("kqsysdb: initializing\n");

    /* Initialize state */
    memset(&kqsysdb_state, 0, sizeof(kqsysdb_state));
    spin_lock_init(&kqsysdb_state.lock);
    mutex_init(&kqsysdb_state.shm_mutex);
    spin_lock_init(&kqsysdb_state.sub_lock);
    INIT_LIST_HEAD(&kqsysdb_state.subscriptions);
    atomic_set(&kqsysdb_state.ready, 0);

    /* Allocate character device region */
    ret = alloc_chrdev_region(&dev, 0, 1, DEVICE_NAME);
    if (ret < 0) {
        pr_err("kqsysdb: failed to allocate chrdev region\n");
        return ret;
    }
    kqsysdb_state.major = MAJOR(dev);

    /* Initialize cdev */
    cdev_init(&kqsysdb_state.cdev, &kqsysdb_fops);
    kqsysdb_state.cdev.owner = THIS_MODULE;

    ret = cdev_add(&kqsysdb_state.cdev, dev, 1);
    if (ret < 0) {
        pr_err("kqsysdb: failed to add cdev\n");
        goto err_cdev;
    }

    /* Create device class */
    kqsysdb_state.class = class_create(CLASS_NAME);
    if (IS_ERR(kqsysdb_state.class)) {
        ret = PTR_ERR(kqsysdb_state.class);
        pr_err("kqsysdb: failed to create class\n");
        goto err_class;
    }

    /* Create device */
    kqsysdb_state.device = device_create(kqsysdb_state.class, NULL,
                                         dev, NULL, DEVICE_NAME);
    if (IS_ERR(kqsysdb_state.device)) {
        ret = PTR_ERR(kqsysdb_state.device);
        pr_err("kqsysdb: failed to create device\n");
        goto err_device;
    }

    /* Initialize generic netlink */
    ret = kqsysdb_genl_init();
    if (ret < 0) {
        pr_err("kqsysdb: failed to initialize netlink\n");
        goto err_netlink;
    }

    pr_info("kqsysdb: initialized (major=%d)\n", kqsysdb_state.major);
    return 0;

err_netlink:
    device_destroy(kqsysdb_state.class, dev);
err_device:
    class_destroy(kqsysdb_state.class);
err_class:
    cdev_del(&kqsysdb_state.cdev);
err_cdev:
    unregister_chrdev_region(dev, 1);
    return ret;
}

static void __exit kqsysdb_exit(void)
{
    struct kqsysdb_subscription *sub, *tmp;
    dev_t dev = MKDEV(kqsysdb_state.major, 0);
    unsigned long flags;

    pr_info("kqsysdb: exiting\n");

    /* Clean up subscriptions */
    spin_lock_irqsave(&kqsysdb_state.sub_lock, flags);
    list_for_each_entry_safe(sub, tmp, &kqsysdb_state.subscriptions, list) {
        list_del(&sub->list);
        kfree(sub);
    }
    spin_unlock_irqrestore(&kqsysdb_state.sub_lock, flags);

    /* Clean up netlink */
    kqsysdb_genl_exit();

    /* Clean up device */
    device_destroy(kqsysdb_state.class, dev);
    class_destroy(kqsysdb_state.class);
    cdev_del(&kqsysdb_state.cdev);
    unregister_chrdev_region(dev, 1);

    pr_info("kqsysdb: exited\n");
}

module_init(kqsysdb_init);
module_exit(kqsysdb_exit);

/* Include netlink implementation */
#include "netlink_kern.c"
