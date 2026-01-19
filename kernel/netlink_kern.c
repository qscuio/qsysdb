/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * netlink_kern.c - Generic Netlink implementation for kernel module
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: GPL-2.0
 *
 * Note: This file is included directly in kqsysdb.c
 */

#include <net/genetlink.h>

/* Netlink attribute policy */
static const struct nla_policy kqsysdb_genl_policy[__KQSYSDB_ATTR_MAX] = {
    [KQSYSDB_ATTR_PATH]       = { .type = NLA_NUL_STRING, .len = QSYSDB_MAX_PATH },
    [KQSYSDB_ATTR_VALUE]      = { .type = NLA_NUL_STRING, .len = QSYSDB_MAX_VALUE },
    [KQSYSDB_ATTR_EVENT_TYPE] = { .type = NLA_U32 },
    [KQSYSDB_ATTR_SEQUENCE]   = { .type = NLA_U64 },
    [KQSYSDB_ATTR_VERSION]    = { .type = NLA_U64 },
    [KQSYSDB_ATTR_TIMESTAMP]  = { .type = NLA_U64 },
    [KQSYSDB_ATTR_FLAGS]      = { .type = NLA_U32 },
    [KQSYSDB_ATTR_ERROR]      = { .type = NLA_S32 },
    [KQSYSDB_ATTR_PATTERN]    = { .type = NLA_NUL_STRING, .len = QSYSDB_MAX_PATH },
    [KQSYSDB_ATTR_SUB_ID]     = { .type = NLA_S32 },
};

/* Multicast group */
static const struct genl_multicast_group kqsysdb_mc_groups[] = {
    { .name = QSYSDB_GENL_MC_GROUP },
};

/* Forward declarations */
static int kqsysdb_genl_set(struct sk_buff *skb, struct genl_info *info);
static int kqsysdb_genl_get(struct sk_buff *skb, struct genl_info *info);
static int kqsysdb_genl_delete(struct sk_buff *skb, struct genl_info *info);
static int kqsysdb_genl_notify(struct sk_buff *skb, struct genl_info *info);
static int kqsysdb_genl_sync(struct sk_buff *skb, struct genl_info *info);

/* Operations */
static const struct genl_small_ops kqsysdb_genl_ops[] = {
    {
        .cmd = KQSYSDB_CMD_SET,
        .validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
        .doit = kqsysdb_genl_set,
    },
    {
        .cmd = KQSYSDB_CMD_GET,
        .validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
        .doit = kqsysdb_genl_get,
    },
    {
        .cmd = KQSYSDB_CMD_DELETE,
        .validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
        .doit = kqsysdb_genl_delete,
    },
    {
        .cmd = KQSYSDB_CMD_NOTIFY,
        .validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
        .doit = kqsysdb_genl_notify,
    },
    {
        .cmd = KQSYSDB_CMD_SYNC,
        .validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
        .doit = kqsysdb_genl_sync,
    },
};

/* Generic netlink family */
static struct genl_family kqsysdb_genl_family = {
    .name = QSYSDB_GENL_NAME,
    .version = QSYSDB_GENL_VERSION,
    .maxattr = KQSYSDB_ATTR_MAX,
    .policy = kqsysdb_genl_policy,
    .module = THIS_MODULE,
    .small_ops = kqsysdb_genl_ops,
    .n_small_ops = ARRAY_SIZE(kqsysdb_genl_ops),
    .mcgrps = kqsysdb_mc_groups,
    .n_mcgrps = ARRAY_SIZE(kqsysdb_mc_groups),
};

/*
 * Helper to send a reply
 */
static int kqsysdb_genl_reply(struct genl_info *info, u8 cmd, int error,
                              const char *path, const char *value)
{
    struct sk_buff *skb;
    void *hdr;
    int ret;

    skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    if (!skb)
        return -ENOMEM;

    hdr = genlmsg_put(skb, info->snd_portid, info->snd_seq,
                      &kqsysdb_genl_family, 0, cmd);
    if (!hdr) {
        nlmsg_free(skb);
        return -EMSGSIZE;
    }

    if (nla_put_s32(skb, KQSYSDB_ATTR_ERROR, error)) {
        genlmsg_cancel(skb, hdr);
        nlmsg_free(skb);
        return -EMSGSIZE;
    }

    if (path && nla_put_string(skb, KQSYSDB_ATTR_PATH, path)) {
        genlmsg_cancel(skb, hdr);
        nlmsg_free(skb);
        return -EMSGSIZE;
    }

    if (value && nla_put_string(skb, KQSYSDB_ATTR_VALUE, value)) {
        genlmsg_cancel(skb, hdr);
        nlmsg_free(skb);
        return -EMSGSIZE;
    }

    genlmsg_end(skb, hdr);

    ret = genlmsg_reply(skb, info);
    return ret;
}

/*
 * Handle SET command from userspace
 */
static int kqsysdb_genl_set(struct sk_buff *skb, struct genl_info *info)
{
    const char *path = NULL;
    const char *value = NULL;
    int ret;

    if (info->attrs[KQSYSDB_ATTR_PATH])
        path = nla_data(info->attrs[KQSYSDB_ATTR_PATH]);

    if (info->attrs[KQSYSDB_ATTR_VALUE])
        value = nla_data(info->attrs[KQSYSDB_ATTR_VALUE]);

    if (!path || !value)
        return kqsysdb_genl_reply(info, KQSYSDB_CMD_SET, KQSYSDB_ERR_INVALID,
                                  NULL, NULL);

    ret = kqsysdb_set(path, value);
    return kqsysdb_genl_reply(info, KQSYSDB_CMD_SET, ret, path, NULL);
}

/*
 * Handle GET command from userspace
 */
static int kqsysdb_genl_get(struct sk_buff *skb, struct genl_info *info)
{
    const char *path = NULL;
    char *value_buf;
    int ret;

    if (info->attrs[KQSYSDB_ATTR_PATH])
        path = nla_data(info->attrs[KQSYSDB_ATTR_PATH]);

    if (!path)
        return kqsysdb_genl_reply(info, KQSYSDB_CMD_GET, KQSYSDB_ERR_INVALID,
                                  NULL, NULL);

    value_buf = kmalloc(QSYSDB_MAX_VALUE, GFP_KERNEL);
    if (!value_buf)
        return kqsysdb_genl_reply(info, KQSYSDB_CMD_GET, KQSYSDB_ERR_NOMEM,
                                  path, NULL);

    ret = kqsysdb_get(path, value_buf, QSYSDB_MAX_VALUE);

    if (ret >= 0) {
        ret = kqsysdb_genl_reply(info, KQSYSDB_CMD_GET, KQSYSDB_OK,
                                 path, value_buf);
    } else {
        ret = kqsysdb_genl_reply(info, KQSYSDB_CMD_GET, ret, path, NULL);
    }

    kfree(value_buf);
    return ret;
}

/*
 * Handle DELETE command from userspace
 */
static int kqsysdb_genl_delete(struct sk_buff *skb, struct genl_info *info)
{
    const char *path = NULL;
    int ret;

    if (info->attrs[KQSYSDB_ATTR_PATH])
        path = nla_data(info->attrs[KQSYSDB_ATTR_PATH]);

    if (!path)
        return kqsysdb_genl_reply(info, KQSYSDB_CMD_DELETE, KQSYSDB_ERR_INVALID,
                                  NULL, NULL);

    ret = kqsysdb_delete(path);
    return kqsysdb_genl_reply(info, KQSYSDB_CMD_DELETE, ret, path, NULL);
}

/*
 * Handle NOTIFY command from userspace (daemon notifying kernel of changes)
 */
static int kqsysdb_genl_notify(struct sk_buff *skb, struct genl_info *info)
{
    const char *path = NULL;
    const char *value = NULL;
    u32 event_type = KQSYSDB_EVENT_NONE;

    if (info->attrs[KQSYSDB_ATTR_PATH])
        path = nla_data(info->attrs[KQSYSDB_ATTR_PATH]);

    if (info->attrs[KQSYSDB_ATTR_VALUE])
        value = nla_data(info->attrs[KQSYSDB_ATTR_VALUE]);

    if (info->attrs[KQSYSDB_ATTR_EVENT_TYPE])
        event_type = nla_get_u32(info->attrs[KQSYSDB_ATTR_EVENT_TYPE]);

    if (path) {
        /* Notify kernel subscribers */
        kqsysdb_notify_subscribers(path, value, event_type);
    }

    return 0;  /* No reply needed for notifications */
}

/*
 * Handle SYNC command - daemon telling us SHM is ready
 */
static int kqsysdb_genl_sync(struct sk_buff *skb, struct genl_info *info)
{
    /* Mark database as ready */
    atomic_set(&kqsysdb_state.ready, 1);
    kqsysdb_state.netlink_ready = true;

    pr_info("kqsysdb: database synchronized with userspace daemon\n");

    return kqsysdb_genl_reply(info, KQSYSDB_CMD_SYNC, KQSYSDB_OK, NULL, NULL);
}

/*
 * Send notification to userspace daemon
 */
static int kqsysdb_notify_userspace(const char *path, int event_type)
{
    struct sk_buff *skb;
    void *hdr;
    int ret;

    if (!kqsysdb_state.netlink_ready)
        return 0;

    skb = genlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
    if (!skb)
        return -ENOMEM;

    hdr = genlmsg_put(skb, 0, 0, &kqsysdb_genl_family, 0, KQSYSDB_CMD_KERN_UPDATE);
    if (!hdr) {
        nlmsg_free(skb);
        return -EMSGSIZE;
    }

    if (nla_put_string(skb, KQSYSDB_ATTR_PATH, path) ||
        nla_put_u32(skb, KQSYSDB_ATTR_EVENT_TYPE, event_type)) {
        genlmsg_cancel(skb, hdr);
        nlmsg_free(skb);
        return -EMSGSIZE;
    }

    genlmsg_end(skb, hdr);

    /* Multicast to all listeners */
    ret = genlmsg_multicast(&kqsysdb_genl_family, skb, 0, 0, GFP_ATOMIC);
    if (ret && ret != -ESRCH)
        pr_warn("kqsysdb: failed to send multicast: %d\n", ret);

    return ret;
}

/*
 * Initialize generic netlink
 */
static int kqsysdb_genl_init(void)
{
    int ret;

    ret = genl_register_family(&kqsysdb_genl_family);
    if (ret < 0) {
        pr_err("kqsysdb: failed to register genetlink family: %d\n", ret);
        return ret;
    }

    pr_info("kqsysdb: registered genetlink family '%s'\n", QSYSDB_GENL_NAME);
    return 0;
}

/*
 * Cleanup generic netlink
 */
static void kqsysdb_genl_exit(void)
{
    genl_unregister_family(&kqsysdb_genl_family);
    pr_info("kqsysdb: unregistered genetlink family\n");
}
