/*
 * Netfilter BSSID Filter Module
 *
 * Filters WiFi traffic by BSSID (access point MAC address)
 * Only allows packets from whitelisted access points
 *
 * Default behavior: Filters ALL WiFi interfaces
 * Optional: Specify a single interface to filter
 *
 * Usage:
 *   # Filter all WiFi interfaces (default)
 *   insmod nf_bssid_filter.ko allowed_macs="aa:bb:cc:dd:ee:ff,11:22:33:44:55:66"
 *
 *   # Filter specific interface only
 *   insmod nf_bssid_filter.ko interface=wlp0s20f3 allowed_macs="aa:bb:cc:dd:ee:ff"
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/ieee80211.h>
#include <linux/etherdevice.h>
#include <linux/list.h>
#include <net/cfg80211.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Michal Srb <michal@redhat.com>");
MODULE_DESCRIPTION("Netfilter BSSID Filter");
MODULE_VERSION("1.0");

/* Module parameters */
static char *interface = NULL;  /* NULL = all WiFi interfaces */
module_param(interface, charp, 0444);
MODULE_PARM_DESC(interface, "Specific WiFi interface to filter (default: all WiFi interfaces)");

static char *allowed_macs = "";
module_param(allowed_macs, charp, 0444);
MODULE_PARM_DESC(allowed_macs, "Comma-separated list of allowed BSSIDs (e.g., aa:bb:cc:dd:ee:ff,11:22:33:44:55:66)");

static bool debug = false;
module_param(debug, bool, 0644);
MODULE_PARM_DESC(debug, "Enable debug logging");

/* Maximum number of allowed BSSIDs and WiFi interfaces */
#define MAX_ALLOWED_BSSIDS 32
#define MAX_WIFI_INTERFACES 8

/* Allowlist storage */
static u8 allowlist[MAX_ALLOWED_BSSIDS][ETH_ALEN];
static int num_allowed = 0;

/* Statistics */
static atomic64_t packets_allowed = ATOMIC64_INIT(0);
static atomic64_t packets_blocked = ATOMIC64_INIT(0);
static atomic64_t packets_total = ATOMIC64_INIT(0);

/* WiFi interface tracking */
struct wifi_iface {
    struct net_device *dev;
    struct nf_hook_ops hook;
    char name[IFNAMSIZ];
};

static struct wifi_iface wifi_interfaces[MAX_WIFI_INTERFACES];
static int num_wifi_interfaces = 0;

/*
 * Parse MAC address from string (format: aa:bb:cc:dd:ee:ff)
 * Returns 0 on success, -1 on error
 */
static int parse_mac(const char *str, u8 *mac)
{
    int i;
    unsigned int tmp[ETH_ALEN];

    if (sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
               &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5]) != ETH_ALEN) {
        return -1;
    }

    for (i = 0; i < ETH_ALEN; i++) {
        mac[i] = (u8)tmp[i];
    }

    return 0;
}

/*
 * Parse comma-separated MAC addresses
 */
static int parse_allowlist(const char *macs)
{
    char *str, *token;
    int count = 0;

    if (!macs || strlen(macs) == 0)
        return 0;

    /* Make a copy since strsep modifies the string */
    str = kstrdup(macs, GFP_KERNEL);
    if (!str)
        return -ENOMEM;

    while ((token = strsep(&str, ",")) && count < MAX_ALLOWED_BSSIDS) {
        /* Skip empty tokens */
        if (strlen(token) == 0)
            continue;

        if (parse_mac(token, allowlist[count]) == 0) {
            pr_info("nf_bssid_filter: Added BSSID %pM\n", allowlist[count]);
            count++;
        } else {
            pr_warn("nf_bssid_filter: Invalid MAC address: %s\n", token);
        }
    }

    kfree(str);
    return count;
}

/*
 * Check if MAC address is in allowlist
 */
static bool is_allowed(const u8 *mac)
{
    int i;

    for (i = 0; i < num_allowed; i++) {
        if (ether_addr_equal(mac, allowlist[i]))
            return true;
    }

    return false;
}

/*
 * Netfilter hook function
 * Called for every packet on the WiFi interface
 */
static unsigned int wifi_filter_hook(void *priv,
                                      struct sk_buff *skb,
                                      const struct nf_hook_state *state)
{
    struct ethhdr *eth;
    const u8 *src_mac;

    if (!skb)
        return NF_ACCEPT;

    /* Get Ethernet header */
    eth = eth_hdr(skb);
    if (!eth)
        return NF_ACCEPT;

    /* Get source MAC address */
    src_mac = eth->h_source;

    /* Update total packet counter */
    atomic64_inc(&packets_total);

    /* If no allowlist configured, allow everything */
    if (num_allowed == 0) {
        atomic64_inc(&packets_allowed);
        return NF_ACCEPT;
    }

    /* Check if source MAC is in allowlist */
    if (is_allowed(src_mac)) {
        atomic64_inc(&packets_allowed);

        if (debug)
            pr_debug("nf_bssid_filter: ALLOW %pM\n", src_mac);

        return NF_ACCEPT;
    }

    /* Not in allowlist - block it */
    atomic64_inc(&packets_blocked);

    pr_info("nf_bssid_filter: BLOCK %pM on %s\n", src_mac, state->in->name);

    return NF_DROP;
}

/*
 * Check if a network device is a WiFi interface
 */
static bool is_wifi_interface(struct net_device *dev)
{
    /* Check if device has wireless extensions */
    if (dev->ieee80211_ptr)
        return true;

    /* Alternative: check device type */
    if (dev->type == ARPHRD_IEEE80211 ||
        dev->type == ARPHRD_IEEE80211_PRISM ||
        dev->type == ARPHRD_IEEE80211_RADIOTAP)
        return true;

    return false;
}

/*
 * Register netfilter hook on a specific WiFi interface
 */
static int register_wifi_hook(struct net_device *dev)
{
    struct wifi_iface *iface;
    int ret;

    if (num_wifi_interfaces >= MAX_WIFI_INTERFACES) {
        pr_warn("nf_bssid_filter: Maximum WiFi interfaces (%d) reached, skipping %s\n",
                MAX_WIFI_INTERFACES, dev->name);
        return -ENOMEM;
    }

    iface = &wifi_interfaces[num_wifi_interfaces];

    /* Store device reference */
    iface->dev = dev;
    dev_hold(dev);
    strncpy(iface->name, dev->name, IFNAMSIZ - 1);
    iface->name[IFNAMSIZ - 1] = '\0';

    /* Setup netfilter hook */
    iface->hook.hook = wifi_filter_hook;
    iface->hook.pf = NFPROTO_NETDEV;
    iface->hook.hooknum = NF_NETDEV_INGRESS;
    iface->hook.priority = NF_IP_PRI_FIRST;
    iface->hook.dev = dev;

    /* Register the hook */
    ret = nf_register_net_hook(&init_net, &iface->hook);
    if (ret < 0) {
        pr_err("nf_bssid_filter: Failed to register hook on %s: %d\n",
               dev->name, ret);
        dev_put(dev);
        return ret;
    }

    pr_info("nf_bssid_filter: Registered hook on %s\n", dev->name);
    num_wifi_interfaces++;

    return 0;
}

/*
 * Find and register hooks on all WiFi interfaces
 */
static int register_all_wifi_hooks(void)
{
    struct net_device *dev;
    int count = 0;

    rtnl_lock();
    for_each_netdev(&init_net, dev) {
        if (is_wifi_interface(dev)) {
            if (register_wifi_hook(dev) == 0)
                count++;
        }
    }
    rtnl_unlock();

    return count;
}

/*
 * Unregister all hooks and release device references
 */
static void unregister_all_hooks(void)
{
    int i;

    for (i = 0; i < num_wifi_interfaces; i++) {
        pr_info("nf_bssid_filter: Unregistering hook on %s\n",
                wifi_interfaces[i].name);
        nf_unregister_net_hook(&init_net, &wifi_interfaces[i].hook);
        dev_put(wifi_interfaces[i].dev);
    }

    num_wifi_interfaces = 0;
}

/*
 * Module initialization
 */
static int __init nf_bssid_filter_init(void)
{
    int ret;
    struct net_device *dev;

    pr_info("nf_bssid_filter: Loading module\n");

    /* Parse allowlist */
    num_allowed = parse_allowlist(allowed_macs);
    if (num_allowed < 0) {
        pr_err("nf_bssid_filter: Failed to parse allowlist\n");
        return num_allowed;
    }

    pr_info("nf_bssid_filter: Loaded %d allowed BSSID(s)\n", num_allowed);

    /* Register hooks on WiFi interface(s) */
    if (interface && strlen(interface) > 0) {
        /* User specified a specific interface */
        pr_info("nf_bssid_filter: Filtering specific interface: %s\n", interface);

        dev = dev_get_by_name(&init_net, interface);
        if (!dev) {
            pr_err("nf_bssid_filter: Interface %s not found\n", interface);
            return -ENODEV;
        }

        if (!is_wifi_interface(dev)) {
            pr_warn("nf_bssid_filter: Warning - %s may not be a WiFi interface\n",
                    interface);
        }

        ret = register_wifi_hook(dev);
        if (ret < 0) {
            dev_put(dev);
            return ret;
        }
    } else {
        /* Auto-detect and filter all WiFi interfaces */
        pr_info("nf_bssid_filter: Auto-detecting WiFi interfaces...\n");

        ret = register_all_wifi_hooks();
        if (ret == 0) {
            pr_err("nf_bssid_filter: No WiFi interfaces found\n");
            return -ENODEV;
        }

        pr_info("nf_bssid_filter: Registered hooks on %d WiFi interface(s)\n", ret);
    }

    pr_info("nf_bssid_filter: Module loaded successfully\n");

    return 0;
}

/*
 * Module cleanup
 */
static void __exit nf_bssid_filter_exit(void)
{
    pr_info("nf_bssid_filter: Unloading module\n");

    /* Unregister all netfilter hooks */
    unregister_all_hooks();

    pr_info("nf_bssid_filter: Module unloaded\n");
    pr_info("nf_bssid_filter: Final stats - Total: %lld, Allowed: %lld, Blocked: %lld\n",
            atomic64_read(&packets_total),
            atomic64_read(&packets_allowed),
            atomic64_read(&packets_blocked));
}

module_init(nf_bssid_filter_init);
module_exit(nf_bssid_filter_exit);
