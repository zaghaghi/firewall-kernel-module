#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <net/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

unsigned int nf_pre_route_hook( unsigned int hooknum, struct sk_buff *skb,
        const struct net_device *in, const struct net_device *out,
        int(*okfn)( struct sk_buff * ) );

static struct nf_hook_ops firewall_ops __read_mostly = {
    .pf = NFPROTO_IPV4,
    .priority = NF_IP_PRI_FIRST,
    .owner = THIS_MODULE,
    .hooknum = NF_INET_PRE_ROUTING,
    .hook = nf_pre_route_hook
};

static int __init my_firewall_init(void)
{
    return nf_register_hook(&firewall_ops);
}

static void __exit my_firewall_exit(void)
{
    nf_unregister_hook(&firewall_ops);
}

unsigned int nf_pre_route_hook( unsigned int hooknum, struct sk_buff *skb,
        const struct net_device *in, const struct net_device *out,
        int(*okfn)( struct sk_buff * ) )
{
    return NF_DROP;
}

module_init(my_firewall_init);
module_exit(my_firewall_exit);

