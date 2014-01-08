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
    .hook = (nf_hookfn *)nf_pre_route_hook
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
    struct ethhdr *eth = eth_hdr(skb); /* Get a pointer to the Ethernet header */
    u_int16_t etype;

    printk( "%s: Received a packet %p, device in = %s\n", __func__,
                skb, in ? in->name : "<NONE>" );

    /* Is this a multicast packet ? */
    if( is_multicast_ether_addr(eth->h_dest) )
    {
        /* Do something */
        printk( "Packet is multicast\n" );
    }

    if( is_broadcast_ether_addr(eth->h_dest) )
    {
        /* Do something else */
        printk( "Packet is broadcast\n");
    }

    /* Get EtherType field */
    etype = ntohs( eth->h_proto );

    if( etype == ETH_P_IP )
    {
        struct iphdr *ip = NULL;
        struct udphdr *udp = NULL;
        struct tcphdr *tcp = NULL;

        /* This is an IP packet */
        ip = ip_hdr(skb);
        if (ip == NULL)
        {
            return NF_ACCEPT;
        }

        if (ip->protocol == IPPROTO_UDP)
        {
            /* UDP packet */
            udp = (struct udphdr *)(skb_network_header(skb) + ip_hdrlen(skb));

            printk( "UDP packet\n");
        }
        else if (ip->protocol == IPPROTO_TCP)
        {
            /* TCP packet */
            tcp = (struct tcphdr *)(skb_network_header(skb) + ip_hdrlen(skb));

            printk( "TCP packet\n");
        }
    }

    return NF_ACCEPT;
}

module_init(my_firewall_init);
module_exit(my_firewall_exit);

