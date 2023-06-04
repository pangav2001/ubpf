#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <stddef.h>
#include <bpf/bpf_endian.h>

static __always_inline int _strcmp (const unsigned char *buf1, const unsigned char *buf2, unsigned long size) {
    unsigned char c1, c2;
    for (unsigned long i = 0; i < size; i++)
    {
        c1 = *buf1++;
        c2 = *buf2++;
        if (c1 != c2) return c1 < c2 ? -1 : 1;
        if (!c1) break;
    }
    return 0;
} 

struct ipv4_lpm_key {
        __u32 prefixlen;
        __u32 data;
};

struct ipv6_lpm_key {
        __u32 prefixlen;
        struct in6_addr *data;
};

extern void register_lpm_tries(void **tables[]);
extern void* bpf_map_lookup_elem(void **map_name, void *key);

// SEC("xdp")
int xdp_standard_acl(void *ctx, size_t len)
{
    void *data = (void *)(long)ctx;
    void *data_end = (void *)(long)ctx + len;
    
    // 90:e2:ba:f7:32:69
    unsigned char my_mac[] = {0x90, 0xe2, 0xba, 0xf7, 0x32, 0x69};
    // 90:E2:BA:F7:30:1D
    unsigned char source_mac[] = {0x90, 0xe2, 0xba, 0xf7, 0x30, 0x1d};
    // 90:E2:BA:F7:31:CD
    unsigned char target_mac[] = {0x90, 0xe2, 0xba, 0xf7, 0x31, 0xcd};
    
    void *ipv4_rules_trie, *ipv6_rules_trie;
    void **tables[] = {&ipv4_rules_trie, &ipv6_rules_trie};
    register_lpm_tries(tables);
    struct ethhdr *eth = data;
    /* Check if eth header is within bounds */
    if ((void *) (eth + 1) > data_end)
    {
        return XDP_DROP;
    }
    /* Don't inspect packet if it's not an IPv4 or IPv6 packet */
    if (eth->h_proto == bpf_htons(ETH_P_IP) || eth->h_proto == bpf_htons(ETH_P_IPV6))
    {
        __u32 permitted_src;
        if (eth->h_proto == bpf_htons(ETH_P_IP))
        {
            struct iphdr *iph;
            __be32 src_ip;
            /* Get the IP header */
            iph = data + sizeof(struct ethhdr);

            /* Check if IP header is within bounds */
            if ((void *) iph + 1 > data_end)
            {
                return XDP_DROP;
            }
            /* Get the source IP */
            src_ip = iph->saddr;

            /* Get the forbidden source IP from the map */
            struct ipv4_lpm_key key = {
                    .prefixlen = 32,
                    .data = src_ip
            };
            permitted_src = (__u32)bpf_map_lookup_elem(&ipv4_rules_trie, &key);
        }
        else
        {
            struct ipv6hdr *ipv6h;
            struct in6_addr src_ip;
            /* Get the IP header */
            ipv6h = data + sizeof(struct ethhdr);

            /* Check if IP header is within bounds */
            if ((void *) ipv6h + 1 > data_end)
            {
                return XDP_DROP;
            }
            /* Get the source IP */
            src_ip = ipv6h->saddr;

            /* Get the forbidden source IP from the map */
            struct ipv6_lpm_key key = {
                    .prefixlen = 128,
                    .data = &src_ip
            };
            permitted_src = (__u32)bpf_map_lookup_elem(&ipv6_rules_trie, &key);
        }

        if (permitted_src) {
            /* Check that source MAC is that of MoonGen sender
           and destination MAC is that of the NIC running the XDP prog*/
            if (!(_strcmp(eth->h_source, source_mac, ETH_ALEN) 
                || _strcmp(eth->h_dest, my_mac, ETH_ALEN))) {
                /* Swap MAC addresses as appropriate */
                __builtin_memcpy(eth->h_source, my_mac, ETH_ALEN);
                __builtin_memcpy(eth->h_dest, target_mac, ETH_ALEN);
                /* Send packet to new destination */
                return XDP_TX;
            }
        }
        else {
            /* Implicit "DENY ANY" at end of list*/
            return XDP_DROP;
        }
    }

    /* Allow the packet if not IPv4/IPv6 packet */
    return XDP_PASS;
}
// char _license[] SEC("license") = "GPL";

// ~/Desktop/toolbox_llvm3.7/clang+llvm-3.7.0-x86_64-linux-gnu-ubuntu-14.04/bin/clang -O2 -target bpf -c standard_acl.c -o standard_acl.o
// ~/Desktop/toolbox_llvm3.7/clang+llvm-3.7.0-x86_64-linux-gnu-ubuntu-14.04/bin/clang -O2 -emit-llvm -c standard_acl.c -o - | llc -march=bpf -mcpu=probe -filetype=obj -o standard_acl.o
// ~/clang+llvm-3.7.0-x86_64-linux-gnu-ubuntu-14.04/bin/clang-3.7 -O2 -target bpf -c standard_acl.c -o standard_acl.o