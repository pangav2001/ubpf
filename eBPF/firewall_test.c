#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/types.h>
#include <arpa/inet.h>
#include <linux/in6.h>
#include <bpf/bpf_endian.h>
#include <stdbool.h>

extern void register_hash_tables(void **tables[]);
extern void* bpf_map_lookup_elem(void **map_name, void *key);
// extern __be16 (*get_protocols())[];
extern __be16* get_protocols();

int xdp_firewall_prog(void *data)
{
    struct ethhdr *eth = (struct ethhdr*)data;
    struct ipv6hdr *iph;
    struct in6_addr src_ip;
    struct in6_addr dst_ip;
    _Bool *forbidden_src_mac, *forbidden_dst_mac, *forbidden_src_ip, *forbidden_dst_ip;
    void *forbidden_src_macs, *forbidden_dst_macs, *forbidden_src_ips, *forbidden_dst_ips;
    void **tables[] = {&forbidden_src_ips, &forbidden_dst_ips, &forbidden_src_macs, &forbidden_dst_macs};
    // __be16 (*protocols)[] = get_protocols();
    // __be16 size = (*protocols)[0];
    // for (__be16 i = 1; i < size; i++) {
    //     if (bpf_htons((*protocols)[i]) == eth->h_proto)
    //         goto inspect;
    // }
    register_hash_tables(tables);
    __be16 *protocols = get_protocols();
    __be16 size = *protocols;
    for (__be16 i = 1; i < size; i++) {
        if (bpf_htons(*(protocols + i)) == eth->h_proto)
            goto inspect;
    }
    inspect:
        if (eth->h_proto == bpf_htons(ETH_P_IPV6))
        {
            iph = data + sizeof(*eth);
            // /* Get the source and destination IPs */
            src_ip = iph->saddr;
            dst_ip = iph->daddr;

            /* Get the forbidden source IP from the map */
            forbidden_src_ip = (_Bool *)bpf_map_lookup_elem(&forbidden_src_ips, &src_ip);
            if (forbidden_src_ip && *forbidden_src_ip)
            {
                return XDP_DROP;
            }

            forbidden_dst_ip = (_Bool *)bpf_map_lookup_elem(&forbidden_dst_ips, &dst_ip);
            if (forbidden_dst_ip && *forbidden_dst_ip)
            {
                return XDP_DROP;
            }
        }
        if (eth->h_proto == bpf_htons(ETH_P_ARP)) 
        {
            forbidden_src_mac = (_Bool *)bpf_map_lookup_elem(&forbidden_src_macs, &eth->h_source);
            if (forbidden_src_mac && *forbidden_src_mac)
            {
                return XDP_DROP;
            }
            
            forbidden_dst_mac = (_Bool *)bpf_map_lookup_elem(&forbidden_dst_macs, &eth->h_dest);
            if (forbidden_dst_mac && *forbidden_dst_mac)
            {
                return XDP_DROP;
            }
        }

    /* Allow the packet */
    return XDP_PASS;
}

// ~/Desktop/toolbox_llvm3.7/clang+llvm-3.7.0-x86_64-linux-gnu-ubuntu-14.04/bin/clang -O2 -target bpf -c firewall_test.c -o firewall_test2.o