#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in6.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/icmpv6.h>
#include <bpf/bpf_endian.h>
extern void csum_replace2(__sum16 *sum, __be16 old, __be16 new);
// eBPF program to drop packets from a specific IP address
int pass(void *pkt, size_t len) {
    uint8_t tmp_mac[ETH_ALEN];
    struct in6_addr tmp_ip;
    struct ethhdr *eth = (struct ethhdr *) pkt;
    struct ipv6hdr *ipv6 = (struct ipv6hdr *) (eth + 1);
    struct icmp6hdr *icmp = (struct icmp6hdr *) (ipv6 + 1);

    if (ntohs(eth->h_proto) != ETH_P_IPV6 ||
        len < (sizeof(*eth) + sizeof(*ipv6) + sizeof(*icmp)) ||
        ipv6->nexthdr != IPPROTO_ICMPV6 ||
        icmp->icmp6_type != ICMPV6_ECHO_REQUEST)
        return XDP_DROP;

    __builtin_memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, tmp_mac, ETH_ALEN);

    __builtin_memcpy(&tmp_ip, &ipv6->saddr, sizeof(tmp_ip));
    __builtin_memcpy(&ipv6->saddr, &ipv6->daddr, sizeof(tmp_ip));
    __builtin_memcpy(&ipv6->daddr, &tmp_ip, sizeof(tmp_ip));

    icmp->icmp6_type = ICMPV6_ECHO_REPLY;

    csum_replace2(&icmp->icmp6_cksum,
            htons(ICMPV6_ECHO_REQUEST << 8),
            htons(ICMPV6_ECHO_REPLY << 8));

    return XDP_PASS;
}