#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <bpf/bpf_endian.h>

// eBPF program to drop packets from a specific IP address
int block_ip(void *opaque) {
    struct ethhdr *eth = (struct ethhdr*)opaque;

    if (eth->h_proto != bpf_htons(ETH_P_ARP)) {
        return XDP_DROP;
    }

    return XDP_PASS;
}