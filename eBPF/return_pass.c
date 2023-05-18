#include <linux/bpf.h>

#ifndef __section
# define __section(NAME)                  \
   __attribute__((section(NAME), used))
#endif

__section("prog")
int my_ebpf_prog(struct xdp_md *ctx) {
    return XDP_PASS;
}

char _license[] __section("license") = "GPL";