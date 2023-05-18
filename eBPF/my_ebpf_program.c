#include <linux/bpf.h>

int my_ebpf_prog(struct xdp_md *ctx) {
    return XDP_PASS;
}

// static int idouble(int a) {
//         return (a * 2);
// }

// int bpf_prog(void *ctx) {
//         int a = 10;
//         a = idouble(a);

//         return (a);
// }