#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int hello_world(struct xdp_md *ctx) {
    
    bpf_printk("Hello World do Kernel! Pacote intercetado.\n");
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";