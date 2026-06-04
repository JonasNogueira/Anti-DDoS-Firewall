#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef bpf_htons
#define bpf_htons(x) __builtin_bswap16(x)
#endif

SEC("xdp")
int inspect_packet(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);

    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    unsigned int src_ip = iph->saddr;
    
    bpf_printk("Pacote recebido de: %pI4\n", &src_ip);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";