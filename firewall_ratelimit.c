#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define PPS_LIMIT 10
#define WINDOW_NS 1000000000ULL
#define BAN_TIME_NS 10000000000ULL

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef bpf_htons
#define bpf_htons(x) __builtin_bswap16(x)
#endif

struct ip_stats
{
    u64 pkt_count;
    u64 window_start;
    u64 blocked_until;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, struct ip_stats);
} stats_map SEC(".maps");

SEC("xdp")
int rate_limiter(struct xdp_md *ctx)
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

    u32 src_ip = iph->saddr;
    u64 now = bpf_ktime_get_ns();

    struct ip_stats *stats = bpf_map_lookup_elem(&stats_map, &src_ip);

    if (!stats)
    {
        struct ip_stats new_stats = {.pkt_count = 1, .window_start = now, .blocked_until = 0};
        bpf_map_update_elem(&stats_map, &src_ip, &new_stats, BPF_ANY);
        return XDP_PASS;
    }

    if (stats->blocked_until > 0) {
        if (now < stats->blocked_until) {
            return XDP_DROP;
        } else {
            stats->blocked_until = 0;
            stats->pkt_count = 1;
            stats->window_start = now;
            return XDP_PASS;
        }
    }

    if (now - stats->window_start >= WINDOW_NS)
    {
        stats->pkt_count = 1;
        stats->window_start = now;
        return XDP_PASS;
    }

    stats->pkt_count++;

    if (stats->pkt_count > PPS_LIMIT)
    {
        stats->blocked_until = now + BAN_TIME_NS; 
        bpf_printk("IP BANIDO POR %d SEGUNDOS: %pI4 (PPS: %llu)\n", (BAN_TIME_NS/1000000000ULL), &src_ip, stats->pkt_count);
        return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";