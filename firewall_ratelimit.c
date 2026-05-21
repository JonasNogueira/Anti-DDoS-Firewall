#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#define PPS_LIMIT 10
#define WINDOW_NS 1000000000ULL

struct ip_stats
{
    __u64 pkt_count;
    __u64 window_start;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
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
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = iph->saddr;
    __u64 now = bpf_ktime_get_ns();

    struct ip_stats *stats = bpf_map_lookup_elem(&stats_map, &src_ip);

    if (!stats)
    {
        struct ip_stats new_stats = {.pkt_count = 1, .window_start = now};
        bpf_map_update_elem(&stats_map, &src_ip, &new_stats, BPF_ANY);
        return XDP_PASS;
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
        bpf_printk("LIMITE EXCEDIDO: %pI4 (PPS: %llu)\n", &src_ip, stats->pkt_count);
        return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";