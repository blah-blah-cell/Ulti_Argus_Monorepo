/*
 * NOTE: If this file appears red (syntax errors) in your IDE, do not panic.
 * This is eBPF C code designed for the Linux Kernel.
 */
#ifndef __linux__
// Simulation/IDE stubs to fix syntax errors on Windows
#define BPF_PERF_OUTPUT(n)                                                     \
  struct {                                                                     \
    void (*perf_submit)(void *ctx, void *data, int sz);                        \
  } n
#define BPF_HASH(n, k, v)                                                      \
  struct {                                                                     \
    v *(*lookup_or_init)(k * key, v *def);                                     \
  } n
#define lock_xadd(p, v)
#define htons(x) x
#define ETH_P_IP 0x0800
#include <stdint.h>
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint16_t u16;
typedef uint8_t u8;
struct xdp_md {
  void *data;
  void *data_end;
};
struct ethhdr {
  u16 h_proto;
};
struct iphdr {
  u8 protocol;
  u32 saddr;
  u32 daddr;
};
struct tcphdr {
  u16 source;
  u16 dest;
};
#define IPPROTO_TCP 6
#define XDP_PASS 2
#define bpf_ktime_get_ns() 0
#define BPF_PTR_CAST(x) (void *)(uintptr_t)(x)
#else
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/in.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#define BPF_PTR_CAST(x) (void *)(long)(x)
#endif

// Data structure to send to userspace
struct flow_feature_t {
  u32 src_ip;
  u32 dst_ip;
  u16 src_port;
  u16 dst_port;
  u32 packet_len;
  u32 timestamp;
};

// Start outputting to a perf buffer for userspace to read
BPF_PERF_OUTPUT(events);

// Map to count packets for basic stats (Retina functionality)
BPF_HASH(packet_stats, u32, u64);

int xdp_prog(struct xdp_md *ctx) {
  void *data_end = BPF_PTR_CAST(ctx->data_end);
  void *data = BPF_PTR_CAST(ctx->data);

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return XDP_PASS;

  // Only process IP packets
  if (eth->h_proto != htons(ETH_P_IP))
    return XDP_PASS;

  struct iphdr *ip = (void *)(eth + 1);
  if ((void *)(ip + 1) > data_end)
    return XDP_PASS;

  // Count this packet
  u32 key = 0;
  u64 zero = 0;
  u64 *count = packet_stats.lookup_or_init(&key, &zero);
  if (count) {
    lock_xadd(count, 1);
  }

  // Only inspect TCP
  if (ip->protocol != IPPROTO_TCP)
    return XDP_PASS;

  struct tcphdr *tcp = (void *)(ip + 1);
  if ((void *)(tcp + 1) > data_end)
    return XDP_PASS;

  // Send metadata to userspace for Analysis (Retina/Mnemosyne)
  struct flow_feature_t flow = {};
  flow.src_ip = ip->saddr;
  flow.dst_ip = ip->daddr;
  flow.src_port = tcp->source;
  flow.dst_port = tcp->dest;
  flow.packet_len = data_end - data;
  flow.timestamp = bpf_ktime_get_ns() / 1000000;

  events.perf_submit(ctx, &flow, sizeof(flow));

  // For now, pass everything. Later we'll add a verdicts map to DROP malicious
  // IPs.
  return XDP_PASS;
}
