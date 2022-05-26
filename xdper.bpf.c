#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <linux/mm.h>

typedef struct event_t
{
	uint32_t len;
	uint32_t proto;
	uint32_t src_addr;
	uint32_t dst_addr;
	uint32_t src_port;
	uint32_t dst_port;
} event_t;

// Create a perf buffer to perf_submit the events [packets] to.
// These events are read by the user space program.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, event_t);
    __uint(max_entries, 32);
} event_table SEC(".maps");

static __always_inline unsigned short is_icmp_ping_request(void *data, void *data_end)
{
	struct ethhdr *eth = data;
	if (data + sizeof(struct ethhdr) >= data_end)
		return 0;

	// if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
	//   return 0;

	struct iphdr *iph = data + sizeof(struct ethhdr);
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) >= data_end)
		return 0;

	if (iph->protocol != 0x01)
		// We're only interested in ICMP packets
		return 0;

	struct icmphdr *icmp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) > data_end)
		return 0;

	return (icmp->type == 8);
}

// try xdp
SEC("xdp_tracer")
int xdp_tracer_prog(struct xdp_md* ctx)
{
	// void* data = (void*)(long int)ctx->data;
	// void* data_end = (void*)(long int)ctx->data_end;

	// if(is_icmp_ping_request(data, data_end))
	// {
		// struct iphdr* iphead = data + sizeof(struct ethhdr);
		// struct icmphdr* icmphead = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
		bpf_printk("we have xdp");
		// TODO: submit to BPF_HASH instead of printk()
		// bpf_printk("ICMP request for %x of type: %x", iphead->daddr, icmphead->type);
	// }

	return 0;
}

char LICENSE[] SEC("license") = "GPL";