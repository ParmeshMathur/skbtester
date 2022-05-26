// #include <bpf/bpf.h>
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define IPPROTO_ICMP	1
#define IPPROTO_UDP		17
#define IPPROTO_TCP		6
#define IPPROTO_IPV6	41
#define ETH_HLEN		14

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

typedef struct event_t
{
	unsigned short int len;
	unsigned short int proto;
	unsigned int src_addr;
	unsigned int src_port;
	unsigned int dst_addr;
	unsigned int dst_port;
} event_t;

struct 
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, event_t);
	__uint(max_entries, 32);
} events_list SEC(".maps");

SEC("socket")
int socket_prog(struct __sk_buff* skb)
{
	u8 buffer[1];
	int err = bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, protocol), buffer, 1);

	int proto = (int)buffer[0];
	bpf_printk("skfilter -- %d", proto);
	switch (proto) {
		case IPPROTO_TCP:
			bpf_printk("TCP packet");
			break;
		case IPPROTO_UDP:
			bpf_printk("UDP packet");
			break;
		case IPPROTO_ICMP:
			bpf_printk("ICMP packet");
			break;
		default:
		break;
	}
	return 0;
}

// SEC("socket")
// int socket_prog(struct __sk_buff* skb)
// {
// 	event_t event;

// 	u8 proto;
// 	u16 t_len;
// 	u32 src;
// 	u32 dst;

// 	int err = bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, protocol), &proto, 1);
// 	err = bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, tot_len), &t_len, 2);
// 	err = bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, saddr), &src, 4);
// 	err = bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, daddr), &dst, 4);

// 	int id=1;
// 	event.proto = proto;
// 	event.len = t_len;
// 	event.src_addr = src;
// 	event.dst_addr = dst;

// 	// int proto = (int)buffer[0];
// 	bpf_printk("skfilter -- %d", proto);
// 	switch (proto) {
// 		case IPPROTO_TCP:
// 			bpf_map_update_elem(&events_list, &id, &event, 0 /* flags */);
// 			bpf_printk("TCP packet");
// 			break;
// 		case IPPROTO_UDP:
// 		{
// 			bpf_map_update_elem(&events_list, &id, &event, 0 /* flags */);
// 			bpf_printk("UDP packet");
// 			break;
// 		}
// 		case IPPROTO_ICMP:
// 		{
// 			bpf_map_update_elem(&events_list, &id, &event, 0 /* flags */);
// 			bpf_printk("ICMP packet");
// 			break;
// 		}
// 		default:
// 		break;
// 	}
// 	return 0;
// }

char LICENSE[] SEC("license") = "GPL";