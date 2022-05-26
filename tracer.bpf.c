#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

typedef struct event_t
{
	unsigned int len;
	unsigned int proto;
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

SEC("tracepoint/tcp/tcp_probe")
int tp_func(struct __sk_buff* skb)
{
	bpf_printk("tracepoint!");
	return 0;
}

char LICENSE[] SEC("license") = "GPL";