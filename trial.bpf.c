#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <linux/mm.h>
// #include <stdio.h>
// #include <linux/bpf.h>

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
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, event_t);
    __uint(max_entries, 32);
} event_table SEC(".maps");

int tracer_func(void* __skb, char* func_name)
{
	struct __sk_buff* skb = (struct __sk_buff*)__skb;
	int packet_length = (int)skb->data_end - (int)skb->data;
	// uint32_t packet_length = skb -> wire_len;
	__u32 ipproto = skb -> protocol;
	bpf_printk("%s: %u", func_name, packet_length);
	return 0;
}

// Attach a kernel probe to the tcp_connect kernel method
SEC("kprobe/tcp_connect")
int tcpconnect(struct __sk_buff* skb) 
{
	// bpf_printk("We have tcpconnect\n");
	// uint32_t packet_length = skb -> wire_len;
	// __u32 ipproto = skb -> protocol;
	// bpf_printk("tcpconnect -len:%u proto:%u", packet_length, ipproto);
	// return 0;
	return tracer_func(skb, (char*)__func__);
}


SEC("kprobe/ip_rcv")
int ip_receiver(struct __sk_buff* skb) 
{
	// bpf_printk("We have tcpconnect\n");
	// uint32_t packet_length = skb -> wire_len;
	// __u32 ipproto = skb -> protocol;
	// bpf_printk("ip receive -len:%d proto:%d", packet_length, ipproto);
	// return 0;
	return tracer_func(skb, (char*)__func__);
}

SEC("kprobe/ip_rcv_finish")
int ip_rcv_fin(struct __sk_buff* skb) 
{
	// bpf_printk("We have tcpconnect\n");
	// uint32_t packet_length = skb -> wire_len;
	// __u32 ipproto = skb -> protocol;
	// bpf_printk("ip rcv fin -len:%d proto:%d", packet_length, ipproto);
	return tracer_func(skb, (char*)__func__);
}

SEC("kprobe/ip_output")
int ip_sender(struct __sk_buff* skb) 
{
	// bpf_printk("We have tcpconnect\n");
	// uint32_t packet_length = skb -> wire_len;
	// __u32 ipproto = skb -> protocol;
	// bpf_printk("ip sending -len:%d proto:%d", packet_length, ipproto);
	return tracer_func(skb, (char*)__func__);
}

SEC("kprobe/ip_finish_output")
int ip_out_fin(struct __sk_buff* skb) 
{
	// bpf_printk("We have tcpconnect\n");
	// uint32_t packet_length = skb -> wire_len;
	// __u32 ipproto = skb -> protocol;
	// bpf_printk("ip out fin -len:%d proto:%d", packet_length, ipproto);
	return tracer_func(skb, (char*)__func__);
}

SEC("kprobe/netif_rx")
int net_if_rx(struct __sk_buff* skb) 
{
	// bpf_printk("We have tcpconnect\n");
	// uint32_t packet_length = skb -> wire_len;
	// __u32 ipproto = skb -> protocol;
	// bpf_printk("net if rx -len:%d proto:%d", packet_length, ipproto);
	return tracer_func(skb, (char*)__func__);
}

// SEC("kprobe/__netif_rceive_skb")
// int netif_rcv_skb(struct __sk_buff* skb) 
// {
// 	// bpf_printk("We have tcpconnect\n");
// 	uint32_t packet_length = skb -> wire_len;
// 	__u32 ipproto = skb -> protocol;
// 	bpf_printk("netif rcv skb -len:%d proto:%d", packet_length, ipproto);
// 	return 0;
// }

SEC("kprobe/tpacket_rcv")
int tpacket_rcv(struct __sk_buff* skb) 
{
	// bpf_printk("We have tcpconnect\n");
	// uint32_t packet_length = skb -> wire_len;
	// __u32 ipproto = skb -> protocol;
	// bpf_printk("tpacket rcv -len:%d proto:%d", packet_length, ipproto);
	return tracer_func(skb, (char*)__func__);
}

SEC("kprobe/packet_rcv")
int packet_rcv(struct __sk_buff* skb) 
{
	// bpf_printk("We have tcpconnect\n");
	// uint32_t packet_length = skb -> wire_len;
	// __u32 ipproto = skb -> protocol;
	// bpf_printk("packet rcv -len:%d proto:%d", packet_length, ipproto);
	return tracer_func(skb, (char*)__func__);
}

SEC("kprobe/napi_gro_receive")
int napi_gro_rcv(struct __sk_buff* skb) 
{
	// bpf_printk("We have tcpconnect\n");
	// uint32_t packet_length = skb -> wire_len;
	// __u32 ipproto = skb -> protocol;
	// bpf_printk("napi gro rcv -len:%d proto:%d", packet_length, ipproto);
	return tracer_func(skb, (char*)__func__);
}

SEC("kprobe/dev_queue_xmit")
int dev_q_xmit(struct __sk_buff* skb) 
{
	// bpf_printk("We have tcpconnect\n");
	// uint32_t packet_length = skb -> wire_len;
	// __u32 ipproto = skb -> protocol;
	// bpf_printk("dev que xmit -len:%d proto:%d", packet_length, ipproto);
	return tracer_func(skb, (char*)__func__);
}

// SEC("socket/")
// int socket_filter(struct __sk_buff* skb)
// {
// 	// uint32_t packet_length = skb -> len;
// 	// bpf_printk("tcpconnect -\tlen:%d\n", packet_length);
// 	bpf_printk("we have tcpconnect\n");
// 	return 0;
// }

// to un-comment second (using socket filter) func without a SEC() definition
// comment the first func
// copy the format of second func from lix rice's video (youtube). 

char LICENSE[] SEC("license") = "GPL";