#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

// #include <vmlinux.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
// #include "skfilter.skel.h"

void trace_reader()
{
	int trace_fd = open("/sys/kernel/debug/tracing/trace_pipe", O_RDONLY, 0);
	if(trace_fd<0) return;
	// TODO: make a map fd and read from that instead of from trace pipe
	int count = 0;

	while(1)
	{
		char buffer[1024];
		size_t sz;
		

		sz = read(trace_fd, buffer, sizeof(buffer)-1);
		if(sz>0) 
		{
			count++;
			buffer[sz]=0;
			// printf("%d\t", count);
			puts(buffer);
		}
	}
}

static inline int open_raw_sock(const char *name)
{
	struct sockaddr_ll sll;
	int sock;

	sock = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
	if (sock < 0) {
		printf("cannot create raw socket\n");
		return -1;
	}

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = if_nametoindex(name);
	sll.sll_protocol = htons(ETH_P_ALL);
	if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		printf("bind to %s: %s\n", name, strerror(errno));
		close(sock);
		return -1;
	}

	return sock;
}

int main(int argc, char const *argv[])
{
	// struct skfilter_bpf *obj;
	int err=0;
	struct rlimit rlim = {
		.rlim_cur = 512UL << 20,
		.rlim_max = 512UL << 20,
	};

	printf("setting elimit\n");
	err = setrlimit(RLIMIT_MEMLOCK, &rlim);
	if (err) {
		fprintf(stderr, "failed to change rlimit\n");
		return 1;
	}

	// obj = skfilter_bpf__open();
	// if(!obj)
	// {
	// 	fprintf(stderr, "Could not open bpf object\n");
	// 	return 1;
	// }

	// if((err = skfilter_bpf__load(obj)))
	// {
	// 	fprintf(stderr, "Could not load bpf program\n");
	// 	goto finish;
	// }

	// if((err = skfilter_bpf__attach(obj)))
	// {
	// 	fprintf(stderr, "Could not attach bpf program\n");
	// 	goto finish;
	// }

	// int map_fd=0;

	// struct bpf_insn prog[] = {
	// 	BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
	// 	BPF_LD_ABS(BPF_B, ETH_HLEN + offsetof(struct iphdr, protocol) /* R0 = ip->proto */),
	// 	BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4), /* *(u32 *)(fp - 4) = r0 */
	// 	BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
	// 	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4), /* r2 = fp - 4 */
	// 	BPF_LD_MAP_FD(BPF_REG_1, map_fd),
	// 	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
	// 	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2),
	// 	BPF_MOV64_IMM(BPF_REG_1, 1), /* r1 = 1 */
	// 	BPF_RAW_INSN(BPF_STX | BPF_XADD | BPF_DW, BPF_REG_0, BPF_REG_1, 0, 0), /* xadd r0 += r1 */
	// 	BPF_MOV64_IMM(BPF_REG_0, 0), /* r0 = 0 */
	// 	BPF_EXIT_INSN(),
	// };

	// prog_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, prog, sizeof(prog), "GPL", 0);

	char filename[32] = "skfilter.bpf.o";
	int prog_fd = 0;

	struct bpf_object *obj;
	printf("before load\n");

	err = bpf_prog_load(filename, BPF_PROG_TYPE_SOCKET_FILTER, &obj, &prog_fd);
	if(err)
	{
		fprintf(stderr, "ERR: loading BPF-OBJ file(%s) (%d): %s\n",
			filename, err, strerror(-err));
		return -1;
	}
	printf("prog loaded\n");

	// sock = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	// int sock = open_raw_sock("lo");
	int sock = open_raw_sock("ens33");
	printf("Raw socket opened\n");
	// sock = open_raw_sock("lo");
	setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd));
	printf("Sock options set\n");

	trace_reader();

// finish:
	return 0;
}