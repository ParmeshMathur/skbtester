#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/resource.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "trial.skel.h"

void trace_reader()
{
	int trace_fd = open("/sys/kernel/debug/tracing/trace_pipe", O_RDONLY, 0);
	if(trace_fd<0) return;

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

int main(int argc, char const *argv[])
{
	struct trial_bpf *obj;
	int err=0;

	struct rlimit rlim = {
		.rlim_cur = 512UL << 20,
		.rlim_max = 512UL << 20,
	};

	err = setrlimit(RLIMIT_MEMLOCK, &rlim);
	if (err) {
		fprintf(stderr, "failed to change rlimit\n");
		return 1;
	}

	obj = trial_bpf__open();
	if(!obj)
	{
		perror("Could not load bpf\n");
		return 1;
	}

	err = trial_bpf__load(obj);
	if(err)
	{
		perror("Could not load object\n");
		goto finish;
	}

	err = trial_bpf__attach(obj);
	if(err)
	{
		perror("Failed to attach bpf program\n");
		goto finish;
	}

	trace_reader();

finish:
	trial_bpf__destroy(obj);
	return err;
}