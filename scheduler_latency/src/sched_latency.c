#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <bpf/libbpf.h>
#include "sched_latency.skel.h"
#include "sched_latency.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level >= LIBBPF_DEBUG)
		return 0;

	return vfprintf(stderr, format, args);
}

bool run = true;
void signal_handler(int signum)
{
	printf("\nCTRL-C pressed. Exiting ...\n");
	run = false;
}

int main(int argc, char *argv[])
{
	struct sched_latency_bpf *skel;
	void *user_ring_buf;
	int *user_msg;
	struct data d;
	int pid = -1;
	int key = 0;
	int data_fd;
	int err;
	int i;

	signal(SIGINT, signal_handler);
	/* get pid from cmdline args */
	for (i = 0; i < argc; i++) {
		if ((strncmp(argv[i], "-p", 2) == 0) ||
		    (strncmp(argv[i], "--pid", 5) == 0)) {
			if ( i+1 <= argc-1 ) {
				sscanf(argv[i+1], "%d", &pid);
				printf("pid to track = %d\n", pid);
				break;
			}
		}
	}

	libbpf_set_print(libbpf_print_fn);

	/* open, load and verify the kernel space code */
	skel = sched_latency_bpf__open_and_load();
	if (!skel) {
		printf("Failed to open BPF object\n");
		return 1;
	}

	/* attach the specified hooks */
	err = sched_latency_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
		sched_latency_bpf__destroy(skel);
		return 1;
	}

	/* Get descriptor of the map through which we'll get the latency data */
	data_fd = bpf_map__fd(skel->maps.latency_data);
	if (data_fd == -1) {
		printf("Failed to created map");
		return 0;
	}

	// BPF_MAP_TYPE_USER_RINGBUF to send pid of task to kernel
	user_ring_buf = user_ring_buffer__new(bpf_map__fd(skel->maps.umap_pid), NULL);
	user_msg = user_ring_buffer__reserve(user_ring_buf, 128);
	if (!user_msg) {
		printf("Failed to reserver user-ring-buffer\n");
		goto out;
	}

	*user_msg = pid;
	user_ring_buffer__submit(user_ring_buf, user_msg);

	while (run == true) {

		/* read latency from map when signal is 1 */
		err = bpf_map_lookup_elem(data_fd, &key, &d);
		if (err < 0)
			printf("failed to read latency data\n");
		else {
			if (d.signal == 1)
				printf("[Scheduling Latency]:\tcomm:%s\tPID:%d\tLatency:%d ns\n", d.comm, d.pid, d.latency);
		}
		sleep(1);

	}

out:
	sched_latency_bpf__destroy(skel);
	return err;
}
