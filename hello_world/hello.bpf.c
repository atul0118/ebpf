#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("tp/sched/sched_switch")
int hello(void *arg)
{
	bpf_printk("Hello world\n");
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
