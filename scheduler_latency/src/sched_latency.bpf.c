#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "sched_latency.h"

#define DEBUG(fmt, ...)			\
	if (debug)			\
	bpf_printk("[DEBUG_ATUL]: " fmt, ##__VA_ARGS__);	\

char LICENSE[] SEC("license") = "Dual BSD/GPL";
volatile const bool debug = 1;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} g_enqueue_ts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} g_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct data);
} latency_data SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, 1);
} umap_pid SEC(".maps");

static long user_buffer_drain_cb(struct bpf_dynptr *dynptr, void *context)
{
	int key = 0;
	int pid;
	int ret;

	ret = bpf_dynptr_read(&pid, sizeof(pid), dynptr, 0, 0);
	if (ret) {
		DEBUG("[user-ring-buffer]: Failed to get data from dynptr\n");
		return 1;
	}
	DEBUG("[user-ring-buffer]: data from userspace=%d\n", pid);

	ret = bpf_map_update_elem(&g_pid, &key, &pid, BPF_ANY);
	if (ret == 0)
		DEBUG("[user-ring-buffer]: Successfully updated pid=%d in g_pid\n", pid);
	return 0;
}

SEC("kprobe/enqueue_task")
int BPF_KPROBE(my_enqueue_cb, struct rq *rq, struct task_struct *p, int flags)
{
	int *pid_from_user = NULL;
	struct data d;
	char comm[32];
	int pid;
	u32 key = 0;
	int cpu;
	u64 ts;
	int ret;

	BPF_CORE_READ_INTO(&comm, p, comm);
	BPF_CORE_READ_INTO(&pid, p, pid);
	BPF_CORE_READ_INTO(&cpu, rq, cpu);

	/* We'll check here if we have pid from user or not. If not, we'll
	 * read user ring buffer to see if user has given any pid.
	 */
	pid_from_user = bpf_map_lookup_elem(&g_pid, &key);
	if (pid_from_user && (*pid_from_user == 0)) {
		ret = bpf_user_ringbuf_drain(&umap_pid, user_buffer_drain_cb, NULL, 0);
		if (ret < 0)
			DEBUG("[user-ring-buffer]: Failed to read pid of task: %d\n", ret);
	}

	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&g_enqueue_ts, &key, &ts, BPF_ANY);
	DEBUG("[enq][%d]: p=%s pid=%d time=%llu\n", cpu, comm, pid, ts);

	/*
	 * Make signal 0 for the task which we want to track
	 */
	if ((pid_from_user) && (*pid_from_user != 0) && (d.pid == *pid_from_user)) {
		d.latency = -1;
		d.signal = 0;
		bpf_map_update_elem(&latency_data, &key, &d, BPF_ANY);
	}
	return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next, unsigned long prev_state)
{
	int *pid_from_user = NULL;
	__u64 *enq_ts = NULL;
	int latency = 0;
	__u32 key = 0;
	struct data d;

	DEBUG("[sched_switch]: prev=%s next=%s\n", prev->comm, next->comm);

	pid_from_user = bpf_map_lookup_elem(&g_pid, &key);
	if ((pid_from_user) && (*pid_from_user != 0) && (next->pid == *pid_from_user)) {
		enq_ts = bpf_map_lookup_elem(&g_enqueue_ts, &key);
		DEBUG("[sched_switch]: tracking pid=%d and next_pid=%d\n", *pid_from_user, next->pid);
		if (enq_ts) {
			u64 cur_ts = bpf_ktime_get_ns();
			latency = cur_ts - *enq_ts;
			DEBUG("[sched_switch][test_app]: Found!! cur_ts=%llu enq=%llu latency=%llu\n\n",
				   cur_ts, *enq_ts, latency);

			d.signal = 1;
			d.latency = latency;
			BPF_CORE_READ_INTO(&d.comm, next, comm);
			BPF_CORE_READ_INTO(&d.pid, next, pid);
			DEBUG("[sched_switch]: updating ringbuf with comm=%s pid=%d\n", d.comm, d.pid);
			bpf_map_update_elem(&latency_data, &key, &d, BPF_ANY);
		}
	}

	return 0;
}
