//
// time calculation
// calculate time between accept() exit ~ close() enter
//

#include "vmlinux.h"
#include "bpf_helpers.h"

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

struct accept_exit {
	u64	unused1;
	u64	unused2;
	
	u32 ret;
};

struct close_entry {
	u64 unused1;
	u64 unused2;

	u64 fd;
};

struct event {
	pid_t pid;
	int ret;
	int fd;
	u64 duration_ns;
};

struct bpf_map_def SEC("maps") exec_start = {
	.type = BPF_MAP_TYPE_HASH,
	.max_entries = 1892,
	.key_size = sizeof(pid_t),
	.value_size = sizeof(u64),
};

struct bpf_map_def SEC("maps") events = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
};

const struct event *unused __attribute__((unused));

SEC("tracepoint/syscalls/sys_exit_accept")
int exit_accept(struct accept_exit* args)
{
	u64 ts = bpf_ktime_get_ns();
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int enter_close(struct close_entry* args)
{
	const pid_t pid = bpf_get_current_pid_tgid() >> 32;
	u64 end_time = bpf_ktime_get_ns();
	u64 *start_time = bpf_map_lookup_elem(&exec_start, &pid);

	bpf_map_delete_elem(&exec_start, &pid);

	if (start_time == 0)
		return 0;

	struct event data = {};
	data.pid = pid;
	data.duration_ns = end_time - *start_time;
	data.fd = args->fd;

	bpf_perf_event_output(args, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));

	return 0;
}