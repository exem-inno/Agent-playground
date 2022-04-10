#include "vmlinux.h"
#include "bpf_helpers.h"

char LICENSE[] SEC("license") = "GPL";

struct bpf_map_def SEC("maps") events = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
};

struct accept_entry {
	u64	unused1;
	u64	unused2;

	u64	fd;
	struct sockaddr* upeer_sockaddr;
	int*	upeer_addrlen;
	int	flag;
};

struct event {
	u32	pid;
	int	fd;
	u32	addrlen;
	u32	addr;
};

const struct event *unused __attribute__((unused));

SEC("tracepoint/syscalls/sys_enter_accept")
int enter_accept(struct accept_entry *args)
{
	struct event info = {};
	struct sockaddr_in* ptr = args->upeer_sockaddr;

	u64 pid_tgid = bpf_get_current_pid_tgid();
	info.pid = pid_tgid & 0xFFFFFFFF;
	info.fd = args->fd;
	bpf_probe_read(&info.addrlen, sizeof(info.addrlen), args->upeer_addrlen);
	bpf_probe_read(&info.addr, sizeof(info.addr), &ptr->sin_addr.s_addr);
	bpf_perf_event_output(args, &events, BPF_F_CURRENT_CPU, &info, sizeof(info));
	return 0;
}
