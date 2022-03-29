#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <linux/bpf.h>

int	main(void) {
	int fd;

	fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(int), sizeof(int), 100, BPF_F_NO_PREALLOC);
	if (fd < 0) {
		perror("bpf map create failed: ");
	}
	return 0;
}