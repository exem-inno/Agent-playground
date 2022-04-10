#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <linux/bpf.h>

void	error_update(int result) {
	if (result == 0)
		printf("Map updated with new element\n");
	else
		printf("Failed to update map with new value: %d (%s)\n", result, strerror(errno));
}

void	error_lookup(int result, int value) {
	if (result == 0)
		printf("Value read from the map : %d\n", value);
	else
		printf("Failed to read value from the map: %d (%s)\n", result, strerror(errno));
}

void	error_delete(int result) {
	if (result == 0)
		printf("Element delete from the map\n");
	else
		printf("Failed to delete element from the map: %d (%s)\n", result, strerror(errno));
}

int	main(void) {
	int fd;
	int key, value, result;

	fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(int), sizeof(int), 100, BPF_F_NO_PREALLOC);
	if (fd < 0) {
		perror("bpf map create failed: ");
	}
	key = 1, value = 1111;
	result = bpf_map_update_elem(fd, &key, &value, BPF_ANY);
	error_update(result);

	key = 1, value = 1111;
	result = bpf_map_update_elem(fd, &key, &value, BPF_NOEXIST);
	error_update(result);

	key = 2, value = 2222;
	result = bpf_map_update_elem(fd, &key, &value, BPF_EXIST);
	error_update(result);

	key = 2, value = 2222;
	result = bpf_map_update_elem(fd, &key, &value, BPF_NOEXIST);
	error_update(result);

	result = bpf_map_lookup_elem(fd, &key, &value);
	error_lookup(result, value);

	key = 3;
	result = bpf_map_lookup_elem(fd, &key, &value);
	error_lookup(result, value);

	key = 2;
	result = bpf_map_delete_elem(fd, &key);
	error_delete(result);

	result = bpf_map_delete_elem(fd, &key);
	error_delete(result);
}