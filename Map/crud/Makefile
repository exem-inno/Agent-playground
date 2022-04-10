CLANG = clang

# INCLUDE_PATH += -I/usr/src/linux/tools/lib/bpf

# LIBRARY_PATH = -L/usr/local/lib64
BPFSO = -lbcc_bpf

.PHONY: clean 

clean:
	rm -f map_crud

map_crud: 	map_crud.c
	clang -o map_crud -std=c89 -lelf $(INCLUDE_PATH) $(LIBRARY_PATH) $(BPFSO) $?

build: map_crud

.DEFAULT_GOAL := build