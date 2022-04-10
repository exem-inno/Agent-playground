APP=accpet_scrape

.PHONY: build
build: gen $(APP)

.PHONY: run
run: build
	sudo ./$(APP)

.PHONY: gen
gen: sum vmlinux src/bpf_bpfel.go

.PHONY: vmlinux
vmlinux: src/bpf/vmlinux.h

.PHONY: sum
sum: go.sum

.PHONY: fmt
fmt: sum
	go fmt src/*.go

.PHONY: clean
clean:
	-rm $(APP)
	-rm src/gen*
	-rm src/bpf/vmlinux.h
	-rm go.sum

$(APP): src/main.go bpf_bpfel.go
	CGO_ENABLED=0 go build -o $(APP) src/*.go

src/bpf/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h

bpf_bpfel.go: src/bpf/accept4.c
	go generate src/*.go

go.sum:
	go mod download github.com/cilium/ebpf
	go get github.com/cilium/ebpf/internal/unix
