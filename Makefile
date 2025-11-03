BPF_CLANG ?= clang
BPF_STRIP ?= llvm-strip
BPF_CFLAGS := -O2 -g -Wall -Werror -target bpf -D__TARGET_ARCH_x86
BPF_SRCS := bpf/xdp_dns_redirect.bpf.c bpf/tc_mirror.bpf.c
BPF_OBJS := $(BPF_SRCS:.c=.o)
GO_BUILD := go build ./...
UI_DIR := web/ui

.PHONY: all bpf go ui clean run fmt

all: bpf go ui

bpf: $(BPF_OBJS)

bpf/%.bpf.o: bpf/%.bpf.c bpf/include/common.h bpf/include/vmlinux.h
	$(BPF_CLANG) $(BPF_CFLAGS) -I bpf/include -c $< -o $@
	$(BPF_STRIP) -g $@

bpf/xdp_dns_redirect.bpf.o: bpf/xdp_dns_redirect.bpf.c bpf/include/common.h bpf/include/vmlinux.h
	$(BPF_CLANG) $(BPF_CFLAGS) -I bpf/include -c $< -o $@
	$(BPF_STRIP) -g $@

bpf/tc_mirror.bpf.o: bpf/tc_mirror.bpf.c bpf/include/common.h bpf/include/vmlinux.h
	$(BPF_CLANG) $(BPF_CFLAGS) -I bpf/include -c $< -o $@
	$(BPF_STRIP) -g $@

bpf/include/vmlinux.h:
	@echo "Generate vmlinux.h via 'bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@'"
	@exit 1

go:
	$(GO_BUILD)

ui:
	cd $(UI_DIR) && npm install && npm run build

fmt:
	gofmt -w cmd pkg

clean:
	rm -f $(BPF_OBJS)
	cd $(UI_DIR) && npm run clean || true
	go clean ./...

