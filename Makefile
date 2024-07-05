DEBUG ?= 1

CFLAGS := -O2 \
	  -g \
	  -Wall \
	  -Werror

ifeq ($(DEBUG),1)
CFLAGS += -DDEBUG="1"
endif

all: load read_count

ebpf_nfilter.o: ebpf_nfilter.c common.h Makefile
	clang -target bpf $(CFLAGS) -c $< -o $@

read_count: read_count.c common.h Makefile
	gcc read_count.c $(CFLAGS) $(shell pkg-config libbpf --cflags --libs) -o $@

IFNAME ?= wlo1
.PHONY: load
load: ebpf_nfilter.o
	sudo tc qdisc delete dev $(IFNAME) clsact || true
	sudo tc qdisc add dev $(IFNAME) clsact
	sudo tc filter add dev $(IFNAME) ingress bpf da obj $< sec classifier
	sudo bpftool prog list
	sudo bpftool map dump name time_deltas
