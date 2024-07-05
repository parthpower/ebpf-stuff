# stuff with eBPF and `tc`

just some adventures with eBPF and `tc` because why not

## What does it do?

**7/4/2024**: attaches a _very crappy_ ebpf program on `tc filter` to measure time difference between packets (i.e. latency)

## Quick start

```shell
# debian/*buntu
# install ebpf stuff
# apt install -y clang llvm libelf-dev libbpf-dev bpfcc-tools linux-headers-$(uname -r) gcc

# get latest bpftools because it has more features like prog prof,
# curl -Lfs https://github.com/libbpf/bpftool/releases/download/v7.4.0/bpftool-v7.4.0-amd64.tar.gz | tar -xzv
# chmod +x ./bpftool

# enable bpf profiling
# sudo sysctl -w kernel.bpf_stats_enabled=1

# build stuff

# set IFNAME to something..
# it does sudo so be careful there

make IFNAME="ens1"

# FYI read_count doesn't really work, use "bpftool map dump name time_deltas"
```
