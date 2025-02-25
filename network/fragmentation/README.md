# Fragmentation
This is a simple program that uses eBPF to detect IPv4 fragmentation.

## How to Build

### Step1 - eBPF code compile
```shell
clang -O2 -target bpf -c frag_detect_kern.c -o frag_detect.o
```

### Step2 - bpf skeleton generate (bpftool use)
```shell
bpftool gen skeleton frag_detect.o > frag_detect.h
```

### Step3 - userspace code compile
```shell
gcc -o frag_detect frag_detect_user.c -lbpf
```

## How to Test

### Step1 - fragmentation detect exec
```shell
sudo ./frag_detect --ifname <ifname>
```

### Step2 - tc qdisc, filter check
* tc qdisc
	```shell
	tc qdisc show | grep clsact
	```

* tc filter
	```shell
	tc filter show dev <ifname> ingress
	```

### Step3 - ping test 

* normal case
	* Packet Recv Machine Terminal
		```shell
		cat /sys/kernel/tracing/trace_pipe
		```
	* Packet Send Machine Terminal
		```shell
		ping <Recv Machine Ipv4>
		```

* fragmentation case
	* Packet Recv Machine Terminal
		```shell
		cat /sys/kernel/tracing/trace_pipe
		```
	* Packet Send Machine Terminal
		```shell
		ping -s 2000 ping <Recv Machine Ipv4>
		```
	* Result
		```
		<idle>-0       [000] ..s..  6549.419673: bpf_trace_printk: IPv4 Fragmentation detected: src=<Send Macine IPv4>, dst=<Recv Machine IPv4>

		<idle>-0       [000] ..s..  6550.426207: bpf_trace_printk: IPv4 Fragmentation detected: src=<Send Macine IPv4>, dst=<Recv Machine IPv4>
		```