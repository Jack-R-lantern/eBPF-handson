# DDoS Blocker
This is a simple program that uses eBPF to defense DDoS Attack.

## How to Build

### Step1
```shell
make build
```

## app argument
```shell
Usage of ./bin/app:
  -addr string
        HTTP listen addr (default "127.0.0.1:8080")
  -if string
        interface name for XDP attach (default "eth0")
  -map string
        BPF map name (IPv4 key) (default "blocked_ips")
  -obj string
        path to BPF ELF object (required)
```

## How To Test
### Step1 - app exec

```shell
sudo ./bin/app -addr <your listen addr> -if <interface name> -obj ./bpf/xdp.o
```

### Step2 - xdp, map check
* xdp
	* check
		```shell
		sudo bpftool prog show name xdp_blocker
		```
	* result
		```
		49: xdp  name xdp_blocker  tag 170bf9a3b818db5a  gpl
			loaded_at 2025-08-23T12:37:29+0000  uid 0
			xlated 288B  jited 170B  memlock 4096B  map_ids 16,18
			btf_id 82
		```

* map
	* check
		```shell
		sudo bpftool map show name <map name | default blocked_ips>
		```
	* result
		```
		16: hash  name blocked_ips  flags 0x0
        key 4B  value 1B  max_entries 1024  memlock 83648B
        btf_id 80
		```

### Step3 - ping test
* Packet Send
	```shell
	ping <your server ip>
	```

* Packet Send Result
	```
	$ ip -br -c a
	lo               UNKNOWN        127.0.0.1/8 ::1/128 
	ens4             UP             10.178.0.15/32 metric 100 fe80::4001:aff:feb2:f/64
	$
	$ ping 10.178.0.13
	PING 10.178.0.13 (10.178.0.13) 56(84) bytes of data.
	64 bytes from 10.178.0.13: icmp_seq=1 ttl=64 time=2.13 ms
	64 bytes from 10.178.0.13: icmp_seq=2 ttl=64 time=0.613 ms
	64 bytes from 10.178.0.13: icmp_seq=3 ttl=64 time=0.654 ms
	64 bytes from 10.178.0.13: icmp_seq=4 ttl=64 time=0.633 ms
	64 bytes from 10.178.0.13: icmp_seq=5 ttl=64 time=0.631 ms
	64 bytes from 10.178.0.13: icmp_seq=6 ttl=64 time=0.628 ms
	64 bytes from 10.178.0.13: icmp_seq=7 ttl=64 time=0.669 ms
	--- 10.178.0.13 ping statistics ---
	7 packets transmitted, 7 received, 0% packet loss, time 6112ms
	rtt min/avg/max/mdev = 0.613/0.850/2.126/0.520 ms
	```
	
### Step4 - block ip
* Request
	```shell
	curl -X POST <your server addr>/block \
	-H "Content-Type: application/json" \
	-d '{"ip":"<block ip>"}'
	```

* Requelst Result
	```shell
	$ curl -X POST http://10.178.0.13:8080/block \
        -H "Content-Type: application/json" \
        -d '{"ip":"10.178.0.15"}'
	{"blocked":"10.178.0.15","status":"ok"}$ 
	```

### Step5 - ping test
* Packet Send
	```shell
	ping <your server ip>
	```

* Packet Send Result
	```shell
	$ ip -br -c a
	lo               UNKNOWN        127.0.0.1/8 ::1/128 
	ens4             UP             10.178.0.15/32 metric 100 fe80::4001:aff:feb2:f/64
	$
	$ ping 10.178.0.13     
	PING 10.178.0.13 (10.178.0.13) 56(84) bytes of data.
	--- 10.178.0.13 ping statistics ---
	4 packets transmitted, 0 received, 100% packet loss, time 3061ms
	```

### Step6 - clear block
* Request
	```shell
	curl -X POST <your server addr>/clear \
	-H "Content-Type: application/json" \
	-d '{"ip":"<block ip>"}'
	```

* Request Result
	```shell
	$ ip -br -c a
	lo               UNKNOWN        127.0.0.1/8 ::1/128
	ens4             UP             10.178.0.13/32 metric 100 fe80::4001:aff:feb2:d/64
	docker0          DOWN           172.17.0.1/16
	$
	$ curl -X POST http://localhost:8080/clear \
	  -H "Cotent-Type: application/json" \
	  -d '{"ip": "10.178.0.15"}'
	{"cleared":"10.178.0.15","status":"ok"}
	```
### Step7 - ping test
* Packet Send
	```shell
	ping <your server ip>
	```

* Packet Send Result
	```shell
	$ ip -br -c a
	lo               UNKNOWN        127.0.0.1/8 ::1/128 
	ens4             UP             10.178.0.15/32 metric 100 fe80::4001:aff:feb2:f/64 

	$ ping 10.178.0.13 -c 3
	PING 10.178.0.13 (10.178.0.13) 56(84) bytes of data.
	64 bytes from 10.178.0.13: icmp_seq=1 ttl=64 time=1.37 ms
	64 bytes from 10.178.0.13: icmp_seq=2 ttl=64 time=0.692 ms
	64 bytes from 10.178.0.13: icmp_seq=3 ttl=64 time=0.677 ms

	--- 10.178.0.13 ping statistics ---
	3 packets transmitted, 3 received, 0% packet loss, time 2029ms
	rtt min/avg/max/mdev = 0.677/0.912/1.368/0.322 ms
	```