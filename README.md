# Luanti eBPF Network Filters

This repository contains high-performance eBPF/XDP programs designed to protect **Luanti** (formerly Minetest) servers from packet-based abuse, such as UDP spam and flooding.

eBPF (extended Berkeley Packet Filter) is a framework that allows loading privileged programs into the Linux kernel, but unlike regular kernel modules, eBPF programs are compiled into a special bytecode instruction set that enables the Linux kernel to verify that the program halts, accesses valid memory, etc., before it runs it in an interpreter or JIT-compiles it into native code for performance. Verifier, interpreter and JIT-compiler are all parts of the upstream Linux kernel.

## Included Filters

- **block_udp**: Filters and bans IPs that send too many UDP "init" packets matching the Luanti protocol format.

More eBPF programs targeting other types of Minetest-related abuse may be added in the future.

---

## Features

- ⚡ **High-performance**: Runs at the XDP layer for minimal latency and maximum throughput.
- 🚫 **Dynamic IP banning**: Automatically blocks abusive IPs.
- 🔁 **Auto-reset tracking**: Resets per-IP counters after a period of inactivity.
- 🎯 **Port filtering**: Only inspects packets to explicitly watched ports.

---

## block_udp: Overview

This eBPF program detects and rate-limits UDP init packets with the following conditions:

- **Protocol ID**: `0x4f457403`
- **Peer ID**: `0x0000` (inexistent)
- **Threshold**: More than 100 packets within 10 seconds from the same IP ➝ IP is banned

### Data Structures (Maps)

| Map Name       | Type         | Key              | Value            | Purpose                           |
|----------------|--------------|------------------|------------------|-----------------------------------|
| `packet_count` | LRU Hash     | `u32` IP         | `struct ip_entry`| Tracks packet count + time per IP |
| `banned_ips`   | Hash         | `u32` IP         | `u8`             | Stores banned IPs                 |
| `watched_ports`| Hash         | `u16` port (BE)  | `u8`             | Ports to inspect for filtering    |

---

## Build and Load Instructions

### 1. Compile the Filter

```sh
clang -O3 -g -mcpu=v3 -target bpf -c block_udp.c -o block_udp.o
```

### 2. Load the Filter

Replace `enp0s6` with your network interface:

```sh
ip link set dev enp0s6 xdp obj block_udp.o sec xdp
```

### 3. Configure Watched Ports

Use `bpftool` to determine the map ID:

```sh
bpftool map
```

Then update the watched port map. Example for port `30001` (hex `0x7531`):

```sh
bpftool map update id <MapID> key 0x75 0x31 value 0x01
```

### 4. Unload the Program

```sh
ip link set dev enp0s6 xdp off
```

> ⚠️ A user-friendly script to automate these steps will be added soon.

---

## Requirements

- Linux with eBPF/XDP support
- `clang`, `llvm`, `bpftool`
- Root privileges to load eBPF programs

---

## License

MIT License

---

## Contributing

Contributions for additional Minetest/Luanti-related eBPF filters are welcome
