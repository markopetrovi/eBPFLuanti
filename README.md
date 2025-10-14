# Luanti eBPF Network Filters

This repository provides high-performance eBPF/XDP programs and a management tool to protect **Luanti** (formerly Minetest) servers from packet-based abuse, such as UDP spam and flooding.

eBPF (extended Berkeley Packet Filter) is a Linux kernel technology that enables safe, sandboxed programs to run in the kernel for high-performance packet filtering. XDP (eXpress Data Path) processes packets at the earliest possible point in the network stack, often with JIT-compiled native code for minimal latency.

## Included Programs

* **`xdp_filter`**: Filters and bans IPs sending excessive UDP "init" packets matching the Luanti protocol.
* **`eBPFtool`**: A standalone CLI tool (no libbpf required) for managing ports, bans, and logs.

## Features

* ⚡ **High-performance**: Operates at the XDP layer for low latency and high throughput.
* 🚫 **Dynamic IP banning**: Automatically blocks abusive IPs.
* 🔁 **Auto-reset tracking**: Clears per-IP counters after inactivity.
* 🎯 **Port filtering**: Inspects only packets sent to specified ports.
* 🛠 **Self-contained CLI**: Uses raw `SYS_bpf` syscalls, no external libraries.
* 📜 **Detailed ban records**: Includes timestamps, duration, port, and reason.
* 📂 **Structured logs**: Outputs `ban_record` entries as a JSON array.

## Program Logic (xdp_filter)

The `xdp_filter` program rate-limits UDP init packets with:
* **Protocol ID**: `0x4f457403`
* **Peer ID**: `0x0000` (inexistent)
* **Threshold**: >100 packets in 10 seconds from one IP triggers a ban.

### Data Structures (Maps)

| Map Name        | Type     | Key             | Value               | Purpose                         |
|-----------------|----------|-----------------|---------------------|---------------------------------|
| `packet_count`  | LRU Hash | `u32` IP        | `struct ip_entry`   | Tracks packet count + timestamp |
| `records`       | Queue    | —               | `struct ban_record` | Ban event log queue             |
| `banned_ips`    | Hash     | `u32` IP        | `struct ban_entry`  | Stores current bans             |
| `watched_ports` | Hash     | `u16` port      | `u8`                | Ports to inspect for filtering  |

## Build and Usage

### 1. Build

Build the eBPF program and management tool:

```sh
make            # Generate vmlinux.h and compile xdp_filter.o, helper.o and eBPFtool
```

**Requirements**: `clang`, `gcc`, `make`, `bpftool`, and a Linux kernel with eBPF/XDP support.

### 2. Load/Unload XDP Filter

Attach the XDP filter to a network interface (e.g., `eth0`):

```sh
sudo ip link set dev <interface> xdp obj xdp_filter.o sec xdp
```

Detach the XDP filter:

```sh
sudo ip link set dev <interface> xdp off
```

**Verify**: Check with `sudo ip link show dev <interface>` (look for `xdp` tag).

**Note**: Replace `<interface>` with your network interface (e.g., `eth0`).

### 3. Load/Pin Helper Program

Load and pin the BPF helper program:

```sh
sudo bpftool prog load helper.o /sys/fs/bpf/xdp/globals/helper type syscall
sudo bpftool prog pin helper.o /sys/fs/bpf/xdp/globals/helper
```

**Verify**: Run `sudo bpftool prog list` to confirm pinning.

### 4. Unload Helper Program

```sh
sudo rm /sys/fs/bpf/xdp/globals/helper
```

### 5. Manage with eBPFtool

Run the management tool:

```sh
./eBPFtool --help
```

**Commands**:
* `dump_ports`: List watched ports.
* `add_port <port>` / `rm_port <port>`: Add/remove watched ports.
* `ban <port> <ip> <duration> <reason>`: Manually ban an IP.
* `unban <ip>`: Remove a ban.
* `list_bans`: Show active bans.
* `is_banned <ip>`: Check if an IP is banned.
* `fetch_logs`: Output JSON array of `ban_record` entries.

## License

Licensed under the GNU General Public License v2.0 (GPLv2). See the [LICENSE](./LICENSE) file for details.
