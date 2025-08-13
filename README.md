---

# Luanti eBPF Network Filters

This repository contains high-performance eBPF/XDP programs and a companion management tool designed to protect **Luanti** (formerly Minetest) servers from packet-based abuse, such as UDP spam and flooding.

eBPF (extended Berkeley Packet Filter) is a Linux kernel technology that allows loading verified, sandboxed programs directly into the kernel for safe, high-performance packet filtering. These programs can be JIT-compiled to native code for minimal latency while maintaining kernel stability.

---

## Included Programs

* **`xdp_filter`** – Filters and bans IPs that send too many UDP “init” packets matching the Luanti protocol format.
* **`eBPFtool`** – A standalone command-line utility (no `bpftool` or libbpf needed) for managing watched ports, bans, and logs.

---

## Features

* ⚡ **High-performance**: Runs at the XDP layer for minimal latency and maximum throughput.
* 🚫 **Dynamic IP banning**: Automatically blocks abusive IPs.
* 🔁 **Auto-reset tracking**: Resets per-IP counters after a period of inactivity.
* 🎯 **Port filtering**: Only inspects packets sent to explicitly watched ports.
* 🛠 **Self-contained management tool**: Uses raw `SYS_bpf` syscalls—no extra libraries required.
* 📜 **Detailed ban records**: Timestamps, duration, last seen port, and reason.
* 📂 **Structured logs**: `fetch_logs` outputs a JSON array of `ban_record` entries for easy parsing.

---

## Program Logic (xdp\_filter)

The program detects and rate-limits UDP init packets:

* **Protocol ID**: `0x4f457403`
* **Peer ID**: `0x0000` (inexistent)
* **Threshold**: More than 100 packets in 10 seconds from the same IP ➝ ban

### Data Structures (Maps)

| Map Name        | Type     | Key             | Value               | Purpose                         |
| --------------- | -------- | --------------- | ------------------- | ------------------------------- |
| `packet_count`  | LRU Hash | `u32` IP        | `struct ip_entry`   | Tracks packet count + timestamp |
| `records`       | Queue    | —               | `struct ban_record` | Ban event log queue             |
| `banned_ips`    | Hash     | `u32` IP        | `struct ban_entry`  | Stores current bans             |
| `watched_ports` | Hash     | `u16` port      | `u8`                | Ports to inspect for filtering  |

---

## Build and Usage

### 1. Build

```sh
make vmlinux   # Generates vmlinux.h for the eBPF program
make           # Compiles the management tool and the eBPF program
```

### 2. Load / Unload the Filter

> Loading/unloading is still done with the `ip` command.

```sh
sudo ip link set dev enp0s6 xdp obj xdp_filter.o sec xdp
sudo ip link set dev enp0s6 xdp off
```

### 3. Manage with eBPFtool

```sh
./eBPFtool --help
```

**Main commands:**

* `dump_ports` – List watched ports
* `add_port <port>` / `rm_port <port>` – Add/remove watched ports
* `ban <port> <ip> <duration> <reason>` – Manually ban an IP
* `unban <ip>` – Unban an IP
* `list_bans` – Show current bans
* `fetch_logs` – Output a JSON array of `ban_record` entries from expired bans and the log queue

---

## Requirements

* Linux kernel with eBPF/XDP support (relatively recent version recommended)
* `clang`, `llvm`, `make`
* Root privileges to load eBPF programs

---

## License

MIT License

---
