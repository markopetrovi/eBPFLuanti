// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Marko Petrović <petrovicmarko2006@gmail.com>
#include "../include/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <shared_defs.h>
#define ETH_P_IP		0x0800

#define PROTOCOL_ID		0x4f457403
#define PEER_ID_INEXISTENT	0

/* !!!!! IPs and ports in maps are in host byte order !!!!!
 * Reason: Correct display by bpftool
 */
struct ip_entry {
	u64 count;
	u64 time;
	u64 first_seen;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 100);
	__type(key, u32);
	__type(value, struct ip_entry);
} packet_count SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10);
	__type(key, u16);
	__type(value, u8);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} watched_ports SEC(".maps");

/* Global functions can only return scalar values */
/* Atomic CAS to update time only if someone else didn't already update to a higher value */
/* __arg_nonnull annotation added in 6.8 */
int __noinline update_time(u64 now, u64 __arg_nonnull *time)
{
	int retries = 4000;
	u64 old_time;
	do {
		old_time = __sync_fetch_and_add(time, 0);
		if (old_time >= now)
			break;
	} while (!__sync_bool_compare_and_swap(time, old_time, now) && retries--);
	return 0;
}

u64 last_called = 0;
#define CREATE_REMINDER_ENTRY 15000000000UL	/* 15 seconds */
int handle_unconfigured_filter()
{
	u64 now = bpf_ktime_get_tai_ns();
	u64 old_time = __sync_fetch_and_add(&last_called, 0);
	if (now > old_time && now - old_time > CREATE_REMINDER_ENTRY) {
		struct ban_record rec = {
			.ban_timestamp = now,
			.autounban_timestamp = now,
			.ban_duration = 0,
			.banned_on_last_port = 0,
			.ip = 0,
			.spam_start_timestamp = now
		};
		#define UNCONFIGURED_MSG "[WARNING]: This is not a ban. init_handler_config map isn't properly set up. This is a notification that the init packet filter cannot work properly"
		__builtin_memcpy(rec.desc, UNCONFIGURED_MSG, sizeof(UNCONFIGURED_MSG));
		bpf_map_push_elem(&records, &rec, 0);
		update_time(now, &last_called);
	}
	return 0;
}

/* All in host byte order */
struct init_handler_args {
	int retval;
	u32 proto_id;
	u16 peer_id;
	u32 src_ip;
	u16 port;
};

#define CONTINUE_ITERATION	0
#define HALT_ITERATION		1
static long handle_init_packet(struct bpf_map *map, const void *key, void *value, void *ctx)
{
	struct init_handler_args *args = ctx;
	struct init_handler_config *config = value;

	if (!config->block_threshold && !config->ip_count_reset_ns) {
		handle_unconfigured_filter();
		return CONTINUE_ITERATION;
	}
	if (args->proto_id == PROTOCOL_ID && args->peer_id == PEER_ID_INEXISTENT) {
		struct ip_entry *entry = bpf_map_lookup_elem(&packet_count, &args->src_ip);
		u64 now = bpf_ktime_get_tai_ns();
		/* Return in this if, so that else isn't needed */
		if (entry) {
			u64 old_time = __sync_fetch_and_add(&entry->time, 0);
			if (now > old_time && now - old_time > config->ip_count_reset_ns)
				goto new_entry;

			/* Increment and check threshold */
			__sync_fetch_and_add(&entry->count, 1);
			u64 new_count = __sync_fetch_and_add(&entry->count, 0);
			if (new_count > config->block_threshold) {
				/* Ban this IP and free the entry, as this handler won't run for it again */
				struct ban_entry val = {
					.timestamp = now,
					.duration = 3600000000000ULL,   /* 1 hour */
					.banned_on_last_port = args->port,
					.spam_start_timestamp = entry->first_seen,
					.state = STATE_ACTIVE
				};
				u64 data[] = {config->block_threshold, now - val.spam_start_timestamp, config->ip_count_reset_ns / NANOSECONDS_PER_SECOND};
				bpf_snprintf(val.desc, DESC_SIZE, "Init packet spam, autoban. Sent %u packets during the time interval of %u seconds without any continuous %u second pause.", data, sizeof(data));
				bpf_map_update_elem(&banned_ips, &args->src_ip, &val, BPF_ANY);
				bpf_map_delete_elem(&packet_count, &args->src_ip);
				args->retval = XDP_DROP;
				return HALT_ITERATION;
			}
			/* Atomic CAS to update time */
			update_time(now, &entry->time);
			return CONTINUE_ITERATION;
		}
new_entry:
		/* Avoid warning: label followed by a declaration is a C23 extension */
		(void)1;
		struct ip_entry ent = {
			.count = 1,
			.time = now,
			.first_seen = now
		};
		bpf_map_update_elem(&packet_count, &args->src_ip, &ent, BPF_ANY);
	}
	return CONTINUE_ITERATION;
}

int __noinline handle_bans(u32 src_ip)
{
	struct ban_entry *entry = bpf_map_lookup_elem(&banned_ips, &src_ip);
	if (!entry)
		return XDP_PASS;

	if (entry->state == STATE_IN_DELETION)
		return XDP_DROP;

	u64 now = bpf_ktime_get_tai_ns();
	u64 expiration_moment = entry->timestamp + entry->duration;

	/* Check if ban has expired and no integer overflow occurred */
	if (expiration_moment < now && expiration_moment > entry->timestamp) {
		if (__sync_bool_compare_and_swap(&entry->state, STATE_ACTIVE, STATE_IN_DELETION)) {
			/* Only one instance will succeed in setting STATE_IN_DELETION */
			struct ban_record rec = {
				.ban_timestamp = entry->timestamp,
				.autounban_timestamp = now,
				.ban_duration = entry->duration,
				.banned_on_last_port = entry->banned_on_last_port,
				.ip = src_ip,
				.spam_start_timestamp = entry->spam_start_timestamp
			};
			__builtin_memcpy(rec.desc, entry->desc, DESC_SIZE);
			bpf_map_delete_elem(&banned_ips, &src_ip);
			bpf_map_push_elem(&records, &rec, BPF_EXIST);
			return XDP_PASS;
		}
		/* If CAS failed, another instance already set STATE_IN_DELETION */
		return XDP_DROP;
	}

	/* Ban is still active and not expired */
	return XDP_DROP;
}

SEC("xdp")
int luanti_filter(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	// Ethernet header
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != __bpf_constant_htons(ETH_P_IP))
		return XDP_PASS;

	// IPv4 header
	struct iphdr *ip = data + sizeof(*eth);
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;
	if (ip->protocol != IPPROTO_UDP)
		return XDP_PASS;

	// UDP header
	struct udphdr *udp = (void *)ip + ip->ihl * 4;
	if ((void *)(udp + 1) > data_end)
		return XDP_PASS;

	// Filter destination port
	u16 port = bpf_ntohs(udp->dest);
	u8 *is_watched = bpf_map_lookup_elem(&watched_ports, &port);
	if (!is_watched || *is_watched != 1)
		return XDP_PASS;

	/*
	 * Payload handlers
	 * Extracting data from payload is done here because only here verifier trusts payload bounds checks
	 * More complex data parsing can be done in an __always_inline function
	*/
	int ret;
	unsigned char *payload = (unsigned char *)(udp + 1);
	u32 src_ip = bpf_ntohl(ip->saddr);

	ret = handle_bans(src_ip);
	if (ret == XDP_DROP)
		return ret;

	if ((void *)(payload + sizeof(u32) + sizeof(u16)) > data_end)
		return XDP_PASS;
	u32 proto_raw;
	u16 peer_raw;
	__builtin_memcpy(&proto_raw, payload, sizeof(proto_raw));
	__builtin_memcpy(&peer_raw, payload + sizeof(proto_raw), sizeof(peer_raw));

	struct init_handler_args args = {
		.proto_id = bpf_ntohl(proto_raw),
		.peer_id = bpf_ntohs(peer_raw),
		.port = port,
		.src_ip = src_ip,
		.retval = XDP_PASS
	};
	bpf_for_each_map_elem(&init_handler_config, handle_init_packet, &args, 0);
	if (args.retval == XDP_DROP)
		return XDP_DROP;

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
