#ifndef SHARED_DEFS_H
#define SHARED_DEFS_H

#define DESC_SIZE 255
#define NANOSECONDS_PER_SECOND 1000000000UL
/* !!!!! IPs and ports in maps are in host byte order !!!!!
 * Reason: Correct display by bpftool
 */

struct ban_entry {
	u64 spam_start_timestamp;
	u64 timestamp;
	u64 duration;
	u16 banned_on_last_port;
	char desc[DESC_SIZE];
	u64 state;
};

struct ban_record {
	u64 spam_start_timestamp;
	u64 ban_timestamp;
	u64 autounban_timestamp;
	u64 ban_duration;
	u32 ip;
	u16 banned_on_last_port;
	char desc[DESC_SIZE];
};

struct init_handler_config {
	u32 block_threshold;
	u64 ip_count_reset_ns;
};

#ifdef __BPF__
#define STATE_ACTIVE 1
#define STATE_IN_DELETION 0

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 100);
	__type(key, u32);
	__type(value, struct ban_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} banned_ips SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 100);
	__uint(value_size, sizeof(struct ban_record));
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} records SEC(".maps");
#endif /* __BPF__ */

#endif /* SHARED_DEFS_H */
