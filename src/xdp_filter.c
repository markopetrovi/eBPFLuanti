#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#define ETH_P_IP		0x0800

#define PROTOCOL_ID		0x4f457403
#define PEER_ID_INEXISTENT	0
#define BLOCK_THRESHOLD		100
#define IP_COUNT_RESET_NS	10000000000ULL	// 10 seconds

struct ip_entry {
	u64 count;
	u64 time;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 100);
	__type(key, u32);	// IP in host byte order
	__type(value, struct ip_entry);
} packet_count SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 300);
	__type(key, u32);	// IP in host byte order
	__type(value, u8);
} banned_ips SEC(".maps");

// Fill this map with bpftool
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10);
	__type(key, u16);	// Port in big-endian (network) byte order, as that's how we write naturally
	__type(value, u8);
} watched_ports SEC(".maps");

// Only functions that return a scalar are supported
// Atomic CAS to update time only if someone else didn't already update to a higher value
static int update_time(u64 now, u64 *time)
{
	int retries = 1000;
	u64 old_time;
	if (!time)
		return 0;
	do {
		old_time = __sync_fetch_and_add(time, 0);
		if (old_time >= now)
			break;
	} while (!__sync_bool_compare_and_swap(time, old_time, now) && retries--);
	return 0;
}

// It's a bit troubling to pass the verifier when this is a separate function
// Verifier checks each function as a separate program, so it loses trust in the payload bounds checks. Thus payload cannot be the argument.
static int handle_init_packet(u32 proto_raw, u16 peer_raw, u32 src_ip)
{
	u32 proto_id = bpf_ntohl(proto_raw);
	u16 peer_id = bpf_ntohs(peer_raw);

	if (proto_id == PROTOCOL_ID && peer_id == PEER_ID_INEXISTENT) {
		struct ip_entry *entry = bpf_map_lookup_elem(&packet_count, &src_ip);
		u64 now = bpf_ktime_get_tai_ns();
		// Return in this if, so that else isn't needed
		if (entry) {
			u64 old_time = __sync_fetch_and_add(&entry->time, 0);
			if (now > old_time && now - old_time > IP_COUNT_RESET_NS)
				goto new_entry;

			// Increment and check threshold
			__sync_fetch_and_add(&entry->count, 1);
			u64 new_count = __sync_fetch_and_add(&entry->count, 0);
			if (new_count > BLOCK_THRESHOLD) {
				// Ban this IP and free the entry, as this handler won't run for it again
				// Delete might fail, but we don't care as there's no sensible error recovery path, and the entry would be deleted by LRU eventually anyway
				u8 val = 1;
				bpf_map_update_elem(&banned_ips, &src_ip, &val, BPF_ANY);
				bpf_map_delete_elem(&packet_count, &src_ip);
				return XDP_DROP;
			}
			// Atomic CAS to update time
			update_time(now, &entry->time);
			return XDP_PASS;
		}
new_entry:
		// Avoid warning: label followed by a declaration is a C23 extension
		(void)1;
		struct ip_entry ent = {
			.count = 1,
			.time = now
		};
		bpf_map_update_elem(&packet_count, &src_ip, &ent, BPF_ANY);
	}
	return XDP_PASS;
}

static int handle_bans(u32 src_ip)
{
	u8 *is_banned = bpf_map_lookup_elem(&banned_ips, &src_ip);
	if (is_banned && *is_banned)
		return XDP_DROP;
	return XDP_PASS;
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
	u8 *is_watched = bpf_map_lookup_elem(&watched_ports, &udp->dest);
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
	ret = handle_init_packet(proto_raw, peer_raw, src_ip);
	if (ret == XDP_DROP)
		return ret;

	return XDP_PASS;
}

char _license[] SEC("license") = "MIT";
