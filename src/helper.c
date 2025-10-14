// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Rithvik Ballari <nexus-x[at]tuta[dot]io>

#include "../include/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <shared_defs.h>

static long __noinline handle_ban_entry(void *map, void *key_ptr, void *value_ptr)
{
	u32 *key = key_ptr;
	struct ban_entry *entry = value_ptr;
	u64 now = bpf_ktime_get_tai_ns();

	volatile u64 *state_ptr = &entry->state;
	if (__sync_val_compare_and_swap(state_ptr, STATE_ACTIVE, STATE_IN_DELETION) != STATE_ACTIVE)
		return 0; // Skip if already in deletion

	// Check expiration with 1-second margin for time skew
	u64 expiration_moment = entry->timestamp + entry->duration;
	if (expiration_moment < now - NANOSECONDS_PER_SECOND && expiration_moment > entry->timestamp) {
		struct ban_record rec = {
			.ban_timestamp = entry->timestamp,
			.autounban_timestamp = now,
			.ban_duration = entry->duration,
			.banned_on_last_port = entry->banned_on_last_port,
			.ip = *key,
			.spam_start_timestamp = entry->spam_start_timestamp
		};
		__builtin_memcpy(rec.desc, entry->desc, DESC_SIZE);
		int push_ret = bpf_map_push_elem(&records, &rec, 0);
		if (push_ret < 0) {
			bpf_printk("Failed to push to records: %d", push_ret);
			__sync_val_compare_and_swap(state_ptr, STATE_IN_DELETION, STATE_ACTIVE);
			return 0;
		}
		int delete_ret = bpf_map_delete_elem(&banned_ips, key);
		if (delete_ret < 0) {
			bpf_printk("Failed to delete from banned_ips: %d", delete_ret);
			__sync_val_compare_and_swap(state_ptr, STATE_IN_DELETION, STATE_ACTIVE);
			return 0;
		}
	} else {
		// Reset state if not expired
		__sync_val_compare_and_swap(state_ptr, STATE_IN_DELETION, STATE_ACTIVE);
	}
	return 0; // Continue iteration
}

SEC("syscall")
int handle_helper()
{
	bpf_for_each_map_elem(&banned_ips, handle_ban_entry, 0, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";
