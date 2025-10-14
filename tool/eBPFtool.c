// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Marko Petrović <petrovicmarko2006@gmail.com>
#define _GNU_SOURCE
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>
#include <sys/timex.h>
#include <stdbool.h>
#define u8 uint8_t
#define u16 uint16_t
#define u32 uint32_t
#define u64 uint64_t
#define NANOSECONDS_PER_SECOND 1000000000UL

static const char *getconfig(const char *name, const char *default_val)
{
	const char *val = getenv(name);
	return val ? val : default_val;
}

#define BANNED_IPS_MAP		1
#define RECORDS_MAP		2
#define WATCHED_PORTS_MAP	4
#define CONFIG_MAP		8
#define HELPER_PROG		16

struct map_fds {
	int banfd, portfd, recordfd, configfd, helperfd;
};

union ipv4_addr {
	uint32_t addr;
	struct {
		uint8_t a, b, c, d;
	};
};

#define DESC_SIZE 255

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
	u32 ip;		/* IP in host byte order */
	u16 banned_on_last_port;
	char desc[DESC_SIZE];
};

struct init_handler_config {
	u32 block_threshold;
	u64 ip_count_reset_ns;
};

static struct map_fds open_object(const char *object_dir, int map_ids)
{
	struct map_fds fds;
	union bpf_attr attr;

	int dirfd = open(object_dir, O_PATH);
	if (dirfd < 0) {
		perror("open(object_dir)");
		exit(1);
	}
	memset(&attr, 0, sizeof(union bpf_attr));
	attr.path_fd = dirfd;
	attr.file_flags = BPF_F_PATH_FD;

	if (map_ids & BANNED_IPS_MAP) {
		attr.pathname = (u64) "banned_ips";
		fds.banfd = syscall(SYS_bpf, BPF_OBJ_GET, &attr, sizeof(union bpf_attr));
		if (fds.banfd < 0) {
			perror("BPF_OBJ_GET banned_ips");
			exit(1);
		}
	}
	if (map_ids & WATCHED_PORTS_MAP) {
		attr.pathname = (u64) "watched_ports";
		fds.portfd = syscall(SYS_bpf, BPF_OBJ_GET, &attr, sizeof(union bpf_attr));
		if (fds.portfd < 0) {
			perror("BPF_OBJ_GET watched_ports");
			exit(1);
		}
	}
	if (map_ids & RECORDS_MAP) {
		attr.pathname = (u64) "records";
		fds.recordfd = syscall(SYS_bpf, BPF_OBJ_GET, &attr, sizeof(union bpf_attr));
		if (fds.recordfd < 0) {
			perror("BPF_OBJ_GET records");
			exit(1);
		}
	}
	if (map_ids & CONFIG_MAP) {
		attr.pathname = (u64) "init_handler_config";
		fds.configfd = syscall(SYS_bpf, BPF_OBJ_GET, &attr, sizeof(union bpf_attr));
		if (fds.configfd < 0) {
			perror("BPF_OBJ_GET init_handler_config");
			exit(1);
		}
	}
	if (map_ids & HELPER_PROG) {
		attr.pathname = (u64) "helper";
		fds.helperfd = syscall(SYS_bpf, BPF_OBJ_GET, &attr, sizeof(union bpf_attr));
		if (fds.helperfd < 0) {
			perror("BPF_OBJ_GET helper");
			exit(1);
		}
	}
	close(dirfd);

	return fds;
}

static void dump_ports(int portfd)
{
	union bpf_attr attr;
	memset(&attr, 0, sizeof(union bpf_attr));
	u16 keys[10];	/* Ports */
	u8 values[10];	/* Should all be 1 */
	u32 batch_params[2] = {0, 0};
	attr.batch.map_fd = portfd;
	attr.batch.in_batch = (u64) &batch_params[0];
	attr.batch.out_batch = (u64) &batch_params[1];
	attr.batch.keys = (u64) keys;
	attr.batch.values = (u64) values;
	printf("Currently watched ports:\n");
	int saved_errno = 0;
	do {
		attr.batch.count = 10;
		/* ENOENT means we just didn't have enough entries to fill a batch of 10 */
		if (syscall(SYS_bpf, BPF_MAP_LOOKUP_BATCH, &attr, sizeof(union bpf_attr)) && errno != ENOENT) {
			perror("bpf(BPF_MAP_LOOKUP_BATCH watched_ports)");
			exit(1);
		}
		saved_errno = errno;
		for (int i = 0; i < attr.batch.count; i++) {
			if (values[i] == 1)
				printf("%u\n", keys[i]);
		}
		* (u32*)attr.batch.in_batch = * (u32*)attr.batch.out_batch;
	} while (saved_errno != ENOENT);
}

static int get_tai_offset()
{
	struct timex buf;
	memset(&buf, 0, sizeof(struct timex));
	int ret = adjtimex(&buf);
	if (ret == -1) {
		perror("adjtimex");
		exit(1);
	}
	if (ret == TIME_ERROR)
		fprintf(stderr, "Warning: System clock isn't properly synchronized.\n");
	return buf.tai;
}
static int tai_offset;

/* Return a (-1)-terminated array of indexes for bans that should be removed */
static int* find_expired_bans(struct ban_entry *entries, int count)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_TAI, &ts)) {
		perror("clock_gettime(CLOCK_TAI)");
		exit(1);
	}
	u64 now = (u64)ts.tv_nsec + (NANOSECONDS_PER_SECOND * (u64)ts.tv_sec);
	int *results = malloc((count+1)*sizeof(int));
	if (!results)
		exit(ENOMEM);
	int res_count = 0;
	for (int i = 0; i < count; i++) {
		u64 expiration_moment = entries[i].timestamp + entries[i].duration;
		/* Expiration moment passed and integer overflow didn't happen */
		if (expiration_moment < now && expiration_moment > entries[i].timestamp)
			results[res_count++] = i;
	}
	results[res_count] = -1;
	return results;
}

static char *prepare_entry_for_printing(struct ban_entry *entry, char *spam_start_timestamp)
{
	/* Convert to seconds and Unix time */
	entry->duration /= NANOSECONDS_PER_SECOND;
	entry->timestamp = (entry->timestamp / NANOSECONDS_PER_SECOND) - tai_offset;
	char *timestamp_str = ctime((long*)&entry->timestamp);
	if (!timestamp_str) {
		perror("ctime");
		exit(1);
	}
	if (entry->spam_start_timestamp) {
		entry->spam_start_timestamp = (entry->spam_start_timestamp / NANOSECONDS_PER_SECOND) - tai_offset;
		spam_start_timestamp = ctime_r((long*)&entry->spam_start_timestamp, spam_start_timestamp);
		if (!spam_start_timestamp) {
			perror("ctime_r");
			exit(1);
		}
	}
	else {
		spam_start_timestamp[0] = '\0';
	}
	return timestamp_str;
}

static char *prepare_record_for_printing(struct ban_record *record, char *spam_start_timestamp, char *ban_timestamp, char *autounban_timestamp)
{
	/* Convert to seconds and Unix time */
	record->ban_duration /= NANOSECONDS_PER_SECOND;
	record->ban_timestamp = (record->ban_timestamp / NANOSECONDS_PER_SECOND) - tai_offset;
	ban_timestamp = ctime_r((long*)&record->ban_timestamp, ban_timestamp);
	if (!ban_timestamp) {
		perror("ctime_r");
		exit(1);
	}
	record->autounban_timestamp = (record->autounban_timestamp / NANOSECONDS_PER_SECOND) - tai_offset;
	autounban_timestamp = ctime_r((long*)&record->autounban_timestamp, autounban_timestamp);
	if (!autounban_timestamp) {
		perror("ctime_r");
		exit(1);
	}
	if (record->spam_start_timestamp) {
		record->spam_start_timestamp = (record->spam_start_timestamp / NANOSECONDS_PER_SECOND) - tai_offset;
		spam_start_timestamp = ctime_r((long*)&record->spam_start_timestamp, spam_start_timestamp);
		if (!spam_start_timestamp) {
			perror("ctime_r");
			exit(1);
		}
	}
	else {
		spam_start_timestamp[0] = '\0';
	}
	return ban_timestamp;
}

/* Simple escape for command-line strings (only " and \) */
static char* simple_json_escape(char* str)
{
	size_t extra_chars = 0, orig_len = 0;
	for (const char* p = str; *p; p++) {
		if (*p == '"' || *p == '\\')
			extra_chars++;
		orig_len++;
	}

	if (extra_chars == 0)
		return str;

	char* escaped = malloc(orig_len + extra_chars + 1);
	if (!escaped) exit(ENOMEM);

	char* dst = escaped;
	for (const char* src = str; *src; src++) {
		if (*src == '"' || *src == '\\') {
			*dst++ = '\\';
		}
		*dst++ = *src;
	}
	*dst = '\0';

	return escaped;
}

static void __attribute__((noreturn)) dispatch_command(int argc, char *argv[])
{
	if (!strcmp(argv[1], "--help")) {
		printf("Supported commands:\n");
		printf("dump_ports: Write all currently watched ports\n");
		printf("add_port <port>: Add port to the watchlist\n");
		printf("rm_port <port>: Remove port from the watchlist\n");
		printf("ban <port (if you're in shell)> <ip> <duration_seconds> <reason>: IP-ban this user on all ports. The <port> argument just shows where they were last spotted.\n");
		printf("unban <ip>: Unban this IP and print the data needed by caller to assemble a ban record\n");
		printf("list_bans: List all bans currently in effect\n");
		printf("is_banned <ip>: Check if the given IP is banned.\n");
		printf("config <block_threshold> <ip_reset_time_ns>: Configure the automatic init packet handler. Specify how many packets (block_threshold) need to be sent without any pause in transmission longer than ip_reset_time_ns\n");
		printf("fetch_logs: Pop elements from the records map and build records from expired entries in the banned_ips table. Output everything for logging purposes. Should only be called by the logging code, call manually only if you know what you're doing.\n");
		exit(0);
	}
	const char *object_dir = getconfig("MAP_DIR", "/sys/fs/bpf/xdp/globals");

	if (!strcmp(argv[1], "dump_ports")) {
		if (argc != 2) {
			fprintf(stderr, "Usage: %s dump_ports\n", argv[0]);
			exit(1);
		}
		struct map_fds fds = open_object(object_dir, WATCHED_PORTS_MAP);
		dump_ports(fds.portfd);
		exit(0);
	}

	if (!strcmp(argv[1], "add_port")) {
		if (argc < 3 || argc > 65535 + 2) {
			fprintf(stderr, "Usage: %s add_port <port1> [port2] ... [portN]\n", argv[0]);
			exit(1);
		}
		struct map_fds fds = open_object(object_dir, WATCHED_PORTS_MAP);
		union bpf_attr attr;
		memset(&attr, 0, sizeof(union bpf_attr));
		attr.map_fd = fds.portfd;
		u8 value = 1;
		attr.value = (u64) &value;
		attr.flags = BPF_NOEXIST;
		for (int i = 2; i < argc; i++) {
			int int_port = atoi(argv[i]);
			if (int_port <= 0 || int_port > 65535) {
				fprintf(stderr, "Failed to parse \"%s\"\n", argv[i]);
				continue;
			}
			u16 port = int_port;
			attr.key = (u64) &port;
			if (syscall(SYS_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(union bpf_attr))) {
				if (errno == EEXIST) {
					fprintf(stderr, "Port %s is already watched.\n", argv[i]);
					continue;
				}
				perror("BPF_MAP_UPDATE_ELEM watched_ports");
				exit(1);
			}
		}
		exit(0);
	}

	if (!strcmp(argv[1], "rm_port")) {
		if (argc < 3 || argc > 65535 + 2) {
			fprintf(stderr, "Usage: %s rm_port <port1> [port2] ... [portN]\n", argv[0]);
			exit(1);
		}
		struct map_fds fds = open_object(object_dir, WATCHED_PORTS_MAP);
		union bpf_attr attr;
		memset(&attr, 0, sizeof(union bpf_attr));
		attr.batch.map_fd = fds.portfd;
		u16 *ports = malloc(sizeof(u16) * (argc-2));
		if (!ports)
			exit(ENOMEM);
		attr.batch.keys = (u64) ports;
		for (int i = 2; i < argc; i++) {
			int port = atoi(argv[i]);
			if (port <= 0 || port > 65535) {
				fprintf(stderr, "Failed to parse \"%s\"\n", argv[i]);
				continue;
			}
			ports[i-2] = port;
			attr.batch.count++;
		}
		unsigned int old_count = attr.batch.count;
		if (syscall(SYS_bpf, BPF_MAP_DELETE_BATCH, &attr, sizeof(union bpf_attr))) {
			if (errno == ENOENT) {
				fprintf(stderr, "Some ports were not found in the watchlist.\n");
			}
			else {
				perror("BPF_MAP_DELETE_BATCH watched_ports");
				exit(1);
			}
		}
		printf("Deleted %u out of parsed %u ports\n", attr.batch.count, old_count);
		exit(0);
	}

	if (!strcmp(argv[1], "ban")) {
		if (argc != 6) {
			fprintf(stderr, "Usage: %s ban <port (if you're in shell)> <ip> <duration_seconds> <reason>\n", argv[0]);
			exit(1);
		}
		struct map_fds fds = open_object(object_dir, BANNED_IPS_MAP);
		struct ban_entry entry;
		int port = atoi(argv[2]);
		if (port <= 0 || port > 65535) {
			fprintf(stderr, "Invalid port %s\n", argv[2]);
			exit(1);
		}
		entry.banned_on_last_port = port;
		struct in_addr addr;
		if (inet_pton(AF_INET, argv[3], &addr) != 1) {
			fprintf(stderr, "Invalid IPv4 address %s\n", argv[3]);
			exit(1);
		}
		u32 key = ntohl(addr.s_addr);
		char *endptr;
		entry.duration = strtoull(argv[4], &endptr, 10);
		if (!entry.duration || *endptr != '\0') {
			fprintf(stderr, "Failed to parse ban duration %s\n", argv[4]);
			if (*endptr != '\0')
				fprintf(stderr, "Found unrecognized character: %c\n", *endptr);
			exit(1);
		}
		if (entry.duration > UINT64_MAX / NANOSECONDS_PER_SECOND)
			entry.duration = UINT64_MAX;
		else
			entry.duration *= NANOSECONDS_PER_SECOND;
		strncpy(entry.desc, argv[5], DESC_SIZE-1);
		entry.desc[DESC_SIZE-1] = '\0';
		struct timespec ts;
		if (clock_gettime(CLOCK_TAI, &ts)) {
			perror("clock_gettime(CLOCK_TAI)");
			exit(1);
		}
		entry.timestamp = (u64)ts.tv_nsec + (NANOSECONDS_PER_SECOND * (u64)ts.tv_sec);
		entry.spam_start_timestamp = 0;
		entry.state = 1; // STATE_ACTIVE

		union bpf_attr attr;
		memset(&attr, 0, sizeof(union bpf_attr));
		attr.map_fd = fds.banfd;
		attr.value = (u64) &entry;
		attr.flags = BPF_NOEXIST;
		attr.key = (u64) &key;
		if (syscall(SYS_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(union bpf_attr))) {
			if (errno == EEXIST)
				fprintf(stderr, "IP %s was already banned.\n", argv[3]);
			else
				perror("BPF_MAP_UPDATE_ELEM watched_ports");
			exit(1);
		}
		exit(0);
	}

	if (!strcmp(argv[1], "unban")) {
		if (argc != 3) {
			fprintf(stderr, "Usage: %s unban <ip>\n", argv[0]);
			exit(1);
		}
		struct map_fds fds = open_object(object_dir, BANNED_IPS_MAP);
		struct in_addr addr;
		if (inet_pton(AF_INET, argv[2], &addr) != 1) {
			fprintf(stderr, "Invalid IPv4 address %s\n", argv[2]);
			exit(1);
		}
		u32 key = ntohl(addr.s_addr);
		union bpf_attr attr;
		memset(&attr, 0, sizeof(union bpf_attr));
		struct ban_entry entry;
		attr.map_fd = fds.banfd;
		attr.value = (u64) &entry;
		attr.key = (u64) &key;
		if (syscall(SYS_bpf, BPF_MAP_LOOKUP_AND_DELETE_ELEM, &attr, sizeof(union bpf_attr))) {
			if (errno == ENOENT)
				fprintf(stderr, "IP %s isn't banned.\n", argv[2]);
			else
				perror("BPF_MAP_LOOKUP_AND_DELETE_ELEM banned_ips");
			exit(1);
		}

		int *res = find_expired_bans(&entry, 1);
		bool is_expired = (res[0] == 0);

		char buf[26];
		char *timestamp_str = prepare_entry_for_printing(&entry, buf);
		/* Strings from ctime already contain \n */
		if (buf[0])
			printf("Spam Start Timestamp: %s", buf);
		printf("Timestamp: %s", timestamp_str);
		printf("Duration: %lu\n", entry.duration);
		printf("Description: %s\n", entry.desc);
		if (is_expired)
			printf("Ban for %s had already expired and was pending removal.\n", argv[2]);
		else
			printf("IP %s unbanned\n", argv[2]);

		exit(0);
	}

	if (!strcmp(argv[1], "list_bans")) {
		if (argc != 2) {
			fprintf(stderr, "Usage: %s list_bans\n", argv[0]);
			exit(1);
		}
		struct map_fds fds = open_object(object_dir, BANNED_IPS_MAP);
		union bpf_attr attr;
		memset(&attr, 0, sizeof(union bpf_attr));
		u32 keys[10];	/* IPs in host byte order */
		struct ban_entry values[10];
		u32 batch_params[2] = {0, 0};
		attr.batch.map_fd = fds.banfd;
		attr.batch.in_batch = (u64) &batch_params[0];
		attr.batch.out_batch = (u64) &batch_params[1];
		attr.batch.keys = (u64) keys;
		attr.batch.values = (u64) values;
		printf("Currently banned IPs:\n");
		int saved_errno = 0;
		do {
			attr.batch.count = 10;
			/* ENOENT means we just didn't have enough entries to fill a batch of 10 */
			if (syscall(SYS_bpf, BPF_MAP_LOOKUP_BATCH, &attr, sizeof(union bpf_attr)) && errno != ENOENT) {
				perror("bpf(BPF_MAP_LOOKUP_BATCH banned_ips)");
				exit(1);
			}
			saved_errno = errno;
			int *res = find_expired_bans(values, attr.batch.count);
			int res_count = 0;
			for (int i = 0; i < attr.batch.count; i++) {
				if (i == res[res_count]) {
					res_count++;
					continue;
				}
				struct in_addr addr;
				addr.s_addr = htonl(keys[i]);
				char *ip_str = inet_ntoa(addr);
				printf("%s {\n", ip_str);
				char buf[26];
				char *timestamp_str = prepare_entry_for_printing(&values[i], buf);
				/* Strings from ctime already contain \n */
				if (buf[0])
					printf("\tSpam Start Timestamp: %s", buf);
				printf("\tTimestamp: %s", timestamp_str);
				printf("\tDuration: %lu\n", values[i].duration);
				printf("\tLast seen on port: %u\n", values[i].banned_on_last_port);
				printf("\tDescription: %s\n}\n", values[i].desc);
			}
			free(res);
			* (u32*)attr.batch.in_batch = * (u32*)attr.batch.out_batch;
		} while (saved_errno != ENOENT);
		exit(0);
	}

	if (!strcmp(argv[1], "fetch_logs")) {
		if (argc != 2) {
			fprintf(stderr, "Usage: %s fetch_logs\n", argv[0]);
			exit(1);
		}
		struct map_fds fds = open_object(object_dir, RECORDS_MAP | HELPER_PROG);
		int prog_fd = fds.helperfd;
		if (prog_fd < 0) {
			fprintf(stderr, "Helper program not opened\n");
			exit(1);
		}

		union bpf_attr attr;
		memset(&attr, 0, sizeof(union bpf_attr));
		attr.test.prog_fd = prog_fd;
		attr.test.ctx_in = 0;
		attr.test.ctx_size_in = 0;
		if (syscall(SYS_bpf, BPF_PROG_RUN, &attr, sizeof(union bpf_attr))) {
			perror("BPF_PROG_RUN helper");
			close(prog_fd);
			exit(1);
		}
		close(prog_fd);

		// Pop and print all records from the records map
		union bpf_attr pop_attr;
		struct ban_record record;
		printf("[");
		bool comma = false;
		while (1) {
			memset(&pop_attr, 0, sizeof(union bpf_attr));
			pop_attr.map_fd = fds.recordfd;
			pop_attr.value = (u64)&record;
			if (syscall(SYS_bpf, BPF_MAP_LOOKUP_AND_DELETE_ELEM, &pop_attr, sizeof(union bpf_attr))) {
				if (errno == ENOENT) {
					break; // No more records
				}
				perror("BPF_MAP_LOOKUP_AND_DELETE_ELEM records");
				exit(1);
			}

			struct in_addr addr;
			addr.s_addr = htonl(record.ip);
			char *ip_str = inet_ntoa(addr);
			char spam_buf[26], ban_buf[26], unban_buf[26];
			prepare_record_for_printing(&record, spam_buf, ban_buf, unban_buf);
			if (comma) {
				printf(",\n");
			} else {
				printf("\n");
			}
			comma = true;
			ban_buf[24] = '\0';
			unban_buf[24] = '\0';
			if (spam_buf[0]) {
				spam_buf[24] = '\0';
			}
			printf("\t{\n");
			printf("\t\t\"ban_timestamp\": \"%s\",\n", ban_buf);
			printf("\t\t\"ban_timestamp\": \"%s\",\n", ban_buf);
			if (spam_buf[0]) {
				printf("\t\t\"spam_start_timestamp\": \"%s\",\n", spam_buf);
			}
			printf("\t\t\"unban_timestamp\": \"%s\",\n", unban_buf);
			printf("\t\t\"ban_duration\": %lu,\n", record.ban_duration);
			printf("\t\t\"ip\": \"%s\",\n", ip_str);
			printf("\t\t\"banned_on_last_port\": %u,\n", record.banned_on_last_port);
			char *escaped_desc = simple_json_escape(record.desc);
			printf("\t\t\"description\": \"%s\"\n\t}", escaped_desc);
			if (escaped_desc != record.desc) {
				free(escaped_desc);
			}
		}
		printf("\n]\n");
		exit(0);
	}

	if (!strcmp(argv[1], "is_banned")) {
		if (argc != 3) {
			fprintf(stderr, "Usage: %s is_banned <ip>\n", argv[0]);
			exit(1);
		}
		struct map_fds fds = open_object(object_dir, BANNED_IPS_MAP);
		struct in_addr addr;
		if (inet_pton(AF_INET, argv[2], &addr) != 1) {
			fprintf(stderr, "Invalid IPv4 address %s\n", argv[2]);
			exit(1);
		}
		u32 key = ntohl(addr.s_addr);

		union bpf_attr attr;
		struct ban_entry entry;
		memset(&attr, 0, sizeof(union bpf_attr));
		attr.map_fd = fds.banfd;
		attr.key = (u64) &key;
		attr.value = (u64) &entry;
		if (syscall(SYS_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(union bpf_attr))) {
			if (errno == ENOENT) {
				printf("IP %s not banned\n", argv[2]);
				exit(0);
			}
			else {
				perror("BPF_MAP_LOOKUP_ELEM banned_ips");
				exit(1);
			}
		}
		int *res = find_expired_bans(&entry, 1);
		if (res[0] == 0) {
			printf("IP %s not banned\n", argv[2]);
			exit(0);
		}
		char buf[26];
		char *timestamp_str = prepare_entry_for_printing(&entry, buf);
		/* Strings from ctime already contain \n */
		printf("Found ban entry:\n");
		printf("\tIP: %s\n", argv[2]);
		if (buf[0])
			printf("\tSpam Start Timestamp: %s", buf);
		printf("\tTimestamp: %s", timestamp_str);
		printf("\tDuration: %lu\n", entry.duration);
		printf("\tLast seen on port: %u\n", entry.banned_on_last_port);
		printf("\tDescription: %s\n", entry.desc);
		exit(0);
	}

	if (!strcmp(argv[1], "config")) {
		if (argc != 4) {
			fprintf(stderr, "Usage: %s config <block_threshold> <ip_reset_time_ns>\n", argv[0]);
			exit(1);
		}
		struct init_handler_config config;
		char *endptr;
		unsigned long block_thresh = strtoul(argv[2], &endptr, 10);
		if (block_thresh > UINT32_MAX)
			config.block_threshold = UINT32_MAX;
		else
			config.block_threshold = block_thresh;
		if (!config.block_threshold || *endptr != '\0') {
			fprintf(stderr, "Failed to parse block threshold %s\n", argv[4]);
			if (*endptr != '\0')
				fprintf(stderr, "Found unrecognized character: %c\n", *endptr);
			exit(1);
		}
		config.ip_count_reset_ns = strtoull(argv[3], &endptr, 10);
		if (!config.ip_count_reset_ns || *endptr != '\0') {
			fprintf(stderr, "Failed to parse ip_reset_time_ns %s\n", argv[4]);
			if (*endptr != '\0')
				fprintf(stderr, "Found unrecognized character: %c\n", *endptr);
			exit(1);
		}
		union bpf_attr attr;
		memset(&attr, 0, sizeof(union bpf_attr));
		struct map_fds fds = open_object(object_dir, CONFIG_MAP);
		attr.map_fd = fds.configfd;
		attr.value = (u64) &config;
		u64 key = 0;
		attr.key = (u64) &key;
		attr.flags = BPF_ANY;
		if (syscall(SYS_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(union bpf_attr))) {
			perror("BPF_MAP_UPDATE_ELEM init_handler_config");
			exit(1);
		}
		exit(0);
	}

	fprintf(stderr, "Unknown command \"%s\"\n", argv[1]);
	fprintf(stderr, "Usage: %s <command>\nTry %s --help\n", argv[0], argv[0]);
	exit(1);
}

int main(int argc, char *argv[])
{
	tai_offset = get_tai_offset();
	if (argc < 2) {
		if (argc == 1)
			fprintf(stderr, "Usage: %s <command>\nTry %s --help\n", argv[0], argv[0]);
		else
			fprintf(stderr, "Usage: eBPFtool <command>\nTry eBPFtool --help\n");
		return 1;
	}
	dispatch_command(argc, argv);
}
