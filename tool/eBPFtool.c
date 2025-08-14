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
#define ALL_MAPS		(BANNED_IPS_MAP | RECORDS_MAP | WATCHED_PORTS_MAP)

struct map_fds {
	int banfd, portfd, recordfd;
};

union ipv4_addr {
    uint32_t addr;
    struct {
        uint8_t a, b, c, d;
    };
};

#define DESC_SIZE 255

struct ban_entry {
	u64 timestamp;
	u64 duration;
	u16 banned_on_last_port;
	char desc[DESC_SIZE];
};

struct ban_record {
	u64 ban_timestamp;
	u64 autounban_timestamp;
	u64 ban_duration;
	u32 ip;		/* IP in host byte order */
	u16 banned_on_last_port;
	char desc[DESC_SIZE];
};

static struct map_fds open_maps(const char *map_dir, int map_ids)
{
	struct map_fds fds;
	union bpf_attr attr;

	int dirfd = open(map_dir, O_PATH);
	if (dirfd < 0) {
		perror("open(map_dir)");
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

static char *prepare_entry_for_printing(struct ban_entry *entry)
{
	/* Convert to seconds and Unix time */
	entry->duration /= NANOSECONDS_PER_SECOND;
	entry->timestamp = (entry->timestamp / NANOSECONDS_PER_SECOND) - get_tai_offset();
	char *timestamp_str = ctime((long*)&entry->timestamp);
	if (!timestamp_str) {
		perror("ctime");
		exit(1);
	}
	return timestamp_str;
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
		printf("fetch_logs: Pop elements from the records map and build records from expired entries in the banned_ips table. Output everything for logging purposes. Should only be called by the logging code, call manually only if you know what you're doing.\n");
		exit(0);
	}
	const char *map_dir = getconfig("MAP_DIR", "/sys/fs/bpf/xdp/globals");

	if (!strcmp(argv[1], "dump_ports")) {
		if (argc != 2) {
			fprintf(stderr, "Usage: %s dump_ports\n", argv[0]);
			exit(1);
		}
		struct map_fds fds = open_maps(map_dir, WATCHED_PORTS_MAP);
		dump_ports(fds.portfd);
		exit(0);
	}

	if (!strcmp(argv[1], "add_port")) {
		if (argc < 3 || argc > 65535 + 2) {
			fprintf(stderr, "Usage: %s add_port <port1> [port2] ... [portN]\n", argv[0]);
			exit(1);
		}
		struct map_fds fds = open_maps(map_dir, WATCHED_PORTS_MAP);
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
		struct map_fds fds = open_maps(map_dir, WATCHED_PORTS_MAP);
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
		struct map_fds fds = open_maps(map_dir, BANNED_IPS_MAP);
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
				fprintf(stderr, "Found unrecognized character: %c", *endptr);
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
		struct map_fds fds = open_maps(map_dir, BANNED_IPS_MAP);
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

		char *timestamp_str = prepare_entry_for_printing(&entry);
		/* Strings from ctime already contain \n */
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
		struct map_fds fds = open_maps(map_dir, BANNED_IPS_MAP);
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
				char *timestamp_str = prepare_entry_for_printing(&values[i]);
				/* Strings from ctime already contain \n */
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
		struct map_fds fds = open_maps(map_dir, BANNED_IPS_MAP | RECORDS_MAP);
		union bpf_attr attr;
		union bpf_attr delete_attr;
		memset(&attr, 0, sizeof(union bpf_attr));
		memset(&delete_attr, 0, sizeof(union bpf_attr));
		u32 keys[10];	/* IPs in host byte order */
		u32 keys_to_delete[10];
		struct ban_entry values[10];
		u32 batch_params[2] = {0, 0};
		delete_attr.batch.map_fd = fds.banfd;
		attr.batch.map_fd = fds.banfd;
		attr.batch.in_batch = (u64) &batch_params[0];
		attr.batch.out_batch = (u64) &batch_params[1];
		attr.batch.keys = (u64) keys;
		delete_attr.batch.keys = (u64) keys_to_delete;
		attr.batch.values = (u64) values;

		time_t now = time(NULL);
		char buf[26];
		char *now_str = ctime_r(&now, buf);
		if (!now_str) {
			perror("ctime_r");
			exit(1);
		}
		/* Strings from ctime already contain \n that messes up formatting here */
		now_str[24] = '\0';

		printf("[");
		int saved_errno = 0;
		/* In JSON, add , after each } but not after the last one, and obviously not before the first entry */
		bool comma = false;
		do {
			attr.batch.count = 10;
			/* ENOENT means we just didn't have enough entries to fill a batch of 10 */
			if (syscall(SYS_bpf, BPF_MAP_LOOKUP_BATCH, &attr, sizeof(union bpf_attr)) && errno != ENOENT) {
				perror("bpf(BPF_MAP_LOOKUP_BATCH banned_ips)");
				exit(1);
			}
			saved_errno = errno;
			int *res = find_expired_bans(values, attr.batch.count);
			delete_attr.batch.count = 0;
			for (int i = 0; res[i] != -1; i++) {
				/* values[res[i]] are expired entries that we iterate over */
				/* keys[res[i]] are corresponding IPs */
				delete_attr.batch.count++;
				keys_to_delete[i] = keys[res[i]];

				struct in_addr addr;
				addr.s_addr = htonl(keys[i]);
				char *ip_str = inet_ntoa(addr);
				char *timestamp_str = prepare_entry_for_printing(&values[i]);
				if (comma)
					printf(",\n");
				else
					printf("\n");
				comma = true;

				/* Strings from ctime already contain \n that messes up formatting here */
				timestamp_str[24] = '\0';
				printf("\t{\n\t\t\"ban_timestamp\": \"%s\",\n", timestamp_str);
				printf("\t\t\"unban_timestamp\": \"%s\",\n", now_str);
				printf("\t\t\"ban_duration\": %lu,\n", values[i].duration);
				printf("\t\t\"ip\": \"%s\",\n", ip_str);
				printf("\t\t\"banned_on_last_port\": %u,\n", values[i].banned_on_last_port);
				char *escaped_desc = simple_json_escape(values[i].desc);
				printf("\t\t\"description\": \"%s\"\n\t}", escaped_desc);
				if (escaped_desc != values[i].desc)
					free(escaped_desc);
			}
			free(res);

			/* ENOENT might mean that the eBPF program deleted some entry in the meantime */
			if (syscall(SYS_bpf, BPF_MAP_DELETE_BATCH, &delete_attr, sizeof(union bpf_attr)) && errno != ENOENT) {
				perror("bpf(BPF_MAP_DELETE_BATCH banned_ips)");
				exit(1);
			}
			* (u32*)attr.batch.in_batch = * (u32*)attr.batch.out_batch;
		} while (saved_errno != ENOENT);

		/* Now handle the records queue */
		memset(&attr, 0, sizeof(union bpf_attr));
		struct ban_record rec;
		attr.map_fd = fds.recordfd;
		attr.value = (u64) &rec;
		while (1) {
			if (syscall(SYS_bpf, BPF_MAP_LOOKUP_AND_DELETE_ELEM, &attr, sizeof(union bpf_attr))) {
				if (errno == ENOENT)
					break;
				perror("BPF_MAP_LOOKUP_AND_DELETE_ELEM records");
				exit(1);
			}
			/* Convert to seconds and Unix time */
			rec.ban_duration /= NANOSECONDS_PER_SECOND;
			int tai = get_tai_offset();
			rec.ban_timestamp = (rec.ban_timestamp / NANOSECONDS_PER_SECOND) - tai;
			rec.autounban_timestamp = (rec.autounban_timestamp / NANOSECONDS_PER_SECOND) - tai;
			char *ban_timestamp_str = ctime((long*)&rec.ban_timestamp);
			if (!ban_timestamp_str) {
				perror("ctime");
				exit(1);
			}
			char *unban_timestamp_str = ctime_r((long*)&rec.autounban_timestamp, buf);
			if (!unban_timestamp_str) {
				perror("ctime_r");
				exit(1);
			}
			struct in_addr addr;
			addr.s_addr = htonl(rec.ip);
			char *ip_str = inet_ntoa(addr);
			if (comma)
				printf(",\n");
			else
				printf("\n");
			comma = true;
			/* Strings from ctime already contain \n that messes up formatting here */
			ban_timestamp_str[24] = unban_timestamp_str[24] = '\0';
			printf("\t{\n\t\t\"ban_timestamp\": \"%s\",\n", ban_timestamp_str);
			printf("\t\t\"unban_timestamp\": \"%s\",\n", unban_timestamp_str);
			printf("\t\t\"ban_duration\": %lu,\n", rec.ban_duration);
			printf("\t\t\"ip\": \"%s\",\n", ip_str);
			printf("\t\t\"banned_on_last_port\": %u,\n", rec.banned_on_last_port);
			char *escaped_desc = simple_json_escape(rec.desc);
			printf("\t\t\"description\": \"%s\"\n\t}", escaped_desc);
			if (escaped_desc != rec.desc)
				free(escaped_desc);
		}
		printf("\n]\n");
		exit(0);
	}

	if (!strcmp(argv[1], "is_banned")) {
		if (argc != 3) {
			fprintf(stderr, "Usage: %s is_banned <ip>\n", argv[0]);
			exit(1);
		}
		struct map_fds fds = open_maps(map_dir, BANNED_IPS_MAP);
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
		char *timestamp_str = prepare_entry_for_printing(&entry);
		/* Strings from ctime already contain \n */
		printf("Found ban entry:\n");
		printf("\tIP: %s\n", argv[2]);
		printf("\tTimestamp: %s", timestamp_str);
		printf("\tDuration: %lu\n", entry.duration);
		printf("\tLast seen on port: %u\n", entry.banned_on_last_port);
		printf("\tDescription: %s\n", entry.desc);
		exit(0);
	}

	fprintf(stderr, "Unknown command \"%s\"\n", argv[1]);
	fprintf(stderr, "Usage: %s <command>\nTry %s --help\n", argv[0], argv[0]);
	exit(1);
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		if (argc == 1)
			fprintf(stderr, "Usage: %s <command>\nTry %s --help\n", argv[0], argv[0]);
		else
			fprintf(stderr, "Usage: eBPFtool <command>\nTry eBPFtool --help\n");
		return 1;
	}
	dispatch_command(argc, argv);
}
