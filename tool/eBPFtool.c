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
	u64 now = (u64)ts.tv_nsec + (1000000000UL * (u64)ts.tv_sec);
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

static void __attribute__((noreturn)) dispatch_command(int argc, char *argv[])
{
	if (!strcmp(argv[1], "--help")) {
		printf("Supported commands:\n");
		printf("dump_ports: Write all currently watched ports\n");
		printf("add_port <port>: Add port to the watchlist\n");
		printf("rm_port <port>: Remove port from the watchlist\n");
		printf("ban <port> <ip> <duration> <reason>: IP-ban this user on all ports. The <port> argument just shows where they were last spotted.\n");
		printf("unban <ip>: Unban this IP and print the data needed by caller to assemble a ban record\n");
		printf("list_bans: List all bans currently in effect\n");
		exit(0);
	}
	const char *map_dir = getconfig("MAP_DIR", "/sys/fs/bpf/xdp/globals");

	if (!strcmp(argv[1], "dump_ports")) {
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
			fprintf(stderr, "Usage: %s ban <port> <ip> <duration> <reason>\n", argv[0]);
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
		strncpy(entry.desc, argv[5], DESC_SIZE-1);
		entry.desc[DESC_SIZE-1] = '\0';
		struct timespec ts;
		if (clock_gettime(CLOCK_TAI, &ts)) {
			perror("clock_gettime(CLOCK_TAI)");
			exit(1);
		}
		entry.timestamp = (u64)ts.tv_nsec + (1000000000UL * (u64)ts.tv_sec);

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
			fprintf(stderr, "Invalid IPv4 address %s\n", argv[3]);
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
		bool is_expired = (res == 0);

		/* Convert to seconds and Unix time */
		entry.duration /= 1000000000ULL;
		entry.timestamp = (entry.timestamp / 1000000000UL) - get_tai_offset();
		char *timestamp_str = ctime((long*)&entry.timestamp);
		if (!timestamp_str) {
			perror("ctime");
			exit(1);
		}
		printf("Timestamp: %s\n", timestamp_str);
		printf("Duration: %lu\n", entry.duration);
		printf("Description: %s\n", entry.desc);
		if (is_expired)
			printf("Ban for %s had already expired and was pending removal.\n", argv[2]);
		else
			printf("IP %s unbanned\n", argv[2]);

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
