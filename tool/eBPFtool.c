#define _GNU_SOURCE
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#define u8 uint8_t
#define u16 uint16_t
#define u32 uint32_t
#define u64 uint64_t

const char *getconfig(const char *name, const char *default_val)
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

struct map_fds open_maps(const char *map_dir, int map_ids)
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

void dump_ports(int portfd)
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

void __attribute__((noreturn)) dispatch_command(int argc, char *argv[])
{
	if (!strcmp(argv[1], "--help")) {
		printf("Supported commands:\n");
		printf("dump_ports: Write all currently watched ports\n");
		printf("add_port <port>: Add port to the watchlist\n");
		printf("rm_port <port>: Remove port from the watchlist\n");
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
			u16 port = atoi(argv[i]);
			if (!port) {
				fprintf(stderr, "Failed to parse \"%s\"\n", argv[i]);
				continue;
			}
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
			ports[i-2] = atoi(argv[i]);
			if (!ports[i-2]) {
				fprintf(stderr, "Failed to parse \"%s\"\n", argv[i]);
				continue;
			}
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
