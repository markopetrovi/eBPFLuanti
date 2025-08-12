# Compilers and flags
BPF_CC = clang
BPF_CFLAGS = -O3 -g -mcpu=v3 -Wall -Werror -target bpf
BPF_TARGET = bin/xdp_filter.o

HOST_CC = gcc
HOST_CFLAGS = -march=native -mtune=native -Wall -Werror -O3
HOST_TARGET = bin/eBPFtool

# Source directories and files
BPF_SRCDIR = src
BPF_SOURCES = $(wildcard $(BPF_SRCDIR)/*.c)

HOST_SRCDIR = tool
HOST_SOURCES = $(wildcard $(HOST_SRCDIR)/*.c)

# Default target - build both
all: $(BPF_TARGET) $(HOST_TARGET)

# vmlinux.h generation target (run manually before building)
vmlinux:
	@if [ ! -f include/vmlinux.h ]; then \
		echo "Generating include/vmlinux.h from kernel BTF..."; \
		mkdir -p include; \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h; \
		echo "vmlinux.h generated successfully"; \
	else \
		echo "include/vmlinux.h already exists"; \
	fi

# Create bin directory if it doesn't exist
bin:
	mkdir -p bin

# Build BPF target
$(BPF_TARGET): $(BPF_SOURCES) | bin
	$(BPF_CC) $(BPF_CFLAGS) -c $(BPF_SOURCES) -o $(BPF_TARGET)

# Build host tool target
$(HOST_TARGET): $(HOST_SOURCES) | bin
	$(HOST_CC) $(HOST_CFLAGS) $(HOST_SOURCES) -o $(HOST_TARGET)

# Individual targets
bpf: $(BPF_TARGET)
tool: $(HOST_TARGET)

# Clean target
clean:
	rm -rf bin/

# Clean everything including vmlinux.h
clean_all: clean
	rm -f include/vmlinux.h
	@if [ -d include ] && [ -z "$(ls -A include 2>/dev/null)" ]; then \
		rmdir include; \
		echo "Removed empty include directory"; \
	fi

# Phony targets
.PHONY: all bpf tool vmlinux clean clean_all
