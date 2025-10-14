# Compilers and flags
BPF_CC = clang
BPF_CFLAGS = -O3 -g -mcpu=v3 -Wall -Werror -target bpf -Iinclude
BPF_XDP_TARGET = bin/xdp_filter.o
BPF_HELPER_TARGET = bin/helper.o

HOST_CC = gcc
HOST_CFLAGS = -march=native -mtune=native -Wall -Werror -O3 -MD -D_FORTIFY_SOURCE=2 -fasynchronous-unwind-tables -fpie -fstack-clash-protection -fstack-protector-strong -Werror=format-security
HOST_LDFLAGS = -Wl,-pie -Wl,-z,defs -Wl,-z,now -Wl,-z,relro
HOST_TARGET = bin/eBPFtool

# Source directories and files
BPF_SRCDIR = src
BPF_XDP_SOURCE = $(BPF_SRCDIR)/xdp_filter.c
BPF_HELPER_SOURCE = $(BPF_SRCDIR)/helper.c

HOST_SRCDIR = tool
HOST_SOURCES = $(wildcard $(HOST_SRCDIR)/*.c)

# Default target - build both eBPF programs and the host tool
all: $(BPF_XDP_TARGET) $(BPF_HELPER_TARGET) $(HOST_TARGET)

# Create bin directory if it doesn't exist
bin:
	mkdir -p bin

# vmlinux.h generation target
vmlinux:
	@if [ ! -f include/vmlinux.h ]; then \
		echo "Generating include/vmlinux.h from kernel BTF..."; \
		mkdir -p include; \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h; \
		echo "vmlinux.h generated successfully"; \
	else \
		echo "include/vmlinux.h already exists"; \
	fi

# Build XDP eBPF target (xdp_filter)
$(BPF_XDP_TARGET): $(BPF_XDP_SOURCE) vmlinux | bin
	$(BPF_CC) $(BPF_CFLAGS) -c $(BPF_XDP_SOURCE) -o $(BPF_XDP_TARGET)

# Build helper eBPF target (helper)
$(BPF_HELPER_TARGET): $(BPF_HELPER_SOURCE) vmlinux | bin
	$(BPF_CC) $(BPF_CFLAGS) -c $(BPF_HELPER_SOURCE) -o $(BPF_HELPER_TARGET)

# Build host tool (eBPFtool)
$(HOST_TARGET): $(HOST_SOURCES) | bin
	$(HOST_CC) $(HOST_CFLAGS) $(HOST_SOURCES) -o $(HOST_TARGET)

# Include dependency files for host tool
-include $(HOST_SOURCES:.c=.d)

# Clean target
clean:
	rm -rf bin/

# Clean everything including vmlinux.h
clean_all: clean
	rm -f include/vmlinux.h

# Phony targets
.PHONY: all bpf tool vmlinux clean clean_all
