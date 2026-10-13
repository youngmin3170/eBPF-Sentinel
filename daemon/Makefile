CC := gcc
CLANG := clang
LLVM_OBJDUMP := llvm-objdump-21

KERNEL_DIR := ../kernel
BUILD_DIR := ../build
INCLUDE_DIR := ../include

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86 -I$(KERNEL_DIR) -I$(INCLUDE_DIR) -I/usr/include/bpf

CFLAGS := -Wall -Wextra -O2 -I$(INCLUDE_DIR) -I/usr/include/bpf
LDFLAGS := -L/usr/lib/x86_64-linux-gnu -lbpf -lelf -lz

EVENT_HEADER := $(INCLUDE_DIR)/event.h

.PHONY: all clean run inspect test

all: $(BUILD_DIR)/vmlinux.h $(BUILD_DIR)/sensor.o $(BUILD_DIR)/sentinel

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Generate vmlinux.h from the running kernel's BTF blob.
# Delete build/vmlinux.h to force regeneration after a kernel upgrade.
$(BUILD_DIR)/vmlinux.h: | $(BUILD_DIR)
	@echo "[*] Generating vmlinux.h from kernel BTF"
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@
	cp $@ $(KERNEL_DIR)/vmlinux.h

# Compile sensor.c to BPF bytecode.
$(BUILD_DIR)/sensor.o: $(KERNEL_DIR)/sensor.c $(BUILD_DIR)/vmlinux.h $(EVENT_HEADER)
	@echo "[*] Compiling sensor.c to sensor.o"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Compile loader.c to native x86-64 binary.
$(BUILD_DIR)/sentinel: loader.c $(EVENT_HEADER)
	@echo "[*] Compiling loader.c to sentinel"
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

# Disassemble BPF bytecode for inspection.
inspect: $(BUILD_DIR)/sensor.o
	$(LLVM_OBJDUMP) -d $<
	
clean:
	@echo "[*] Cleaning build artifacts"
	rm -rf $(BUILD_DIR)

run: all
	@echo "[*] Launching sentinel (requires root)"
	sudo $(BUILD_DIR)/sentinel

test: all
	@echo "[*] Running Sentinel test suite"
	sudo python3 -m pytest ../tests -v