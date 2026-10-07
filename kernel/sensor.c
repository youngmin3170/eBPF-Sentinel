// SPDX-License-Identifier: GPL-2.0
/*
 * eBPF program that runs in the kernel and captures events of interest.
 * Compiled to sensor.o by the Makefile, loaded by loader.c.
 *
 * Each event is packaged as a struct event and sent to user-space via a
 * ring buffer.  The struct layout is carefully designed to be compact
 * (fits in 80 bytes) while still capturing key info about the process and
 * syscall.  The filename field is overloaded to hold either a file path or
 * an "ip:port" string for connect events, which keeps the ML token
 * vocabulary small and consistent across syscall types.
 *
 * The is_noisy_comm() function filters out processes that trigger syscalls at
 * such a high rate with no threat signal that they would overwhelm the ring
 * buffer and ML engine.  This is a simple heuristic based on observed data;
 * it can be expanded or made more sophisticated as needed.
 *
 * Note: this program must be compiled with clang's -target bpf option, not
 * regular x86_64.  The Makefile handles this automatically.
*/

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define SYSCALL_EXECVE 1
#define SYSCALL_OPENAT 2
#define SYSCALL_CONNECT 3

/* Event envelope sent to user-space via the ring buffer.
 * Must stay byte-for-byte identical to struct event in loader.c. */
struct event {
	u32 pid;
	u32 uid;
	u32 syscall_type;
	char comm[16];
	char filename[64];  // path for execve/openat; ip:port string for connect 
};

// 256 KB ring buffer — holds about 2900 events before backpressure kicks in. 
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* Processes that fire syscalls at extremely high rate with no threat signal.
 * Dropping them in the kernel saves ring-buffer bandwidth and user-space CPU. */
static __always_inline bool is_noisy_comm(const char *comm)
{
	if (bpf_strncmp(comm, 16, "xfce4-panel-gen") == 0) return true;
	if (bpf_strncmp(comm, 16, "wrapper-2.0") == 0) return true;
	if (bpf_strncmp(comm, 16, "cpuUsage.sh") == 0) return true;
	if (bpf_strncmp(comm, 16, "sh") == 0) return true;
	if (bpf_strncmp(comm, 16, "node") == 0) return true;
	return false;
}

static __always_inline void fill_common(struct event *e, u32 syscall_type)
{
	u64 id = bpf_get_current_pid_tgid();
	e->pid = id >> 32;
	e->uid = bpf_get_current_uid_gid();
	e->syscall_type = syscall_type;
}

/* Hook 1: execve - fires when any process launches a new binary.
 * args[0] = filename ptr, args[1] = argv, args[2] = envp */
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
	char comm[16];
	bpf_get_current_comm(comm, sizeof(comm));

	if (is_noisy_comm(comm)) {
		return 0;
	}

	struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		return 0;
	}

	fill_common(e, SYSCALL_EXECVE);
	__builtin_memcpy(e->comm, comm, sizeof(e->comm));
	bpf_probe_read_user_str(e->filename, sizeof(e->filename),
	                        (void *)ctx->args[0]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* Hook 2: openat - fires on every file open.
 * Ransomware triggers hundreds of these in rapid succession before encrypting.
 * args[0] = dirfd, args[1] = filename ptr, args[2] = flags */
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
	char comm[16];
	bpf_get_current_comm(comm, sizeof(comm));
	if (is_noisy_comm(comm)) {
		return 0;
	}

	struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		return 0;
	}

	fill_common(e, SYSCALL_OPENAT);
	__builtin_memcpy(e->comm, comm, sizeof(e->comm));
	bpf_probe_read_user_str(e->filename, sizeof(e->filename),
	                        (void *)ctx->args[1]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* Hook 3: connect - fires when a process initiates a TCP/UDP connection.
 * This catches reverse shells the moment they phone home, before any data
 * is exchanged.  We encode the destination as "ip:port" in the filename
 * field so the ML token vocabulary stays uniform across all syscall types.
 * args[0] = sockfd, args[1] = sockaddr ptr, args[2] = addrlen */
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx)
{
	char comm[16];
	bpf_get_current_comm(comm, sizeof(comm));
	if (is_noisy_comm(comm)) {
		return 0;
	}

	struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		return 0;
	}

	fill_common(e, SYSCALL_CONNECT);
	__builtin_memcpy(e->comm, comm, sizeof(e->comm));

	/* Read the sockaddr from user space to extract ip:port.
	 * We only handle AF_INET (IPv4) - AF_INET6 and AF_UNIX fall through
	 * as "connect:?" which the ML model treats as an unknown token. */
	struct sockaddr_in sa;
	__builtin_memset(&sa, 0, sizeof(sa));
	bpf_probe_read_user(&sa, sizeof(sa), (void *)ctx->args[1]);

	if (sa.sin_family == 2 /* AF_INET */) {
		/* Format: "ddd.ddd.ddd.ddd:ppppp\0" — fits in 64 bytes. */
		u8 *b = (u8 *)&sa.sin_addr.s_addr;
		u16 port = __builtin_bswap16(sa.sin_port);
		BPF_SNPRINTF(e->filename, sizeof(e->filename),
		             "%d.%d.%d.%d:%d",
		             b[0], b[1], b[2], b[3], port);
	} else {
		__builtin_memcpy(e->filename, "?", 2);
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
