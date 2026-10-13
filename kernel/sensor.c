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
 * Note: this program must be compiled with clang's -target bpf option, not
 * regular x86_64.  The Makefile handles this automatically.
*/

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "event.h"


// 256 KB ring buffer — holds about 2900 events before backpressure kicks in. 
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");


static __always_inline void fill_common(struct event *e, u32 event_type)
{	
	e->timestamp_ns = bpf_ktime_get_ns();

    u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    e->uid = bpf_get_current_uid_gid();

    e->event_type = event_type;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

static __always_inline void fill_exec_args(struct event *e, const char *const *argv)
{
    e->data.exec.argc = 0;

    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        const char *arg_ptr = NULL;

        if (bpf_probe_read_user(&arg_ptr, sizeof(arg_ptr), &argv[i]) < 0) {
            break;
        }

        if (!arg_ptr) {
            break;
        }

        if (bpf_probe_read_user_str(e->data.exec.args[i], sizeof(e->data.exec.args[i]), arg_ptr) < 0) {
            break;
        }

        e->data.exec.argc++;
    }
}

/* Hook 1: execve - fires when any process launches a new binary.
 * args[0] = filename ptr, args[1] = argv, args[2] = envp */
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
	char comm[16];
	bpf_get_current_comm(comm, sizeof(comm));

	

	struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		return 0;
	}
	__builtin_memset(&e->data, 0, sizeof(e->data));


	fill_common(e, EVENT_EXECVE);
	__builtin_memcpy(e->comm, comm, sizeof(e->comm));
	bpf_probe_read_user_str(e->data.exec.filename, sizeof(e->data.exec.filename), (void *)ctx->args[0]);
	
	const char *const *argv = (const char *const *)ctx->args[1];
	
	fill_exec_args(e, argv);
	
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
	

	struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		return 0;
	}

	fill_common(e, EVENT_OPENAT);
	__builtin_memcpy(e->comm, comm, sizeof(e->comm));
	bpf_probe_read_user_str(e->data.file.filename, sizeof(e->data.file.filename), (void *)ctx->args[1]);
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
	

	struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		return 0;
	}

	fill_common(e, EVENT_CONNECT);
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
		BPF_SNPRINTF(e->data.network.address, sizeof(e->data.network.address),
		             "%d.%d.%d.%d:%d",
		             b[0], b[1], b[2], b[3], port);
	} else {
		__builtin_memcpy(e->data.network.address, "?", 2);
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int trace_execveat(struct trace_event_raw_sys_enter *ctx)
{
    char comm[COMM_LEN];
    bpf_get_current_comm(comm, sizeof(comm));

    
        

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
	}

    __builtin_memset(&e->data, 0, sizeof(e->data));

    fill_common(e, EVENT_EXECVEAT);
    __builtin_memcpy(e->comm, comm, sizeof(e->comm));

    bpf_probe_read_user_str(e->data.exec.filename, sizeof(e->data.exec.filename), (void *)ctx->args[1]);

    const char *const *argv = (const char *const *)ctx->args[2];

    fill_exec_args(e, argv);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int trace_process_exit(void *ctx)
{
    (void)ctx;

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
		return 0;
	}

    __builtin_memset(&e->data, 0, sizeof(e->data));

    fill_common(e, EVENT_PROCESS_EXIT);

    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int trace_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
		return 0;
	}

    __builtin_memset(&e->data, 0, sizeof(e->data));

    fill_common(e, EVENT_PROCESS_FORK);

    e->pid = ctx->parent_pid;
    e->data.process.child_pid = ctx->child_pid;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
