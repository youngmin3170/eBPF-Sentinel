// SPDX-License-Identifier: GPL-2.0
/*
 * loader.c - User-space loader for the eBPF sensor
 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define SYSCALL_EXECVE 1
#define SYSCALL_OPENAT 2
#define SYSCALL_CONNECT 3

#define SOCKET_PATH "/tmp/sentinel.sock"
#define RINGBUF_NAME "rb"

// Must be byte-for-byte identical to struct event in sensor.c.
typedef uint32_t u32;
struct event {
	u32 pid;
	u32 uid;
	u32 syscall_type;
	char comm[16];
	char filename[64];
};

static int server_fd = -1;
static int client_fd = -1;
static volatile sig_atomic_t exiting = 0;

static void handle_signal(int sig)
{
	(void)sig;
	exiting = 1;
}

/* Ring-buffer callback — invoked once per event by ring_buffer__poll().
 * Forwards raw bytes to Python over the Unix socket; falls back to stdout
 * when no client is connected so standalone testing still works. */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	(void)ctx;
	(void)data_sz;
	const struct event *e = data;

	if (client_fd != -1) {
		if (write(client_fd, e, sizeof(*e)) < 0) {
			close(client_fd);
			client_fd = -1;
		}
		return 0;
	}

	const char *type_str =
	    (e->syscall_type == SYSCALL_EXECVE)  ? "execve"  :
	    (e->syscall_type == SYSCALL_OPENAT)  ? "openat"  :
	    (e->syscall_type == SYSCALL_CONNECT) ? "connect" : "unknown";

	printf("[%s] PID: %-6u | UID: %-4u | Comm: %-16s | %s\n",
	       type_str, e->pid, e->uid, e->comm, e->filename);
	fflush(stdout);
	return 0;
}

static int setup_unix_socket(void)
{
	unlink(SOCKET_PATH);

	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		return -1;
	}

	struct sockaddr_un addr = {0};
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		close(fd);
		return -1;
	}

	listen(fd, 1);

	/* Sentinel runs as root; Python ML engine runs as the login user.
	 * chmod to 0666 so the non-root process can connect. */
	chmod(SOCKET_PATH, 0666);

	int flags = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	return fd;
}

static struct bpf_link *attach_prog(struct bpf_object *obj, const char *name)
{
	struct bpf_program *prog = bpf_object__find_program_by_name(obj, name);
	if (!prog) {
		fprintf(stderr, "ERROR: program '%s' not found in sensor.o\n", name);
		return NULL;
	}
	struct bpf_link *link = bpf_program__attach(prog);
	if (libbpf_get_error(link)) {
		fprintf(stderr, "ERROR: failed to attach '%s'\n", name);
		return NULL;
	}
	return link;
}

int main(void)
{
	signal(SIGINT,  handle_signal);
	signal(SIGTERM, handle_signal);

	struct bpf_object *obj = bpf_object__open_file("sensor.o", NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: failed to open sensor.o\n");
		return 1;
	}
	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: kernel verifier rejected sensor.o\n");
		return 1;
	}

	struct bpf_link *link_execve  = attach_prog(obj, "trace_execve");
	struct bpf_link *link_openat  = attach_prog(obj, "trace_openat");
	struct bpf_link *link_connect = attach_prog(obj, "trace_connect");
	if (!link_execve || !link_openat || !link_connect)
		return 1;

	int map_fd = bpf_object__find_map_fd_by_name(obj, RINGBUF_NAME);
	struct ring_buffer *rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "ERROR: failed to create ring buffer\n");
		return 1;
	}

	server_fd = setup_unix_socket();
	if (server_fd < 0)
		return 1;

	printf("eBPF-Sentinel active.\n");
	printf("  Hooks : execve + openat + connect\n");
	printf("  Socket: %s\n", SOCKET_PATH);
	printf("  Waiting for ML engine... (printing events until connected)\n\n");

	while (!exiting) {
		if (client_fd == -1) {
			client_fd = accept(server_fd, NULL, NULL);
			if (client_fd != -1) {
				printf("[+] ML engine connected.\n");
				fflush(stdout);
			}
		}
		ring_buffer__poll(rb, 100);
	}

	ring_buffer__free(rb);
	bpf_link__destroy(link_execve);
	bpf_link__destroy(link_openat);
	bpf_link__destroy(link_connect);
	bpf_object__close(obj);

	if (client_fd != -1)
		close(client_fd);
	if (server_fd != -1)
		close(server_fd);
	unlink(SOCKET_PATH);

	printf("\n[*] Sentinel shut down cleanly.\n");
	return 0;
}
