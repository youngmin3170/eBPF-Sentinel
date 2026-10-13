#ifndef SENTINEL_EVENT_H
#define SENTINEL_EVENT_H

#define EVENT_EXECVE 1
#define EVENT_OPENAT 2
#define EVENT_CONNECT 3
#define EVENT_EXECVEAT 4
#define EVENT_PROCESS_EXIT 5
#define EVENT_PROCESS_FORK 6

#define COMM_LEN 16
#define PATH_LEN 64
#define MAX_ARGS 6
#define ARG_LEN 32
#define NET_ADDR_LEN 64

struct exec_event_data {
    char filename[PATH_LEN];

    __u32 argc;
    char args[MAX_ARGS][ARG_LEN];
};

struct file_event_data {
    char filename[PATH_LEN];
};

struct network_event_data {
    char address[NET_ADDR_LEN];
};

struct process_event_data {
    __u32 child_pid;
};

struct event {
    __u64 timestamp_ns;

    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 event_type;

    char comm[COMM_LEN];

    union {
        struct exec_event_data exec;
        struct file_event_data file;
        struct network_event_data network;
        struct process_event_data process;
    } data;
};

#endif