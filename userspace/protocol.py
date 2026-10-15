import ctypes


EVENT_EXECVE = 1
EVENT_OPENAT = 2
EVENT_CONNECT = 3
EVENT_EXECVEAT = 4
EVENT_PROCESS_EXIT = 5
EVENT_PROCESS_FORK = 6

COMM_LEN = 16
PATH_LEN = 64
MAX_ARGS = 6
ARG_LEN = 32
NET_ADDR_LEN = 64


class ExecEventData(ctypes.Structure):
    _fields_ = [
        ("filename", ctypes.c_char * PATH_LEN),
        ("argc", ctypes.c_uint32),
        ("args", (ctypes.c_char * ARG_LEN) * MAX_ARGS),
    ]


class FileEventData(ctypes.Structure):
    _fields_ = [
        ("filename", ctypes.c_char * PATH_LEN),
    ]


class NetworkEventData(ctypes.Structure):
    _fields_ = [
        ("address", ctypes.c_char * NET_ADDR_LEN),
    ]


class ProcessEventData(ctypes.Structure):
    _fields_ = [
        ("child_pid", ctypes.c_uint32),
        ("child_tid", ctypes.c_uint32),
    ]


class EventData(ctypes.Union):
    _fields_ = [
        ("exec", ExecEventData),
        ("file", FileEventData),
        ("network", NetworkEventData),
        ("process", ProcessEventData),
    ]


class Event(ctypes.Structure):
    _fields_ = [
        ("timestamp_ns", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("tid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("event_type", ctypes.c_uint32),
        ("comm", ctypes.c_char * COMM_LEN),
        ("data", EventData),
    ]


EVENT_SIZE = ctypes.sizeof(Event)