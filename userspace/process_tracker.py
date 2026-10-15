from dataclasses import dataclass, field
from userspace.protocol import EVENT_EXECVE, EVENT_EXECVEAT, EVENT_PROCESS_EXIT, EVENT_PROCESS_FORK


@dataclass
class ProcessInfo:
    pid: int
    ppid: int | None = None

    uid: int | None = None
    comm: str = ""
    executable: str = ""

    argv: list[str] = field(default_factory=list)

    start_ns: int | None = None
    exec_ns: int | None = None
    exit_ns: int | None = None

    children: set[int] = field(default_factory=set)



class ProcessTracker:
    def __init__(self):
        self.processes: dict[int, ProcessInfo] = {}
    
    def handle_event(self, event):
        if event.event_type == EVENT_PROCESS_FORK:
            self.handle_fork(event)

        elif event.event_type in (EVENT_EXECVE, EVENT_EXECVEAT):
            self.handle_exec(event)

        elif event.event_type == EVENT_PROCESS_EXIT:
            self.handle_exit(event)

    def handle_fork(self, event):
        parent_pid = event.pid
        child_pid = event.data.process.child_pid
        child_tid = event.data.process.child_tid

        if child_pid != child_tid:
            return

        parent = self.processes.get(parent_pid)

        if parent is None:
            parent = ProcessInfo(pid=parent_pid, ppid=event.ppid, uid=event.uid, comm=decode_c_string(event.comm))
            self.processes[parent_pid] = parent

        child = ProcessInfo(pid=child_pid, ppid=parent_pid, uid=event.uid, start_ns=event.timestamp_ns)

        self.processes[child_pid] = child

        parent.children.add(child_pid)
    
    def handle_exec(self, event):
        pid = event.pid

        process = self.processes.get(pid)

        if process is None:
            process = ProcessInfo(pid=pid, ppid=event.ppid)
            self.processes[pid] = process

        process.ppid = event.ppid
        process.uid = event.uid
        process.comm = decode_c_string(event.comm)
        process.executable = decode_c_string(event.data.exec.filename)

        process.argv = [decode_c_string(event.data.exec.args[i]) for i in range(event.data.exec.argc)]

        process.exec_ns = event.timestamp_ns

    def handle_exit(self, event):
        pid = event.pid

        process = self.processes.get(pid)

        if process is None:
            process = ProcessInfo(pid=pid, ppid=event.ppid, uid=event.uid, comm=decode_c_string(event.comm))
            self.processes[pid] = process

        process.exit_ns = event.timestamp_ns

    def get_children(self, pid):
        process = self.processes.get(pid)

        if process is None:
            return []

        return [self.processes[child_pid] for child_pid in process.children if child_pid in self.processes]

    def get_descendants(self, pid):
        descendants = []

        for child in self.get_children(pid):
            descendants.append(child)
            descendants.extend(self.get_descendants(child.pid))

        return descendants
    
    def render_tree(self, pid):
        if pid not in self.processes:
            return ""

        lines = []

        def walk(current_pid, prefix="", connector=""):
            process = self.processes[current_pid]

            name = process.comm or process.executable or "?"

            lines.append(f"{prefix}{connector}{process.pid} {name}")

            children = [child_pid for child_pid in process.children if child_pid in self.processes]

            children.sort()

            for index, child_pid in enumerate(children):
                is_last = index == len(children) - 1

                child_connector = ("└── " if is_last else "├── ")

                child_prefix = prefix + ("    " if is_last else "│   ")

                walk(child_pid, child_prefix, child_connector,)

        walk(pid)

        return "\n".join(lines)

def decode_c_string(value):
    return bytes(value).split(b"\0", 1)[0].decode("utf-8", errors="replace")