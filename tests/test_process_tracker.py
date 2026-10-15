from userspace.process_tracker import ProcessTracker
from userspace.protocol import (
    Event,
    EVENT_EXECVE,
    EVENT_PROCESS_EXIT,
    EVENT_PROCESS_FORK,
)


def test_fork_creates_parent_child_relationship():
    tracker = ProcessTracker()

    event = Event()
    event.event_type = EVENT_PROCESS_FORK
    event.timestamp_ns = 1000
    event.pid = 100
    event.ppid = 50
    event.uid = 1000
    event.data.process.child_pid = 200
    event.data.process.child_tid = 200

    tracker.handle_fork(event)

    assert 100 in tracker.processes
    assert 200 in tracker.processes

    parent = tracker.processes[100]
    child = tracker.processes[200]

    assert event.data.process.child_pid == event.data.process.child_tid
    assert child.ppid == 100
    assert 200 in parent.children
    assert child.start_ns == 1000


def test_exec_enriches_existing_process():
    tracker = ProcessTracker()

    fork = Event()
    fork.event_type = EVENT_PROCESS_FORK
    fork.timestamp_ns = 1000
    fork.pid = 100
    fork.ppid = 50
    fork.uid = 1000
    fork.data.process.child_pid = 200
    fork.data.process.child_tid = 200

    tracker.handle_event(fork)

    exec_event = Event()
    exec_event.event_type = EVENT_EXECVE
    exec_event.timestamp_ns = 2000
    exec_event.pid = 200
    exec_event.ppid = 100
    exec_event.uid = 1000
    exec_event.comm = b"python3"
    exec_event.data.exec.filename = b"/usr/bin/python3"
    exec_event.data.exec.argc = 2
    exec_event.data.exec.args[0].value = b"/usr/bin/python3"
    exec_event.data.exec.args[1].value = b"script.py"

    tracker.handle_event(exec_event)

    process = tracker.processes[200]

    assert process.ppid == 100
    assert process.comm == "python3"
    assert process.executable == "/usr/bin/python3"
    assert process.argv == [
        "/usr/bin/python3",
        "script.py",
    ]
    assert process.exec_ns == 2000


def test_exit_marks_process_as_exited():
    tracker = ProcessTracker()

    event = Event()
    event.event_type = EVENT_PROCESS_EXIT
    event.timestamp_ns = 3000
    event.pid = 200
    event.ppid = 100
    event.uid = 1000
    event.comm = b"python3"

    tracker.handle_event(event)

    process = tracker.processes[200]

    assert process.exit_ns == 3000

def test_thread_fork_is_ignored():
    tracker = ProcessTracker()

    event = Event()
    event.event_type = EVENT_PROCESS_FORK
    event.timestamp_ns = 1000
    event.pid = 100
    event.ppid = 50
    event.uid = 1000

    event.data.process.child_pid = 100
    event.data.process.child_tid = 101

    tracker.handle_event(event)

    assert 101 not in tracker.processes


def test_process_tree():
    tracker = ProcessTracker()

    fork1 = Event()
    fork1.event_type = EVENT_PROCESS_FORK
    fork1.pid = 100
    fork1.ppid = 50
    fork1.uid = 1000
    fork1.timestamp_ns = 1000
    fork1.data.process.child_pid = 200
    fork1.data.process.child_tid = 200

    tracker.handle_event(fork1)

    fork2 = Event()
    fork2.event_type = EVENT_PROCESS_FORK
    fork2.pid = 200
    fork2.ppid = 100
    fork2.uid = 1000
    fork2.timestamp_ns = 2000
    fork2.data.process.child_pid = 300
    fork2.data.process.child_tid = 300

    tracker.handle_event(fork2)

    assert tracker.processes[200].ppid == 100
    assert tracker.processes[300].ppid == 200

    descendants = tracker.get_descendants(100)

    assert [p.pid for p in descendants] == [200, 300]

def test_render_tree():
    tracker = ProcessTracker()

    fork1 = Event()
    fork1.event_type = EVENT_PROCESS_FORK
    fork1.pid = 100
    fork1.ppid = 50
    fork1.uid = 1000
    fork1.data.process.child_pid = 200
    fork1.data.process.child_tid = 200

    tracker.handle_event(fork1)

    fork2 = Event()
    fork2.event_type = EVENT_PROCESS_FORK
    fork2.pid = 200
    fork2.ppid = 100
    fork2.uid = 1000
    fork2.data.process.child_pid = 300
    fork2.data.process.child_tid = 300

    tracker.handle_event(fork2)

    tree = tracker.render_tree(100)

    assert "100" in tree
    assert "200" in tree
    assert "300" in tree