"""Shared loopback fixtures and harness client for the native TCP proxy tests.

This module is test-only.  It contains no TCP relay/forwarding implementation:
the data path under test is always the production tcp_proxy::Engine behind
``engine_harness``.  Python owns backend/client sockets, payload generation,
byte assertions, /proc observation and process cleanup.

Everything binds loopback only.  Ports are ephemeral.  Child processes are
task-owned and cleaned up explicitly; no broad pkill is used.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import queue
import random
import select
import selectors
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterable, Optional

AF_INET = socket.AF_INET
AF_INET6 = socket.AF_INET6
SOCK_STREAM = socket.SOCK_STREAM

LOOPBACK_V4 = "127.0.0.1"
LOOPBACK_V6 = "::1"
WILDCARD_V4 = "0.0.0.0"
WILDCARD_V6 = "::"

TCP_ESTABLISHED = "01"
TCP_SYN_SENT = "02"
TCP_SYN_RECV = "03"
TCP_FIN_WAIT1 = "04"
TCP_FIN_WAIT2 = "05"
TCP_TIME_WAIT = "06"
TCP_CLOSE = "07"
TCP_CLOSE_WAIT = "08"
TCP_LAST_ACK = "09"
TCP_LISTEN = "0A"
TCP_CLOSING = "0B"

STATE_NAMES = {
    TCP_ESTABLISHED: "ESTABLISHED",
    TCP_SYN_SENT: "SYN_SENT",
    TCP_SYN_RECV: "SYN_RECV",
    TCP_FIN_WAIT1: "FIN_WAIT1",
    TCP_FIN_WAIT2: "FIN_WAIT2",
    TCP_TIME_WAIT: "TIME_WAIT",
    TCP_CLOSE: "CLOSE",
    TCP_CLOSE_WAIT: "CLOSE_WAIT",
    TCP_LAST_ACK: "LAST_ACK",
    TCP_LISTEN: "LISTEN",
    TCP_CLOSING: "CLOSING",
}


# ---------------------------------------------------------------------------
# Time and small helpers
# ---------------------------------------------------------------------------


class Deadline:
    def __init__(self, seconds: float):
        self.seconds = seconds
        self.end = time.monotonic() + seconds

    def remaining(self) -> float:
        return max(0.0, self.end - time.monotonic())

    def expired(self) -> bool:
        return time.monotonic() >= self.end


def wait_for(predicate: Callable[[], bool], timeout: float, interval: float = 0.01,
             description: str = "condition") -> bool:
    deadline = Deadline(timeout)
    while not deadline.expired():
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


def sleep_until_stop(stop_event: threading.Event, seconds: float) -> None:
    deadline = time.monotonic() + seconds
    while not stop_event.is_set():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        stop_event.wait(min(remaining, 0.05))


def free_port(host: str = LOOPBACK_V4, family: Optional[int] = None) -> int:
    """Find a free port, releasing it before the caller binds.

    This is a best-effort fixture allocation: another process can claim the
    port in between. Callers must treat bind failures as setup failures.
    """
    if family is None:
        family = AF_INET6 if ":" in host else AF_INET
    sock = socket.socket(family, SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def free_ports(count: int, host: str = LOOPBACK_V4) -> list[int]:
    """Allocate ``count`` distinct loopback ports, then release all of them.

    All sockets are bound concurrently so the kernel cannot hand the same
    ephemeral port to two callers before either is released.
    """
    if count < 1:
        raise ValueError("count must be positive")
    family = AF_INET6 if ":" in host else AF_INET
    socks: list[socket.socket] = []
    try:
        for _ in range(count):
            sock = socket.socket(family, SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, 0))
            socks.append(sock)
        return [int(sock.getsockname()[1]) for sock in socks]
    finally:
        for sock in socks:
            sock.close()


def ipv6_available() -> bool:
    try:
        sock = socket.socket(AF_INET6, SOCK_STREAM)
        try:
            sock.bind((LOOPBACK_V6, 0))
            return True
        finally:
            sock.close()
    except OSError:
        return False


def deterministic_payload(size: int, seed: int) -> bytes:
    """Deterministic payload containing every byte value, NULs and 0xff runs."""
    if size < 0:
        raise ValueError("size must be nonnegative")
    rng = random.Random(seed)
    data = bytearray(rng.randbytes(size))
    for i in range(min(size, 256)):
        data[i] = i
    if size >= 1024:
        data[256:512] = b"\x00" * 256
        data[512:768] = b"\xff" * 256
    if size >= 2048:
        pattern = bytes(range(256)) * 4
        data[-1024:] = pattern[:1024]
    return bytes(data)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def recv_exact(sock: socket.socket, size: int, timeout: float) -> bytes:
    deadline = Deadline(timeout)
    chunks = bytearray()
    while len(chunks) < size:
        remaining = deadline.remaining()
        if remaining <= 0:
            exc = TimeoutError(f"recv_exact timed out with {len(chunks)}/{size} bytes")
            exc.received = len(chunks)
            raise exc
        sock.settimeout(remaining)
        try:
            chunk = sock.recv(min(65536, size - len(chunks)))
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError) as exc:
            exc.received = len(chunks)
            raise
        if not chunk:
            exc = EOFError(f"EOF after {len(chunks)}/{size} bytes")
            exc.received = len(chunks)
            raise exc
        chunks.extend(chunk)
    return bytes(chunks)


def recv_until_eof(sock: socket.socket, timeout: float) -> bytes:
    deadline = Deadline(timeout)
    chunks = bytearray()
    while True:
        remaining = deadline.remaining()
        if remaining <= 0:
            raise TimeoutError(f"recv_until_eof timed out with {len(chunks)} bytes")
        sock.settimeout(remaining)
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            raise TimeoutError(f"recv_until_eof timed out with {len(chunks)} bytes")
        if not chunk:
            return bytes(chunks)
        chunks.extend(chunk)


def recv_until_eof_or_reset(sock: socket.socket, timeout: float) -> bytes:
    """Read to EOF, preserving bytes already received before a reset."""
    chunks = bytearray()
    deadline = Deadline(timeout)
    sock.settimeout(0.5)
    while not deadline.expired():
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            continue
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            return bytes(chunks)
        if not chunk:
            return bytes(chunks)
        chunks.extend(chunk)
    return bytes(chunks)


def wait_until_closed(sock: socket.socket, timeout: float) -> float:
    """Wait for EOF/reset; return elapsed seconds.  Raises on timeout."""
    started = time.monotonic()
    deadline = Deadline(timeout)
    sock.settimeout(0.5)
    while not deadline.expired():
        try:
            data = sock.recv(65536)
        except socket.timeout:
            continue
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            return time.monotonic() - started
        if not data:
            return time.monotonic() - started
    raise TimeoutError(f"socket still open after {timeout:.2f}s")


def connect_socket(host: str, port: int, timeout: float = 3.0,
                   source: Optional[str] = None) -> socket.socket:
    family = AF_INET6 if ":" in host else AF_INET
    sock = socket.socket(family, SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass
    if source is not None:
        sock.bind((source, 0))
    sock.connect((host, port))
    return sock


def try_connect(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        sock = connect_socket(host, port, timeout)
    except OSError:
        return False
    sock.close()
    return True


def wait_port_listening(host: str, port: int, timeout: float = 5.0) -> bool:
    return wait_for(lambda: try_connect(host, port, 0.2), timeout,
                    interval=0.02, description=f"{host}:{port} listening")


# ---------------------------------------------------------------------------
# /proc observation
# ---------------------------------------------------------------------------


def proc_fd_count(pid: int) -> int:
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except FileNotFoundError:
        return -1
    except OSError:
        return -1


def proc_thread_count(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/status", "r", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("Threads:"):
                    return int(line.split()[1])
    except (FileNotFoundError, OSError, ValueError):
        pass
    return -1


def proc_rss_kb(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/status", "r", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except (FileNotFoundError, OSError, ValueError):
        pass
    return -1


def proc_cpu_ticks(pid: int) -> Optional[int]:
    """Return utime+stime clock ticks, or None if the process is gone."""
    try:
        with open(f"/proc/{pid}/stat", "r", encoding="utf-8") as handle:
            raw = handle.read()
    except (FileNotFoundError, OSError):
        return None
    # comm may contain spaces/parentheses; fields start after the last ')'.
    if ")" not in raw:
        return None
    fields = raw[raw.rfind(")") + 2:].split()
    try:
        return int(fields[11]) + int(fields[12])
    except (IndexError, ValueError):
        return None


def clock_ticks_per_second() -> int:
    try:
        return int(os.sysconf("SC_CLK_TCK"))
    except (ValueError, OSError):
        return 100


def proc_fds(pid: int) -> list[str]:
    try:
        return os.listdir(f"/proc/{pid}/fd")
    except (FileNotFoundError, OSError):
        return []


def proc_socket_inodes(pid: int) -> set[int]:
    inodes: set[int] = set()
    for fd in proc_fds(pid):
        try:
            target = os.readlink(f"/proc/{pid}/fd/{fd}")
        except OSError:
            continue
        if target.startswith("socket:[") and target.endswith("]"):
            try:
                inodes.add(int(target[len("socket:["):-1]))
            except ValueError:
                pass
    return inodes


def proc_tcp_table(pid: int) -> list[dict]:
    rows: list[dict] = []
    for name, family in (("tcp", AF_INET), ("tcp6", AF_INET6)):
        path = f"/proc/{pid}/net/{name}"
        try:
            with open(path, "r", encoding="utf-8") as handle:
                handle.readline()
                for line in handle:
                    fields = line.split()
                    if len(fields) < 10:
                        continue
                    local, remote, state = fields[1], fields[2], fields[3]
                    try:
                        local_port = int(local.rsplit(":", 1)[1], 16)
                        remote_port = int(remote.rsplit(":", 1)[1], 16)
                        inode = int(fields[9])
                    except (ValueError, IndexError):
                        continue
                    rows.append({
                        "family": "inet6" if family == AF_INET6 else "inet",
                        "local": local,
                        "remote": remote,
                        "local_port": local_port,
                        "remote_port": remote_port,
                        "state": state,
                        "state_name": STATE_NAMES.get(state, state),
                        "inode": inode,
                    })
        except (FileNotFoundError, OSError):
            continue
    return rows


def proc_socket_states(pid: int) -> list[dict]:
    inodes = proc_socket_inodes(pid)
    return [row for row in proc_tcp_table(pid) if row["inode"] in inodes]


def proc_state_counts(pid: int) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in proc_socket_states(pid):
        name = row["state_name"]
        counts[name] = counts.get(name, 0) + 1
    return counts


def proc_has_remote_port(pid: int, port: int, state: Optional[str] = None) -> bool:
    for row in proc_socket_states(pid):
        if row["remote_port"] == port and (state is None or row["state"] == state):
            return True
    return False


def wait_syn_sent(pid: int, port: int, timeout: float) -> bool:
    return wait_for(lambda: proc_has_remote_port(pid, port, TCP_SYN_SENT),
                    timeout, interval=0.01,
                    description=f"Engine SYN_SENT to port {port}")


def find_syn_sent_socket(pid: int, port: int,
                         exclude_local_ports: Iterable[int] = ()) -> Optional[dict]:
    """Return one Engine-owned SYN_SENT socket row for ``port``, if any.

    The row carries local port and inode so a later accept can be attributed to
    this exact Engine probe instead of to unrelated backlog fillers.
    """
    excluded = set(exclude_local_ports)
    for row in proc_socket_states(pid):
        if row["remote_port"] != port or row["state"] != TCP_SYN_SENT:
            continue
        if row["local_port"] in excluded:
            continue
        return row
    return None


def wait_syn_sent_socket(pid: int, port: int, timeout: float,
                         exclude_local_ports: Iterable[int] = ()) -> Optional[dict]:
    """Wait for an Engine probe in SYN_SENT and return its socket metadata."""
    found: list[Optional[dict]] = [None]
    excluded = set(exclude_local_ports)

    def predicate() -> bool:
        found[0] = find_syn_sent_socket(pid, port, excluded)
        return found[0] is not None

    if not wait_for(predicate, timeout, interval=0.01,
                    description=f"Engine SYN_SENT socket metadata to port {port}"):
        return None
    return found[0]


# ---------------------------------------------------------------------------
# Test backends (thread-per-flow test-side only)
# ---------------------------------------------------------------------------


class Backend:
    """Loopback backend with echo / greeting / half-close / sink modes.

    Modes:
      echo                 echo every byte, close after client EOF
      greeting             send greeting on accept, then echo
      half_close           read to EOF, optionally wait, send response, close
      half_close_silent    read to EOF, then stay silent (forces engine timeout)
      reverse_half_close   send response + SHUT_WR, then read client to EOF
      sink                 discard every byte
      close_after_first    read one chunk and close without echo
    """

    def __init__(self, mode: str = "echo", host: str = LOOPBACK_V4, port: int = 0,
                 greeting: bytes = b"", response: bytes = b"",
                 half_close_delay: float = 0.0, pause_read: float = 0.0,
                 backlog: int = 128, name: Optional[str] = None):
        self.mode = mode
        self.host = host
        self._family = AF_INET6 if ":" in host else AF_INET
        self._requested_port = port
        self.greeting = greeting
        self.response = response
        self.half_close_delay = half_close_delay
        self.pause_read = pause_read
        self.backlog = backlog
        self.name = name or f"backend-{mode}"

        self._stop = threading.Event()
        self._accepting = threading.Event()
        self._accepting.set()
        self._lock = threading.Lock()
        self._listen_sock: Optional[socket.socket] = None
        self._accept_thread: Optional[threading.Thread] = None
        self._handler_threads: list[threading.Thread] = []
        self._conns: set[socket.socket] = set()
        self._fillers: list[socket.socket] = []

        self.connections_total = 0
        self.rejected_total = 0
        self.bytes_c2s = 0
        self.bytes_s2c = 0
        self.eof_total = 0
        self.last_eof_time: Optional[float] = None
        self.accepted_addresses: list[tuple] = []
        self.error_count = 0
        self.errors: list[str] = []

        self._open_listener()
        self._start_accept_thread()

    @property
    def port(self) -> int:
        sock = self._listen_sock
        if sock is not None:
            return int(sock.getsockname()[1])
        return self._requested_port

    def _open_listener(self) -> None:
        sock = socket.socket(self._family, SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if self._family == AF_INET6:
            try:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            except OSError:
                pass
        sock.bind((self.host, self._requested_port))
        sock.listen(self.backlog)
        sock.settimeout(0.2)
        with self._lock:
            self._listen_sock = sock
            self._requested_port = int(sock.getsockname()[1])

    def start_listening(self) -> bool:
        with self._lock:
            if self._listen_sock is not None:
                return False
            if self._stop.is_set():
                raise RuntimeError("backend already stopped")
            previous = self._accept_thread
        if previous is not None and previous.is_alive():
            previous.join(timeout=2.0)
            if previous.is_alive():
                raise TimeoutError("retired backend accept thread did not stop")
        self._open_listener()
        self._start_accept_thread()
        return True

    def close_listener(self) -> None:
        with self._lock:
            sock = self._listen_sock
            self._listen_sock = None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    def pause_accept(self) -> None:
        self._accepting.clear()

    def resume_accept(self) -> None:
        self._accepting.set()

    def _start_accept_thread(self) -> None:
        if self._accept_thread is not None and self._accept_thread.is_alive():
            return
        self._accept_thread = threading.Thread(
            target=self._accept_loop, name=f"{self.name}-accept", daemon=True)
        self._accept_thread.start()

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            if not self._accepting.is_set():
                time.sleep(0.02)
                continue
            with self._lock:
                sock = self._listen_sock
            if sock is None:
                return
            try:
                conn, addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            conn.settimeout(0.2)
            thread = threading.Thread(target=self._handle, args=(conn, addr),
                                      name=f"{self.name}-flow", daemon=True)
            with self._lock:
                self.connections_total += 1
                self.accepted_addresses.append(addr)
                self._conns.add(conn)
                self._handler_threads.append(thread)
            thread.start()

    def _record_error(self, exc: BaseException) -> None:
        with self._lock:
            self.error_count += 1
            if len(self.errors) < 32:
                self.errors.append(f"{type(exc).__name__}: {exc}")

    def _send_all(self, conn: socket.socket, data: bytes) -> None:
        view = memoryview(data)
        while view and not self._stop.is_set():
            try:
                sent = conn.send(view)
            except socket.timeout:
                continue
            except OSError as exc:
                raise exc
            if sent <= 0:
                raise ConnectionError("send returned zero")
            with self._lock:
                self.bytes_s2c += sent
            view = view[sent:]

    def _read_loop(self, conn: socket.socket, echo: bool) -> None:
        while not self._stop.is_set():
            try:
                data = conn.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                return
            if not data:
                with self._lock:
                    self.eof_total += 1
                    self.last_eof_time = time.monotonic()
                return
            with self._lock:
                self.bytes_c2s += len(data)
            if echo:
                self._send_all(conn, data)

    def _handle(self, conn: socket.socket, addr) -> None:
        try:
            if self.pause_read > 0:
                sleep_until_stop(self._stop, self.pause_read)

            if self.mode == "reverse_half_close":
                if self.response:
                    self._send_all(conn, self.response)
                try:
                    conn.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                self._read_loop(conn, echo=False)
                return

            if self.mode == "greeting" and self.greeting:
                self._send_all(conn, self.greeting)

            if self.mode in ("echo", "greeting"):
                self._read_loop(conn, echo=True)
                return

            if self.mode == "sink":
                self._read_loop(conn, echo=False)
                return

            if self.mode == "close_after_first":
                try:
                    data = conn.recv(65536)
                except OSError:
                    data = b""
                if data:
                    with self._lock:
                        self.bytes_c2s += len(data)
                return

            if self.mode in ("half_close", "half_close_silent"):
                self._read_loop(conn, echo=False)
                if self.half_close_delay > 0:
                    sleep_until_stop(self._stop, self.half_close_delay)
                if self.mode == "half_close_silent":
                    sleep_until_stop(self._stop, 10.0)
                    return
                if self.response:
                    self._send_all(conn, self.response)
                return
        except OSError as exc:
            if not self._stop.is_set():
                self._record_error(exc)
        finally:
            with self._lock:
                self._conns.discard(conn)
            try:
                conn.close()
            except OSError:
                pass

    # -- queue saturation helpers ------------------------------------------

    def fill_accept_queue(self, max_fillers: int = 12,
                          probe_timeout: float = 0.25) -> bool:
        """Fill the listening backlog without accepting; True if a probe stayed pending."""
        with self._lock:
            port = self.port
        fillers: list[socket.socket] = []
        saw_pending = False
        try:
            for _ in range(max_fillers):
                sock = socket.socket(self._family, SOCK_STREAM)
                sock.setblocking(False)
                try:
                    rc = sock.connect_ex((self.host, port))
                except OSError:
                    sock.close()
                    break
                if rc not in (0, errno.EINPROGRESS, errno.EALREADY, errno.EWOULDBLOCK):
                    sock.close()
                    break
                _, writable, _ = select.select([], [sock], [], probe_timeout)
                fillers.append(sock)
                if not writable:
                    saw_pending = True
                    break
        finally:
            with self._lock:
                self._fillers.extend(fillers)
        return saw_pending

    def release_fillers(self) -> None:
        with self._lock:
            fillers = self._fillers
            self._fillers = []
        for sock in fillers:
            try:
                sock.close()
            except OSError:
                pass

    # -- waits and stats ---------------------------------------------------

    def wait_connections(self, count: int, timeout: float = 5.0) -> bool:
        return wait_for(lambda: self.connections_total >= count, timeout)

    def wait_bytes_c2s(self, count: int, timeout: float = 10.0) -> bool:
        return wait_for(lambda: self.bytes_c2s >= count, timeout)

    def wait_eof(self, count: int, timeout: float = 10.0) -> bool:
        return wait_for(lambda: self.eof_total >= count, timeout)

    def stats(self) -> dict:
        with self._lock:
            active = len(self._conns)
            return {
                "name": self.name,
                "mode": self.mode,
                "host": self.host,
                "port": self.port,
                "connections_total": self.connections_total,
                "active_connections": active,
                "bytes_client_to_server": self.bytes_c2s,
                "bytes_server_to_client": self.bytes_s2c,
                "eof_total": self.eof_total,
                "error_count": self.error_count,
                "errors": list(self.errors),
            }

    def stop(self) -> None:
        self._stop.set()
        self.close_listener()
        self.release_fillers()
        with self._lock:
            conns = list(self._conns)
            self._conns.clear()
            threads = list(self._handler_threads)
            accept_thread = self._accept_thread
        for conn in conns:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass
        if accept_thread is not None:
            accept_thread.join(timeout=1.0)
        deadline = Deadline(2.0)
        for thread in threads:
            thread.join(timeout=max(0.0, deadline.remaining()))

    def __enter__(self) -> "Backend":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()


class Blackhole:
    """Listening backlog with no accept() until explicitly started."""

    def __init__(self, host: str = LOOPBACK_V4, port: int = 0, backlog: int = 1,
                 name: str = "blackhole"):
        self.host = host
        self._family = AF_INET6 if ":" in host else AF_INET
        self._requested_port = port
        self.backlog = backlog
        self.name = name
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._sock = socket.socket(self._family, SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self._requested_port))
        self._sock.listen(self.backlog)
        self._sock.settimeout(0.2)
        self._requested_port = int(self._sock.getsockname()[1])
        self._fillers: list[socket.socket] = []
        self._accept_thread: Optional[threading.Thread] = None
        self._conns: set[socket.socket] = set()
        self.accepted_addresses: list[tuple] = []
        self.connections_total = 0
        self.bytes_c2s = 0
        self.bytes_s2c = 0

    @property
    def port(self) -> int:
        return self._requested_port

    def accepted_peer_ports(self) -> list[int]:
        """Client-side source ports of connections this endpoint accepted."""
        with self._lock:
            return [int(address[1]) for address in self.accepted_addresses]

    def fill(self, max_fillers: int = 12, probe_timeout: float = 0.25) -> bool:
        fillers: list[socket.socket] = []
        saw_pending = False
        for _ in range(max_fillers):
            sock = socket.socket(self._family, SOCK_STREAM)
            sock.setblocking(False)
            try:
                rc = sock.connect_ex((self.host, self.port))
            except OSError:
                sock.close()
                break
            if rc not in (0, errno.EINPROGRESS, errno.EALREADY, errno.EWOULDBLOCK):
                sock.close()
                break
            _, writable, _ = select.select([], [sock], [], probe_timeout)
            fillers.append(sock)
            if not writable:
                saw_pending = True
                break
        with self._lock:
            self._fillers.extend(fillers)
        return saw_pending

    def start_accepting(self, echo: bool = True) -> None:
        if self._accept_thread is not None and self._accept_thread.is_alive():
            return
        self._accept_thread = threading.Thread(target=self._accept_loop, args=(echo,),
                                               name=f"{self.name}-accept", daemon=True)
        self._accept_thread.start()

    def _accept_loop(self, echo: bool) -> None:
        while not self._stop.is_set():
            try:
                conn, _addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            conn.settimeout(0.2)
            with self._lock:
                self.connections_total += 1
                self.accepted_addresses.append(_addr)
                self._conns.add(conn)
            threading.Thread(target=self._handle, args=(conn, echo),
                             name=f"{self.name}-flow", daemon=True).start()

    def _handle(self, conn: socket.socket, echo: bool) -> None:
        try:
            while not self._stop.is_set():
                try:
                    data = conn.recv(65536)
                except socket.timeout:
                    continue
                except OSError:
                    return
                if not data:
                    return
                with self._lock:
                    self.bytes_c2s += len(data)
                if echo:
                    try:
                        conn.sendall(data)
                    except OSError:
                        return
                    with self._lock:
                        self.bytes_s2c += len(data)
        finally:
            with self._lock:
                self._conns.discard(conn)
            try:
                conn.close()
            except OSError:
                pass

    def fail(self) -> None:
        """Close the listener and all fillers so pending connects get RST."""
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        with self._lock:
            fillers = self._fillers
            self._fillers = []
            conns = list(self._conns)
            self._conns.clear()
        for sock in fillers + conns:
            try:
                sock.close()
            except OSError:
                pass

    release = fail

    def stats(self) -> dict:
        return {
            "name": self.name,
            "port": self.port,
            "connections_total": self.connections_total,
            "accepted_peer_ports": self.accepted_peer_ports(),
            "bytes_client_to_server": self.bytes_c2s,
            "bytes_server_to_client": self.bytes_s2c,
        }

    def stop(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        with self._lock:
            fillers = self._fillers
            self._fillers = []
            conns = list(self._conns)
            self._conns.clear()
        for sock in fillers + conns:
            try:
                sock.close()
            except OSError:
                pass
        thread = self._accept_thread
        if thread is not None:
            thread.join(timeout=1.0)

    def __enter__(self) -> "Blackhole":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()


class Squatter:
    """A foreign listener that intentionally owns a port."""

    def __init__(self, host: str = LOOPBACK_V4, port: int = 0):
        family = AF_INET6 if ":" in host else AF_INET
        self._sock = socket.socket(family, SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self._sock.listen(8)
        self.host = host
        self.port = int(self._sock.getsockname()[1])

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass

    def __enter__(self) -> "Squatter":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


# ---------------------------------------------------------------------------
# Task-owned TLS fixtures (ephemeral CA/cert; no real credentials)
# ---------------------------------------------------------------------------


class TlsUnavailable(RuntimeError):
    """The openssl tool required to create ephemeral test material is absent."""


def generate_test_tls_material(directory: Path | str) -> dict:
    """Create a throw-away CA and localhost server certificate with openssl.

    Everything is written below ``directory`` (callers use TemporaryDirectory).
    SANs cover ``localhost`` and 127.0.0.1 so Python hostname verification is
    exercised over loopback.
    """
    openssl = shutil.which("openssl")
    if not openssl:
        raise TlsUnavailable("openssl not found in PATH; TLS regression cannot run")
    base = Path(directory)
    base.mkdir(parents=True, exist_ok=True)
    ca_key = base / "ca.key"
    ca_cert = base / "ca.pem"
    server_key = base / "server.key"
    server_csr = base / "server.csr"
    server_cert = base / "server.pem"
    ext = base / "server.ext"
    ext.write_text(
        "subjectAltName=DNS:localhost,IP:127.0.0.1\n"
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n",
        encoding="utf-8",
    )
    commands = [
        [openssl, "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes",
         "-days", "2", "-keyout", str(ca_key), "-out", str(ca_cert),
         "-subj", "/CN=task4-native-tcp-proxy-test-ca",
         "-addext", "basicConstraints=critical,CA:TRUE"],
        [openssl, "req", "-newkey", "rsa:2048", "-sha256", "-nodes",
         "-keyout", str(server_key), "-out", str(server_csr),
         "-subj", "/CN=localhost"],
        [openssl, "x509", "-req", "-in", str(server_csr), "-CA", str(ca_cert),
         "-CAkey", str(ca_key), "-CAcreateserial", "-days", "2", "-sha256",
         "-extfile", str(ext), "-out", str(server_cert)],
    ]
    for command in commands:
        completed = subprocess.run(command, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, timeout=30, check=False)
        if completed.returncode != 0:
            raise RuntimeError(
                f"openssl failed ({' '.join(command[:3])}): "
                f"{completed.stderr.decode('utf-8', 'replace')[-800:]}")
    return {
        "openssl": openssl,
        "ca_cert": str(ca_cert),
        "server_cert": str(server_cert),
        "server_key": str(server_key),
    }


def tls_client_context(cafile: str) -> ssl.SSLContext:
    """Client context that verifies the ephemeral CA and the server hostname."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.load_verify_locations(cafile=cafile)
    return context


class TlsEchoBackend:
    """TLS endpoint that terminates the client handshake and echoes bytes.

    This is a test endpoint, not a proxy: the production Engine only forwards
    the encrypted byte stream.  It verifies that the Engine is TLS-agnostic and
    preserves an exact binary stream across many buffer boundaries.
    """

    def __init__(self, certfile: str, keyfile: str, host: str = LOOPBACK_V4,
                 port: int = 0, name: str = "tls-echo"):
        self.host = host
        self._family = AF_INET6 if ":" in host else AF_INET
        self.name = name
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._context.minimum_version = ssl.TLSVersion.TLSv1_2
        self._context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        self._sock = socket.socket(self._family, SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, port))
        self._sock.listen(64)
        self._sock.settimeout(0.2)
        self._port = int(self._sock.getsockname()[1])
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._conns: set[socket.socket] = set()
        self._threads: list[threading.Thread] = []
        self.connections_total = 0
        self.handshake_errors = 0
        self.bytes_c2s = 0
        self.bytes_s2c = 0
        self.eof_total = 0
        self.close_total = 0
        self.close_errors = 0
        self.errors: list[str] = []
        self._accept_thread = threading.Thread(
            target=self._accept_loop, name=f"{self.name}-accept", daemon=True)
        self._accept_thread.start()

    @property
    def port(self) -> int:
        return self._port

    def _record_error(self, exc: BaseException) -> None:
        with self._lock:
            if len(self.errors) < 16:
                self.errors.append(f"{type(exc).__name__}: {exc}")

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            conn.settimeout(10.0)
            with self._lock:
                self.connections_total += 1
                self._conns.add(conn)
            thread = threading.Thread(target=self._handle, args=(conn,),
                                      name=f"{self.name}-flow", daemon=True)
            with self._lock:
                self._threads.append(thread)
            thread.start()

    def _handle(self, conn: socket.socket) -> None:
        tls_conn = None
        try:
            tls_conn = self._context.wrap_socket(conn, server_side=True)
            with self._lock:
                self._conns.discard(conn)
                self._conns.add(tls_conn)
            while not self._stop.is_set():
                data = tls_conn.recv(65536)
                if not data:
                    with self._lock:
                        self.eof_total += 1
                    break
                with self._lock:
                    self.bytes_c2s += len(data)
                tls_conn.sendall(data)
                with self._lock:
                    self.bytes_s2c += len(data)
            try:
                tls_conn.unwrap()
                if not self._stop.is_set():
                    with self._lock:
                        self.close_total += 1
            except (ssl.SSLError, OSError) as exc:
                if not self._stop.is_set():
                    with self._lock:
                        self.close_errors += 1
                    self._record_error(exc)
        except (ssl.SSLError, OSError, ValueError) as exc:
            if not self._stop.is_set():
                with self._lock:
                    self.handshake_errors += 1
                self._record_error(exc)
        finally:
            for sock in (tls_conn, conn):
                if sock is None:
                    continue
                with self._lock:
                    self._conns.discard(sock)
                try:
                    sock.close()
                except OSError:
                    pass

    def stats(self) -> dict:
        with self._lock:
            return {
                "name": self.name,
                "host": self.host,
                "port": self.port,
                "connections_total": self.connections_total,
                "handshake_errors": self.handshake_errors,
                "bytes_client_to_server": self.bytes_c2s,
                "bytes_server_to_client": self.bytes_s2c,
                "eof_total": self.eof_total,
                "close_total": self.close_total,
                "close_errors": self.close_errors,
                "errors": list(self.errors),
            }

    def wait_connections(self, count: int, timeout: float = 5.0) -> bool:
        return wait_for(lambda: self.connections_total >= count, timeout)

    def stop(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        with self._lock:
            conns = list(self._conns)
            self._conns.clear()
            threads = list(self._threads)
        for sock in conns:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass
        deadline = Deadline(2.0)
        self._accept_thread.join(timeout=max(0.0, deadline.remaining()))
        for thread in threads:
            thread.join(timeout=max(0.0, deadline.remaining()))

    def __enter__(self) -> "TlsEchoBackend":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()


# ---------------------------------------------------------------------------
# Configuration builders (frozen header field names)
# ---------------------------------------------------------------------------


def settings(**overrides) -> dict:
    row = {
        "id": 1,
        "worker_threads": 2,
        "max_connections": 10000,
        "buffer_size": 16384,
        "shutdown_timeout_ms": 5000,
        "half_close_timeout_ms": 30000,
    }
    row.update(overrides)
    return row


def hostgroup(hostgroup_id: int, source_protocol: str = "MYSQL",
              source_hostgroup: Optional[int] = None, **overrides) -> dict:
    """Product tcp_hostgroups row: a mandatory native HGM mapping.

    Four-table configuration has no balance/health/server columns.  The row
    names one existing MySQL or PostgreSQL hostgroup; that protocol HGM owns
    backend selection, health, limits and counters.
    """
    row = {
        "hostgroup_id": hostgroup_id,
        "source_protocol": source_protocol,
        "source_hostgroup": hostgroup_id if source_hostgroup is None else source_hostgroup,
        "comment": "",
    }
    row.update(overrides)
    return row


def server(server_id: int, hostgroup_id: int, port: int, hostname: str = LOOPBACK_V4,
           **overrides) -> dict:
    row = {
        "server_id": server_id,
        "hostgroup_id": hostgroup_id,
        "hostname": hostname,
        "port": port,
        "status": "ONLINE",
        "weight": 1,
        "max_connections": 1000,
        "backup": 0,
        "comment": "",
    }
    row.update(overrides)
    return row


def listener(listener_id: int, bind_port: int, default_hostgroup: int,
             bind_address: str = LOOPBACK_V4, **overrides) -> dict:
    row = {
        "listener_id": listener_id,
        "active": 1,
        "bind_address": bind_address,
        "bind_port": bind_port,
        "default_hostgroup": default_hostgroup,
        "max_connections": 10000,
        "connect_timeout_ms": 2000,
        "idle_timeout_ms": 60000,
        "max_connect_attempts": 3,
        "comment": "",
    }
    row.update(overrides)
    return row


def rule(rule_id: int, **overrides) -> dict:
    row = {
        "rule_id": rule_id,
        "active": 1,
        "listener_id": None,
        "source_cidr": None,
        "action": "ROUTE",
        "destination_hostgroup": None,
        "comment": "",
    }
    row.update(overrides)
    return row


class ScenarioConfig(dict):
    """Product four-table config plus a separate explicit fixture list.

    The dict itself is exactly product Config (settings/hostgroups/listeners/
    rules) and is what engine_harness receives as `config`.  Backend fixture
    controls live only in the `.backend_fixtures` attribute and are sent as the
    top-level sibling `backend_fixtures`; they are never part of config JSON.
    """

    def __init__(self, product: dict, backend_fixtures: Iterable[dict] = ()):
        super().__init__(product)
        self.backend_fixtures = list(backend_fixtures)


def config(settings_row: Optional[dict] = None, hostgroups: Iterable[dict] = (),
           backend_fixtures: Iterable[dict] = (), listeners: Iterable[dict] = (),
           rules: Iterable[dict] = ()) -> ScenarioConfig:
    """Return product Config plus explicitly named TEST backend fixtures."""
    product = {
        "settings": settings_row if settings_row is not None else settings(),
        "hostgroups": list(hostgroups),
        "listeners": list(listeners),
        "rules": list(rules),
    }
    return ScenarioConfig(product, backend_fixtures)


def simple_config(port: int, backend_port: int, listener_id: int = 1,
                  server_id: int = 1, hostgroup_id: int = 1,
                  settings_row: Optional[dict] = None,
                  listener_overrides: Optional[dict] = None,
                  server_overrides: Optional[dict] = None,
                  hostname: str = LOOPBACK_V4,
                  bind_address: str = LOOPBACK_V4,
                  source_protocol: str = "MYSQL",
                  source_hostgroup: Optional[int] = None) -> dict:
    listener_row = listener(listener_id, port, hostgroup_id, bind_address=bind_address)
    if listener_overrides:
        listener_row.update(listener_overrides)
    server_row = server(server_id, hostgroup_id, backend_port, hostname=hostname)
    if server_overrides:
        server_row.update(server_overrides)
    return config(
        settings_row=settings_row,
        hostgroups=[hostgroup(hostgroup_id, source_protocol=source_protocol,
                              source_hostgroup=source_hostgroup)],
        backend_fixtures=[server_row],
        listeners=[listener_row],
    )


def product_config(envelope: dict) -> dict:
    """Return the product Config dict; backend fixtures are not config."""
    if isinstance(envelope, ScenarioConfig):
        return dict(envelope)
    return dict(envelope)


def observation_provider(observation: dict) -> dict:
    """Provider document from an explicit combined snapshot observation."""
    provider = observation.get("backend_provider")
    return provider if isinstance(provider, dict) else {}


def provider_servers(observation: dict) -> list:
    """TEST provider fixture rows from a combined observation response."""
    return list(observation_provider(observation).get("servers") or [])


def provider_server(observation: dict, server_id: int) -> Optional[dict]:
    return find_row(provider_servers(observation), "server_id", server_id)


# ---------------------------------------------------------------------------
# Harness client (newline-delimited JSON over stdio)
# ---------------------------------------------------------------------------


class HarnessError(RuntimeError):
    pass


class HarnessClient:
    def __init__(self, harness_path: str, stderr_path: Optional[str] = None,
                 default_timeout: float = 15.0):
        self.harness_path = harness_path
        self.default_timeout = default_timeout
        self._stderr_handle = None
        if stderr_path:
            self._stderr_handle = open(stderr_path, "wb")
            stderr_target = self._stderr_handle
        else:
            stderr_target = subprocess.DEVNULL
        self.proc = subprocess.Popen(
            [harness_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=stderr_target,
            bufsize=0,
            close_fds=True,
        )
        assert self.proc.stdin is not None
        os.set_blocking(self.proc.stdin.fileno(), False)
        self._write_lock = threading.Lock()
        self._pending_lock = threading.Lock()
        self._pending: dict[int, queue.Queue] = {}
        self._next_id = 1
        self._buffer = bytearray()
        self._closed = False
        self._reader = threading.Thread(target=self._read_loop, name="harness-reader",
                                        daemon=True)
        self._reader.start()

    @property
    def pid(self) -> int:
        return int(self.proc.pid)

    def _read_loop(self) -> None:
        stdout = self.proc.stdout
        assert stdout is not None
        while True:
            try:
                chunk = os.read(stdout.fileno(), 65536)
            except OSError:
                break
            if not chunk:
                break
            self._buffer.extend(chunk)
            while True:
                newline = self._buffer.find(b"\n")
                if newline < 0:
                    break
                raw = bytes(self._buffer[:newline])
                del self._buffer[:newline + 1]
                if not raw.strip():
                    continue
                try:
                    response = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                rid = response.get("id")
                if not isinstance(rid, int):
                    continue
                with self._pending_lock:
                    waiter = self._pending.pop(rid, None)
                if waiter is not None:
                    waiter.put(response)
        self._closed = True
        with self._pending_lock:
            pending = list(self._pending.values())
            self._pending.clear()
        for waiter in pending:
            waiter.put(HarnessError("harness process closed stdout"))

    def request(self, op: str, timeout: Optional[float] = None, **payload) -> dict:
        timeout = self.default_timeout if timeout is None else timeout
        deadline = time.monotonic() + timeout
        with self._pending_lock:
            rid = self._next_id
            self._next_id += 1
            waiter: queue.Queue = queue.Queue(maxsize=1)
            self._pending[rid] = waiter
        message = {"id": rid, "op": op}
        message.update(payload)
        raw = (json.dumps(message, separators=(",", ":")) + "\n").encode("utf-8")
        acquired = False
        try:
            acquired = self._write_lock.acquire(timeout=max(0, deadline - time.monotonic()))
            if not acquired:
                raise queue.Empty
            stdin = self.proc.stdin
            if stdin is None or stdin.closed:
                raise HarnessError("harness stdin closed")
            fd = stdin.fileno()
            sent = 0
            while sent < len(raw):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise queue.Empty
                _, writable, _ = select.select([], [fd], [], remaining)
                if not writable:
                    raise queue.Empty
                try:
                    sent += os.write(fd, raw[sent:])
                except BlockingIOError:
                    continue
            self._write_lock.release()
            acquired = False
            response = waiter.get(timeout=max(0, deadline - time.monotonic()))
        except queue.Empty as exc:
            # A partial JSON line cannot be recovered safely. Terminating the
            # owned child also unblocks other requests and guarantees cleanup.
            if acquired and self.proc.poll() is None:
                self.proc.terminate()
            raise TimeoutError(f"harness request {op!r} timed out after {timeout}s") from exc
        finally:
            if acquired:
                self._write_lock.release()
            with self._pending_lock:
                self._pending.pop(rid, None)
        if isinstance(response, Exception):
            raise response
        return response

    def ping(self, timeout: float = 5.0) -> dict:
        return self.request("ping", timeout=timeout)

    @staticmethod
    def _request_payload(cfg: dict) -> dict:
        if isinstance(cfg, ScenarioConfig):
            return {"config": dict(cfg), "backend_fixtures": cfg.backend_fixtures}
        return {"config": dict(cfg)}

    def validate(self, cfg: dict, timeout: Optional[float] = None) -> dict:
        return self.request("validate", timeout=timeout, **self._request_payload(cfg))

    def start(self, cfg: dict, timeout: Optional[float] = None) -> dict:
        return self.request("start", timeout=timeout, **self._request_payload(cfg))

    def apply(self, cfg: dict, timeout: Optional[float] = None) -> dict:
        return self.request("apply", timeout=timeout, **self._request_payload(cfg))

    def snapshot(self, timeout: Optional[float] = None) -> dict:
        """Product Snapshot only; never augmented with test fixture data."""
        return self.request("snapshot", timeout=timeout)["snapshot"]

    def observation(self, timeout: Optional[float] = None) -> dict:
        """Explicit combined test observation: product snapshot + provider doc."""
        response = self.request("snapshot", timeout=timeout)
        return {"snapshot": response["snapshot"],
                "backend_provider": response.get("backend_provider") or {}}

    def provider_snapshot(self, timeout: Optional[float] = None) -> dict:
        """TEST fixture counters only, via the dedicated provider op."""
        return self.request("provider_snapshot", timeout=timeout)["backend_provider"]

    def config(self, timeout: Optional[float] = None) -> dict:
        return self.request("config", timeout=timeout)

    def stop(self, timeout: Optional[float] = None) -> dict:
        return self.request("stop", timeout=timeout)

    def apply_concurrent(self, configs: list[dict], timeout: Optional[float] = None) -> dict:
        payload = {"configs": [], "backend_fixtures": []}
        for cfg in configs:
            if isinstance(cfg, ScenarioConfig):
                payload["configs"].append(dict(cfg))
                payload["backend_fixtures"].append(cfg.backend_fixtures)
            else:
                payload["configs"].append(dict(cfg))
                payload["backend_fixtures"].append([])
        return self.request("apply_concurrent", timeout=timeout, **payload)

    def apply_stop_race(self, cfg: dict, timeout: Optional[float] = None) -> dict:
        return self.request("apply_stop_race", timeout=timeout,
                            **self._request_payload(cfg))

    def quit(self, timeout: float = 5.0) -> None:
        if self.proc.poll() is not None:
            return
        try:
            self.request("quit", timeout=timeout)
        except (HarnessError, TimeoutError, BrokenPipeError):
            pass
        try:
            assert self.proc.stdin is not None
            self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            pass

    def close(self) -> None:
        if self.proc.poll() is None:
            try:
                self.stop(timeout=5.0)
            except (HarnessError, TimeoutError, BrokenPipeError, OSError):
                pass
            try:
                self.quit(timeout=5.0)
            except (HarnessError, TimeoutError, OSError, ValueError):
                pass
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                try:
                    self.proc.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    pass
        if self._stderr_handle is not None:
            try:
                self._stderr_handle.close()
            except OSError:
                pass

    def __enter__(self) -> "HarnessClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


class SnapshotWaitTimeout(TimeoutError):
    """Predicate did not become true before the snapshot wait deadline."""

    def __init__(self, message: str, last_snapshot: Optional[dict]):
        super().__init__(message)
        self.last_snapshot = last_snapshot


def wait_snapshot(client: HarnessClient, predicate: Callable[[dict], bool],
                  timeout: float, interval: float = 0.02) -> dict:
    """Poll snapshots until ``predicate`` is true.

    Raises :class:`SnapshotWaitTimeout` on deadline expiry (or if the harness
    stops answering) instead of returning the last non-matching snapshot.  The
    last observation is embedded in the error and exposed as ``last_snapshot``
    so a failed wait can never be mistaken for a satisfied predicate.
    """
    deadline = Deadline(timeout)
    last = None
    while not deadline.expired():
        try:
            last = client.snapshot(timeout=min(2.0, max(0.2, deadline.remaining())))
        except (TimeoutError, HarnessError) as exc:
            raise SnapshotWaitTimeout(
                f"snapshot poll failed after {timeout:.2f}s: "
                f"{type(exc).__name__}: {exc}; last snapshot={last!r}", last) from exc
        if predicate(last):
            return last
        time.sleep(interval)
    try:
        last = client.snapshot(timeout=min(2.0, max(0.2, deadline.remaining())))
    except (TimeoutError, HarnessError):
        pass
    raise SnapshotWaitTimeout(
        f"snapshot predicate not satisfied within {timeout:.2f}s; "
        f"last snapshot={last!r}", last)


def find_row(rows: Iterable[dict], key: str, value) -> Optional[dict]:
    for row in rows:
        if row.get(key) == value:
            return row
    return None


def harness_available(path: str) -> bool:
    return bool(path) and os.path.isfile(path) and os.access(path, os.X_OK)


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return ""
