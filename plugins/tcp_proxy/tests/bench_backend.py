#!/usr/bin/env python3
"""Task-owned selector-based echo backend used by every benchmark mode.

Started as a separate process so its PID, CPU ticks, RSS, threads and fds can be
measured independently of the Python benchmark client.  The same echo protocol
(echo every received byte, in order) is used for direct, native Engine and
HAProxy modes.

Writes a ready JSON file after bind, and a final stats JSON on SIGTERM.
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import selectors
import signal
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

STOP = False


def _stop(signum, frame):  # noqa: ARG001
    global STOP
    STOP = True


def write_json_atomic(path: str, payload: dict) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, target)


class Connection:
    __slots__ = ("sock", "fd", "inbuf", "outbuf", "accepted_at")

    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.fd = sock.fileno()
        self.inbuf = bytearray()
        self.outbuf = bytearray()
        self.accepted_at = time.monotonic()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--ready-file", required=True)
    parser.add_argument("--stats-file", required=True)
    parser.add_argument("--backlog", type=int, default=512)
    parser.add_argument("--max-connections", type=int, default=4096)
    parser.add_argument("--read-chunk", type=int, default=262144)
    parser.add_argument("--max-out-buffer", type=int, default=4 * 1024 * 1024)
    parser.add_argument("--stats-interval", type=float, default=0.5)
    args = parser.parse_args(argv)

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    family = socket.AF_INET6 if ":" in args.host else socket.AF_INET
    listener = socket.socket(family, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.host, args.port))
    listener.listen(args.backlog)
    listener.setblocking(False)
    port = int(listener.getsockname()[1])

    connections_total = 0
    active: dict[int, Connection] = {}
    bytes_c2s = 0
    bytes_s2c = 0
    rejected_total = 0
    started = time.monotonic()
    last_stats = 0.0

    def write_stats() -> None:
        write_json_atomic(args.stats_file, {
            "pid": os.getpid(),
            "host": args.host,
            "port": port,
            "updated_utc": datetime.now(timezone.utc).isoformat(),
            "elapsed_s": time.monotonic() - started,
            "connections_total": connections_total,
            "rejected_total": rejected_total,
            "active_connections": len(active),
            "bytes_client_to_server": bytes_c2s,
            "bytes_server_to_client": bytes_s2c,
        })

    selector = selectors.DefaultSelector()
    selector.register(listener, selectors.EVENT_READ, data=None)

    write_json_atomic(args.ready_file, {
        "pid": os.getpid(),
        "host": args.host,
        "port": port,
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "started_monotonic": started,
        "python": sys.version,
    })

    try:
        while not STOP:
            if args.stats_interval > 0 and time.monotonic() - last_stats >= args.stats_interval:
                write_stats()
                last_stats = time.monotonic()
            for key, mask in selector.select(timeout=0.1):
                if key.data is None:
                    while True:
                        try:
                            conn, _addr = listener.accept()
                        except BlockingIOError:
                            break
                        except OSError:
                            break
                        if len(active) >= args.max_connections:
                            rejected_total += 1
                            try:
                                conn.close()
                            except OSError:
                                pass
                            continue
                        conn.setblocking(False)
                        try:
                            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        except OSError:
                            pass
                        state = Connection(conn)
                        active[state.fd] = state
                        connections_total += 1
                        selector.register(conn, selectors.EVENT_READ, data=state)
                    continue

                state: Connection = key.data
                if mask & selectors.EVENT_READ:
                    try:
                        data = state.sock.recv(args.read_chunk)
                    except BlockingIOError:
                        data = None
                    except OSError:
                        data = b""
                    if data:
                        bytes_c2s += len(data)
                        state.outbuf.extend(data)
                    elif data == b"":
                        # EOF: flush pending bytes then close.
                        if not state.outbuf:
                            _close(selector, state)
                            active.pop(state.fd, None)
                            continue
                if mask & selectors.EVENT_WRITE or state.outbuf:
                    if state.outbuf:
                        try:
                            sent = state.sock.send(state.outbuf)
                        except BlockingIOError:
                            sent = 0
                        except OSError:
                            _close(selector, state)
                            active.pop(state.fd, None)
                            continue
                        if sent:
                            del state.outbuf[:sent]
                            bytes_s2c += sent
                    _update_interest(selector, state)
                if mask & selectors.EVENT_READ and not state.outbuf:
                    _update_interest(selector, state)
                if state.outbuf and len(state.outbuf) > args.max_out_buffer:
                    # Client is not draining; stop reading until it does.
                    _interest(selector, state, read=False, write=True)
    finally:
        try:
            selector.unregister(listener)
        except (KeyError, ValueError):
            pass
        try:
            listener.close()
        except OSError:
            pass
        for state in list(active.values()):
            try:
                state.sock.close()
            except OSError:
                pass
        selector.close()
        write_stats()
    return 0


def _close(selector: selectors.BaseSelector, state: Connection) -> None:
    try:
        selector.unregister(state.sock)
    except (KeyError, ValueError):
        pass
    try:
        state.sock.close()
    except OSError:
        pass


def _interest(selector: selectors.BaseSelector, state: Connection,
              read: bool, write: bool) -> None:
    events = 0
    if read and not state.outbuf:
        events |= selectors.EVENT_READ
    if write or state.outbuf:
        events |= selectors.EVENT_WRITE
    if not events:
        events = selectors.EVENT_READ
    try:
        selector.modify(state.sock, events, data=state)
    except (KeyError, ValueError):
        pass


def _update_interest(selector: selectors.BaseSelector, state: Connection) -> None:
    _interest(selector, state, read=not state.outbuf, write=bool(state.outbuf))


if __name__ == "__main__":
    sys.exit(main())
