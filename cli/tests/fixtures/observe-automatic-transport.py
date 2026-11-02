#!/usr/bin/env python3
"""Transparent stdio/Unix relay for the real NativeSurface process boundary."""
import json
import os
import selectors
import socket
import sys

wire = open(os.environ["OBSERVE_AUTOMATIC_WIRE"], "x", encoding="utf-8", buffering=1)
peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
peer.connect(os.environ["OBSERVE_AUTOMATIC_SOCKET"])
selector = selectors.DefaultSelector()
selector.register(sys.stdin.fileno(), selectors.EVENT_READ, "client")
selector.register(peer, selectors.EVENT_READ, "server")
pending = {"client": b"", "server": b""}


def record(direction, chunk):
    pending[direction] += chunk
    while b"\n" in pending[direction]:
        line, pending[direction] = pending[direction].split(b"\n", 1)
        wire.write(json.dumps({"direction": direction, "frame": json.loads(line)}) + "\n")


try:
    while selector.get_map():
        for key, _ in selector.select():
            direction = key.data
            chunk = os.read(key.fd, 65536)
            if not chunk:
                selector.unregister(key.fileobj)
                if direction == "client":
                    peer.shutdown(socket.SHUT_WR)
                else:
                    selector.close()
                    break
            else:
                record(direction, chunk)
                if direction == "client":
                    peer.sendall(chunk)
                else:
                    sys.stdout.buffer.write(chunk)
                    sys.stdout.buffer.flush()
finally:
    peer.close()
    wire.close()
