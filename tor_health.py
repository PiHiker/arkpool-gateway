"""Authenticated loopback Tor readiness; prints no cookie or network details."""
from pathlib import Path
import os
import socket
import sys


def control_unix():
    """Opt-in per-client control socket for runtimes sharing loopback."""
    mode = os.environ.get('TOR_CONTROL_UNIX', '0')
    if mode not in ('0', '1'):
        raise ValueError('invalid Tor control mode')
    return mode == '1'


def control_connection():
    if not control_unix():
        return socket.create_connection(('127.0.0.1', 9051), timeout=2)
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        conn.settimeout(2)
        conn.connect('/var/lib/tor/control.sock')
        return conn
    except BaseException:
        conn.close()
        raise


def ready():
    try:
        cookie = Path("/var/lib/tor/control.authcookie").read_bytes()
        if len(cookie) != 32:
            return False
        with control_connection() as conn:
            conn.sendall(b"AUTHENTICATE " + cookie.hex().encode() +
                         b"\r\nGETINFO status/bootstrap-phase network-liveness\r\nQUIT\r\n")
            response = b""
            while len(response) < 8192:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                response += chunk
        return (response.startswith(b"250 OK\r\n") and
                b"250-status/bootstrap-phase=" in response and b"PROGRESS=100 " in response
                and b"250-network-liveness=up\r\n" in response and len(response) < 8192)
    except (OSError, ValueError):
        return False


if __name__ == "__main__":
    sys.exit(0 if ready() else 1)
