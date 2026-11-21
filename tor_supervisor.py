"""Restart a persistently stalled Tor process without Docker socket access."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
from tor_health import control_unix, ready

HEARTBEAT = Path("/run/tor-socks/ready")
CHECK_INTERVAL = 5
CHILD_STOP_TIMEOUT = 7


def main():
    os.umask(0o077)
    HEARTBEAT.unlink(missing_ok=True)
    command = ['tor', '-f', '/app/torrc']
    if control_unix():
        # Disable TCP control entirely. The private state volume is not shared
        # with the gateway, ingress, other Tor client, or setup page.
        command.extend(['--ControlPort', '0', '--ControlSocket', '/var/lib/tor/control.sock'])
    process = subprocess.Popen(command,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    stopped = threading.Event()

    def stop(*_):
        # Wake the supervisor loop immediately. Child termination stays in the
        # single bounded cleanup path so repeated signals cannot race it.
        stopped.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    last_good = time.monotonic()
    bootstrapped = False
    try:
        while process.poll() is None and not stopped.is_set():
            healthy = ready()
            if stopped.is_set():
                break
            if healthy:
                temporary = HEARTBEAT.with_suffix(".tmp")
                temporary.write_text(str(time.time()), encoding="ascii")
                temporary.replace(HEARTBEAT)
                last_good = time.monotonic()
                if not bootstrapped:
                    print("Tor bootstrap complete; onion-only transport ready", flush=True)
                bootstrapped = True
            else:
                HEARTBEAT.unlink(missing_ok=True)
                limit = 180 if bootstrapped else 600
                if time.monotonic() - last_good > limit:
                    print("Tor readiness stalled; restarting container", flush=True)
                    break
            stopped.wait(CHECK_INTERVAL)
    finally:
        HEARTBEAT.unlink(missing_ok=True)
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=CHILD_STOP_TIMEOUT)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    return 0 if stopped.is_set() else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        print("Tor supervisor failed; private details suppressed", file=sys.stderr)
        sys.exit(1)
