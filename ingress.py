"""Bounded LAN listener forwarding only to the networkless gateway's Unix socket."""
import asyncio
from collections import Counter
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import sys
import time
from tls_identity import STATE as TLS_STATE, ensure_identity, ca_digest, certificate_status, refresh_identity

from gateway import (MAX_CONNECTIONS, MAX_CONNECTIONS_PER_SOURCE, MAX_LINE, SHUTDOWN_DRAIN_POLL,
                     SHUTDOWN_DRAIN_SECONDS, WRITE_TIMEOUT, SessionActivity,
                     close, allowed_miners, miner_allowed)

UPSTREAM_PATH = "/run/arkpool/gateway.sock"
NATIVE_UPSTREAM_PATH = "/run/arkpool/native.sock"
HEALTH_PATH = "/tmp/ingress-health.sock"
TLS_HANDSHAKE_TIMEOUT = 5
TLS_CHECK_INTERVAL = 6 * 3600
TLS_RETRY_INTERVAL = 300
TLS_STATUS_PATH = '/tmp/ingress-tls-status.sock'


class TLSRuntime:
    def __init__(self, root, host, context):
        self.root, self.host, self.context = root, host, context
        self.expected_ca = ca_digest(root)
        self.status = dict(certificate_status(root), enabled=True, state='valid', checked_at=time.time())

    def available(self):
        now = time.time()
        return (self.context is not None and self.status['ca_expires_at'] > now
                and self.status['server_expires_at'] > now)

    async def refresh(self):
        try:
            context, status = await asyncio.to_thread(refresh_identity, self.root, self.host, self.expected_ca)
        except Exception:
            # Existing sessions retain their SSL objects. Refuse new handshakes
            # while verification/renewal is failing; never rotate the CA.
            self.context = None
            self.status.update(state='maintenance_required', checked_at=time.time())
            print('TLS maintenance requires attention; new TLS sessions refused; private details suppressed', flush=True)
            return False
        self.context = context
        self.status = dict(status, enabled=True, state='valid', checked_at=time.time())
        if status['ca_maintenance_due']:
            print('TLS CA expiry approaching; operator maintenance required', flush=True)
        return True

    async def monitor(self):
        delay = TLS_CHECK_INTERVAL
        while True:
            await asyncio.sleep(delay)
            delay = TLS_CHECK_INTERVAL if await self.refresh() else TLS_RETRY_INTERVAL


async def tls_status_connection(_reader, writer, runtime):
    try:
        result = dict(runtime.status, accepting_new_tls=runtime.available()) if runtime else {'enabled': False}
        writer.write(json.dumps(result).encode() + b'\n')
        await asyncio.wait_for(writer.drain(), 2)
    finally:
        await close(writer)


async def accept_tls(listener, server_socket, context):
    """Enforce source and connection limits before spending resources on TLS."""
    loop = asyncio.get_running_loop()
    while True:
        conn, peer = await loop.sock_accept(server_socket)
        source = peer[0]
        if not listener.reserve_source(source):
            conn.close()
            continue
        active_context = context.context if isinstance(context, TLSRuntime) and context.available() else context
        if isinstance(context, TLSRuntime) and not context.available():
            listener.release_source(source)
            conn.close()
            continue
        try:
            task = asyncio.create_task(listener.handle_tls(conn, active_context, source))
            listener.active.add(task)
        except BaseException:
            listener.release_source(source)
            conn.close()
            raise


async def copy_stream(reader, writer, activity=None):
    activity = activity if activity is not None else SessionActivity()
    while data := await activity.read(reader.read(MAX_LINE)):
        # Gateway independently validates complete frames and bounds assembly.
        activity.touch()
        writer.write(data)
        await asyncio.wait_for(writer.drain(), WRITE_TIMEOUT)


class Ingress:
    def __init__(self, miners, upstream_path=UPSTREAM_PATH):
        self.miners = miners
        self.upstream_path = upstream_path
        self.active = set()
        self.active_sources = Counter()

    def reserve_source(self, source):
        """Atomically reserve global and per-source capacity before any await."""
        if (not source or not miner_allowed(source, self.miners)
                or len(self.active) >= MAX_CONNECTIONS
                or self.active_sources[source] >= MAX_CONNECTIONS_PER_SOURCE):
            return False
        self.active_sources[source] += 1
        return True

    def release_source(self, source):
        count = self.active_sources.get(source, 0)
        if count <= 1:
            self.active_sources.pop(source, None)
        else:
            self.active_sources[source] = count - 1

    async def handle(self, reader, writer, reserved_source=None):
        task = asyncio.current_task()
        peer = writer.get_extra_info("peername")
        source = peer[0] if peer else None
        owns_reservation = reserved_source is None
        if owns_reservation:
            admitted = self.reserve_source(source)
        else:
            admitted = source == reserved_source and task in self.active
        if not admitted:
            await close(writer)
            return
        if owns_reservation:
            self.active.add(task)
        upstream = None
        pumps = []
        try:
            remote, upstream = await asyncio.wait_for(
                asyncio.open_unix_connection(self.upstream_path, limit=MAX_LINE), 5)
            # Trusted local envelope: actual TCP peer, never client-supplied data.
            upstream.write(ipaddress.IPv4Address(peer[0]).packed)
            await asyncio.wait_for(upstream.drain(), 5)
            activity = SessionActivity()
            pumps = [asyncio.create_task(copy_stream(reader, upstream, activity)),
                     asyncio.create_task(copy_stream(remote, writer, activity))]
            done, _ = await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
            for completed in done:
                completed.result()
        except asyncio.CancelledError:
            raise
        except (OSError, ValueError, asyncio.TimeoutError):
            pass
        finally:
            try:
                for pump in pumps:
                    pump.cancel()
                if pumps:
                    await asyncio.gather(*pumps, return_exceptions=True)
                if upstream:
                    await close(upstream)
                await close(writer)
            finally:
                if owns_reservation:
                    self.release_source(source)
                    self.active.discard(task)

    async def handle_tls(self, conn, context, source):
        writer = None
        try:
            loop = asyncio.get_running_loop()
            reader = asyncio.StreamReader(limit=MAX_LINE)
            protocol = asyncio.StreamReaderProtocol(reader)
            limits = {'ssl_handshake_timeout': TLS_HANDSHAKE_TIMEOUT}
            if sys.version_info >= (3, 11):
                limits['ssl_shutdown_timeout'] = 2
            transport, _ = await loop.connect_accepted_socket(
                lambda: protocol, conn, ssl=context, **limits)
            writer = asyncio.StreamWriter(transport, protocol, reader, loop)
            await self.handle(reader, writer, source)
        except (OSError, ValueError, asyncio.TimeoutError):
            pass
        finally:
            try:
                if writer:
                    await close(writer)
            finally:
                conn.close()
                self.release_source(source)
                self.active.discard(asyncio.current_task())

    async def shutdown(self):
        active = list(self.active)
        for task in active:
            task.cancel()
        await asyncio.gather(*active, return_exceptions=True)

    async def drain(self, timeout=SHUTDOWN_DRAIN_SECONDS):
        """Keep established streams briefly while the gateway settles replies."""
        deadline = asyncio.get_running_loop().time() + timeout
        while self.active and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(SHUTDOWN_DRAIN_POLL)
        return len(self.active)


async def health_connection(_reader, writer, tls_task=None, runtime=None, native_server=None):
    ready = (Path(UPSTREAM_PATH).is_socket() and (tls_task is None or not tls_task.done())
             and (runtime is None or runtime.available())
             and (native_server is None or (native_server.is_serving() and Path(NATIVE_UPSTREAM_PATH).is_socket())))
    writer.write(b"ok\n" if ready else b"unready\n")
    await writer.drain()
    await close(writer)


async def serve(miners):
    from dashboard_status import start_publisher
    native_port = os.environ.get('LAN_V2_PORT')
    if native_port is not None and (not native_port.isdecimal() or not 1 <= int(native_port) <= 65535
                                   or int(native_port) in (3333, 3334)):
        raise ValueError('invalid native V2 listener port')
    tls_enabled = os.environ.get('TLS_ENABLED', '0')
    if tls_enabled not in ('0', '1'):
        raise ValueError('invalid TLS setting')
    context = ensure_identity(TLS_STATE, os.environ['LAN_IP']) if tls_enabled == '1' else None
    runtime = TLSRuntime(TLS_STATE, os.environ['LAN_IP'], context) if context else None
    listener = Ingress(miners)
    loop = asyncio.get_running_loop()
    loop.set_exception_handler(lambda *_: print("LAN listener task failed; details suppressed", flush=True))
    stopped = asyncio.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(signum, stopped.set)
    Path(HEALTH_PATH).unlink(missing_ok=True)
    server = await asyncio.start_server(listener.handle, "0.0.0.0", 3333, limit=MAX_LINE, backlog=16)
    native_server = None
    if native_port is not None:
        native_listener = Ingress(miners, NATIVE_UPSTREAM_PATH)
        # One shared admission budget across plain V1, TLS V1 and native V2.
        native_listener.active = listener.active
        native_listener.active_sources = listener.active_sources
        native_server = await asyncio.start_server(native_listener.handle, '0.0.0.0', int(native_port),
                                                   limit=MAX_LINE, backlog=16)
    tls_socket = tls_accept_task = None
    monitor_task = None
    if context:
        tls_socket = socket.create_server(('0.0.0.0', 3334), backlog=16)
        tls_socket.setblocking(False)
        tls_accept_task = asyncio.create_task(accept_tls(listener, tls_socket, runtime))
        monitor_task = asyncio.create_task(runtime.monitor())
    health = await asyncio.start_unix_server(lambda r, w: health_connection(r, w, tls_accept_task, runtime, native_server), HEALTH_PATH, limit=64)
    Path(TLS_STATUS_PATH).unlink(missing_ok=True)
    status = await asyncio.start_unix_server(lambda r, w: tls_status_connection(r, w, runtime), TLS_STATUS_PATH, limit=64)
    def dashboard_snapshot():
        result = {'listener_ready': server.is_serving() and (native_server is None or native_server.is_serving()),
                  'tls_enabled': runtime is not None}
        if runtime:
            result.update(runtime.status, accepting_new_tls=runtime.available())
        return result
    dashboard_task = start_publisher('ingress', dashboard_snapshot)
    print("LAN listener ready; TLS " + ('enabled' if context else 'disabled') + "; client access policy enforced", flush=True)
    stop_task = asyncio.create_task(stopped.wait())
    try:
        if tls_accept_task:
            done, _ = await asyncio.wait([stop_task, tls_accept_task, monitor_task], return_when=asyncio.FIRST_COMPLETED)
            if monitor_task in done:
                monitor_task.result()
            if tls_accept_task in done:
                tls_accept_task.result()
        else:
            await stop_task
    finally:
        if dashboard_task:
            dashboard_task.cancel()
            await asyncio.gather(dashboard_task, return_exceptions=True)
        stop_task.cancel()
        await asyncio.gather(stop_task, return_exceptions=True)
        server.close()
        if native_server:
            native_server.close()
            await native_server.wait_closed()
        health.close()
        status.close()
        if tls_accept_task:
            tls_accept_task.cancel()
            tls_socket.close()
        await server.wait_closed()
        await health.wait_closed()
        await status.wait_closed()
        if monitor_task:
            monitor_task.cancel()
            await asyncio.gather(monitor_task, return_exceptions=True)
        if tls_accept_task:
            await asyncio.gather(tls_accept_task, return_exceptions=True)
        await listener.drain()
        await listener.shutdown()


def main():
    os.umask(0o077)
    if sys.argv[1:] == ['tls-status']:
        with socket.socket(socket.AF_UNIX) as conn:
            conn.settimeout(3)
            conn.connect(TLS_STATUS_PATH)
            data = b''
            while len(data) < 4096:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            if len(data) >= 4096:
                raise ValueError('oversize TLS status')
            print(json.dumps(json.loads(data)))
        return 0
    if sys.argv[1:] == ["healthcheck"]:
        with socket.socket(socket.AF_UNIX) as conn:
            conn.settimeout(3)
            conn.connect(HEALTH_PATH)
            return 0 if conn.recv(16) == b"ok\n" else 1
    if sys.argv[1:]:
        return 2
    asyncio.run(serve(allowed_miners()))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        print("LAN listener stopped; configuration or transport failure; details suppressed", file=sys.stderr)
        sys.exit(1)
