"""Bounded native SV2 relay; miner and pool perform end-to-end Noise authentication."""
import asyncio
import ipaddress
import itertools
import hashlib
import hmac
import secrets
from collections import Counter
import json
import os
import time
from pathlib import Path
from gateway import socks_connect, close, miner_allowed, allowed_miners, onion_hostname, TOR_ROUTES, tor_recently_ready
from ingress import SessionActivity

CONNECT_TIMEOUT = 7
# Encrypted transport liveness, not a share-acknowledgment deadline. Outgoing
# miner traffic must not keep an indefinitely silent upstream connected.
UPSTREAM_SILENCE_TIMEOUT = 600
ROUTE_COOLDOWN_BASE = 15
ROUTE_COOLDOWN_MAX = 120
SESSION_IDS = itertools.count(1)

def event(kind, **fields):
    print(json.dumps({'event': kind, **fields}, sort_keys=True), flush=True)

async def pump(reader, writer, activity, session, direction, on_data=None):
    transferred = 0
    reason = 'cancelled'
    try:
        while True:
            if direction == 'pool_to_miner':
                data = await asyncio.wait_for(reader.read(16384), UPSTREAM_SILENCE_TIMEOUT)
            else:
                data = await activity.read(reader.read(16384))
            if not data:
                reason = 'eof'
                return
            if on_data is not None:
                on_data()
                on_data = None
            activity.touch()
            writer.write(data)
            await asyncio.wait_for(writer.drain(), 30)
            transferred += len(data)
    except (OSError, asyncio.TimeoutError) as exc:
        reason = type(exc).__name__
        raise
    finally:
        event('stream_closed', session=session, direction=direction,
              reason=reason, bytes=transferred)

class Relay:
    def __init__(self, miners, host, port):
        self.miners, self.host, self.port = miners, host, port
        self.active = 0
        self.sources = Counter()
        self.sessions = {}
        self.isolation_secret = secrets.token_bytes(32)
        self.route_failures = {}
        self.route_cooldowns = {}

    def route_failed(self, index):
        failures = min(self.route_failures.get(index, 0) + 1, 5)
        self.route_failures[index] = failures
        self.route_cooldowns[index] = time.monotonic() + min(
            ROUTE_COOLDOWN_MAX, ROUTE_COOLDOWN_BASE * 2 ** (failures - 1))

    def route_succeeded(self, index):
        self.route_failures.pop(index, None)
        self.route_cooldowns.pop(index, None)

    def isolation_auth(self, source):
        token = hmac.new(self.isolation_secret, source.encode("ascii"), hashlib.sha256).hexdigest()[:32]
        return b"arkpool-sv2", token.encode("ascii")

    async def connect(self, source="test"):
        auth = self.isolation_auth(source)
        async def attempt(index, route):
            started = time.monotonic()
            try:
                reader, writer = await asyncio.wait_for(
                    socks_connect(self.host, self.port, route.socks_path, auth), CONNECT_TIMEOUT)
                event('tor_connected', route=index, seconds=round(time.monotonic()-started, 3))
                return reader, writer, index
            except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError) as exc:
                self.route_failed(index)
                event('tor_attempt_failed', route=index, reason=type(exc).__name__)
                return None

        now = time.monotonic()
        tasks = [asyncio.create_task(attempt(index, route))
                 for index, route in enumerate(TOR_ROUTES)
                 if (tor_recently_ready(route.ready_path)
                     and self.route_cooldowns.get(index, 0) <= now)]
        winner = None
        try:
            for future in asyncio.as_completed(tasks):
                result = await future
                if result is not None:
                    winner = result
                    return result
            raise OSError('No usable Tor route within connection budget')
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, tuple) and result is not winner:
                    await close(result[1])

    async def handle(self, reader, writer):
        if self.active >= 8:
            event('session_refused', reason='capacity')
            await close(writer)
            return
        self.active += 1
        session = next(SESSION_IDS)
        started = time.monotonic()
        upstream = None
        admitted_source = None
        pumps = []
        try:
            source = str(ipaddress.IPv4Address(await asyncio.wait_for(reader.readexactly(4), 5)))
            if not miner_allowed(source, self.miners):
                event('session_refused', session=session, reason='source_policy')
                return
            if self.sources[source] >= 2:
                event("session_refused", session=session, reason="source_capacity")
                return
            self.sources[source] += 1
            admitted_source = source
            remote, upstream, route = await self.connect(source)
            self.sessions[session] = {"session": session, "client_ip": source, "route": "A" if route == 0 else "B", "started_at_monotonic": started}
            activity = SessionActivity()
            miner_pump = asyncio.create_task(
                pump(reader, upstream, activity, session, 'miner_to_pool'))
            pool_pump = asyncio.create_task(
                pump(remote, writer, activity, session, 'pool_to_miner',
                     lambda: self.route_succeeded(route)))
            pumps = [miner_pump, pool_pump]
            done, _ = await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
            if pool_pump in done:
                self.route_failed(route)
            for task in done:
                task.result()
        except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError) as exc:
            event('session_error', session=session, reason=type(exc).__name__)
        finally:
            for task in pumps:
                task.cancel()
            if pumps:
                await asyncio.gather(*pumps, return_exceptions=True)
            if upstream:
                await close(upstream)
            await close(writer)
            self.sessions.pop(session, None)
            self.active -= 1
            if admitted_source is not None:
                self.sources[admitted_source] -= 1
                if not self.sources[admitted_source]:
                    del self.sources[admitted_source]
            event('session_closed', session=session, seconds=round(time.monotonic()-started, 3))

async def publish_routes(relay, root):
    from dashboard_status import write_snapshot
    while True:
        rows = [dict(row) for row in relay.sessions.values()]
        if os.environ.get('DASHBOARD_CLIENT_IPS') != '1':
            for row in rows: row.pop('client_ip', None)
        value = {'schema_version': 1, 'sampled_at': time.time(), 'sessions': rows}
        try:
            await asyncio.to_thread(write_snapshot, Path(root), value)
        except (OSError, ValueError):
            event('route_snapshot_unavailable')
        await asyncio.sleep(5)


async def main():
    if os.environ.get('UPSTREAM_PROTOCOL', 'SV2') != 'SV2':
        raise ValueError('Native relay requires SV2-only upstream')
    port = int(os.environ['SV2_POOL_PORT'])
    if not 1 <= port <= 65535:
        raise ValueError('Invalid SV2 pool port')
    relay = Relay(allowed_miners(), onion_hostname(os.environ['SV2_POOL_ONION']), port)
    path = Path('/run/arkpool/gateway.sock')
    if path.exists():
        path.unlink()
    server = await asyncio.start_unix_server(relay.handle, path=str(path))
    path.chmod(0o600)
    publisher = asyncio.create_task(publish_routes(relay, os.environ['NATIVE_STATUS_ROOT'])) if os.environ.get('NATIVE_STATUS_ROOT') else None
    try:
        async with server:
            await server.serve_forever()
    finally:
        if publisher:
            publisher.cancel()
            await asyncio.gather(publisher, return_exceptions=True)

if __name__ == '__main__':
    asyncio.run(main())
