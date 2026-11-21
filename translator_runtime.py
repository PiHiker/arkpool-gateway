"""Isolated SRI runtime: only loopback TCP and existing Tor Unix sockets."""
import asyncio
import ipaddress
import json
import os
import re
import time
from pathlib import Path
import tomllib
from native_relay import Relay, pump
from ingress import SessionActivity
from gateway import (FRAME_TIMEOUT, close, onion_hostname, allowed_miners,
                     miner_allowed, require_authorization, validate_frame)

MAX_LINE = 65536
SHARE_RESPONSE_TIMEOUT = 120


class ShareProgress:
    """Observe forwarded shares, never miner-local acceptance or idle hash gaps."""

    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.pending = 0
        self.waiting_since = None

    def observe(self, message):
        if message == 'SubmitSharesExtended: valid share, forwarding':
            if not self.pending:
                self.waiting_since = self.clock()
            self.pending += 1
            return
        resolved = 0
        match = re.fullmatch(
            r'Received: SubmitSharesSuccess\(channel_id=\d+, last_sequence_number=\d+, '
            r'new_submits_accepted_count=(\d{1,10}), new_shares_sum=\d+\)', message)
        if match:
            resolved = int(match[1])
        elif message == 'Received: SubmitSharesError(':
            resolved = 1
        if resolved and self.pending:
            self.pending = max(0, self.pending - resolved)
            self.waiting_since = self.clock() if self.pending else None

    def stalled(self, timeout=SHARE_RESPONSE_TIMEOUT):
        return self.waiting_since is not None and self.clock() - self.waiting_since >= timeout


async def watch_share_progress(progress, timeout=SHARE_RESPONSE_TIMEOUT, poll_seconds=5):
    while not progress.stalled(timeout):
        await asyncio.sleep(poll_seconds)


def safe_log(line):
    """Keep protocol evidence without SRI's identity/job debug payloads."""
    for pattern in (
        r'Downstream \d+ registered successfully',
        r'Received mining.authorize from Sv1 downstream \d+',
        r'Downstream: \d+ disconnected',
        r'Received: SetupConnectionSuccess\(used_version: 2, flags: 0x[0-9a-fA-F]+\)',
        r'Received: SubmitSharesSuccess\(channel_id=\d+, last_sequence_number=\d+, new_submits_accepted_count=\d+, new_shares_sum=\d+\)',
    ):
        match = re.search(pattern, line)
        if match:
            return match[0]
    for marker in ('Received: NewExtendedMiningJob', 'Received: SetNewPrevHash',
                   'Received: SubmitSharesError(',
                   'SubmitSharesExtended: valid share, forwarding'):
        if marker in line:
            return marker
    if 'ERROR' in line or 'WARN' in line:
        return 'Translator diagnostic: inspect protocol readiness; private details suppressed'
    return None


async def bounded_lines(reader, limit=MAX_LINE):
    """Drain oversized diagnostics without retaining them or stalling the child."""
    pending = bytearray()
    dropping = False
    while chunk := await reader.read(4096):
        for part in chunk.splitlines(keepends=True):
            # splitlines also recognizes CR, but only LF ends our wire record.
            ended = part.endswith(b'\n')
            if not dropping:
                if len(pending) + len(part) > limit:
                    pending.clear()
                    dropping = True
                else:
                    pending.extend(part)
            if ended:
                if not dropping:
                    yield bytes(pending)
                pending.clear()
                dropping = False


async def log_output(reader, progress=None):
    async for line in bounded_lines(reader):
        message = safe_log(line.decode('utf-8', errors='replace'))
        if message:
            if progress is not None:
                progress.observe(message)
            print(message, flush=True)


def validate_request(line, identity):
    if len(line) > MAX_LINE or not line.endswith(b'\n'):
        raise ValueError('oversize or incomplete request')
    value = json.loads(line)
    if not isinstance(value, dict):
        raise ValueError('request object required')
    if value.get('method') in ('mining.authorize', 'mining.submit'):
        params = value.get('params')
        if not isinstance(params, list) or not params or params[0] != identity:
            raise ValueError('configured owner identity required')
    return line


async def read_request(reader, activity):
    """Read one V1 request with a deadline independent of reverse traffic."""
    first = await activity.read(reader.read(1))
    if not first:
        return b''
    if first == b'\n':
        return first
    return first + await asyncio.wait_for(reader.readline(), FRAME_TIMEOUT)


async def bootstrap(identity, keepalive=False):
    # Open the aggregate channel before the pool's setup-to-open deadline.
    # No shares are submitted. Appliance mode retains this client because SRI
    # vardiff emits a zero-hashrate UpdateChannel when its last client leaves.
    retained = False
    for _ in range(100):
        try:
            reader, writer = await asyncio.open_connection('127.0.0.1', 34255)
            break
        except OSError:
            await asyncio.sleep(.2)
    else:
        raise OSError('translator listener unavailable')
    try:
        for value in [
            {'id': 1, 'method': 'mining.configure', 'params': [['version-rolling'], {'version-rolling.mask': '1fffe000', 'version-rolling.min-bit-count': 2}]},
            {'id': 2, 'method': 'mining.subscribe', 'params': ['ArkPool-channel-readiness']},
            {'id': 3, 'method': 'mining.authorize', 'params': [identity, 'x']},
        ]:
            writer.write((json.dumps(value) + '\n').encode())
        await writer.drain()
        authorized = False
        async with asyncio.timeout(25):
            while line := await reader.readline():
                value = json.loads(line)
                if value.get('id') == 3:
                    authorized = value.get('result') is True
                if value.get('method') == 'mining.notify' and authorized:
                    print('Translator authenticated V2 job ready', flush=True)
                    if keepalive:
                        retained = True
                        return reader, writer
                    return
        raise OSError('no authorized translated job')
    finally:
        if not retained:
            await close(writer)


async def drain_bootstrap(reader):
    """Keep the internal readiness client alive without ever submitting shares."""
    while line := await asyncio.wait_for(reader.readline(), 180):
        validate_frame(line)


class MinerBridge:
    def __init__(self, identity):
        self.identity = identity
        self.miners = allowed_miners()
        self.active = 0
        self.sources = {}

    async def handle(self, reader, writer):
        if self.active >= 8:
            await close(writer)
            return
        self.active += 1
        source = None
        upstream = None
        tasks = []
        try:
            candidate = str(ipaddress.IPv4Address(await asyncio.wait_for(reader.readexactly(4), 5)))
            if not miner_allowed(candidate, self.miners) or self.sources.get(candidate, 0) >= 2:
                raise ValueError('source policy')
            source = candidate
            self.sources[source] = self.sources.get(source, 0) + 1
            remote, upstream = await asyncio.open_connection('127.0.0.1', 34255)
            activity = SessionActivity()
            authorization_ready = asyncio.Event()

            async def requests():
                while line := await read_request(reader, activity):
                    activity.touch()
                    upstream.write(validate_request(line, self.identity))
                    if json.loads(line).get('method') == 'mining.authorize':
                        authorization_ready.set()
                    await asyncio.wait_for(upstream.drain(), 30)

            tasks = [asyncio.create_task(requests()),
                     asyncio.create_task(pump(remote, writer, activity, 0, 'translator_to_miner')),
                     asyncio.create_task(require_authorization(authorization_ready))]
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
        except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError) as error:
            print('Translator client closed: ' + type(error).__name__, flush=True)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            if upstream:
                await close(upstream)
            await close(writer)
            self.active -= 1
            if source:
                self.sources[source] -= 1
                if not self.sources[source]:
                    del self.sources[source]


async def main():
    if os.environ.get('UPSTREAM_PROTOCOL', 'SV2') != 'SV2':
        raise ValueError('translator requires V2-only upstream')
    keepalive = os.environ.get('TRANSLATOR_KEEPALIVE', '0')
    if keepalive not in ('0', '1'):
        raise ValueError('invalid translator readiness setting')
    config_path = os.environ.get('TRANSLATOR_CONFIG', '/config/translator.toml')
    config = tomllib.loads(Path(config_path).read_text())
    if len(config['upstreams']) != 1 or config['upstreams'][0]['address'] != '127.0.0.1' or config['upstreams'][0]['port'] != 34256:
        raise ValueError('one Tor-only loopback upstream required')
    identity = config['upstreams'][0]['user_identity']
    bridge = MinerBridge(identity)
    relay = Relay([], onion_hostname(os.environ['SV2_POOL_ONION']), int(os.environ['SV2_POOL_PORT']))
    active = 0
    connection_lost = asyncio.Event()

    async def upstream(reader, writer):
        nonlocal active
        if active >= 1:
            await close(writer)
            return
        active += 1
        peer = None
        route = None
        tasks = []
        try:
            remote, peer, route = await relay.connect('translator-owner')
            print('Translator Tor path ' + ('A' if route == 0 else 'B'), flush=True)
            activity = SessionActivity()
            translator_pump = asyncio.create_task(
                pump(reader, peer, activity, 1, 'translator_to_pool'))
            pool_pump = asyncio.create_task(
                pump(remote, writer, activity, 1, 'pool_to_translator',
                     lambda: relay.route_succeeded(route)))
            tasks = [translator_pump, pool_pump]
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            if pool_pump in done:
                relay.route_failed(route)
            for task in done:
                task.result()
        except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError) as error:
            print('Translator Tor path unavailable: ' + type(error).__name__, flush=True)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            if peer:
                await close(peer)
            await close(writer)
            active -= 1
            # A new authenticated aggregate channel requires a fresh bootstrap.
            # Do not keep a previously-ready V1 listener serving stale work.
            connection_lost.set()

    server = await asyncio.start_server(upstream, '127.0.0.1', 34256)
    process = await asyncio.create_subprocess_exec('/app/translator_sv2', '-c', config_path,
                                                   stdout=asyncio.subprocess.PIPE,
                                                   stderr=asyncio.subprocess.STDOUT, limit=MAX_LINE)
    progress = ShareProgress()
    logger = asyncio.create_task(log_output(process.stdout, progress))
    frontend = None
    process_waiter = loss_waiter = readiness_task = share_watchdog = None
    readiness_connection = None
    try:
        readiness_connection = await bootstrap(identity, keepalive == '1')
        if readiness_connection:
            readiness_task = asyncio.create_task(drain_bootstrap(readiness_connection[0]))
        path = Path(os.environ.get('TRANSLATOR_SOCKET', '/run/arkpool/gateway.sock'))
        if path.exists():
            path.unlink()
        frontend = await asyncio.start_unix_server(bridge.handle, path=str(path), limit=MAX_LINE)
        path.chmod(0o600)
        process_waiter = asyncio.create_task(process.wait())
        loss_waiter = asyncio.create_task(connection_lost.wait())
        share_watchdog = asyncio.create_task(watch_share_progress(progress))
        watched = [process_waiter, loss_waiter, logger, share_watchdog]
        if readiness_task:
            watched.append(readiness_task)
        await asyncio.wait(watched,
                           return_when=asyncio.FIRST_COMPLETED)
        if connection_lost.is_set():
            print('Translator upstream unavailable; V2 restart required', flush=True)
        elif readiness_task and readiness_task.done():
            print('Translator readiness lost; V2 restart required', flush=True)
        elif share_watchdog.done():
            print('Translator upstream share responses stalled; V2 restart required', flush=True)
    finally:
        if frontend:
            frontend.close()
        server.close()
        if process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), 5)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
        try:
            await asyncio.wait_for(asyncio.gather(server.wait_closed(),
                                   *([frontend.wait_closed()] if frontend else [])), 5)
        except asyncio.TimeoutError:
            pass  # asyncio.run cancels remaining handlers on process exit.
        logger.cancel()
        if readiness_connection:
            await close(readiness_connection[1])
        for task in (process_waiter, loss_waiter, readiness_task, share_watchdog):
            if task:
                task.cancel()
        await asyncio.gather(logger, *(t for t in (process_waiter, loss_waiter, readiness_task, share_watchdog) if t),
                             return_exceptions=True)
    raise SystemExit(process.returncode)


if __name__ == '__main__':
    asyncio.run(main())
