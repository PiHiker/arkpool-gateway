"""Appliance V1/native-V2 ingress with V2-only upstream in one networkless role."""
import asyncio
from collections import Counter
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import tempfile
import time

from dashboard_status import start_publisher
from gateway import (MAX_LINE, MiningSession, TOR_ROUTES, allowed_miners,
                     ark_account_fingerprint, close, forward, miner_allowed,
                     require_authorization, tor_recently_ready)
from ingress import SessionActivity
from native_relay import Relay
from translator_runtime import bounded_lines
import v2_config

MAX_SESSIONS = 8
MAX_PER_SOURCE = 2
RETRY_MAX = 30
BOOTSTRAP_TIMEOUT = 60
STOP_TIMEOUT = 5


def translator_toml(config):
    """Only validated opaque values are interpolated; all destinations are fixed."""
    config = v2_config.validate(config)
    if not config['ark_identity']:
        raise ValueError('translation requires an exact owner')
    return '\n'.join([
        'downstream_address = "127.0.0.1"', 'downstream_port = 34255',
        'min_supported_version = 2', 'max_supported_version = 2',
        'downstream_extranonce2_size = 2', 'verify_payout = false',
        'aggregate_channels = true', 'supported_extensions = []',
        'required_extensions = []', '[downstream_difficulty_config]',
        'min_individual_miner_hashrate = 100000000000.0',
        'shares_per_minute = 6.0', 'enable_vardiff = true',
        'job_keepalive_interval_secs = 60', '[[upstreams]]',
        'address = "127.0.0.1"', 'port = 34256',
        'authority_pubkey = ' + json.dumps(config['authority_pubkey']),
        'user_identity = ' + json.dumps(config['ark_identity']), '',
    ])


def write_private_config(directory, config):
    directory.mkdir(mode=0o700, parents=False, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise ValueError('private configuration directory required')
    directory.chmod(0o700)
    fd, temporary = tempfile.mkstemp(prefix='.translator-', dir=directory)
    try:
        with os.fdopen(fd, 'w', encoding='ascii') as stream:
            stream.write(translator_toml(config))
            stream.flush()
            os.fsync(stream.fileno())
        destination = directory / 'translator.toml'
        os.replace(temporary, destination)
        return destination
    finally:
        Path(temporary).unlink(missing_ok=True)


class PrefixReader:
    """Replay only the four trusted ingress bytes consumed by shared admission."""
    def __init__(self, reader, header):
        self.reader, self.header = reader, header

    async def readexactly(self, count):
        if self.header is not None:
            if count != 4:
                raise ValueError('invalid prefix read')
            header, self.header = self.header, None
            return header
        return await self.reader.readexactly(count)

    def __getattr__(self, name):
        return getattr(self.reader, name)


class DualGateway:
    def __init__(self, config, socket_dir=Path('/run/arkpool'), temporary=Path('/tmp'),
                 app=Path('/app')):
        self.config = v2_config.validate(config)
        self.socket_dir, self.temporary, self.app = socket_dir, temporary, app
        self.child_socket = temporary / 'translator-gateway.sock'
        self.health_socket = temporary / 'gateway-health.sock'
        self.miners = allowed_miners()
        self.native = Relay(self.miners, config['pool_onion'], config['pool_port'])
        self.active = 0
        self.sources = Counter()
        self.sessions = {}
        self.clients = set()
        self.v1_clients = set()
        self.child = None
        self.child_ready = False
        self.restart_requested = False
        self.route = None
        self.pending = 0
        self.counts = Counter()
        self.route_counts = [Counter(), Counter()]
        self.connections = Counter()

    @property
    def translation_enabled(self):
        return bool(self.config['ark_identity'])

    def translator_available(self):
        if not self.child_ready or self.child is None or self.child.returncode is not None:
            return False
        try:
            return stat.S_ISSOCK(self.child_socket.lstat().st_mode)
        except OSError:
            return False

    def ready(self):
        tor_ready = any(tor_recently_ready(route.ready_path) for route in TOR_ROUTES)
        return tor_ready and (not self.translation_enabled or self.translator_available())

    async def health(self, _reader, writer):
        try:
            writer.write(b'ok\n' if self.ready() else b'unready\n')
            await asyncio.wait_for(writer.drain(), 2)
        finally:
            await close(writer)

    async def handle(self, reader, writer, native=False):
        task = asyncio.current_task()
        source = None
        if self.active >= MAX_SESSIONS or (not native and not self.translator_available()):
            await close(writer)
            return
        self.active += 1
        self.clients.add(task)
        try:
            header = await asyncio.wait_for(reader.readexactly(4), 5)
            candidate = str(ipaddress.IPv4Address(header))
            if not miner_allowed(candidate, self.miners) or self.sources[candidate] >= MAX_PER_SOURCE:
                raise ValueError('source policy')
            source = candidate
            self.sources[source] += 1
            if native:
                await self.native.handle(PrefixReader(reader, header), writer)
            else:
                self.v1_clients.add(task)
                await self.translate(reader, writer, header, source)
        except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError):
            pass  # Never log peer headers, usernames or protocol payloads.
        finally:
            self.v1_clients.discard(task)
            self.clients.discard(task)
            self.active -= 1
            if source is not None:
                self.sources[source] -= 1
                if not self.sources[source]:
                    del self.sources[source]
            await close(writer)

    async def translate(self, reader, writer, header, source):
        upstream = None
        tasks = []
        session = None
        try:
            if not self.translator_available():
                return
            remote, upstream = await asyncio.wait_for(
                asyncio.open_unix_connection(self.child_socket, limit=MAX_LINE), 3)
            upstream.write(header)
            await asyncio.wait_for(upstream.drain(), 3)
            session = MiningSession(Counter(), self.route, client_ip=source)
            self.sessions[id(session)] = session
            activity = SessionActivity()
            tasks = [asyncio.create_task(forward(reader, upstream, activity, session)),
                     asyncio.create_task(forward(remote, writer, activity, session, True)),
                     asyncio.create_task(require_authorization(session.authorization_ready))]
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            if session:
                session.finish()
                self.sessions.pop(id(session), None)
            if upstream:
                await close(upstream)

    def observe(self, line):
        if line in ('Translator Tor path A', 'Translator Tor path B'):
            self.route = 'tor-1' if line.endswith('A') else 'tor-2'
            self.connections[self.route] += 1
        elif line == 'Translator authenticated V2 job ready' and self.route:
            self.child_ready = True
        elif line in ('Translator upstream unavailable; V2 restart required',
                      'Translator readiness lost; V2 restart required'):
            self.child_ready = False
            self.restart_requested = True
            for task in list(self.v1_clients):
                task.cancel()
        key, amount = None, 1
        if line in ('Received: NewExtendedMiningJob', 'Received: SetNewPrevHash'):
            key = 'jobs'
        elif line == 'SubmitSharesExtended: valid share, forwarding':
            key = 'submitted'
        elif line == 'Received: SubmitSharesError(':
            key = 'rejected'
        else:
            match = re.fullmatch(r'Received: SubmitSharesSuccess\(channel_id=\d{1,20}, last_sequence_number=\d{1,20}, new_submits_accepted_count=(\d{1,15}), new_shares_sum=\d{1,20}\)', line)
            if match:
                key, amount = 'accepted', int(match[1])
        if key and self.route:
            index = 0 if self.route == 'tor-1' else 1
            self.counts[key] = min(10**15, self.counts[key] + amount)
            self.route_counts[index][key] = min(10**15, self.route_counts[index][key] + amount)
            if key == 'submitted':
                if self.pending < 1024:
                    self.pending += 1
                else:
                    self.counts['untracked'] += 1
                    self.route_counts[index]['untracked'] += 1
            elif key in ('accepted', 'rejected'):
                self.pending = max(0, self.pending - amount)

    def settle_pending(self):
        if self.pending and self.route:
            index = 0 if self.route == 'tor-1' else 1
            self.counts['unanswered'] += self.pending
            self.route_counts[index]['unanswered'] += self.pending
        self.pending = 0

    async def read_child(self, reader):
        async for line in bounded_lines(reader):
            self.observe(line.decode('utf-8', errors='replace').strip())

    async def stop_child(self, process):
        # The process session includes SRI grandchildren, even if its Python
        # parent exited unexpectedly. Never signal the gateway's process group.
        if process.pid == os.getpgrp():
            raise ValueError('child process group required')
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            await asyncio.wait_for(process.wait(), STOP_TIMEOUT)
        except asyncio.TimeoutError:
            pass
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            await process.wait()

    async def supervise(self):
        config_path = write_private_config(self.temporary / 'arkpool-translator', self.config)
        delay = 1
        try:
            while True:
                self.child_socket.unlink(missing_ok=True)
                self.child_ready = False
                self.restart_requested = False
                self.route = None
                started = time.monotonic()
                logger = waiter = None
                process = None
                try:
                    env = dict(os.environ, TRANSLATOR_CONFIG=str(config_path),
                               TRANSLATOR_SOCKET=str(self.child_socket), TRANSLATOR_KEEPALIVE='1',
                               UPSTREAM_PROTOCOL='SV2',
                               SV2_POOL_ONION=self.config['pool_onion'],
                               SV2_POOL_PORT=str(self.config['pool_port']), RUST_LOG='debug')
                    process = await asyncio.create_subprocess_exec(
                        sys.executable, str(self.app / 'translator_runtime.py'),
                        env=env, stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.STDOUT, start_new_session=True)
                    self.child = process
                    logger = asyncio.create_task(self.read_child(process.stdout))
                    waiter = asyncio.create_task(process.wait())
                    while not waiter.done() and not logger.done():
                        if self.restart_requested:
                            raise TimeoutError('translator upstream disconnected')
                        if not self.translator_available() and time.monotonic() - started > BOOTSTRAP_TIMEOUT:
                            raise TimeoutError('translator bootstrap deadline')
                        await asyncio.wait((waiter, logger), timeout=.25, return_when=asyncio.FIRST_COMPLETED)
                except (OSError, ValueError, TimeoutError):
                    print('V1 translator unavailable; retrying V2 only', flush=True)
                finally:
                    self.child_ready = False
                    self.settle_pending()
                    self.child = None
                    self.child_socket.unlink(missing_ok=True)
                    for task in list(self.v1_clients):
                        task.cancel()
                    await asyncio.gather(*list(self.v1_clients), return_exceptions=True)
                    if process:
                        await self.stop_child(process)
                    for task in (logger, waiter):
                        if task:
                            task.cancel()
                    await asyncio.gather(*(t for t in (logger, waiter) if t), return_exceptions=True)
                delay = 1 if time.monotonic() - started >= 60 else min(RETRY_MAX, delay * 2)
                await asyncio.sleep(delay)
        finally:
            config_path.unlink(missing_ok=True)

    def snapshot(self):
        rows = []
        for session in self.sessions.values():
            row = session.snapshot()
            row.update(miner_protocol='SV1', counts={'accepted': None, 'rejected': None},
                       accepted_work=None, uptime_seconds=row['age_seconds'])
            rows.append(row)
        now = time.monotonic()
        for native in list(self.native.sessions.values()):
            rows.append(dict(route='tor-1' if native['route'] == 'A' else 'tor-2',
                             client_ip=native['client_ip'], miner_protocol='SV2',
                             job_state='encrypted', last_job_age_seconds=None,
                             counts={'accepted': None, 'rejected': None},
                             uptime_seconds=max(0, now-native['started_at_monotonic'])))
        routes = []
        for index, route in enumerate(TOR_ROUTES):
            label = 'tor-' + str(index+1)
            routes.append(dict(route=label, bootstrap_ready=tor_recently_ready(route.ready_path),
                               cooldown_seconds=0, connection_attempts=self.connections[label],
                               connection_successes=self.connections[label],
                               active_sessions=sum(row['route'] == label for row in rows),
                               mining=dict(self.route_counts[index], pending_submissions=self.pending if label == self.route else 0)))
        fingerprint = ark_account_fingerprint(self.config['ark_identity'])
        return dict(sessions=rows, routes=routes, mining=dict(self.counts, pending_submissions=self.pending),
                    upstream_protocol='SV2', translation_enabled=self.translation_enabled,
                    translation_ready=self.translator_available(),
                    counter_basis='aggregate_pool_acknowledgments' if self.translation_enabled else 'encrypted_unavailable',
                    tor_isolation='shared' if self.translation_enabled else 'miner',
                    account_fingerprints=[fingerprint] if fingerprint and self.child_ready else [])

    async def serve(self, stop):
        servers, tasks = [], []
        paths = [self.socket_dir/'native.sock', self.socket_dir/'gateway.sock', self.health_socket]
        try:
            for path in paths:
                path.unlink(missing_ok=True)
            servers.append(await asyncio.start_unix_server(
                lambda r, w: self.handle(r, w, True), path=paths[0], limit=MAX_LINE, backlog=16))
            servers.append(await asyncio.start_unix_server(self.handle, path=paths[1], limit=MAX_LINE, backlog=16))
            servers.append(await asyncio.start_unix_server(self.health, path=paths[2], limit=64, backlog=16))
            for path in paths:
                path.chmod(0o600)
            if self.translation_enabled:
                tasks.append(asyncio.create_task(self.supervise()))
            publisher = start_publisher('gateway', self.snapshot)
            if publisher:
                tasks.append(publisher)
            stopped = asyncio.create_task(stop.wait())
            try:
                monitored = [stopped] + [task for task in tasks if task is not publisher]
                done, _ = await asyncio.wait(monitored, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    task.result()
            finally:
                stopped.cancel()
                await asyncio.gather(stopped, return_exceptions=True)
        finally:
            for server in servers:
                server.close()
            for task in tasks + list(self.clients):
                task.cancel()
            await asyncio.gather(*tasks, *list(self.clients), return_exceptions=True)
            await asyncio.gather(*(server.wait_closed() for server in servers))
            for path in paths:
                path.unlink(missing_ok=True)


async def main():
    if os.environ.get('UPSTREAM_PROTOCOL', 'SV2') != 'SV2':
        raise ValueError('V2 upstream required')
    config = v2_config.read(os.environ['GATEWAY_V2_CONFIG'])
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    loop.set_exception_handler(lambda *_: print('Gateway task failed; private details suppressed', flush=True))
    await DualGateway(config).serve(stop)


def cli(arguments=None):
    arguments = sys.argv[1:] if arguments is None else arguments
    os.umask(0o077)
    if arguments == ['healthcheck']:
        from gateway import healthcheck
        return 0 if healthcheck() else 1
    if arguments not in ([], ['serve']):
        return 2
    asyncio.run(main())
    return 0


if __name__ == '__main__':
    try:
        sys.exit(cli())
    except Exception:
        print('V2 gateway stopped; configuration or runtime failure; private details suppressed', file=sys.stderr)
        sys.exit(1)
