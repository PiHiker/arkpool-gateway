"""Bounded Stratum V1 bridge: exact LAN clients -> redundant Tor -> one v3 onion."""
import asyncio
from collections import Counter
import base64
from dataclasses import dataclass
import hashlib
import hmac
import ipaddress
import json
import math
import os
from pathlib import Path
import signal
import socket
import struct
import sys
import time
import secrets

from route_quality import (RouteQuality, subscription_probe, PROBE_TIMEOUT,
                           PROBE_INTERVAL, WARMUP_INTERVAL)

HEALTH_PATH = "/tmp/gateway-health.sock"
STATUS_PATH = "/tmp/gateway-status.sock"
INGRESS_PATH = "/run/arkpool/gateway.sock"
MAX_LINE = 16384
MAX_JSON_DEPTH = 32
MAX_CONNECTIONS = 8
MAX_CONNECTIONS_PER_SOURCE = 2
SOCKS_CONNECT_TIMEOUT = 30
ROUTE_COOLDOWN_BASE = 15
ROUTE_COOLDOWN_MAX = 120
JOB_STALE_SECONDS = 300
JOB_WATCH_INTERVAL = 15
RECOVERY_COOLDOWN = 60
RECOVERY_WINDOW = 3600
RECOVERY_LIMIT = 3
IDLE_TIMEOUT = 600
FRAME_TIMEOUT = 600
WRITE_TIMEOUT = 30
AUTHORIZATION_TIMEOUT = 60
SHUTDOWN_DRAIN_SECONDS = 5
SHUTDOWN_DRAIN_POLL = 0.05
PRIVATE_NETWORKS = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32M_CONSTANT = 0x2BC830A3


@dataclass(frozen=True)
class TorRoute:
    socks_path: str
    ready_path: Path


TOR_ROUTES = (
    TorRoute("/run/tor-a/socks", Path("/run/tor-a/ready")),
    TorRoute("/run/tor-b/socks", Path("/run/tor-b/ready")),
)


def private_ipv4(value):
    address = ipaddress.IPv4Address(value)
    if str(address) != value or not any(address in network for network in PRIVATE_NETWORKS):
        raise ValueError("private IPv4 required")
    return value


def allowed_miners(environ=None):
    values = os.environ if environ is None else environ
    lan = private_ipv4(values.get("LAN_IP", ""))
    value = values.get("MINER_IPS", "")
    if value == "lan":
        return frozenset({"lan"})
    if value == "subnet":
        text = values.get("LAN_CIDR", "")
        try:
            network = ipaddress.IPv4Network(text, strict=True)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            raise ValueError("explicit private LAN CIDR required") from None
        if (network.prefixlen > 30 or not any(network.subnet_of(private) for private in PRIVATE_NETWORKS)
                or ipaddress.IPv4Address(lan) not in network):
            raise ValueError("LAN CIDR must contain LAN_IP and stay within RFC1918 space")
        return frozenset({"subnet:" + str(network)})
    miners = frozenset(private_ipv4(item.strip()) for item in value.split(","))
    if not 1 <= len(miners) <= 16 or lan in miners:
        raise ValueError("configure LAN access or exact miner addresses")
    return miners


def miner_allowed(source, miners):
    if miners == frozenset({"lan"}):
        try:
            private_ipv4(source)
            return True
        except (ValueError, TypeError):
            return False
    if len(miners) == 1:
        policy = next(iter(miners))
        if policy.startswith("subnet:"):
            try:
                address = ipaddress.IPv4Address(source)
                return str(address) == source and address in ipaddress.IPv4Network(policy[7:])
            except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, TypeError):
                return False
    return source in miners


def account_pins(value, miners):
    """Parse optional exact-source to Ark-account fingerprints."""
    if not value:
        return ()
    if miners == frozenset({'lan'}) or (len(miners) == 1 and
            next(iter(miners)).startswith('subnet:')):
        raise ValueError('account pins require exact miner addresses')
    pins = {}
    for item in value.split(','):
        source, separator, fingerprint = item.partition('=')
        source = private_ipv4(source)
        if (not separator or source not in miners or source in pins
                or len(fingerprint) != 64
                or any(char not in '0123456789abcdef' for char in fingerprint)):
            raise ValueError('invalid miner account pin')
        pins[source] = fingerprint
    return tuple(sorted(pins.items()))


def onion_hostname(value):
    if len(value) != 62 or not value.endswith(".onion") or value != value.lower():
        raise ValueError("v3 onion hostname required")
    try:
        decoded = base64.b32decode(value[:-6].upper())
    except (ValueError, base64.binascii.Error):
        raise ValueError("invalid onion encoding") from None
    checksum = hashlib.sha3_256(b".onion checksum" + decoded[:32] + b"\x03").digest()[:2]
    if len(decoded) != 35 or decoded[-1] != 3 or not hmac.compare_digest(decoded[32:34], checksum):
        raise ValueError("invalid onion checksum")
    return value


def ark_account_fingerprint(value):
    """Return only a checksum-validated Ark address hash; never retain the address."""
    if (not isinstance(value, str) or not 12 <= len(value) <= 220
            or value != value.lower() or not value.startswith('ark1')):
        return None
    separator = value.rfind('1')
    if separator < 1 or separator + 7 > len(value):
        return None
    try:
        data = [BECH32_ALPHABET.index(char) for char in value[separator + 1:]]
    except ValueError:
        return None
    checksum = 1
    for item in ([ord(char) >> 5 for char in value[:separator]] + [0]
                 + [ord(char) & 31 for char in value[:separator]] + data):
        top = checksum >> 25
        checksum = (checksum & 0x1FFFFFF) << 5 ^ item
        for bit, generator in enumerate((0x3B6A57B2, 0x26508E6D, 0x1EA119FA,
                                         0x3D4233DD, 0x2A1462B3)):
            if (top >> bit) & 1:
                checksum ^= generator
    if value[:separator] != 'ark' or checksum != BECH32M_CONSTANT:
        return None
    return hashlib.sha256(value.encode('ascii')).hexdigest()


@dataclass(frozen=True)
class Config:
    lan_ip: str
    miners: frozenset
    onion: str
    port: int
    route_policy: str = 'round-robin'
    tor_isolation: str = 'miner'
    dashboard_client_ips: bool = False
    account_pins: tuple = ()

    @classmethod
    def load(cls, environ=None):
        values = os.environ if environ is None else environ
        lan = private_ipv4(values.get("LAN_IP", ""))
        miners = allowed_miners(values)
        port = int(values.get("POOL_PORT", "3333"))
        if not 1 <= port <= 65535:
            raise ValueError("invalid pool port")
        policy = values.get('TOR_ROUTE_POLICY', 'round-robin')
        if policy not in ('round-robin', 'latency'):
            raise ValueError('invalid Tor route policy')
        isolation = values.get('TOR_ISOLATION', 'miner')
        if isolation not in ('miner', 'session', 'shared'):
            raise ValueError('invalid Tor isolation policy')
        dashboard_client_ips = values.get('DASHBOARD_CLIENT_IPS', '0')
        if dashboard_client_ips not in ('0', '1'):
            raise ValueError('invalid dashboard client-IP setting')
        pins = account_pins(values.get('MINER_ACCOUNT_PINS', ''), miners)
        return cls(lan, miners, onion_hostname(values.get("POOL_ONION", "")), port,
                   policy, isolation, dashboard_client_ips == '1', pins)


async def close(writer):
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=2)
    except (OSError, asyncio.TimeoutError):
        pass


async def socks_connect(host, port, path, auth=None):
    # Only an AF_UNIX connection is possible here. No destination DNS lookup,
    # TCP dial, alternate host, or clearnet fallback exists in the bridge.
    reader, writer = await asyncio.open_unix_connection(path, limit=MAX_LINE)
    try:
        method = 2 if auth is not None else 0
        writer.write(bytes((5, 1, method)))
        await writer.drain()
        if await reader.readexactly(2) != bytes((5, method)):
            raise ValueError("SOCKS authentication refused")
        if auth is not None:
            username, password = auth
            if not (isinstance(username, bytes) and isinstance(password, bytes)
                    and 1 <= len(username) <= 255 and 1 <= len(password) <= 255):
                raise ValueError("invalid SOCKS isolation credentials")
            writer.write(bytes((1, len(username))) + username
                         + bytes((len(password),)) + password)
            await writer.drain()
            if await reader.readexactly(2) != b"\x01\x00":
                raise ValueError("SOCKS authentication refused")
        destination = host.encode("ascii")
        writer.write(b"\x05\x01\x00\x03" + bytes([len(destination)]) + destination + struct.pack("!H", port))
        await writer.drain()
        version, reply, reserved, address_type = await reader.readexactly(4)
        if (version, reply, reserved) != (5, 0, 0):
            raise ValueError("SOCKS connection refused")
        if address_type == 1:
            length = 4
        elif address_type == 4:
            length = 16
        elif address_type == 3:
            length = (await reader.readexactly(1))[0]
        else:
            raise ValueError("invalid SOCKS response")
        await reader.readexactly(length + 2)
        return reader, writer
    except BaseException:
        await close(writer)
        raise


class SessionActivity:
    """Share idle time across pumps without cancelling a still-pending read."""

    def __init__(self):
        self.touch()

    def touch(self):
        self.last = asyncio.get_running_loop().time()

    async def read(self, operation):
        pending = asyncio.create_task(operation)
        try:
            while True:
                remaining = IDLE_TIMEOUT - (asyncio.get_running_loop().time() - self.last)
                if remaining <= 0:
                    raise asyncio.TimeoutError
                try:
                    return await asyncio.wait_for(asyncio.shield(pending), remaining)
                except asyncio.TimeoutError:
                    if pending.done():
                        return pending.result()
                    # Other-direction traffic may have extended the deadline.
        finally:
            pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)


def unambiguous_object(pairs):
    result, seen = {}, set()
    for key, value in pairs:
        folded = key.casefold()
        if "\x00" in key or folded in seen or (folded == "method" and key != "method"):
            raise ValueError("ambiguous Stratum object")
        seen.add(folded)
        result[key] = value
    return result


def reject_constant(_value):
    raise ValueError("nonstandard JSON constant")


def bounded_json_depth(text):
    # Bound nesting before invoking a recursive JSON parser. Frame size alone
    # permits thousands of containers, including messages sent to small miners.
    # Brackets inside strings (including escaped quotes/backslashes) are data.
    depth = 0
    in_string = escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise ValueError("Stratum JSON nesting limit exceeded")
        elif char in "]}":
            depth -= 1
            if depth < 0:
                raise ValueError("invalid Stratum JSON nesting")
    # json.loads still validates matching container types and complete syntax.


def validate_frame(line):
    if len(line) > MAX_LINE or not line.endswith(b"\n"):
        raise ValueError("unbounded Stratum frame")
    # UTF-8 objects only: no batches, blank keepalives, duplicate/case-aliased
    # keys, or C-string-truncated methods. Never rewrite accepted wire bytes.
    text = line.decode("utf-8")
    bounded_json_depth(text)
    message = json.loads(text, object_pairs_hook=unambiguous_object,
                         parse_constant=reject_constant)
    if not isinstance(message, dict):
        raise ValueError("unsupported Stratum frame")
    if "method" in message:
        method = message["method"]
        if not isinstance(method, str) or "\x00" in method or method == "client.reconnect":
            raise ValueError("unsupported Stratum method or redirect")
    return message


class MiningSession:
    """Bounded, passive response correlation; never retain credentials or frames."""
    def __init__(self, totals, route, clock=time.monotonic, route_totals=None,
                 client_ip=None, expected_account_fingerprint=None):
        self.totals, self.route, self.clock = totals, route, clock
        self.route_totals = route_totals
        self.client_ip = client_ip
        self.expected_account_fingerprint = expected_account_fingerprint
        self.started = clock()
        self.last_job = self.last_accepted = self.authorized = None
        self.pending = {}
        self.pending_accounts = {}
        self.account_fingerprint = None
        self.counts = Counter()
        self.difficulty = None
        self.ack_ms = self.ack_max_ms = None
        self.ack_total_ms = 0
        self.ack_count = 0
        self.recovery_blocked = False
        self.finished = False
        self.authorization_ready = asyncio.Event()

    def job_stale(self):
        reference = self.last_job if self.last_job is not None else self.authorized
        return reference is not None and self.clock() - reference >= JOB_STALE_SECONDS

    def count(self, key):
        self.add(key, 1)

    def add(self, key, value):
        self.counts[key] += value
        self.totals[key] += value
        if self.route_totals is not None:
            self.route_totals[key] += value

    def expire(self):
        now = self.clock()
        for key, (method, sent, _difficulty) in list(self.pending.items()):
            if now - sent >= 300:
                del self.pending[key]
                self.pending_accounts.pop(key, None)
                if method == 'mining.submit':
                    self.count('unanswered')

    def observe(self, message, upstream):
        if self.finished:
            return
        self.expire()
        now = self.clock()
        method = message.get('method')
        if not upstream and self.expected_account_fingerprint is not None and method in (
                'mining.authorize', 'mining.submit'):
            params = message.get('params')
            fingerprint = ark_account_fingerprint(
                params[0] if isinstance(params, list) and params else None)
            if fingerprint != self.expected_account_fingerprint:
                raise ValueError('configured account pin mismatch')
        if upstream and method == 'mining.set_difficulty':
            params = message.get('params')
            difficulty = params[0] if isinstance(params, list) and params else None
            valid_difficulty = ((type(difficulty) is int and 0 < difficulty <= 10**15)
                                or (type(difficulty) is float and math.isfinite(difficulty)
                                    and 0 < difficulty <= 10**15))
            if valid_difficulty:
                self.difficulty = difficulty
        if upstream and method == 'mining.notify':
            self.last_job = now
            self.count('jobs')
        ident = message.get('id')
        if type(ident) not in (int, str) or len(str(ident)) > 128:
            if not upstream and method == 'mining.submit':
                self.count('submitted')
                self.count('untracked')
            return
        # Hash request identifiers too: some clients put identifying text here.
        key = hashlib.sha256(json.dumps(ident).encode()).digest()
        if not upstream and method is not None:
            if method == 'mining.submit':
                self.count('submitted')
            if key in self.pending:
                # Both submissions lose safe correlation, not just the newer
                # one. Retain the marker after replies so a second old reply
                # cannot acknowledge a new request inside the tracking window.
                if self.pending[key][0] == 'mining.submit':
                    self.count('untracked')
                if method == 'mining.submit':
                    self.count('untracked')
                self.pending[key] = ('ambiguous', now, None)
                self.pending_accounts.pop(key, None)
                self.count('ambiguous_ids')
            elif len(self.pending) < 128:
                kind = method if method in ('mining.submit', 'mining.authorize') else None
                self.pending[key] = (kind, now, self.difficulty if kind == 'mining.submit' else None)
                if kind == 'mining.authorize':
                    params = message.get('params')
                    fingerprint = ark_account_fingerprint(
                        params[0] if isinstance(params, list) and params else None)
                    if fingerprint is not None:
                        self.pending_accounts[key] = fingerprint
            elif method == 'mining.submit':
                self.count('untracked')
        elif upstream and method is None and ('result' in message or 'error' in message):
            request = self.pending.get(key)
            if request is None or request[0] == 'ambiguous':
                return
            del self.pending[key]
            kind, sent, difficulty = request
            success = message.get('result') is True and message.get('error') is None
            if kind == 'mining.authorize' and success:
                self.authorized = now
                self.authorization_ready.set()
                self.account_fingerprint = self.pending_accounts.get(key)
            self.pending_accounts.pop(key, None)
            if kind == 'mining.submit':
                if success:
                    self.count('accepted')
                    if difficulty is not None:
                        self.add('accepted_difficulty', difficulty)
                        self.count('accepted_difficulty_known')
                    self.last_accepted = now
                elif message.get('result') is False or message.get('error') is not None:
                    self.count('rejected')
                else:
                    self.count('unknown_responses')
                self.ack_ms = round((now - sent) * 1000, 3)
                self.ack_count += 1
                self.ack_total_ms += self.ack_ms
                self.ack_max_ms = max(self.ack_max_ms or 0, self.ack_ms)

    def finish(self):
        """Settle observation-only counters after pumps stop; never replay work."""
        if self.finished:
            return
        self.finished = True
        for method, _sent, _difficulty in self.pending.values():
            if method == 'mining.submit':
                self.count('unanswered')
        self.pending.clear()
        self.pending_accounts.clear()

    def snapshot(self):
        self.expire()
        now = self.clock()
        accepted = self.counts['accepted']
        known = self.counts['accepted_difficulty_known']
        result = {'route': self.route, 'age_seconds': round(now - self.started, 1),
                'last_job_age_seconds': None if self.last_job is None else round(now - self.last_job, 1),
                'last_accepted_age_seconds': None if self.last_accepted is None else round(now - self.last_accepted, 1),
                'counts': dict(self.counts), 'pending_requests': len(self.pending),
                'pending_submissions': sum(method == 'mining.submit' for method, _sent, _difficulty in self.pending.values()),
                'difficulty': self.difficulty,
                'accepted_work': self.counts['accepted_difficulty'] if known == accepted else None,
                'job_state': ('stale' if self.job_stale() else 'fresh' if self.last_job is not None else 'awaiting_jobs'),
                'recovery_blocked': self.recovery_blocked,
                'ack_last_ms': self.ack_ms, 'ack_max_ms': self.ack_max_ms,
                'ack_mean_ms': round(self.ack_total_ms / self.ack_count, 3) if self.ack_count else None}
        if self.client_ip is not None:
            result['client_ip'] = self.client_ip
        return result


async def forward(reader, writer, activity=None, session=None, upstream=False,
                  on_message=None):
    activity = activity if activity is not None else SessionActivity()
    while True:
        first = await activity.read(reader.read(1))
        if not first:
            return
        # Once a frame starts, opposite-direction activity cannot extend its
        # assembly deadline. A partial-frame drip must not hold a slot forever.
        line = first if first == b"\n" else first + await asyncio.wait_for(
            reader.readline(), timeout=FRAME_TIMEOUT)
        message = validate_frame(line)
        if session is not None:
            session.observe(message, upstream)
        if on_message is not None:
            on_message(message)
        activity.touch()
        # Preserve every original byte, including the miner's Ark username.
        writer.write(line)
        await asyncio.wait_for(writer.drain(), timeout=WRITE_TIMEOUT)


async def require_authorization(event):
    """Close a reserved V1 slot unless pool authorization completes promptly."""
    await asyncio.wait_for(event.wait(), AUTHORIZATION_TIMEOUT)
    await asyncio.Event().wait()


class Bridge:
    def __init__(self, config, routes=TOR_ROUTES):
        if not routes:
            raise ValueError("at least one Tor route required")
        self.config, self.routes = config, tuple(routes)
        self.route_cursor = 0
        self.active = set()
        self.active_sources = Counter()
        self.opened = self.closed = self.refused = self.failed = 0
        self.route_retries = 0
        self.mining_totals = Counter()
        self.route_mining_totals = {'tor-' + str(n + 1): Counter()
                                    for n, _ in enumerate(self.routes)}
        self.sessions = {}
        self.route_failures = {}
        self.route_cooldowns = {}
        self.route_successes = Counter()
        self.route_attempts = Counter()
        self.recovery_times = []
        self.job_recoveries = 0
        self.route_quality = RouteQuality()
        self.probe_task = None
        self.isolation_secret = secrets.token_bytes(32)

    def isolation_auth(self, source=None, purpose='miner'):
        if purpose == 'probe':
            try:
                route_index = self.routes.index(source)
            except ValueError as error:
                raise ValueError('known Tor route required for probe isolation') from error
            token = hmac.new(self.isolation_secret, b'probe:' + str(route_index).encode('ascii'),
                             hashlib.sha256).hexdigest()[:32]
        elif self.config.tor_isolation == 'session':
            token = secrets.token_hex(16)
        elif self.config.tor_isolation == 'miner':
            if source is None:
                raise ValueError('miner source required for Tor isolation')
            token = hmac.new(self.isolation_secret, source.encode('ascii'),
                             hashlib.sha256).hexdigest()[:32]
        else:
            token = hmac.new(self.isolation_secret, b'shared', hashlib.sha256).hexdigest()[:32]
        return b'arkpool', token.encode('ascii')

    def ready_routes(self):
        now = time.monotonic()
        return [r for r in self.routes if tor_recently_ready(r.ready_path)
                and self.route_cooldowns.get(r, 0) <= now]

    def admission_snapshot(self, ready=None):
        ready = self.ready_routes() if ready is None else ready
        heartbeat_ready = sum(tor_recently_ready(r.ready_path) for r in self.routes)
        state = ('ready' if ready else 'cooldown' if heartbeat_ready else 'tor_unready')
        return {'state': state, 'eligible_routes': len(ready),
                'heartbeat_ready_routes': heartbeat_ready, 'total_routes': len(self.routes)}

    def route_preference(self, ready):
        if self.config.route_policy != 'latency':
            return None, 'round_robin'
        return self.route_quality.preference(ready)

    async def probe_route(self, route):
        async def connect():
            return await socks_connect(self.config.onion, self.config.port, route.socks_path,
                                       self.isolation_auth(route, purpose='probe'))
        try:
            elapsed = await asyncio.wait_for(subscription_probe(connect, validate_frame, close),
                                             timeout=PROBE_TIMEOUT)
        except (OSError, ValueError, asyncio.IncompleteReadError, asyncio.TimeoutError, RecursionError):
            elapsed = None
        # Separate from mining/session counters and real-connection cooldowns.
        self.route_quality.record(route, elapsed)

    async def probe_routes(self):
        """One outstanding probe total; no retries, circuit control or TCP fallback."""
        due, attempts = {}, Counter()
        while True:
            for route in self.routes:
                if route not in self.ready_routes() or due.get(route, 0) > time.monotonic():
                    continue
                await self.probe_route(route)
                attempts[route] += 1
                delay = (WARMUP_INTERVAL + secrets.randbelow(6) if attempts[route] < 3
                         else PROBE_INTERVAL - 30 + secrets.randbelow(61))
                due[route] = time.monotonic() + delay
            await asyncio.sleep(5)

    def start_probes(self):
        if self.config.route_policy == 'latency' and self.probe_task is None:
            self.probe_task = asyncio.create_task(self.probe_routes())
        return self.probe_task

    def reserve_recovery(self, now):
        self.recovery_times = [t for t in self.recovery_times if now - t < RECOVERY_WINDOW]
        if len(self.recovery_times) >= RECOVERY_LIMIT:
            return False
        if self.recovery_times and now - self.recovery_times[-1] < RECOVERY_COOLDOWN:
            return False
        self.recovery_times.append(now)
        self.job_recoveries += 1
        return True

    async def watch_jobs(self, session, route):
        while True:
            await asyncio.sleep(JOB_WATCH_INTERVAL)
            session.recovery_blocked = False
            if not session.job_stale():
                continue
            now = time.monotonic()
            alternate = any(r != route and tor_recently_ready(r.ready_path)
                            and self.route_cooldowns.get(r, 0) <= now for r in self.routes)
            if not alternate or not self.reserve_recovery(now):
                session.recovery_blocked = True
                continue
            # Close only this session; never replay shares or restart devices.
            self.route_failed(route)
            print('Job watchdog: stale session closed for miner reconnect; route cooldown applied', flush=True)
            return

    def route_failed(self, route):
        failures = min(self.route_failures.get(route, 0) + 1, 5)
        self.route_failures[route] = failures
        self.route_cooldowns[route] = time.monotonic() + min(
            ROUTE_COOLDOWN_MAX, ROUTE_COOLDOWN_BASE * 2 ** (failures - 1))

    def route_succeeded(self, route):
        self.route_failures.pop(route, None)
        self.route_cooldowns.pop(route, None)
        self.route_successes[route] += 1

    def route_candidates(self):
        ready = self.ready_routes()
        if not ready:
            return []
        start = self.route_cursor % len(ready)
        self.route_cursor = (self.route_cursor + 1) % len(ready)
        ordered = ready[start:] + ready[:start]
        preferred, _ = self.route_preference(ready)
        return ([preferred] + [r for r in ordered if r != preferred]) if preferred else ordered

    async def open_upstream(self, source=None):
        last_error = None
        candidates = self.route_candidates()
        for index, route in enumerate(candidates):
            self.route_attempts[route] += 1
            try:
                reader, writer = await asyncio.wait_for(
                    socks_connect(self.config.onion, self.config.port, route.socks_path,
                                  self.isolation_auth(source)),
                    timeout=SOCKS_CONNECT_TIMEOUT)
                return reader, writer, self.routes.index(route)
            except asyncio.CancelledError:
                raise
            except (OSError, ValueError, asyncio.IncompleteReadError, asyncio.TimeoutError) as error:
                last_error = error
                self.route_failed(route)
                # A failed first attempt is only a retry when another eligible
                # Tor route will actually be attempted. Keep the metric honest
                # when a deployment temporarily has just one usable route.
                if index + 1 < len(candidates):
                    self.route_retries += 1
        if last_error is not None:
            raise last_error
        raise OSError("no ready Tor route")

    async def handle(self, reader, writer):
        # Only the trusted LAN ingress mounts this private socket. Reserve a
        # slot before reading its fixed-size source envelope to bound clients.
        if len(self.active) >= MAX_CONNECTIONS:
            self.refused += 1
            await close(writer)
            return
        task = asyncio.current_task()
        self.active.add(task)
        upstream_writer = None
        pumps = []
        source = None
        source_admitted = False
        try:
            source = str(ipaddress.IPv4Address(await asyncio.wait_for(reader.readexactly(4), 5)))
            if not miner_allowed(source, self.config.miners):
                self.refused += 1
                return
            if self.active_sources[source] >= MAX_CONNECTIONS_PER_SOURCE:
                self.refused += 1
                return
            self.active_sources[source] += 1
            source_admitted = True
            upstream_reader, upstream_writer, route_index = await self.open_upstream(source)
            self.opened += 1
            route_label = 'tor-' + str(route_index + 1)
            session = MiningSession(self.mining_totals, route_label,
                                    route_totals=self.route_mining_totals.setdefault(route_label, Counter()),
                                    client_ip=source if self.config.dashboard_client_ips else None,
                                    expected_account_fingerprint=dict(self.config.account_pins).get(source))
            self.sessions[task] = session
            activity = SessionActivity()
            route = self.routes[route_index]
            route_confirmed = False

            def confirm_route(_message):
                nonlocal route_confirmed
                if not route_confirmed:
                    route_confirmed = True
                    self.route_succeeded(route)

            miner_pump = asyncio.create_task(
                forward(reader, upstream_writer, activity, session))
            pool_pump = asyncio.create_task(
                forward(upstream_reader, writer, activity, session, True,
                        confirm_route))
            pumps = [miner_pump, pool_pump,
                     asyncio.create_task(require_authorization(session.authorization_ready)),
                     asyncio.create_task(self.watch_jobs(session, route))]
            done, _ = await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
            if pool_pump in done:
                self.route_failed(route)
            for completed in done:
                completed.result()
        except asyncio.CancelledError:
            raise
        except (OSError, ValueError, asyncio.IncompleteReadError, asyncio.TimeoutError, RecursionError):
            self.failed += 1
        finally:
            for pump in pumps:
                pump.cancel()
            try:
                if pumps:
                    await asyncio.gather(*pumps, return_exceptions=True)
            finally:
                session = self.sessions.pop(task, None)
                if session is not None:
                    session.finish()
                try:
                    if upstream_writer is not None:
                        await close(upstream_writer)
                finally:
                    try:
                        await close(writer)
                    finally:
                        if source_admitted:
                            self.active_sources[source] -= 1
                            if self.active_sources[source] == 0:
                                del self.active_sources[source]
                        self.active.discard(task)
                        self.closed += 1

    def snapshot(self):
        sessions = [s.snapshot() for s in self.sessions.values()]
        account_fingerprints = sorted({s.account_fingerprint for s in self.sessions.values()
                                       if s.account_fingerprint is not None})
        ready = self.ready_routes()
        preferred, reason = self.route_preference(ready)
        return {'schema_version': 1, 'scope': 'gateway_process', 'persistent': False,
                'admission': self.admission_snapshot(ready),
                'tor_isolation': self.config.tor_isolation,
                'route_selection': {'policy': self.config.route_policy,
                    'preferred_route': 'tor-' + str(self.routes.index(preferred) + 1) if preferred else None,
                    'reason': reason},
                'accepted_share_source': 'correlated_pool_response_not_payment',
                'account_fingerprints': account_fingerprints,
                'connections': {'active': len(self.active), 'opened': self.opened,
                                'closed': self.closed, 'failed': self.failed,
                                'refused': self.refused, 'route_retries': self.route_retries},
                'job_recoveries': self.job_recoveries,
                'mining': dict(self.mining_totals,
                    pending_submissions=sum(s['pending_submissions'] for s in sessions)),
                'sessions': sessions,
                'routes': [{'route': 'tor-' + str(n + 1),
                            'bootstrap_ready': tor_recently_ready(r.ready_path),
                            'cooldown_seconds': round(max(0, self.route_cooldowns.get(r, 0) - time.monotonic()), 1),
                            'consecutive_failures': self.route_failures.get(r, 0),
                            'connection_attempts': self.route_attempts[r],
                            'connection_successes': self.route_successes[r],
                            'active_sessions': sum(s['route'] == 'tor-' + str(n + 1) for s in sessions),
                            'mining': dict(self.route_mining_totals.setdefault('tor-' + str(n + 1), Counter()),
                                pending_submissions=sum(s['pending_submissions'] for s in sessions
                                                        if s['route'] == 'tor-' + str(n + 1))),
                            'probe': self.route_quality.snapshot(r)}
                           for n, r in enumerate(self.routes)]}

    async def shutdown(self):
        if self.probe_task:
            self.probe_task.cancel()
            await asyncio.gather(self.probe_task, return_exceptions=True)
        active = list(self.active)
        for task in active:
            task.cancel()
        await asyncio.gather(*active, return_exceptions=True)

    def pending_submissions(self):
        return sum(method == 'mining.submit' for session in self.sessions.values()
                   for method, _sent, _difficulty in session.pending.values())

    async def drain_pending(self, timeout=SHUTDOWN_DRAIN_SECONDS):
        """Give already-forwarded shares a short reply window; never replay them."""
        initial = self.pending_submissions()
        deadline = asyncio.get_running_loop().time() + timeout
        while self.pending_submissions() and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(SHUTDOWN_DRAIN_POLL)
        return initial, self.pending_submissions()


def tor_recently_ready(ready_path):
    try:
        age = time.time() - float(ready_path.read_text(encoding="ascii"))
        return 0 <= age <= 30
    except (OSError, ValueError):
        return False


async def health_connection(_reader, writer, bridge):
    # A fresh Tor heartbeat is necessary but not sufficient for admitting a
    # miner: routes in backoff have just failed an upstream connection. Surface
    # the temporary outage instead of reporting a misleading healthy state.
    writer.write(b"ok\n" if bridge.admission_snapshot()['state'] == 'ready' else b"unready\n")
    await writer.drain()
    await close(writer)


async def status_connection(_reader, writer, bridge):
    try:
        writer.write(json.dumps(bridge.snapshot()).encode() + b'\n')
        await asyncio.wait_for(writer.drain(), 2)
    finally:
        await close(writer)


async def serve(config):
    from dashboard_status import start_publisher
    bridge = Bridge(config, TOR_ROUTES)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(signum, stop.set)
    # Never let asyncio's exception reporter print peer addresses or frames.
    loop.set_exception_handler(lambda *_: print("Gateway task failed; private details suppressed", flush=True))
    Path(HEALTH_PATH).unlink(missing_ok=True)
    Path(INGRESS_PATH).unlink(missing_ok=True)
    Path(STATUS_PATH).unlink(missing_ok=True)
    server = await asyncio.start_unix_server(bridge.handle, INGRESS_PATH, limit=MAX_LINE, backlog=16)
    health = await asyncio.start_unix_server(
        lambda reader, writer: health_connection(reader, writer, bridge),
        HEALTH_PATH, limit=64)
    status = await asyncio.start_unix_server(lambda r, w: status_connection(r, w, bridge), STATUS_PATH, limit=64)
    dashboard_task = start_publisher('gateway', bridge.snapshot)
    bridge.start_probes()
    print("Networkless gateway started; redundant onion-only forwarding; no wallet custody", flush=True)
    try:
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=60)
            except asyncio.TimeoutError:
                print(f"Gateway totals: active={len(bridge.active)} opened={bridge.opened} closed={bridge.closed} refused={bridge.refused} failed={bridge.failed} route_retries={bridge.route_retries}", flush=True)
    finally:
        if dashboard_task:
            dashboard_task.cancel()
            await asyncio.gather(dashboard_task, return_exceptions=True)
        # Stop new sessions first. Existing streams get a short opportunity to
        # settle already-forwarded share responses before forced cancellation.
        server.close()
        await server.wait_closed()
        initial_pending, remaining_pending = await bridge.drain_pending()
        if initial_pending:
            print(f"Gateway shutdown drain: pending_start={initial_pending} pending_remaining={remaining_pending}", flush=True)
        health.close()
        status.close()
        await health.wait_closed()
        await status.wait_closed()
        await bridge.shutdown()


def healthcheck():
    with socket.socket(socket.AF_UNIX) as conn:
        conn.settimeout(3)
        conn.connect(HEALTH_PATH)
        return conn.recv(16) == b"ok\n"


def selfcheck():
    """Exercise production-only parsing, policy and isolation invariants offline."""
    key = bytes(range(32))
    checksum = hashlib.sha3_256(b".onion checksum" + key + b"\x03").digest()[:2]
    onion = base64.b32encode(key + checksum + b"\x03").decode().lower() + ".onion"
    config = Config.load({"LAN_IP": "192.168.1.10", "MINER_IPS": "subnet",
                          "LAN_CIDR": "192.168.1.0/24", "POOL_ONION": onion,
                          "TOR_ISOLATION": "miner"})
    if not miner_allowed("192.168.1.70", config.miners) or miner_allowed("10.0.0.1", config.miners):
        return False
    if validate_frame(b'{"method":"mining.notify","params":[]}\n')["method"] != "mining.notify":
        return False
    bridge = Bridge(config)
    first = bridge.isolation_auth("192.168.1.70")
    return (first == bridge.isolation_auth("192.168.1.70")
            and first != bridge.isolation_auth("192.168.1.71")
            and b"192.168.1.70" not in first)


def main():
    os.umask(0o077)
    command = sys.argv[1:] or ["serve"]
    if command == ["healthcheck"]:
        return 0 if healthcheck() else 1
    if command == ["selfcheck"]:
        return 0 if selfcheck() else 1
    if command == ["telemetry"]:
        with socket.socket(socket.AF_UNIX) as conn:
            conn.settimeout(3)
            conn.connect(STATUS_PATH)
            data = b''
            while len(data) < 65536:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            if len(data) >= 65536:
                raise ValueError('oversize status')
            print(json.dumps(json.loads(data)))
        return 0
    config = Config.load()
    if command == ["check-config"]:
        print("Gateway configuration valid; private details suppressed")
        return 0
    if command != ["serve"]:
        return 2
    asyncio.run(serve(config))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        print("Gateway stopped; configuration or transport failure; private details suppressed", file=sys.stderr)
        sys.exit(1)
