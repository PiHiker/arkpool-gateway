"""Bounded physical-miner hashrate observations; no reconstructed history."""
import json
import math
import os
from pathlib import Path
import stat
import time
import uuid

INTERVAL = 900
RETENTION = 86400
MAX_POINTS = 96
MAX_BYTES = 65536
MAX_RATE = 10**15


def number(value, maximum):
    if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= maximum:
        raise ValueError('invalid hashrate observation')
    return value


def observation(value):
    expected, observed = value['expected'], value['observed']
    if type(expected) is not int or type(observed) is not int or not 0 <= expected <= 8 or not 0 <= observed <= expected:
        raise ValueError('invalid miner counts')
    known = None if value['known_ghs'] is None else number(value['known_ghs'], MAX_RATE)
    total = None if value['total_ghs'] is None else number(value['total_ghs'], MAX_RATE)
    if (observed == 0) != (known is None):
        raise ValueError('invalid known hashrate')
    if (expected > 0 and observed == expected) != (total is not None) or (total is not None and total != known):
        raise ValueError('invalid total hashrate')
    result = dict(total_ghs=total, known_ghs=known, observed=observed, expected=expected)
    if 'oldest_source_age_seconds' in value:
        result['oldest_source_age_seconds'] = number(value['oldest_source_age_seconds'], 300)
    if 'miners' in value:
        miners = value['miners']
        if not isinstance(miners, dict) or len(miners) > 8 or any(k not in tuple(str(i) for i in range(1, 9)) for k in miners):
            raise ValueError('invalid miner series')
        result['miners'] = {k: None if v is None else number(v, MAX_RATE / 8) for k, v in miners.items()}
        rates = [v for v in result['miners'].values() if v is not None]
        if len(miners) != expected or len(rates) != observed or (rates and not math.isclose(sum(rates), known, rel_tol=1e-12)):
            raise ValueError('inconsistent miner series')
    return result


def aggregate(rows, config):
    # A physical device contributes once. TCP sessions are never rate inputs.
    devices = {}
    for row, item in zip(rows, config):
        identity = item.get('physical_id') or item['url']
        rate = None
        if row.get('available') and row.get('mining_target_verified') is True:
            try: rate = number(row.get('hashrate_ghs'), MAX_RATE / 8)
            except ValueError: pass
        if identity in devices:
            # Conflicting duplicate observations are unknown, not added together.
            if devices[identity] != rate: devices[identity] = None
        else: devices[identity] = rate
    for item in config[len(rows):]: devices.setdefault(item.get('physical_id') or item['url'], None)
    if not devices: return observation(dict(known_ghs=None, total_ghs=None, observed=0, expected=0))
    rates = [v for v in devices.values() if v is not None]
    known = sum(rates) if rates else None
    result = dict(known_ghs=known, total_ghs=known if len(rates) == len(devices) else None,
                  observed=len(rates), expected=len(devices))
    ages = [number(r['source_age_seconds'], 300) for r in rows if r.get('available') and r.get('mining_target_verified') and 'source_age_seconds' in r]
    if ages: result['oldest_source_age_seconds'] = max(ages)
    return observation(result)


def clean_points(points, now):
    number(now, 10**11)
    if not isinstance(points, list) or len(points) > MAX_POINTS:
        raise ValueError('oversize hashrate history')
    by_bucket = {}
    for item in points:
        sampled = number(item['sampled_at'], 10**11)
        point = dict(sampled_at=sampled, **observation(item))
        if now - RETENTION < sampled <= now:
            bucket = int(sampled // INTERVAL)
            if bucket in by_bucket: raise ValueError('duplicate history interval')
            by_bucket[bucket] = point
    return sorted(by_bucket.values(), key=lambda p: p['sampled_at'])[-MAX_POINTS:]


def bounded_read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        meta = os.fstat(stream.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1 or meta.st_size > MAX_BYTES:
            raise ValueError('invalid history file')
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES: raise ValueError('oversize history file')
    return json.loads(raw)


def atomic_write(path, value):
    raw = json.dumps(value, allow_nan=False, separators=(',', ':')).encode()
    if len(raw) > MAX_BYTES: raise ValueError('oversize history file')
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary = '.hashrate-' + uuid.uuid4().hex + '.tmp'
    try:
        try:
            existing = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
            if not stat.S_ISREG(existing.st_mode) or existing.st_nlink != 1:
                raise ValueError('invalid history destination')
        except FileNotFoundError: pass
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        try: os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError: pass
        os.close(directory)


class History:
    def __init__(self, path, now=None, scope=None):
        self.path = Path(path)
        self.scope = scope
        now = time.time() if now is None else now
        try:
            saved = bounded_read(self.path)
            if saved.get('scope') != scope: raise ValueError('changed miner scope')
            if saved.get('schema_version') != 1: raise ValueError('unknown history schema')
            self.points = clean_points(saved['points'], now)
            self.saved_points = saved['points']
        except (OSError, ValueError, KeyError, TypeError):
            self.points = []
            self.saved_points = []

    def sample(self, current, now=None):
        now = time.time() if now is None else now
        current = observation(current)
        previous = self.points
        self.points = clean_points(previous, now)
        bucket = int(now // INTERVAL)
        if not any(int(p['sampled_at'] // INTERVAL) == bucket for p in self.points):
            self.points = (self.points + [dict(sampled_at=now, **current)])[-MAX_POINTS:]
        if self.points != self.saved_points:
            atomic_write(self.path, {'schema_version': 1, 'scope': self.scope, 'points': self.points})
            self.saved_points = self.points[:]
        return self.points


class Presence:
    """Small durable contact ledger; credentials and raw device data never enter it."""
    def __init__(self, path, scope, count, now=None):
        self.path, self.scope = Path(path), scope
        now = time.time() if now is None else number(now, 10**11)
        if type(count) is not int or not 1 <= count <= 8: raise ValueError('invalid roster size')
        keys = {str(i) for i in range(1, count + 1)}
        self.contacts = {k: now for k in keys}  # Initial observation grace, not a claimed contact.
        try:
            saved = bounded_read(self.path)
            if saved.get('scope') != scope or saved.get('schema_version') != 1 or set(saved['contacts']) != keys:
                raise ValueError('changed roster')
            self.contacts = {k: number(v, 10**11) for k, v in saved['contacts'].items()}
            if any(v > now for v in self.contacts.values()): raise ValueError('future contact')
        except (OSError, ValueError, KeyError, TypeError):
            self.contacts = {k: now for k in keys}
        self.saved = None

    def visible(self, rows, config, now=None):
        now = time.time() if now is None else number(now, 10**11)
        result, active_config = [], []
        for index, (row, item) in enumerate(zip(rows, config), 1):
            key = str(index)
            if row.get('available') is True:
                age = number(row.get('source_age_seconds', 0), 300)
                self.contacts[key] = max(0, now - age)
            elif self.contacts[key] > now:
                self.contacts[key] = now  # Clock rollback must not retain a future timestamp.
            if now - self.contacts[key] < RETENTION:
                result.append(dict(row, miner_number=index))
                active_config.append(item)
        if self.contacts != self.saved:
            # Tiny ledger only: the 96-point history is still written once per interval.
            atomic_write(self.path, dict(schema_version=1, scope=self.scope, contacts=self.contacts))
            self.saved = dict(self.contacts)
        return result, active_config


def miner_series(rows):
    return {str(r['miner_number']): (number(r['hashrate_ghs'], MAX_RATE / 8)
            if r.get('available') and r.get('mining_target_verified') is True else None) for r in rows}
