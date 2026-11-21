"""Opt-in, one-way appliance status snapshots. Never read mining payloads or keys."""
import asyncio
import ipaddress
import json
import math
import os
from pathlib import Path
import secrets
import stat
import time

ROOT = Path('/run/arkpool-dashboard')
MAX_BYTES = 16384
STALE_SECONDS = 30
INTERVAL = 5
PRIVATE = tuple(ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
HEX64 = frozenset('0123456789abcdef')


def number(value, maximum=10**15):
    if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= maximum:
        raise ValueError('invalid status number')
    return value


def boolean(value):
    if type(value) is not bool:
        raise ValueError('invalid status boolean')
    return value


def choice(value, allowed):
    if value not in allowed or not isinstance(value, str):
        raise ValueError('invalid status label')
    return value


def route_probe(value):
    value = {} if value is None else value
    if not isinstance(value, dict):
        raise ValueError('invalid probe summary')
    samples = number(value.get('samples', 0), 5)
    successes = number(value.get('successes', 0), 5)
    last = value.get('last_success')
    median = value.get('median_ms')
    age = value.get('last_sample_age_seconds')
    if (type(samples) is not int or type(successes) is not int or successes > samples
            or (samples == 0 and any(v is not None for v in (last, median, age)))
            or (samples > 0 and (last is None or age is None))
            or (last is True and successes == 0)
            or ((successes > 0) != (median is not None))):
        raise ValueError('invalid probe summary')
    return {'samples': samples, 'successes': successes,
            'last_success': None if last is None else boolean(last),
            'median_ms': None if median is None else number(median, 20000),
            'last_sample_age_seconds': None if age is None else number(age, 900)}


def gateway_view(value, include_client_ips=False):
    """An explicit allowlist, even if upstream telemetry gains private fields."""
    upstream = choice(value.get('upstream_protocol', 'SV1'), ('SV1', 'SV2'))
    basis = choice(value.get('counter_basis', 'session_pool_responses'),
                   ('session_pool_responses', 'aggregate_pool_acknowledgments', 'encrypted_unavailable'))
    aggregate = basis == 'aggregate_pool_acknowledgments'
    encrypted_only = basis == 'encrypted_unavailable'
    if (aggregate or encrypted_only) and upstream != 'SV2':
        raise ValueError('V2 counter basis requires V2')
    sessions, routes = value['sessions'], value['routes']
    if not isinstance(sessions, list) or len(sessions) > 8 or not isinstance(routes, list) or len(routes) != 2:
        raise ValueError('invalid status collection')
    rows = []
    for session in sessions:
        protocol = choice(session.get('miner_protocol', 'SV1'), ('SV1', 'SV2'))
        encrypted = protocol == 'SV2'
        if encrypted and upstream != 'SV2':
            raise ValueError('native V2 requires V2 upstream')
        age = session['last_job_age_seconds']
        accepted_value = session.get('counts', {}).get('accepted', None if encrypted else 0)
        rejected_value = session.get('counts', {}).get('rejected', None if encrypted else 0)
        accepted = None if (aggregate or encrypted) and accepted_value is None else number(accepted_value)
        rejected = None if (aggregate or encrypted) and rejected_value is None else number(rejected_value)
        difficulty = session.get('difficulty')
        work = session.get('accepted_work')
        difficulty = None if difficulty is None else number(difficulty)
        work = None if work is None else number(work)
        if encrypted and (session['job_state'] != 'encrypted' or any(
                item is not None for item in (age, accepted, rejected, difficulty, work))):
            raise ValueError('encrypted relay cannot observe mining payloads')
        if encrypted_only and not encrypted:
            raise ValueError('native-only counters cannot contain V1 sessions')
        if difficulty is not None and difficulty <= 0:
            raise ValueError('invalid share difficulty')
        if (work is not None and (accepted is None or (accepted == 0 and work != 0) or (accepted > 0 and work <= 0))):
            raise ValueError('invalid accepted work')
        row = {'route': choice(session['route'], ('tor-1', 'tor-2')),
                     'job_state': choice(session['job_state'], ('encrypted',) if encrypted else ('fresh', 'stale', 'awaiting_jobs')),
                     'miner_protocol': protocol,
                     'uptime_seconds': None if session.get('uptime_seconds') is None else number(session['uptime_seconds']),
                     'last_job_age_seconds': None if age is None else number(age),
                     'accepted': accepted,
                     'rejected': rejected,
                     'difficulty': difficulty,
                     'accepted_work': work}
        if include_client_ips:
            address = ipaddress.IPv4Address(session['client_ip'])
            if str(address) != session['client_ip'] or not any(address in network for network in PRIVATE):
                raise ValueError('invalid private client address')
            row['client_ip'] = str(address)
        rows.append(row)
    paths = []
    for r in routes:
        label = choice(r['route'], ('tor-1', 'tor-2'))
        route_counts = r.get('mining', {})
        if not isinstance(route_counts, dict):
            raise ValueError('invalid route mining summary')
        active = r.get('active_sessions', sum(s['route'] == label for s in rows))
        if type(active) is not int or not 0 <= active <= 8:
            raise ValueError('invalid route session count')
        pending = None if encrypted_only else route_counts.get('pending_submissions', 0)
        if not encrypted_only and (type(pending) is not int or not 0 <= pending <= 1024):
            raise ValueError('invalid route pending count')
        probe = route_probe(r.get('probe'))
        on_route = [s for s in rows if s['route'] == label]
        work_state = ('tor_unready' if not r['bootstrap_ready'] else
                      'cooldown' if r['cooldown_seconds'] else
                      'stale_jobs' if any(s['job_state'] == 'stale' for s in on_route) else
                      'fresh_jobs' if any(s['job_state'] == 'fresh' for s in on_route) else
                      'subscription_verified' if probe['last_success'] is True else
                      'unverified')
        paths.append({'route': label,
              'work_state': work_state,
              'bootstrap_ready': boolean(r['bootstrap_ready']),
              'cooldown_seconds': number(r['cooldown_seconds']),
              'connection_attempts': number(r['connection_attempts']),
              'connection_successes': number(r['connection_successes']),
              'active_sessions': active,
              'mining': dict({k: None if encrypted_only else number(route_counts.get(k, 0)) for k in
                         ('submitted', 'accepted', 'rejected', 'unanswered', 'untracked',
                          'unknown_responses', 'jobs')}, pending_submissions=pending),
              'probe': probe})
    if {r['route'] for r in paths} != {'tor-1', 'tor-2'}:
        raise ValueError('duplicate route')
    if sum(r['active_sessions'] for r in paths) != len(rows):
        raise ValueError('inconsistent route session counts')
    admission = value.get('admission')
    if admission is None:
        heartbeat_ready = sum(r['bootstrap_ready'] for r in paths)
        eligible = sum(r['bootstrap_ready'] and r['cooldown_seconds'] == 0 for r in paths)
        admission = {'state': 'ready' if eligible else 'cooldown' if heartbeat_ready else 'tor_unready',
                     'eligible_routes': eligible, 'heartbeat_ready_routes': heartbeat_ready,
                     'total_routes': len(paths)}
    if not isinstance(admission, dict):
        raise ValueError('invalid admission summary')
    admission = {'state': choice(admission['state'], ('ready', 'cooldown', 'tor_unready')),
                 'eligible_routes': number(admission['eligible_routes'], 2),
                 'heartbeat_ready_routes': number(admission['heartbeat_ready_routes'], 2),
                 'total_routes': number(admission['total_routes'], 2)}
    if (any(type(admission[k]) is not int for k in ('eligible_routes', 'heartbeat_ready_routes', 'total_routes'))
            or admission['total_routes'] != 2
            or admission['eligible_routes'] > admission['heartbeat_ready_routes']
            or (admission['state'] == 'ready') != (admission['eligible_routes'] > 0)
            or (admission['state'] == 'cooldown') != (
                admission['eligible_routes'] == 0 and admission['heartbeat_ready_routes'] > 0)
            or (admission['state'] == 'tor_unready') != (
                admission['eligible_routes'] == 0 and admission['heartbeat_ready_routes'] == 0)):
        raise ValueError('invalid admission summary')
    counts = value['mining']
    selection = value.get('route_selection', {'policy': 'round-robin', 'preferred_route': None, 'reason': 'round_robin'})
    if not isinstance(selection, dict):
        raise ValueError('invalid route selection')
    preferred = selection['preferred_route']
    selection = {'policy': choice(selection['policy'], ('round-robin', 'latency')),
                 'preferred_route': None if preferred is None else choice(preferred, ('tor-1', 'tor-2')),
                 'reason': choice(selection['reason'], ('round_robin', 'warming_up', 'no_ready',
                          'single_ready', 'insufficient_successes', 'similar', 'more_reliable', 'faster'))}
    pending = counts.get('pending_submissions')
    if pending is not None and (type(pending) is not int or not 0 <= pending <= 1024):
        raise ValueError('invalid pending share count')
    isolation = choice(value.get('tor_isolation', 'unknown'),
                       ('miner', 'session', 'shared', 'unknown'))
    fingerprints = value.get('account_fingerprints', [])
    if (not isinstance(fingerprints, list) or len(fingerprints) > 8
            or any(not isinstance(item, str) or len(item) != 64
                   or any(char not in HEX64 for char in item) for item in fingerprints)
            or fingerprints != sorted(set(fingerprints))):
        raise ValueError('invalid account fingerprints')
    return {'active_sessions': len(rows), 'sessions': rows, 'routes': paths,
            'upstream_protocol': upstream,
            'counter_basis': basis,
            'translation_enabled': boolean(value.get('translation_enabled', aggregate)),
            'translation_ready': boolean(value.get('translation_ready', aggregate)),
            'admission': admission,
            'tor_isolation': isolation,
            'account_fingerprints': fingerprints,
            'route_selection': selection,
            'mining': dict({k: None if encrypted_only else number(counts.get(k, 0)) for k in
                       ('submitted', 'accepted', 'rejected', 'unanswered', 'untracked', 'unknown_responses', 'jobs')},
                           pending_submissions=None if encrypted_only else pending)}


def ingress_view(value):
    result = {'listener_ready': boolean(value['listener_ready']),
              'tls_enabled': boolean(value['tls_enabled'])}
    if result['tls_enabled']:
        result.update(accepting_new_tls=boolean(value['accepting_new_tls']),
                      ca_maintenance_due=boolean(value['ca_maintenance_due']),
                      server_expires_at=number(value['server_expires_at']),
                      ca_expires_at=number(value['ca_expires_at']))
    return result


def clean(role, value, include_client_ips=False):
    if role == 'gateway':
        return gateway_view(value, include_client_ips)
    if role == 'ingress':
        return ingress_view(value)
    raise ValueError('invalid role')


def write_snapshot(root, value):
    """Atomic small regular-file writes; mount must be a dedicated status volume."""
    data = json.dumps(value, allow_nan=False, separators=(',', ':')).encode()
    if len(data) > MAX_BYTES:
        raise ValueError('status too large')
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temp = '.status-' + secrets.token_hex(8)
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
        os.replace(temp, 'status.json', src_dir_fd=directory, dst_dir_fd=directory)
    finally:
        try:
            os.unlink(temp, dir_fd=directory)
        except FileNotFoundError:
            pass
        os.close(directory)


async def publish(role, source, root=ROOT, interval=INTERVAL, include_client_ips=False):
    """At most one outstanding filesystem write; failures never close mining."""
    epoch = secrets.token_hex(16)
    started = time.time()
    while True:
        try:
            data = clean(role, source(), include_client_ips)
            envelope = {'schema_version': 1, 'role': role, 'process': epoch,
                        'started_at': started, 'sampled_at': time.time(), 'data': data}
            # Filesystem latency cannot block the transport event loop.
            await asyncio.to_thread(write_snapshot, root, envelope)
        except (OSError, ValueError, TypeError, KeyError, RecursionError):
            pass  # Consumers mark missing/old data unavailable; no secret error logs.
        await asyncio.sleep(interval)


def start_publisher(role, source):
    # No default Docker topology/state change; appliance adapters opt in.
    if os.environ.get('DASHBOARD_SNAPSHOTS') == '1':
        include_client_ips = role == 'gateway' and os.environ.get('DASHBOARD_CLIENT_IPS', '0') == '1'
        return asyncio.create_task(publish(role, source, include_client_ips=include_client_ips))
    return None


def read_snapshot(root, role, now=None, include_client_ips=False):
    now = time.time() if now is None else now
    try:
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            fd = os.open('status.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        finally:
            os.close(directory)
        with os.fdopen(fd, 'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError('regular status required')
            value = json.loads(stream.read(MAX_BYTES + 1))
            if stream.tell() > MAX_BYTES:
                raise ValueError('status too large')
        if value['schema_version'] != 1 or value['role'] != role:
            raise ValueError('invalid schema')
        age = now - number(value['sampled_at'])
        if age < -2 or age > STALE_SECONDS:
            return {'state': 'stale', 'data': None}
        epoch = value['process']
        if not isinstance(epoch, str) or len(epoch) != 32 or any(c not in '0123456789abcdef' for c in epoch):
            raise ValueError('invalid process marker')
        # Revalidate schema and redact at the browser boundary as well.
        data = value['data']
        if role == 'gateway':
            data = gateway_view({'sessions': [dict(s, counts=s) for s in data['sessions']],
                                 'routes': data['routes'], 'mining': data['mining'],
                                 'upstream_protocol': data.get('upstream_protocol', 'SV1'),
                                 'counter_basis': data.get('counter_basis', 'session_pool_responses'),
                                 'translation_enabled': data.get('translation_enabled', data.get('counter_basis') == 'aggregate_pool_acknowledgments'),
                                 'translation_ready': data.get('translation_ready', data.get('counter_basis') == 'aggregate_pool_acknowledgments'),
                                 **({'account_fingerprints': data['account_fingerprints']}
                                    if 'account_fingerprints' in data else {}),
                                 **({'tor_isolation': data['tor_isolation']} if 'tor_isolation' in data else {}),
                                 **({'admission': data['admission']} if 'admission' in data else {}),
                                 **({'route_selection': data['route_selection']} if 'route_selection' in data else {})},
                                include_client_ips)
        else:
            data = ingress_view(data)
        return {'state': 'current', 'age_seconds': round(max(0, age), 1),
                'process': epoch, 'started_at': number(value['started_at']), 'data': data}
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        return {'state': 'unavailable', 'data': None}


def dashboard(root=ROOT):
    include_client_ips = os.environ.get('DASHBOARD_CLIENT_IPS', '0') == '1'
    return {'schema_version': 1, 'scope': 'process_observations_not_payment',
            'gateway': read_snapshot(Path(root)/'gateway', 'gateway', include_client_ips=include_client_ips),
            'ingress': read_snapshot(Path(root)/'ingress', 'ingress')}
