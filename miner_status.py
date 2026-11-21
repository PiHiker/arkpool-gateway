"""Opt-in miner observations. No mining control, wallet data or payload inspection."""
import base64
import ipaddress
import json
import math
import multiprocessing
from multiprocessing.connection import wait
import os
from pathlib import Path
import re
import time
import urllib.request
from urllib.parse import urlsplit

MAX_BYTES = 65536
FETCH_TOTAL_TIMEOUT = 6
MAX_FETCH_WORKERS = 4
from hashrate_history import History, aggregate, atomic_write, bounded_read, clean_points, observation, Presence, miner_series


def private_miner_ip(value):
    ip = ipaddress.IPv4Address(value)
    if str(ip) != value or not any(ip in ipaddress.IPv4Network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')):
        raise ValueError('private miner address required')
    return value


def numeric(value):
    if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 10**15:
        raise ValueError('invalid observation')
    return value


def clean(value):
    if not isinstance(value, dict) or value.get('schema_version') != 1:
        raise ValueError('invalid snapshot')
    sampled = numeric(value['sampled_at'])
    miners = value['miners']
    if not isinstance(miners, list) or not 0 <= len(miners) <= 8:
        raise ValueError('invalid miners')
    rows = []
    for m in miners:
        if not isinstance(m, dict) or not re.fullmatch(r'[A-Za-z0-9 _-]{1,32}', m['label']):
            raise ValueError('invalid label')
        row = {'label': m['label'], 'available': m['available']}
        if 'miner_number' in m:
            if type(m['miner_number']) is not int or not 1 <= m['miner_number'] <= 8: raise ValueError('invalid miner number')
            row['miner_number'] = m['miner_number']
        if 'miner_ip' in m: row['miner_ip'] = private_miner_ip(m['miner_ip'])
        target = m.get('mining_target_verified', False)
        if type(target) is not bool: raise ValueError('invalid target evidence')
        row['mining_target_verified'] = target
        if type(row['available']) is not bool:
            raise ValueError('invalid availability')
        if row['available']:
            for key, allowed in [('protocol', ('SV1', 'SV2', 'unknown')), ('primary_protocol', ('SV1', 'SV2', 'unknown')), ('upstream_protocol', ('SV2', 'unknown'))]:
                if m[key] not in allowed: raise ValueError('invalid protocol')
                row[key] = m[key]
            for key in ['connected', 'authenticated', 'fallback', 'fallback_enabled', 'trial_endpoint']:
                if type(m[key]) is not bool: raise ValueError('invalid flag')
                row[key] = m[key]
            for key in ['hashrate_ghs', 'accepted', 'rejected', 'uptime_seconds']:
                row[key] = numeric(m[key])
            route = m.get('tor_route', 'unknown')
            if route not in ('A','B','unknown'): raise ValueError('invalid route')
            row['tor_route'] = route
            if 'source_age_seconds' in m:
                row['source_age_seconds'] = numeric(m['source_age_seconds'])
                if row['source_age_seconds'] > 300: raise ValueError('external observation too old')
            age = m['job_age_seconds']
            row['job_age_seconds'] = None if age is None else numeric(age)
            if (not row['connected'] and (row['protocol'] != 'unknown' or row['authenticated'])) or (row['authenticated'] and row['protocol'] != 'SV2'):
                raise ValueError('inconsistent protocol evidence')
        if row['available'] and row['upstream_protocol'] == 'SV2' and not (row['authenticated'] and row['protocol'] == 'SV2' and row['trial_endpoint']):
            raise ValueError('upstream V2 evidence missing')
        rows.append(row)
    if len({r['label'] for r in rows}) != len(rows): raise ValueError('duplicate miner')
    numbered = [r['miner_number'] for r in rows if 'miner_number' in r]
    if len(numbered) != len(set(numbered)): raise ValueError('duplicate miner number')
    counts=value.get('native_route_counts')
    if counts is not None and (not isinstance(counts,dict) or set(counts)!={'A','B'} or any(type(v) is not int or not 0<=v<=8 for v in counts.values()) or sum(counts.values())>8):
        raise ValueError('invalid native route counts')
    result = {'schema_version': 1, 'sampled_at': sampled, 'miners': rows, 'native_route_counts': counts}
    if 'hashrate' in value:
        result['hashrate'] = observation(value['hashrate'])
        result['hashrate_history'] = clean_points(value.get('hashrate_history', []), sampled)
        if type(value.get('history_available')) is not bool: raise ValueError('invalid history state')
        result['history_available'] = value['history_available']
    return result


def read_snapshot(root, now=None, include_miner_ips=False):
    try:
        p = Path(root)/'miners'/'status.json'
        data = clean(bounded_read(p))
        if not include_miner_ips:
            for row in data['miners']: row.pop('miner_ip', None)
        age = (time.time() if now is None else now) - data['sampled_at']
        if not 0 <= age <= 30: return {'state': 'stale', 'data': None}
        if 'hashrate_history' in data:
            data['hashrate_history'] = clean_points(data['hashrate_history'], time.time() if now is None else now)
        return {'state': 'current', 'age_seconds': age, 'data': data}
    except (OSError, ValueError, TypeError, KeyError):
        return {'state': 'unavailable', 'data': None}


def gateway_bindings(value):
    if not isinstance(value, list) or not 1 <= len(value) <= 8: raise ValueError('invalid gateway bindings')
    labels, clients = set(), set()
    for item in value:
        if set(item) != {'label', 'client_ip', 'gateway_host', 'gateway_port', 'account_fingerprint'}:
            raise ValueError('invalid gateway binding fields')
        if not re.fullmatch(r'[A-Za-z0-9 _-]{1,32}', item['label']): raise ValueError('invalid binding label')
        for field in ('client_ip', 'gateway_host'):
            ip = ipaddress.IPv4Address(item[field])
            if str(ip) != item[field] or not any(ip in ipaddress.IPv4Network(n) for n in ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']):
                raise ValueError('private exact binding required')
        if type(item['gateway_port']) is not int or not 1 <= item['gateway_port'] <= 65535: raise ValueError('invalid binding port')
        if not re.fullmatch(r'[0-9a-f]{64}', item['account_fingerprint']): raise ValueError('invalid bound account fingerprint')
        if item['label'] in labels or item['client_ip'] in clients: raise ValueError('ambiguous physical miner binding')
        labels.add(item['label']); clients.add(item['client_ip'])
    return value


def join_gateway_evidence(snapshot, gateway, bindings, host, port):
    # Bind this collector row to this web instance's gateway and an observed
    # authorized source. Never infer upstream protocol from a global preference.
    if snapshot.get('state') != 'current' or gateway.get('state') != 'current': return snapshot
    data = gateway['data']
    if (data.get('upstream_protocol') != 'SV2' or data.get('counter_basis') != 'aggregate_pool_acknowledgments'
            or data.get('translation_ready') is False or data.get('translation_enabled') is False
            or not data.get('account_fingerprints')): return snapshot
    ready_routes = {r['route'] for r in data.get('routes', []) if r.get('bootstrap_ready') is True}
    matches = {b['label']:b for b in gateway_bindings(bindings) if b['gateway_host'] == host and b['gateway_port'] == port and b['account_fingerprint'] in data['account_fingerprints']}
    rows = []
    for original in snapshot['data']['miners']:
        row = dict(original); binding = matches.get(row['label'])
        if (binding and row.get('available') is True and row.get('connected') is True
                and row.get('protocol') == 'SV1' and row.get('mining_target_verified') is True
                and row.get('trial_endpoint') is True):
            sessions = [s for s in data.get('sessions', []) if s.get('client_ip') == binding['client_ip'] and s.get('miner_protocol', 'SV1') == 'SV1']
            # Legacy observers publish only after the authenticated V2-job marker;
            # require current jobs on the exact bound source as well. Explicit
            # runtime unready always overrides that legacy evidence.
            if sessions and all(s.get('job_state') == 'fresh' and type(s.get('last_job_age_seconds')) in (int,float)
                    and 0 <= s['last_job_age_seconds'] <= 180 and s.get('route') in ready_routes for s in sessions):
                row['upstream_protocol'] = 'SV2'
                row['upstream_evidence'] = 'matched_translator'
                # A physical miner can have multiple connections. Only name a
                # Tor client when all matched sessions agree on that route.
                routes = {s['route'] for s in sessions}
                route = next(iter(routes)) if len(routes) == 1 else None
                row['tor_route'] = {'tor-1': 'A', 'tor-2': 'B'}.get(route, 'unknown')
                # V1 remains plaintext/TLS locally; this is not miner Noise auth.
                row['authenticated'] = False
        rows.append(row)
    return dict(snapshot, data=dict(snapshot['data'], miners=rows))


def with_gateway_evidence(snapshot, root):
    path = os.environ.get('TRANSLATED_MINER_BINDINGS')
    if not path: return snapshot
    try:
        from dashboard_status import read_snapshot as read_gateway
        bindings = gateway_bindings(bounded_read(Path(path)))
        gateway = read_gateway(Path(root)/'gateway', 'gateway', include_client_ips=True)
        return join_gateway_evidence(snapshot, gateway, bindings, os.environ['LAN_IP'], int(os.environ.get('LAN_PORT', '3333')))
    except (OSError, ValueError, TypeError, KeyError):
        return snapshot


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('redirect refused')


def validate_config(config):
    if not isinstance(config, list) or not 1 <= len(config) <= 8: raise ValueError('invalid config')
    origins, identities, labels = set(), set(), set()
    for c in config:
        kind = c.get('kind', 'bitaxe')
        if kind not in ('bitaxe', 'summary-api', 'snapshot-file'): raise ValueError('invalid telemetry adapter')
        if kind == 'snapshot-file':
            if set(c) - {'kind', 'label', 'physical_id', 'max_age_seconds', 'display_ip'} or not {'kind','label','physical_id'} <= set(c):
                raise ValueError('snapshot adapter accepts no origin or path')
            if not re.fullmatch(r'[A-Za-z0-9 _-]{1,32}', c['label']) or not re.fullmatch(r'[A-Za-z0-9_-]{1,32}', c['physical_id']):
                raise ValueError('invalid snapshot identity')
            if c['physical_id'] in identities or c['label'] in labels: raise ValueError('duplicate physical miner')
            maximum = c.get('max_age_seconds', 30)
            if type(maximum) is not int or not 30 <= maximum <= 300: raise ValueError('invalid external freshness bound')
            if 'display_ip' in c: private_miner_ip(c['display_ip'])
            identities.add(c['physical_id']); labels.add(c['label']); continue
        u = urlsplit(c['url'])
        ip = ipaddress.IPv4Address(u.hostname)
        private = any(ip in ipaddress.IPv4Network(n) for n in ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'])
        ports = (None, 80, 8080) if kind == 'summary-api' else (None, 80)
        if (not private or u.scheme != 'http' or u.username or u.password or u.path or u.query or u.fragment or u.port not in ports):
            raise ValueError('exact private miner origin required')
        if not re.fullmatch(r'[A-Za-z0-9 _-]{1,32}', c['label']): raise ValueError('invalid label')
        identity = c.get('physical_id', c['url'])
        if 'physical_id' in c and not re.fullmatch(r'[A-Za-z0-9_-]{1,32}', identity): raise ValueError('invalid physical miner ID')
        if str(ip) in origins or identity in identities or c['label'] in labels:
            raise ValueError('duplicate physical miner')
        origins.add(str(ip)); identities.add(identity); labels.add(c['label'])
        for k in (['username', 'password', 'expected_gateway', 'authority_key'] if kind == 'bitaxe' else ['expected_gateway']):
            if not isinstance(c[k], str) or not c[k] or '\n' in c[k]: raise ValueError('invalid private config')
        if type(c['expected_port']) is not int or not 1 <= c['expected_port'] <= 65535: raise ValueError('invalid port')
    return config


def observe(info, c):
    primary = next(p for p in info['pools'] if p['id'] == info['primaryPoolIndex'])
    fallback = bool(info['isUsingFallbackStratum'])
    active_id = info['secondaryPoolIndex'] if fallback else info['primaryPoolIndex']
    active = next((p for p in info['pools'] if p['id'] == active_id), {})
    connected = info['connectionDiagnostics']['poolConnected'] is True
    protocol = active.get('stratumProtocol', 'unknown') if connected else 'unknown'
    security = info.get('poolConnectionSecurity')
    if protocol == 'SV2' and security not in ('noise', 'noise-unverified'): protocol = 'unknown'
    if protocol == 'SV1' and security not in ('tls', 'plaintext'): protocol = 'unknown'
    authenticated = protocol == 'SV2' and security == 'noise' and active.get('stratumV2RequireAuth') is True and active.get('stratumV2AuthorityPubkey') == c['authority_key']
    endpoint = active.get('stratumURL') == c['expected_gateway'] and active.get('stratumPort') == c['expected_port']
    return {'label': c['label'], 'available': True, 'connected': connected, 'protocol': protocol,
            'primary_protocol': primary.get('stratumProtocol', 'unknown'),
            'upstream_protocol': 'SV2' if authenticated and endpoint else 'unknown',
            'authenticated': authenticated,
            'fallback': fallback,
            'fallback_enabled': any(p['id'] == info['secondaryPoolIndex'] and p.get('stratumURL') for p in info['pools']),
            'trial_endpoint': active.get('stratumURL') == c['expected_gateway'] and active.get('stratumPort') == c['expected_port'],
            'mining_target_verified': connected and endpoint,
            'hashrate_ghs': info['hashRate_1m'], 'accepted': info['sharesAccepted'], 'rejected': info['sharesRejected'],
            'uptime_seconds': info['uptimeSeconds'], 'job_age_seconds': info['connectionDiagnostics']['lastWorkAgeSeconds']}


def fetch(c):
    try:
        if c.get('kind') == 'summary-api': return fetch_summary(c)
        if c.get('kind') == 'snapshot-file': return fetch_snapshot(c)
        auth = base64.b64encode((c['username'] + ':' + c['password']).encode()).decode()
        req = urllib.request.Request(c['url']+'/api/system/info', headers={'Authorization': 'Basic '+auth, 'Origin': c['url']})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open(req, timeout=4) as r: raw = r.read(131073)
        if len(raw) > 131072: raise ValueError('oversize miner response')
        result = observe(json.loads(raw), c)
        return clean({'schema_version': 1, 'sampled_at': time.time(), 'miners': [result]})['miners'][0]
    except Exception:
        # Never log raw exceptions, HTTP headers, response bodies or secrets.
        return {'label': c['label'], 'available': False}


def _fetch_worker(connection, config, fetcher):
    try:
        try:
            result = fetcher(config)
        except BaseException:
            result = {'label': config['label'], 'available': False}
        connection.send(result)
    except BaseException:
        pass  # Parent timeout or shutdown; never log response or credential details.
    finally:
        connection.close()


def _stop_worker(process):
    process.join(.1)
    if process.is_alive():
        process.terminate()
        process.join(.5)
    if process.is_alive():
        process.kill()
        process.join(.5)


def fetch_all(config, timeout=FETCH_TOTAL_TIMEOUT, max_workers=MAX_FETCH_WORKERS,
              fetcher=fetch, context=None):
    """Fetch miners concurrently while enforcing a killable total deadline."""
    if type(timeout) not in (int, float) or timeout <= 0:
        raise ValueError('positive fetch deadline required')
    if type(max_workers) is not int or not 1 <= max_workers <= 8:
        raise ValueError('bounded worker count required')
    context = multiprocessing.get_context('fork') if context is None else context
    results = [None] * len(config)
    waiting = iter(enumerate(config))
    active = {}

    def start_one():
        try:
            index, item = next(waiting)
        except StopIteration:
            return False
        receive, send = context.Pipe(duplex=False)
        process = context.Process(target=_fetch_worker, args=(send, item, fetcher), daemon=True)
        process.start()
        send.close()
        active[receive] = (index, item, process, time.monotonic())
        return True

    for _ in range(min(max_workers, len(config))):
        start_one()
    try:
        while active:
            now = time.monotonic()
            remaining = min(max(0, timeout - (now - started))
                            for _index, _item, _process, started in active.values())
            ready = wait(list(active), timeout=min(.05, remaining))
            for connection in ready:
                index, item, process, _started = active.pop(connection)
                try:
                    row = connection.recv()
                    row = clean({'schema_version': 1, 'sampled_at': time.time(),
                                 'miners': [row]})['miners'][0]
                    if row['label'] != item['label']:
                        raise ValueError('worker label mismatch')
                    results[index] = row
                except (EOFError, OSError, ValueError, TypeError, KeyError):
                    results[index] = {'label': item['label'], 'available': False}
                finally:
                    connection.close()
                    _stop_worker(process)
                start_one()
            now = time.monotonic()
            for connection, (index, item, process, started) in list(active.items()):
                if now - started < timeout:
                    continue
                active.pop(connection)
                connection.close()
                _stop_worker(process)
                results[index] = {'label': item['label'], 'available': False}
                start_one()
    finally:
        for connection, (_index, _item, process, _started) in active.items():
            connection.close()
            _stop_worker(process)
    return results


def fetch_snapshot(c, now=None):
    # An existing trusted monitor can export sanitized observations without
    # granting this collector network access to a quarantined management API.
    root = Path(os.environ.get('MINER_STATUS_ROOT', '/run/miner-status'))
    value = bounded_read(root / ('external-' + c['physical_id'] + '.json'))
    if set(value) != {'schema_version', 'sampled_at', 'miner'} or value.get('schema_version') != 1: raise ValueError('invalid external schema')
    sampled = numeric(value['sampled_at'])
    now = time.time() if now is None else now
    if not 0 <= now - sampled <= c.get('max_age_seconds', 30): raise ValueError('stale external observation')
    row = dict(value['miner'], label=c['label'], source_age_seconds=now-sampled)
    return clean({'schema_version': 1, 'sampled_at': sampled, 'miners': [row]})['miners'][0]


def summary_request(c, command):
    if command not in ('summary', 'pools'): raise ValueError('read-only command required')
    req = urllib.request.Request(c['url'] + '/api',
          data=json.dumps({'command': command}).encode(),
          headers={'Content-Type': 'application/json'}, method='POST')
    with urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect()).open(req, timeout=4) as response:
        raw = response.read(131073)
    if len(raw) > 131072: raise ValueError('oversize miner response')
    return json.loads(raw)


def observe_summary(summary, pools, c):
    records = summary['SUMMARY']
    if not isinstance(records, list) or len(records) != 1: raise ValueError('invalid summary')
    record = records[0]
    entries = pools['POOLS']
    if not isinstance(entries, list) or len(entries) > 8: raise ValueError('invalid pools')
    active = [p for p in entries if p.get('Stratum Active') is True]
    endpoint = False
    if len(active) == 1:
        target = urlsplit(active[0].get('URL', ''))
        endpoint = (target.scheme in ('stratum+tcp', 'stratum+ssl') and
                    target.hostname == c['expected_gateway'] and target.port == c['expected_port'] and
                    not target.username and not target.password and not target.path and not target.query and not target.fragment)
    connected = len(active) == 1 and active[0].get('Status') == 'Alive'
    return {'label': c['label'], 'available': True, 'connected': connected,
            'protocol': 'SV1' if connected else 'unknown', 'primary_protocol': 'SV1',
            'upstream_protocol': 'unknown', 'authenticated': False,
            'fallback': len(active) == 1 and not endpoint, 'fallback_enabled': len(entries) > 1,
            'trial_endpoint': endpoint, 'mining_target_verified': connected and endpoint,
            'hashrate_ghs': numeric(record['GHS 1m']), 'accepted': numeric(record['Accepted']),
            'rejected': numeric(record['Rejected']), 'uptime_seconds': numeric(record['Elapsed']),
            'job_age_seconds': None}


def fetch_summary(c):
    result = observe_summary(summary_request(c, 'summary'), summary_request(c, 'pools'), c)
    return clean({'schema_version': 1, 'sampled_at': time.time(), 'miners': [result]})['miners'][0]


def fetch_routes(config):
    try:
        from native_status import clean as clean_routes, private_ip
        u = urlsplit(config['url'])
        private_ip(u.hostname)
        if u.scheme != 'http' or u.username or u.password or u.path != '/api/routes' or u.query or u.fragment:
            raise ValueError('invalid native route endpoint')
        token = config['token']
        if len(token) != 64 or any(c not in '0123456789abcdef' for c in token): raise ValueError('invalid token')
        req = urllib.request.Request(config['url'], headers={'Authorization':'Bearer '+token})
        with urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect()).open(req,timeout=3) as r: raw=r.read(16385)
        if len(raw)>16384: raise ValueError('oversize routes')
        return clean_routes(json.loads(raw))['sessions']
    except Exception:
        return None


def read_local_routes(root):
    """Read only a bounded, fresh relay snapshot; never a mining socket."""
    try:
        from native_status import clean as clean_routes
        return clean_routes(bounded_read(Path(root) / 'status.json'))['sessions']
    except (OSError, ValueError, KeyError, TypeError):
        return None


def attach_routes(rows, config, routes):
    for row, miner in zip(rows, config):
        row['tor_route'] = 'unknown'
        if row.get('available') and row.get('connected') and row.get('trial_endpoint'):
            source = urlsplit(miner.get('url', '')).hostname
            if not source: continue
            matches = [r for r in routes if r.get('client_ip') == source]
            if len(matches) == 1: row['tor_route'] = matches[0]['route']
    return rows


def main():
    config = validate_config(bounded_read(Path(os.environ['MINER_STATUS_CONFIG'])))
    route_root = os.environ.get('NATIVE_ROUTES_ROOT')
    if route_root and os.environ.get('NATIVE_ROUTES_CONFIG'):
        raise ValueError('select one native route source')
    route_config = json.loads(Path(os.environ['NATIVE_ROUTES_CONFIG']).read_text()) if os.environ.get('NATIVE_ROUTES_CONFIG') else None
    root = Path(os.environ.get('MINER_STATUS_ROOT', '/run/miner-status'))
    root.mkdir(exist_ok=True)
    import hashlib
    scope = hashlib.sha256(json.dumps([{k: c.get(k) for k in ('kind', 'physical_id', 'url', 'expected_gateway', 'expected_port', 'max_age_seconds')} for c in config], sort_keys=True).encode()).hexdigest()
    history = History(root/'hashrate-history.json', scope=scope)
    presence = Presence(root/'miner-contacts.json', scope, len(config))
    while True:
        rows = fetch_all(config)
        routes = read_local_routes(route_root) if route_root else fetch_routes(route_config) if route_config else None
        rows = attach_routes(rows, config, routes or [])
        for row, item in zip(rows, config):
            address = item.get('display_ip') if item.get('kind') == 'snapshot-file' else urlsplit(item['url']).hostname
            if address: row['miner_ip'] = private_miner_ip(address)
        now = time.time()
        rows, active_config = presence.visible(rows, config, now)
        current_rate = dict(aggregate(rows, active_config), miners=miner_series(rows))
        history_ok = True
        try: points = history.sample(current_rate, now)
        except (OSError, ValueError): points, history_ok = [], False
        data = clean({'schema_version': 1, 'sampled_at': now, 'miners': rows, 'native_route_counts': None if routes is None else {r:sum(s['route']==r for s in routes) for r in ('A','B')}, 'hashrate': current_rate, 'hashrate_history': points, 'history_available': history_ok})
        raw = json.dumps(data, allow_nan=False).encode()
        if len(raw) > MAX_BYTES: raise ValueError('oversize status')
        atomic_write(root/'status.json', data)
        time.sleep(10)


if __name__ == '__main__': main()
