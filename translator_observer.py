"""Local read-only Docker log observer; publishes bounded, redacted status only."""
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
from dashboard_status import gateway_view, write_snapshot

ROOT = Path(os.environ.get('TRANSLATOR_STATUS_STATE_ROOT', str(Path(__file__).parent)))
CONTAINER = os.environ.get('TRANSLATOR_CONTAINER', 'arkpool-translator-1')
if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}', CONTAINER):
    raise ValueError('invalid translator container name')


def epoch(text):
    return datetime.fromisoformat(text.replace('Z', '+00:00')).timestamp()


def update(state, line):
    stamp, _, message = line.partition(' ')
    moment = epoch(stamp)
    if 'Translator Tor path ' in message:
        route = message.strip().rsplit(' ', 1)[-1]
        if route in ('A', 'B'):
            state['route'] = 'tor-1' if route == 'A' else 'tor-2'
    if 'Translator authenticated V2 job ready' in message:
        state['verified'] = True
    match = re.search(r'Downstream (\d+) registered successfully', message)
    if match:
        state['sessions'][match[1]] = False
    match = re.search(r'Received mining.authorize from Sv1 downstream (\d+)', message)
    if match and match[1] in state['sessions']:
        state['sessions'][match[1]] = True
    match = re.search(r'Downstream: (\d+) disconnected', message)
    if match:
        state['sessions'].pop(match[1], None)
    if 'Received: NewExtendedMiningJob' in message or 'Received: SetNewPrevHash' in message:
        state['job_at'] = moment
        state['jobs'] += 1
    if 'SubmitSharesExtended: valid share, forwarding' in message:
        state['submitted'] += 1
    match = re.search(r'Received: SubmitSharesSuccess\(.*new_submits_accepted_count=(\d+),', message)
    if match:
        state['accepted'] += int(match[1])
    if 'Received: SubmitSharesError(' in message:
        state['rejected'] += 1
    if len(state['sessions']) > 8:
        raise ValueError('session limit')


def fresh_state(started):
    return dict(started=started, cursor=started, seen=[], sessions={}, route=None,
                verified=False, job_at=None, jobs=0, submitted=0, accepted=0, rejected=0)


def snapshot(state, config, now):
    if not state['verified'] or not state['route']:
        raise ValueError('V2 not verified')
    age = None if state['job_at'] is None else max(0, now - state['job_at'])
    rows = [dict(route=state['route'], client_ip=config['client_ip'],
                 last_job_age_seconds=age,
                 job_state='awaiting_jobs' if age is None else 'fresh' if age <= 180 else 'stale',
                 counts={'accepted': None, 'rejected': None})
            for authorized in state['sessions'].values() if authorized]
    counts = {k: state[k] for k in ('submitted', 'accepted', 'rejected', 'jobs')}
    counts['pending_submissions'] = max(0, state['submitted'] - state['accepted'] - state['rejected'])
    routes = []
    for index, root in enumerate(config['tor_roots'], 1):
        try:
            ready = 0 <= now - float((Path(root)/'ready').read_text()) <= 30
        except (OSError, ValueError):
            ready = False
        name = 'tor-' + str(index)
        routes.append(dict(route=name, bootstrap_ready=ready, cooldown_seconds=0,
                           connection_attempts=int(name == state['route']),
                           connection_successes=int(name == state['route']),
                           mining=counts if name == state['route'] else {}))
    data = gateway_view(dict(sessions=rows, routes=routes, mining=counts,
                             upstream_protocol='SV2', counter_basis='aggregate_pool_acknowledgments',
                             tor_isolation='shared', account_fingerprints=[config['account_fingerprint']]), True)
    return dict(schema_version=1, role='gateway', process=hashlib.sha256(state['started'].encode()).hexdigest()[:32],
                started_at=epoch(state['started']), sampled_at=now, data=data)


def poll(config):
    info = json.loads(subprocess.check_output(['docker', 'inspect', CONTAINER], timeout=5))[0]
    if not info['State']['Running']:
        return
    started = info['State']['StartedAt']
    state_file = ROOT/'observer-state.json'
    state = json.loads(state_file.read_text()) if state_file.exists() else fresh_state(started)
    if state['started'] != started:
        state = fresh_state(started)
    # Logs are bounded by Docker rotation. Refuse a truncated backlog instead of
    # turning incomplete history into apparently accurate counts.
    process = subprocess.Popen(['docker', 'logs', '--timestamps', '--since', state['cursor'], CONTAINER],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        raw = process.stdout.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError('log backlog too large')
        if process.wait(timeout=5) != 0:
            raise ValueError('logs unavailable')
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
    seen = set(state['seen'])
    for line in sorted(raw.decode('utf-8', errors='replace').splitlines(), key=lambda item: item.partition(' ')[0]):
        digest = hashlib.sha256(line.encode()).hexdigest()
        if digest in seen:
            continue
        update(state, line)
        stamp = line.partition(' ')[0]
        if stamp != state['cursor']:
            state['cursor'], state['seen'] = stamp, []
        state['seen'].append(digest)
    envelope = snapshot(state, config, time.time())
    temp = ROOT/'observer-state.tmp'
    temp.write_text(json.dumps(state));temp.chmod(0o600);temp.replace(state_file)
    root = ROOT/'status'
    write_snapshot(root, envelope)
    os.chown(root/'status.json', 10001, 10001)


if __name__ == '__main__':
    config = json.loads((ROOT/'observer-config.json').read_text())
    while True:
        try:
            poll(config)
        except Exception as error:
            print('Translator status unavailable: ' + type(error).__name__, flush=True)
        time.sleep(5)
