"""Local, settings-preserving transport upgrades. No miner or wallet API calls."""
import argparse
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time
import uuid

from preflight import read_settings

ROOT = Path(__file__).resolve().parent
SERVICES = ('gateway', 'ingress', 'tor-a', 'tor-b')
TRANSPORT = ('gateway', 'ingress')
IMAGE = re.compile(r'sha256:[0-9a-f]{64}\Z')
DOCKER = ['docker', '--host', 'unix:///var/run/docker.sock']
DEFAULT_DEPENDENCIES = {
    'gateway': {'tor-a': 'service_started', 'tor-b': 'service_started'},
    'ingress': {'gateway': 'service_healthy'},
}


def legacy_dependency_model(model, name, labels):
    """Reconstruct only verified Compose 2.26.1 --no-deps hash pruning.

    Never accept an arbitrary dependency edit: limit this compatibility path
    to our stock graph and an exact recorded subset. All other fields remain
    in Compose's hash, and the real upgrade/rollback model stays untouched.
    """
    expected = DEFAULT_DEPENDENCIES.get(name)
    if not expected or labels.get('com.docker.compose.version') != '2.26.1':
        return None
    declared = model['services'][name].get('depends_on', {})
    if not isinstance(declared, dict) or set(declared) != set(expected):
        return None
    for service, condition in expected.items():
        value = declared[service]
        if (not isinstance(value, dict) or set(value) - {'condition', 'required', 'restart'}
                or value.get('condition') != condition or value.get('required') is not True
                or value.get('restart', False) is not False):
            return None
    recorded = labels.get('com.docker.compose.depends_on')
    if not isinstance(recorded, str):
        return None
    retained = {}
    for entry in recorded.split(',') if recorded else []:
        parts = entry.split(':')
        if len(parts) != 3:
            return None
        service, condition, restart = parts
        if (service in retained or service not in expected
                or condition != expected[service] or restart != 'false'):
            return None
        retained[service] = declared[service]
    if set(retained) == set(declared):
        return None
    candidate = copy.deepcopy(model)
    if retained:
        candidate['services'][name]['depends_on'] = copy.deepcopy(retained)
    else:
        candidate['services'][name].pop('depends_on')
    return candidate


def config_hashes(output):
    hashes = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) != 2 or fields[0] in hashes:
            raise Blocked('deployment_config_drift')
        hashes[fields[0]] = fields[1]
    if set(hashes) != set(SERVICES):
        raise Blocked('deployment_config_drift')
    return hashes


def resolved_model_input(model):
    # Compose 2.26.1 config escapes every dollar when rendering JSON. Reverse
    # that encoding once before --no-interpolate, never expand environment or
    # shell expressions. Reject unexpected unescaped dollars conservatively.
    data = json.dumps(model)
    if '$' in data.replace('$$', ''):
        raise Blocked('deployment_config_drift')
    return data.replace('$$', '$')


class Blocked(Exception):
    """Only fixed, public reason codes belong in this exception."""


def read_file(path, private=False):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_size > 4 * 1024**2
                or (private and (info.st_uid != os.geteuid() or info.st_mode & 0o077))):
            raise Blocked('unsafe_file')
        return stream.read()


def atomic(path, value):
    temp = path.with_name('.write-' + uuid.uuid4().hex)
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        fd = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        temp.unlink(missing_ok=True)


def private_dir(path):
    path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise Blocked('unsafe_state_directory')


def command_env(settings):
    env = {k: v for k, v in os.environ.items()
           if not k.startswith('COMPOSE_') and k not in
           ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH')}
    env.update(settings)
    return env


def fingerprint(obj):
    """Effective settings must survive an image change, including custom limits."""
    config = obj['Config']
    host = copy.deepcopy(obj['HostConfig'])
    # Docker may serialize an unset DNS list as null after recreation.
    # Only canonicalize absent/empty lists; explicit resolvers/options still compare.
    for key in ('Dns', 'DnsOptions', 'DnsSearch'):
        if host.get(key) is None:
            host[key] = []
    # Compose may reorder semantically unordered mount/capability collections
    # when recreating from its canonical JSON model. Do not mistake that for a
    # settings change; retain full mount properties and all other host values.
    for key in ('Mounts', 'Binds', 'VolumesFrom', 'CapDrop', 'CapAdd', 'SecurityOpt'):
        if isinstance(host.get(key), list):
            host[key] = sorted(host[key], key=lambda x: json.dumps(x, sort_keys=True))
    return {
        'config': {k: config.get(k) for k in
                   ('User', 'Cmd', 'Entrypoint', 'WorkingDir', 'Healthcheck', 'StopSignal')},
        'env': sorted(config.get('Env') or []),
        'host': host,
        'mounts': sorted(obj['Mounts'], key=lambda x: x['Destination']),
    }


def image_override(images):
    if set(images) != set(TRANSPORT) or not all(IMAGE.fullmatch(x) for x in images.values()):
        raise Blocked('invalid_image_pin')
    return {'services': {name: {'image': value, 'pull_policy': 'never'} for name, value in images.items()}}


class Upgrader:
    def __init__(self, root=ROOT):
        self.root = root.resolve()
        self.store = self.root / '.arkpool-upgrade'
        self.changed = False
        self.runtime_changed = False
        self.settings = read_settings(self.root / '.env')
        self.env = command_env(self.settings)

    def run(self, args, timeout=30, data=None):
        try:
            return subprocess.run(args, cwd=self.root, env=self.env, capture_output=True,
                                  text=True, input=data, timeout=timeout, check=True).stdout
        except (OSError, subprocess.SubprocessError):
            raise Blocked('command_failed') from None

    def files(self):
        # These are the standard Compose files this helper supports. Never
        # silently discard a user override or follow symlinks to private files.
        if any((self.root/n).exists() for n in ('compose.yml', 'docker-compose.yml', 'docker-compose.yaml')):
            raise Blocked('ambiguous_compose_files')
        result = [self.root/'compose.yaml']
        if self.settings.get('TLS_ENABLED') == '1':
            result.append(self.root/'compose.tls.yaml')
        overrides = [self.root/n for n in ('compose.override.yaml', 'compose.override.yml')
                     if os.path.lexists(self.root/n)]
        if len(overrides) > 1:
            raise Blocked('ambiguous_compose_overrides')
        result += overrides
        for path in result:
            read_file(path)
        return result

    def compose(self):
        args = DOCKER + ['compose', '--project-directory', str(self.root), '--env-file', str(self.root/'.env')]
        for path in self.files():
            args += ['-f', str(path)]
        active = self.store/'active.json'
        if os.path.lexists(active):
            data = json.loads(read_file(active, private=True))
            images = {k: v['image'] for k, v in data['services'].items()}
            if data != image_override(images):
                raise Blocked('unmanaged_image_override')
            args += ['-f', str(active)]
        return args

    def state(self):
        if not os.path.lexists(self.store/'state.json'):
            return None
        return json.loads(read_file(self.store/'state.json', private=True))

    def snapshot(self):
        result = {}
        for service in SERVICES:
            ids = self.run(self.compose() + ['ps', '-a', '-q', service]).split()
            if len(ids) != 1:
                raise Blocked('expected_one_existing_container_per_service')
            result[service] = json.loads(self.run(DOCKER + ['inspect', ids[0]]))[0]
        return result

    def hashes(self):
        return {p.name: hashlib.sha256(read_file(p, private=p.name == '.env')).hexdigest()
                for p in self.files() + [self.root/'.env']}

    def unchanged(self, record):
        if self.hashes() != record['file_hashes']:
            raise Blocked('settings_changed_manual_review_required')

    def health(self, snapshot, images, baseline=None):
        for service in SERVICES:
            obj = snapshot[service]
            if not obj['State']['Running']:
                raise Blocked('service_not_running')
            if service in TRANSPORT:
                if obj['Image'] != images[service] or obj['State'].get('Health', {}).get('Status') != 'healthy':
                    raise Blocked('transport_not_healthy')
                hc = obj['HostConfig']
                if (obj['Config']['User'] != '10001:10001' or not hc['ReadonlyRootfs']
                        or 'ALL' not in hc['CapDrop'] or 'no-new-privileges:true' not in hc['SecurityOpt']
                        or hc.get('Privileged') or (service == 'gateway' and hc['NetworkMode'] != 'none')):
                    raise Blocked('isolation_changed')
                if baseline and fingerprint(obj) != fingerprint(baseline[service]):
                    raise Blocked('effective_settings_changed')
            elif baseline:
                old = baseline[service]
                if any(obj[k] != old[k] for k in ('Id', 'Image', 'RestartCount')) or obj['State']['StartedAt'] != old['State']['StartedAt']:
                    raise Blocked('tor_changed_manual_review_required')
        if not snapshot['ingress']['NetworkSettings'].get('Ports', {}).get('3333/tcp'):
            raise Blocked('listener_not_published')

    def inspect_model(self, baseline):
        model = json.loads(self.run(self.compose() + ['config', '--format', 'json']))
        if set(model['services']) != set(SERVICES):
            raise Blocked('unsupported_project_topology')
        # Comparing Compose's own hashes catches edited resource limits,
        # environment, mounts, health commands, ports, and image overrides.
        hashes = config_hashes(self.run(self.compose() + ['config', '--hash', '*']))
        for name, obj in baseline.items():
            labels = obj['Config']['Labels']
            if labels.get('com.docker.compose.project') != model['name']:
                raise Blocked('deployment_config_drift')
            saved = labels.get('com.docker.compose.config-hash')
            if saved == hashes[name]:
                continue
            candidate = legacy_dependency_model(model, name, labels)
            if candidate is None:
                raise Blocked('deployment_config_drift')
            # Already-resolved private values travel on stdin, not argv or disk.
            # Do not interpolate literal dollar signs a second time.
            alternate = config_hashes(self.run(
                DOCKER + ['compose', '--project-directory', str(self.root), '-f', '-',
                          'config', '--no-interpolate', '--hash', '*'],
                data=resolved_model_input(candidate)))
            if saved != alternate[name]:
                raise Blocked('deployment_config_drift')
        return model

    def apply_model(self, path, project):
        # The private resolved model freezes interpolation and pins actual image
        # IDs. Never build, pull, restart Tor, remove volumes, or touch the miner.
        self.runtime_changed = True
        self.run(DOCKER + ['compose', '--project-directory', str(self.root), '--project-name', project,
                          '-f', str(path), 'up', '-d', '--no-deps', '--no-build', '--pull', 'never',
                          '--wait', '--wait-timeout', '90', *TRANSPORT], timeout=120)

    def transaction_dir(self, record):
        if not re.fullmatch(r'[0-9a-f]{32}', record['transaction']):
            raise Blocked('invalid_transaction')
        return self.store/record['transaction']

    def restore(self, record):
        self.unchanged(record)
        directory = self.transaction_dir(record)
        baseline = json.loads(read_file(directory/'baseline.json', private=True))
        images = {s: baseline[s]['Image'] for s in TRANSPORT}
        for image in images.values():
            self.run(DOCKER + ['image', 'inspect', image])
        # Preserve user files; restoration changes only the tool-owned image pin.
        atomic(self.store/'active.json', image_override(images))
        record['phase'] = 'rolling_back'
        atomic(self.store/'state.json', record)
        self.apply_model(directory/'rollback.json', record['project'])
        self.health(self.snapshot(), images, baseline)
        record['phase'] = 'rolled_back'
        atomic(self.store/'state.json', record)

    def upgrade(self, image):
        if not IMAGE.fullmatch(image or ''):
            raise Blocked('use_exact_local_image_id')
        previous = self.state()
        if previous and previous['phase'] not in ('healthy', 'rolled_back', 'test_failed'):
            raise Blocked('unfinished_upgrade_use_rollback')
        before_hashes = self.hashes()
        baseline = self.snapshot()
        old = {s: baseline[s]['Image'] for s in TRANSPORT}
        self.health(baseline, old)
        model = self.inspect_model(baseline)
        candidate = json.loads(self.run(DOCKER + ['image', 'inspect', image]))[0]
        if candidate['Id'] != image or candidate['Config'].get('User') != '10001:10001':
            raise Blocked('unsupported_candidate_image')
        if all(x == image for x in old.values()):
            return 'already_current'
        record = {'schema_version': 1, 'transaction': uuid.uuid4().hex, 'phase': 'testing',
                  'project': model['name'], 'file_hashes': before_hashes, 'candidate': image,
                  'created_at': int(time.time())}
        directory = self.transaction_dir(record)
        directory.mkdir(mode=0o700)
        self.changed = True
        for path in self.files() + [self.root/'.env']:
            # O_EXCL prevents replacing a backup; private modes protect settings.
            fd = os.open(directory/path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(read_file(path, private=path.name == '.env'))
                stream.flush()
                os.fsync(stream.fileno())
        atomic(directory/'baseline.json', baseline)
        rollback = copy.deepcopy(model)
        updated = copy.deepcopy(model)
        for name in TRANSPORT:
            rollback['services'][name]['image'] = old[name]
            updated['services'][name]['image'] = image
            for item in (rollback, updated):
                item['services'][name]['pull_policy'] = 'never'
        atomic(directory/'rollback.json', rollback)
        atomic(directory/'candidate.json', updated)
        atomic(self.store/'state.json', record)
        test_name = 'arkpool-candidate-test-' + record['transaction']
        try:
            try:
                self.run(DOCKER + ['run', '--name', test_name, '--rm', '--pull', 'never', '--network', 'none', '--read-only',
                                  '--tmpfs', '/tmp:rw,noexec,nosuid,size=32m', '--cap-drop', 'ALL',
                                  '--security-opt', 'no-new-privileges:true', '--user', '10001:10001',
                                  '--memory', '256m', '--cpus', '1', '--pids-limit', '64',
                                  '--entrypoint', 'python3', image, '/app/gateway.py', 'selfcheck'], timeout=120)
            finally:
                # Killing a timed-out Docker CLI need not stop its container.
                # Remove only this transaction's disposable networkless test;
                # it has no user volumes, settings, or production credentials.
                try:
                    self.run(DOCKER + ['container', 'inspect', test_name])
                except Blocked:
                    pass
                else:
                    self.run(DOCKER + ['container', 'rm', '-f', test_name])
            self.unchanged(record)
            current = self.snapshot()
            if any(current[s]['Id'] != baseline[s]['Id'] for s in SERVICES):
                raise Blocked('deployment_changed_during_test')
            self.health(current, old, baseline)
        except (Exception, KeyboardInterrupt):
            record['phase'] = 'test_failed'
            atomic(directory/'test-result.json', record)
            # A failed candidate must not erase the last successful transaction
            # and its manual rollback target.
            atomic(self.store/'state.json', previous if previous else record)
            raise Blocked('candidate_test_or_pre_cutover_check_failed') from None
        record['phase'] = 'pending'
        atomic(self.store/'state.json', record)
        try:
            atomic(self.store/'active.json', image_override({s: image for s in TRANSPORT}))
            self.apply_model(directory/'candidate.json', record['project'])
            self.unchanged(record)
            self.health(self.snapshot(), {s: image for s in TRANSPORT}, baseline)
            record['phase'] = 'healthy'
            atomic(self.store/'state.json', record)
        except (Exception, KeyboardInterrupt) as error:
            try:
                record['failure_reason'] = str(error) if isinstance(error, Blocked) else 'cutover_interrupted_or_failed'
                self.restore(record)
            except (Exception, KeyboardInterrupt):
                record['phase'] = 'rollback_failed'
                atomic(self.store/'state.json', record)
                raise Blocked('rollback_failed_manual_recovery_required') from None
            return 'upgrade_failed_rolled_back'
        return 'services_healthy_verify_mining'

    def rollback(self):
        record = self.state()
        if not record or record['phase'] in ('testing', 'test_failed'):
            raise Blocked('no_cutover_to_rollback')
        if record['phase'] == 'rolled_back':
            return 'already_rolled_back'
        self.changed = True
        self.restore(record)
        return 'rolled_back_verify_mining'


def result(status, instance=None):
    return {'schema_version': 1, 'result': status,
            'mutations_performed': bool(instance and instance.changed),
            'runtime_change_attempted': bool(instance and instance.runtime_changed),
            'mining_verified': False, 'payout_verified': False,
            'scope': 'gateway_and_ingress_only'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('upgrade', 'rollback', 'upgrade-status', 'compose'))
    parser.add_argument('--image')
    parser.add_argument('--confirm-interruption', action='store_true')
    parser.add_argument('--json', action='store_true')
    args, extra = parser.parse_known_args(argv)
    instance = None
    code = 0
    try:
        if args.action != 'compose' and extra:
            raise Blocked('unexpected_arguments')
        if args.action in ('upgrade', 'rollback') and not args.confirm_interruption:
            raise Blocked('confirmation_required')
        instance = Upgrader()
        if args.action == 'compose':
            # Existing gateway.sh commands honor the persistent image pin too.
            return subprocess.call(instance.compose() + extra, cwd=instance.root, env=instance.env)
        if args.action == 'upgrade-status':
            record = instance.state()
            output = result(record['phase'] if record else 'no_upgrade_record')
            output['status_scope'] = 'saved_transaction_not_live_health'
        else:
            existed = instance.store.exists()
            private_dir(instance.store)
            instance.changed = not existed
            lock_existed = (instance.store/'lock').exists()
            fd = os.open(instance.store/'lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            instance.changed |= not lock_existed
            with os.fdopen(fd, 'r+') as lock:
                if os.fstat(lock.fileno()).st_mode & 0o077:
                    raise Blocked('unsafe_lock')
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise Blocked('upgrade_already_running') from None
                output = result(instance.upgrade(args.image) if args.action == 'upgrade'
                                else instance.rollback(), instance)
                if output['result'] == 'upgrade_failed_rolled_back':
                    code = 2
    except (Exception, KeyboardInterrupt) as error:
        reason = str(error) if isinstance(error, Blocked) else 'operation_failed_details_suppressed'
        output, code = result(reason, instance), 1
    if args.json:
        print(json.dumps(output, sort_keys=True))
    else:
        print(output['result'])
        print('Local service checks only. Verify fresh jobs and accepted shares separately; no wallet actions performed.')
    return code


if __name__ == '__main__':
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    sys.exit(main())
