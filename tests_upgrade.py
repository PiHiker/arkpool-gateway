"""Offline upgrade tests: synthetic Docker state, no real daemon or mining."""
import contextlib
import copy
import fcntl
import hashlib
import io
import json
import os
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import upgrade as u
from tests_release import onion

OLD = 'sha256:' + '1' * 64
NEW = 'sha256:' + '2' * 64


def container(service, image=OLD):
    return {'Id': service + '-old', 'Image': image, 'RestartCount': 0,
            'Config': {'User': '10001:10001', 'Env': ['PRIVATE_SETTING=do-not-print'],
                       'Cmd': ['python3', '/app/' + service + '.py'],
                       'Labels': {'com.docker.compose.project': 'fixture',
                                  'com.docker.compose.config-hash': service + '-hash'}},
            'HostConfig': {'ReadonlyRootfs': True, 'CapDrop': ['ALL'],
                           'SecurityOpt': ['no-new-privileges:true'], 'Memory': 123456789,
                           'NetworkMode': 'none' if service == 'gateway' else 'fixture-net'},
            'Mounts': [{'Destination': '/data', 'Name': service + '-preserved', 'RW': True}],
            'State': {'Running': True, 'StartedAt': 'before', 'Health': {'Status': 'healthy'}},
            'NetworkSettings': {'Ports': {'3333/tcp': [{'HostIp': '192.168.1.10', 'HostPort': '7777'}]}}}


class Fake(u.Upgrader):
    def __init__(self, root):
        super().__init__(root)
        self.objects = {s: container(s) for s in u.SERVICES}
        self.calls = []
        self.model = {'name': 'fixture', 'services': {s: {'image': OLD, 'pull_policy': 'never'} for s in u.SERVICES}}
        self.fail_test = self.fail_start = self.fail_restore = False
        self.drift_on_test = self.tor_drift = self.settings_drift = False
        self.interrupt_start = False

    def snapshot(self):
        return copy.deepcopy(self.objects)

    def run(self, args, timeout=30, data=None):
        self.calls.append(args)
        if 'config' in args and '--format' in args:
            return json.dumps(self.model)
        if '--hash' in args:
            return '\n'.join(s + ' ' + s + '-hash' for s in u.SERVICES)
        if 'image' in args and 'inspect' in args:
            return json.dumps([{'Id': args[-1], 'Config': {'User': '10001:10001'}}])
        if 'container' in args and 'inspect' in args:
            raise u.Blocked('command_failed')  # --rm already removed the fixture.
        if 'run' in args:
            if self.drift_on_test:
                with (self.root/'.env').open('a') as stream:
                    stream.write('# operator edit\n')
            if self.fail_test:
                raise u.Blocked('command_failed')
            return ''
        if 'up' in args:
            model = json.loads(Path(args[args.index('-f')+1]).read_text())
            candidate = model['services']['gateway']['image'] == NEW
            if candidate and self.interrupt_start:
                raise KeyboardInterrupt
            if (candidate and self.fail_start) or (not candidate and self.fail_restore):
                raise u.Blocked('command_failed')
            for s in u.TRANSPORT:
                self.objects[s]['Image'] = model['services'][s]['image']
                self.objects[s]['Id'] = s + ('-new' if candidate else '-restored')
            if candidate and self.tor_drift:
                self.objects['tor-a']['RestartCount'] += 1
            if candidate and self.settings_drift:
                self.objects['gateway']['HostConfig']['Memory'] = 1
            if not candidate:
                self.objects['gateway']['HostConfig']['Memory'] = 123456789
            return ''
        raise AssertionError('unexpected command')


class HashFake(Fake):
    """Deterministic field-sensitive hashes; real Compose is tested separately."""
    def __init__(self, root):
        super().__init__(root)
        self.inputs = []
        for name, dependencies in u.DEFAULT_DEPENDENCIES.items():
            self.model['services'][name]['depends_on'] = {
                key: {'condition': condition, 'required': True}
                for key, condition in dependencies.items()}
        self.model['services']['gateway']['environment'] = {'PRIVATE_SETTING': 'literal-$$VALUE'}

    @staticmethod
    def hash_service(service, rendered=True):
        data = json.dumps(service, sort_keys=True)
        if rendered:
            data = data.replace('$$', '$')
        return hashlib.sha256(data.encode()).hexdigest()

    def run(self, args, timeout=30, data=None):
        if '--hash' not in args:
            return super().run(args, timeout, data)
        self.calls.append(args)
        if data is not None:
            self.inputs.append(data)
        model = json.loads(data) if data is not None else self.model
        return '\n'.join(s + ' ' + self.hash_service(model['services'][s], rendered=data is None)
                         for s in u.SERVICES)

    def record(self, pruned=None, retained=()):
        for name, obj in self.objects.items():
            service = copy.deepcopy(self.model['services'][name])
            if name == pruned:
                service['depends_on'] = {s: service['depends_on'][s] for s in retained}
                if not service['depends_on']:
                    del service['depends_on']
            labels = obj['Config']['Labels']
            labels['com.docker.compose.version'] = '2.26.1'
            labels['com.docker.compose.depends_on'] = ','.join(
                key + ':' + value['condition'] + ':false'
                for key, value in service.get('depends_on', {}).items())
            labels['com.docker.compose.config-hash'] = self.hash_service(service)


class DependencyHashTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root/'.env').write_text('LAN_IP=192.168.1.10\nMINER_IPS=lan\nPOOL_ONION='+onion()+'\n')
        (self.root/'.env').chmod(0o600)
        (self.root/'compose.yaml').write_text('name: fixture\nservices: {}\n')
        self.app = HashFake(self.root)
        self.app.record('gateway')

    def test_full_model_needs_no_compatibility_path(self):
        self.app.record()
        self.assertEqual(self.app.inspect_model(self.app.snapshot()), self.app.model)
        self.assertEqual(self.app.inputs, [])

    def test_no_deps_preserves_returned_model_and_never_mutates_runtime(self):
        before = copy.deepcopy(self.app.model)
        files = {p.name: p.read_bytes() for p in self.root.iterdir()}
        self.assertEqual(self.app.inspect_model(self.app.snapshot()), before)
        self.assertEqual(self.app.model, before)
        self.assertEqual(files, {p.name: p.read_bytes() for p in self.root.iterdir()})
        self.assertTrue(all('config' in c for c in self.app.calls))
        self.assertNotIn('depends_on', json.loads(self.app.inputs[0])['services']['gateway'])
        command = self.app.calls[-1]
        self.assertEqual(command[command.index('-f')+1], '-')
        self.assertIn('--no-interpolate', command)
        self.assertNotIn('literal-$VALUE', ' '.join(command))
        self.assertEqual(json.loads(self.app.inputs[0])['services']['gateway']['environment'],
                         {'PRIVATE_SETTING': 'literal-$VALUE'})

    def test_compose_dollar_escaping_is_decoded_exactly_once(self):
        value = '$$VALUE $${VALUE:-literal} $$$$ $$(not-a-command)'
        self.app.model['services']['gateway']['environment']['PRIVATE_SETTING'] = value
        self.app.record('gateway')
        self.assertEqual(self.app.inspect_model(self.app.snapshot()), self.app.model)
        self.assertEqual(json.loads(self.app.inputs[0])['services']['gateway']['environment'],
                         {'PRIVATE_SETTING': '$VALUE ${VALUE:-literal} $$ $(not-a-command)'})

    def test_unexpected_unescaped_dollars_fail_closed(self):
        for value in ('$VALUE', '$$$VALUE', '${VALUE}', '$$', '$'):
            with self.subTest(value=value):
                if value == '$$':
                    self.assertEqual(json.loads(u.resolved_model_input({'test': value})), {'test': '$'})
                else:
                    with self.assertRaisesRegex(u.Blocked, 'deployment_config_drift'):
                        u.resolved_model_input({'test': value})

    def test_recorded_partial_subset_and_ingress_only_pruning(self):
        for name, retained in [('gateway', ('tor-a',)), ('gateway', ('tor-b',)), ('ingress', ())]:
            with self.subTest(name=name, retained=retained):
                self.app.record(name, retained)
                self.assertEqual(self.app.inspect_model(self.app.snapshot()), self.app.model)

    def test_changed_runtime_fields_are_still_blocked(self):
        changes = {'environment': {'PRIVATE_SETTING': 'different'}, 'mem_limit': 123,
                   'volumes': ['changed:/data'], 'network_mode': 'host',
                   'command': ['different'], 'image': NEW, 'read_only': False,
                   'cap_drop': [], 'ports': ['9999:3333'],
                   'healthcheck': {'test': ['CMD', 'false']}}
        original = copy.deepcopy(self.app.model)
        for field, value in changes.items():
            with self.subTest(field=field):
                self.app.model = copy.deepcopy(original)
                self.app.model['services']['gateway'][field] = value
                with self.assertRaisesRegex(u.Blocked, 'deployment_config_drift'):
                    self.app.inspect_model(self.app.snapshot())

    def test_custom_dependency_edits_cannot_be_hidden_by_pruning(self):
        changes = [None, {}, {'tor-a': {'condition': 'service_started', 'required': True}},
                   {'tor-a': {}, 'tor-b': {}, 'ingress': {}}]
        original = copy.deepcopy(self.app.model['services']['gateway']['depends_on'])
        for field, value in [('condition', 'service_healthy'), ('required', False),
                             ('required', 1), ('restart', True), ('unknown', False)]:
            changed = copy.deepcopy(original)
            changed['tor-a'][field] = value
            changes.append(changed)
        for changed in changes:
            with self.subTest(dependencies=changed):
                self.app.model['services']['gateway']['depends_on'] = changed
                with self.assertRaisesRegex(u.Blocked, 'deployment_config_drift'):
                    self.app.inspect_model(self.app.snapshot())
        self.assertEqual(self.app.inputs, [])

    def test_explicit_default_restart_false_is_supported(self):
        self.app.model['services']['gateway']['depends_on']['tor-a']['restart'] = False
        self.assertEqual(self.app.inspect_model(self.app.snapshot()), self.app.model)

    def test_unknown_missing_or_malformed_dependency_evidence_is_blocked(self):
        labels = self.app.objects['gateway']['Config']['Labels']
        for value in (None, False, ' ', 'tor-a', 'tor-a:service_started',
                      'tor-a:service_started:true', 'tor-a:service_healthy:false',
                      'other:service_started:false', 'tor-a:service_started:false,',
                      'tor-a:service_started:false,tor-a:service_started:false',
                      'tor-a:service_started:false,tor-b:service_started:false'):
            with self.subTest(label=value):
                if value is None:
                    labels.pop('com.docker.compose.depends_on', None)
                else:
                    labels['com.docker.compose.depends_on'] = value
                with self.assertRaisesRegex(u.Blocked, 'deployment_config_drift'):
                    self.app.inspect_model(self.app.snapshot())
        self.assertEqual(self.app.inputs, [])

    def test_unverified_compose_versions_are_not_normalized(self):
        for version in ('', '2.26.2', '2.27.0', '5.0.0'):
            with self.subTest(version=version):
                self.app.objects['gateway']['Config']['Labels']['com.docker.compose.version'] = version
                with self.assertRaisesRegex(u.Blocked, 'deployment_config_drift'):
                    self.app.inspect_model(self.app.snapshot())
        self.assertEqual(self.app.inputs, [])

    def test_project_mismatch_never_uses_compatibility_path(self):
        self.app.objects['gateway']['Config']['Labels']['com.docker.compose.project'] = 'other'
        with self.assertRaisesRegex(u.Blocked, 'deployment_config_drift'):
            self.app.inspect_model(self.app.snapshot())
        self.assertEqual(self.app.inputs, [])

    def test_wrong_saved_hash_is_not_bypassed(self):
        self.app.objects['gateway']['Config']['Labels']['com.docker.compose.config-hash'] = 'wrong'
        with self.assertRaisesRegex(u.Blocked, 'deployment_config_drift'):
            self.app.inspect_model(self.app.snapshot())
        self.assertEqual(len(self.app.inputs), 1)

    def test_tor_hash_changes_are_never_normalized(self):
        self.app.record()
        self.app.objects['tor-a']['Config']['Labels']['com.docker.compose.config-hash'] = 'wrong'
        with self.assertRaisesRegex(u.Blocked, 'deployment_config_drift'):
            self.app.inspect_model(self.app.snapshot())
        self.assertEqual(self.app.inputs, [])

    def test_hash_output_requires_unique_complete_service_set(self):
        valid = '\n'.join(s + ' hash' for s in u.SERVICES)
        self.assertEqual(set(u.config_hashes(valid)), set(u.SERVICES))
        for value in ('', 'gateway', valid+'\ngateway duplicate',
                      valid+'\nother hash', valid.replace('tor-b hash', ''), valid+' extra'):
            with self.subTest(output=value):
                with self.assertRaisesRegex(u.Blocked, 'deployment_config_drift'):
                    u.config_hashes(value)

    def test_stdin_command_failures_do_not_leak_private_model(self):
        with patch.object(u.subprocess, 'run', side_effect=subprocess.CalledProcessError(
                1, ['docker'], stderr='private-input')) as run:
            with self.assertRaisesRegex(u.Blocked, '^command_failed$'):
                u.Upgrader.run(self.app, ['docker'], data='private-input')
        self.assertEqual(run.call_args.kwargs['input'], 'private-input')


class UpgradeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        env = self.root/'.env'
        env.write_text('LAN_IP=192.168.1.10\nMINER_IPS=192.168.1.70\nPOOL_ONION='+onion()+'\nLAN_PORT=7777\n')
        env.chmod(0o600)
        (self.root/'compose.yaml').write_text('name: fixture\nservices: {}\n')
        (self.root/'compose.override.yaml').write_text('# private custom limits\nservices: {}\n')
        self.app = Fake(self.root)
        u.private_dir(self.app.store)

    def test_success_preserves_user_files_and_tor(self):
        before = {p.name: (p.read_bytes(), p.stat().st_mode, p.stat().st_mtime_ns)
                  for p in self.app.files() + [self.root/'.env']}
        tor = copy.deepcopy(self.app.objects['tor-a'])
        self.assertEqual(self.app.upgrade(NEW), 'services_healthy_verify_mining')
        for name, values in before.items():
            p = self.root/name
            self.assertEqual((p.read_bytes(), p.stat().st_mode, p.stat().st_mtime_ns), values)
        self.assertEqual(tor, self.app.objects['tor-a'])
        record = self.app.state()
        directory = self.app.transaction_dir(record)
        self.assertEqual((directory/'.env').read_bytes(), before['.env'][0])
        self.assertEqual((directory/'.env').stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.app.store.stat().st_mode & 0o777, 0o700)
        for call in self.app.calls:
            if 'up' in call:
                self.assertEqual(call[-2:], ['gateway', 'ingress'])
                self.assertIn('--no-deps', call)
                self.assertIn('--no-build', call)
            self.assertNotIn('down', call)
            self.assertNotIn('prune', call)
        self.assertIn(str(self.app.store/'active.json'), self.app.compose())

    def test_candidate_runs_without_network_mounts_or_config(self):
        self.app.upgrade(NEW)
        call = next(c for c in self.app.calls if 'run' in c)
        self.assertEqual(call[call.index('--network')+1], 'none')
        self.assertNotIn('--env-file', call)
        self.assertNotIn('--mount', call)
        self.assertNotIn('-v', call)
        self.assertIn('--read-only', call)
        self.assertEqual(call[-2:], ['/app/gateway.py', 'selfcheck'])

    def test_tls_overlay_is_opt_in_and_included_in_settings_preservation(self):
        self.assertNotIn(self.app.root/'compose.tls.yaml', self.app.files())
        (self.app.root/'compose.tls.yaml').write_text('services: {}\n')
        self.app.settings['TLS_ENABLED'] = '1'
        self.assertIn(self.app.root/'compose.tls.yaml', self.app.files())
        self.assertIn('compose.tls.yaml', self.app.hashes())

    def test_failed_candidate_never_recreates_services(self):
        self.app.fail_test = True
        with self.assertRaises(u.Blocked):
            self.app.upgrade(NEW)
        self.assertFalse(any('up' in c for c in self.app.calls))
        self.assertFalse((self.app.store/'active.json').exists())

    def test_failed_start_automatically_restores_exact_old_images(self):
        self.app.fail_start = True
        self.assertEqual(self.app.upgrade(NEW), 'upgrade_failed_rolled_back')
        self.assertEqual(self.app.state()['phase'], 'rolled_back')
        self.assertTrue(all(self.app.objects[s]['Image'] == OLD for s in u.TRANSPORT))

    def test_interruption_during_cutover_rolls_back(self):
        self.app.interrupt_start = True
        self.assertEqual(self.app.upgrade(NEW), 'upgrade_failed_rolled_back')

    def test_effective_custom_settings_change_triggers_rollback(self):
        self.app.settings_drift = True
        self.assertEqual(self.app.upgrade(NEW), 'upgrade_failed_rolled_back')
        self.assertEqual(self.app.objects['gateway']['HostConfig']['Memory'], 123456789)

    def test_failed_rollback_is_explicit_and_retryable(self):
        self.app.fail_start = self.app.fail_restore = True
        with self.assertRaisesRegex(u.Blocked, 'rollback_failed'):
            self.app.upgrade(NEW)
        self.assertEqual(self.app.state()['phase'], 'rollback_failed')
        self.app.fail_restore = False
        self.assertEqual(self.app.rollback(), 'rolled_back_verify_mining')

    def test_manual_rollback_preserves_settings(self):
        self.app.upgrade(NEW)
        env = (self.root/'.env').read_bytes()
        self.assertEqual(self.app.rollback(), 'rolled_back_verify_mining')
        self.assertEqual((self.root/'.env').read_bytes(), env)
        self.assertEqual(self.app.rollback(), 'already_rolled_back')

    def test_operator_edit_is_never_overwritten_by_rollback(self):
        self.app.upgrade(NEW)
        (self.root/'.env').write_text('# changed by operator\n')
        with self.assertRaisesRegex(u.Blocked, 'settings_changed'):
            self.app.rollback()
        self.assertEqual((self.root/'.env').read_text(), '# changed by operator\n')

    def test_settings_change_during_test_prevents_cutover(self):
        self.app.drift_on_test = True
        with self.assertRaises(u.Blocked):
            self.app.upgrade(NEW)
        self.assertFalse(any('up' in c for c in self.app.calls))
        self.assertIn('operator edit', (self.root/'.env').read_text())

    def test_unfinished_transaction_blocks_new_upgrade(self):
        u.atomic(self.app.store/'state.json', {'phase': 'pending'})
        with self.assertRaisesRegex(u.Blocked, 'unfinished_upgrade'):
            self.app.upgrade(NEW)
        self.assertEqual(self.app.calls, [])

    def test_config_drift_blocks_before_container_changes(self):
        self.app.objects['gateway']['Config']['Labels']['com.docker.compose.config-hash'] = 'different'
        with self.assertRaisesRegex(u.Blocked, 'config_drift'):
            self.app.upgrade(NEW)
        self.assertFalse(any('up' in c for c in self.app.calls))

    def test_tor_change_is_not_claimed_as_success(self):
        self.app.tor_drift = True
        with self.assertRaisesRegex(u.Blocked, 'rollback_failed'):
            self.app.upgrade(NEW)

    def test_immutable_local_image_required(self):
        for value in ('latest', 'example/image:latest', '', 'sha256:short'):
            with self.assertRaisesRegex(u.Blocked, 'exact_local_image'):
                self.app.upgrade(value)
        self.assertEqual(self.app.calls, [])

    def test_mount_order_is_not_a_settings_change(self):
        first, second = container('gateway'), container('gateway')
        mounts = [{'Target':'/a','Source':'one','ReadOnly':True},
                  {'Target':'/b','Source':'two','ReadOnly':False}]
        first['HostConfig']['Mounts'] = mounts
        second['HostConfig']['Mounts'] = list(reversed(mounts))
        self.assertEqual(u.fingerprint(first), u.fingerprint(second))
        second['HostConfig']['Mounts'][0] = dict(mounts[1], ReadOnly=True)
        self.assertNotEqual(u.fingerprint(first), u.fingerprint(second))

    def test_unset_dns_lists_match_null_but_explicit_dns_drift_is_refused(self):
        for key in ('Dns', 'DnsOptions', 'DnsSearch'):
            first, second = container('gateway'), container('gateway')
            first['HostConfig'][key] = []
            second['HostConfig'][key] = None
            self.assertEqual(u.fingerprint(first), u.fingerprint(second))
            second['HostConfig'][key] = ['changed-fixture']
            self.assertNotEqual(u.fingerprint(first), u.fingerprint(second))

    def test_failed_next_candidate_retains_previous_rollback_target(self):
        self.app.upgrade(NEW)
        previous = self.app.state()
        self.app.fail_test = True
        with self.assertRaises(u.Blocked):
            self.app.upgrade('sha256:'+'3'*64)
        self.assertEqual(self.app.state(), previous)
        self.assertEqual(self.app.rollback(), 'rolled_back_verify_mining')

    def test_symlinked_config_refused(self):
        path = self.root/'compose.override.yaml'
        path.rename(self.root/'original')
        path.symlink_to(self.root/'original')
        with self.assertRaises(OSError):
            self.app.files()

    def test_state_directory_symlink_and_public_permissions_refused(self):
        self.app.store.chmod(0o755)
        with self.assertRaises(u.Blocked):
            u.private_dir(self.app.store)
        target = self.root/'link'
        target.symlink_to(self.app.store)
        with self.assertRaises(u.Blocked):
            u.private_dir(target)

    def test_remote_docker_and_compose_environment_cannot_redirect(self):
        with patch.dict(os.environ, {'DOCKER_HOST': 'tcp://bad', 'DOCKER_CONTEXT': 'remote',
                                    'COMPOSE_FILE': '/private', 'LAN_IP': 'bad'}):
            env = u.command_env({'LAN_IP': '192.168.1.10'})
        self.assertNotIn('DOCKER_HOST', env)
        self.assertNotIn('DOCKER_CONTEXT', env)
        self.assertNotIn('COMPOSE_FILE', env)
        self.assertEqual(env['LAN_IP'], '192.168.1.10')

    def test_no_confirmation_means_no_docker_or_filesystem_actions(self):
        with patch.object(u, 'Upgrader') as constructor, contextlib.redirect_stdout(io.StringIO()) as output:
            code = u.main(['upgrade', '--image', NEW, '--json'])
        constructor.assert_not_called()
        data = json.loads(output.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(data['result'], 'confirmation_required')
        self.assertFalse(data['mutations_performed'])

    def test_private_command_errors_are_suppressed_in_json(self):
        with patch.object(u, 'Upgrader', side_effect=ValueError('PRIVATE_ONION_PASSWORD')), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(u.main(['upgrade-status', '--json']), 1)
        self.assertNotIn('PRIVATE_ONION_PASSWORD', output.getvalue())
        self.assertFalse(json.loads(output.getvalue())['mining_verified'])

    def test_concurrent_upgrade_is_refused(self):
        fd = os.open(self.app.store/'lock', os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with patch.object(u, 'Upgrader', return_value=self.app), contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(u.main(['upgrade','--image',NEW,'--confirm-interruption','--json']),1)
            self.assertEqual(json.loads(output.getvalue())['result'],'upgrade_already_running')
            self.assertEqual(self.app.calls, [])
        finally:
            os.close(fd)

    def test_status_is_read_only_and_does_not_claim_live_health(self):
        with patch.object(u, 'Upgrader', return_value=self.app), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(u.main(['upgrade-status','--json']),0)
        data=json.loads(output.getvalue())
        self.assertEqual(data['result'],'no_upgrade_record')
        self.assertFalse(data['mutations_performed'])
        self.assertEqual(data['status_scope'],'saved_transaction_not_live_health')
        self.assertFalse((self.app.store/'lock').exists())
        self.assertEqual(self.app.calls, [])


if __name__ == '__main__':
    unittest.main()
