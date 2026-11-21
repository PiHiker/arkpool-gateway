import base64
import hashlib
import io
import json
import re
import secrets
import shlex
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import preflight
import pairing
import deployment_version
from scripts.build_release import FILES, build
from scripts import check_public_source as source_screen

ROOT = Path(__file__).resolve().parent


class WorkflowTrustTests(unittest.TestCase):
    def test_image_publication_requires_explicit_protected_authorization(self):
        workflow = (ROOT / '.gitlab-ci.yml').read_text()
        blocks = dict(re.findall(r'^([\w-]+):\n(.*?)(?=^[\w-]+:|\Z)', workflow, re.M | re.S))
        publication_control = blocks['variables']
        self.assertRegex(publication_control,
                         r'(?m)^  ARKPOOL_PUBLISH_IMAGES:\n'
                         r'    value: "0"\n'
                         r'    options:\n'
                         r'      - "0"\n'
                         r'      - "1"\n')
        rules = []
        for job in ('publish-native-image', 'publish-multiarch-index'):
            block = blocks[job]
            rule_block = re.search(r'^  rules:\n(.*?)(?=^  \w|\Z)', block, re.M | re.S).group(1)
            expressions = re.findall(r"^    - if: '(.*)'$", rule_block, re.M)
            self.assertEqual(len(expressions), 1)
            self.assertNotIn('when:', rule_block)  # No unconditional/manual escape rule.
            rules.append(expressions)
        self.assertEqual(rules[0], rules[1])
        self.assertIn('extends: publish-multiarch-index', blocks['publish-translator-index'])
        self.assertNotIn('rules:', blocks['publish-translator-index'])
        self.assertIn('needs: [publish-native-image]', blocks['publish-multiarch-index'])

        # Evaluate the actual restricted equality/conjunction rules over launch
        # scenarios; this does not invoke GitLab or execute pipeline scripts.
        def allowed(expression, env):
            results = []
            for clause in expression.split(' && '):
                left, operator, right = shlex.split(clause)
                self.assertEqual(operator, '==')
                resolve = lambda value: env.get(value[1:], '') if value.startswith('$') else value
                results.append(resolve(left) == resolve(right))
            return all(results)

        web_rule = rules[0][0]
        launch = dict(CI_PIPELINE_SOURCE='web', CI_COMMIT_BRANCH='main',
                      CI_DEFAULT_BRANCH='main', CI_COMMIT_REF_PROTECTED='true',
                      ARKPOOL_PUBLISH_IMAGES='1')
        self.assertTrue(allowed(web_rule, launch))
        for source in ('push', 'merge_request_event', 'schedule', 'api', 'trigger', 'parent_pipeline'):
            self.assertFalse(allowed(web_rule, dict(launch, CI_PIPELINE_SOURCE=source)))
        for changed in ({'ARKPOOL_PUBLISH_IMAGES': ''}, {'ARKPOOL_PUBLISH_IMAGES': '0'},
                        {'CI_COMMIT_REF_PROTECTED': 'false'}, {'CI_COMMIT_BRANCH': 'feature'},
                        {'CI_COMMIT_BRANCH': '', 'CI_COMMIT_TAG': 'v0.1.2-alpha.1'}):
            self.assertFalse(allowed(web_rule, dict(launch, **changed)))

        # Open MRs suppress only duplicate push pipelines, not an authorized web run.
        self.assertIn('"push" && $CI_COMMIT_BRANCH && $CI_OPEN_MERGE_REQUESTS', blocks['workflow'])

    def test_published_index_requires_architecture_revision_and_digest(self):
        from scripts.publish_image_index import descriptor, MANIFEST
        body = json.dumps({'schemaVersion': 2, 'mediaType': MANIFEST}).encode()
        digest = 'sha256:' + hashlib.sha256(body).hexdigest()
        revision = 'a' * 40
        config = {'architecture': 'arm64', 'os': 'linux', 'config': {'Labels': {'org.opencontainers.image.revision': revision}}}
        self.assertEqual(descriptor(body, digest, config, 'arm64', revision)['platform']['architecture'], 'arm64')
        for wanted_digest, arch, rev in [('sha256:'+'0'*64, 'arm64', revision), (digest, 'amd64', revision), (digest, 'arm64', 'b'*40)]:
            with self.assertRaises(ValueError):
                descriptor(body, wanted_digest, config, arch, rev)

    def test_registry_redirect_never_leaks_authorization_to_blob_host(self):
        from scripts.publish_image_index import SafeRedirect
        from urllib.request import Request
        request = Request('https://registry.gitlab.com/v2/example/blobs/example', headers={'Authorization': 'Bearer test-only'})
        redirected = SafeRedirect().redirect_request(request, None, 302, '', {}, 'https://storage.example.invalid/blob')
        self.assertIsNone(redirected.get_header('Authorization'))
        with self.assertRaises(ValueError):
            SafeRedirect().redirect_request(request, None, 302, '', {}, 'http://storage.example.invalid/blob')

    def test_operator_runner_only_runs_automatic_jobs_for_release_refs(self):
        workflow = (ROOT / '.forgejo/workflows/ci.yml').read_text()
        triggers = workflow.split('jobs:', 1)[0]
        self.assertNotIn('pull_request:', triggers)
        self.assertIn("branches: ['main']", triggers)
        for pattern in ('hermes/**', 'fix/**', 'feat/**'):
            self.assertNotIn(pattern, triggers)
        self.assertIn('merge_request_event', (ROOT / '.gitlab-ci.yml').read_text())


def onion():
    key = bytes(range(32))
    digest = hashlib.sha3_256(b'.onion checksum' + key + b'\x03').digest()[:2]
    return base64.b32encode(key + digest + b'\x03').decode().lower() + '.onion'


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'VERSION').write_text('0.1.0-alpha.1\n')
        self.env = self.root / '.env'
        self.env.write_text('LAN_IP=192.168.1.10\nMINER_IPS=192.168.1.70\nPOOL_ONION=' + onion() + '\n')
        self.env.chmod(0o600)
        self.calls = []

    def invoke(self, args):
        self.calls.append(args)
        if args[0] == 'ip':
            return json.dumps([{'ifname': 'eth0', 'addr_info': [
                {'family': 'inet', 'local': '192.168.1.10', 'prefixlen': 24}]}])
        if args[0] == 'ss':
            return ''
        if 'compose' in args:
            return '2.26.1\n'
        return '{"Os":"linux"}'

    def report(self, invoke=None):
        with patch('preflight.shutil.disk_usage', return_value=shutil._ntuple_diskusage(10**10, 0, 10**10)):
            return preflight.run(self.root, invoke or self.invoke)

    def test_read_only_secret_free(self):
        before = self.env.read_bytes(), self.env.stat().st_mode, self.env.stat().st_mtime_ns
        report, code = self.report()
        self.assertIn(code, (0, 2))  # Low-memory test hosts may report a warning.
        self.assertFalse(report['mutations_performed'])
        self.assertFalse(report['ready_for_mining'])
        self.assertNotIn(onion(), json.dumps(report))
        self.assertNotIn('192.168.1.10', json.dumps(report))
        self.assertEqual(before, (self.env.read_bytes(), self.env.stat().st_mode, self.env.stat().st_mtime_ns))
        self.assertEqual(set(a[0] for a in self.calls), {'docker', 'ip', 'ss'})
        self.assertTrue(all(a[1:3] == ['--host', 'unix:///var/run/docker.sock'] for a in self.calls if a[0]=='docker'))

    def test_missing_config(self):
        self.env.unlink()
        self.assertEqual(self.report()[1], 1)

    def test_route_policy_is_literal_optional_and_validated_without_probe(self):
        original = self.env.read_text()
        for policy in ('latency', 'round-robin'):
            self.env.write_text(original + 'TOR_ROUTE_POLICY=' + policy + '\n')
            self.assertEqual(preflight.read_settings(self.env)['TOR_ROUTE_POLICY'], policy)
        for policy in ('fastest', 'yes', 'latency;id'):
            self.env.write_text(original + 'TOR_ROUTE_POLICY=' + policy + '\n')
            with self.assertRaises(ValueError): preflight.read_settings(self.env)

    def test_symlink_rejected(self):
        self.env.rename(self.root / 'private')
        self.env.symlink_to(self.root / 'private')
        self.assertEqual(self.report()[1], 1)

    def test_dashboard_client_ip_optin_is_validated_and_preserved(self):
        from upgrade import Upgrader
        shutil.copyfile(ROOT / 'compose.yaml', self.root / 'compose.yaml')
        original = self.env.read_text()
        for value in ('0', '1'):
            self.env.write_text(original + 'DASHBOARD_CLIENT_IPS=' + value + '\n')
            before = self.env.read_bytes(), self.env.stat().st_mtime_ns
            instance = Upgrader(self.root)
            self.assertEqual(instance.settings['DASHBOARD_CLIENT_IPS'], value)
            self.assertEqual(instance.env['DASHBOARD_CLIENT_IPS'], value)
            self.assertIn('compose', instance.compose())
            self.assertEqual(before, (self.env.read_bytes(), self.env.stat().st_mtime_ns))
        for value in ('yes', 'true', '2', '-1'):
            self.env.write_text(original + 'DASHBOARD_CLIENT_IPS=' + value + '\n')
            with self.subTest(value=value), self.assertRaises(ValueError):
                Upgrader(self.root)

    def test_permissions_not_repaired(self):
        self.env.chmod(0o644)
        self.assertEqual(self.report()[1], 1)
        self.assertEqual(self.env.stat().st_mode & 0o777, 0o644)

    def test_config_must_belong_to_the_deployment_owner(self):
        with patch('preflight.os.geteuid', return_value=self.env.stat().st_uid + 1):
            with self.assertRaises(ValueError):
                preflight.read_settings(self.env)
            self.assertEqual(self.report()[1], 1)
        self.assertEqual(preflight.read_settings(self.env)['LAN_PORT'], '3333')

    def test_literal_parser_rejects_expansion_duplicates_and_extra_keys(self):
        original = self.env.read_text()
        for extra in ('LAN_PORT=$(id)\n', 'LAN_IP=192.168.1.11\n', 'WALLET_KEY=private\n', 'LAN_PORT=0\n'):
            with self.subTest(extra=extra):
                self.env.write_text(original + extra)
                with self.assertRaises(ValueError):
                    preflight.read_settings(self.env)

    def test_occupied_port_is_review_not_repair(self):
        def invoke(args):
            return 'LISTEN 0 128 0.0.0.0:3333 0.0.0.0:*\n' if args[0]=='ss' else self.invoke(args)
        report, code = self.report(invoke)
        self.assertEqual(code, 2)
        self.assertEqual(next(c['status'] for c in report['checks'] if c['check']=='listener_port'), 'warn')

    def test_detected_lan_cidr_and_overlap_warning(self):
        self.env.write_text('LAN_IP=192.168.1.10\nMINER_IPS=subnet\nLAN_CIDR=192.168.1.0/24\nPOOL_ONION=' + onion() + '\n')
        self.assertEqual(preflight.suggested_lan_cidr(self.root, self.invoke), '192.168.1.0/24')
        report, _ = self.report()
        self.assertEqual(next(c['status'] for c in report['checks'] if c['check'] == 'lan_cidr'), 'pass')
        self.assertEqual(next(c['status'] for c in report['checks'] if c['check'] == 'network_overlap'), 'pass')

        def overlap(args):
            if args[0] == 'ip':
                return json.dumps([
                    {'ifname': 'eth0', 'addr_info': [
                        {'family': 'inet', 'local': '192.168.1.10', 'prefixlen': 24}]},
                    {'ifname': 'docker0', 'addr_info': [
                        {'family': 'inet', 'local': '192.168.1.1', 'prefixlen': 24}]},
                ])
            return self.invoke(args)
        report, code = self.report(overlap)
        self.assertEqual(code, 2)
        self.assertEqual(next(c['status'] for c in report['checks'] if c['check'] == 'network_overlap'), 'warn')

    def test_nonmatching_lan_cidr_requires_review_without_rewriting_config(self):
        self.env.write_text('LAN_IP=192.168.1.10\nMINER_IPS=subnet\nLAN_CIDR=192.168.0.0/16\nPOOL_ONION=' + onion() + '\n')
        before = self.env.read_bytes()
        report, code = self.report()
        self.assertEqual(code, 2)
        self.assertEqual(next(c['status'] for c in report['checks'] if c['check'] == 'lan_cidr'), 'warn')
        self.assertEqual(self.env.read_bytes(), before)

    def test_unavailable_tools_fail_safely(self):
        self.assertEqual(self.report(lambda _: None)[1], 1)

    def test_tls_is_optional_and_ports_only_conflict_when_enabled(self):
        self.assertEqual(preflight.read_settings(self.env)['TLS_ENABLED'], '0')
        original = self.env.read_text()
        self.env.write_text(original + 'LAN_PORT=3334\n')
        self.assertEqual(preflight.read_settings(self.env)['LAN_PORT'], '3334')
        self.env.write_text(original + 'TLS_ENABLED=1\nLAN_PORT=3334\n')
        with self.assertRaises(ValueError):
            preflight.read_settings(self.env)
        self.env.write_text(original + 'TLS_ENABLED=1\nLAN_TLS_PORT=4444\n')
        self.assertEqual(preflight.read_settings(self.env)['LAN_TLS_PORT'], '4444')
        for value in ('yes', '2', 'true'):
            self.env.write_text(original + 'TLS_ENABLED=' + value + '\n')
            with self.assertRaises(ValueError):
                preflight.read_settings(self.env)

    def test_shhark_status_token_and_port_are_private_literal_settings(self):
        original = self.env.read_text()
        self.env.write_text(original + 'SHHARK_STATUS_TOKEN=' + 'a' * 64 + '\n')
        settings = preflight.read_settings(self.env)
        self.assertEqual(settings['SHHARK_STATUS_PORT'], '3335')
        for extra in ('SHHARK_STATUS_TOKEN=short\n', 'SHHARK_STATUS_TOKEN=' + 'A' * 64 + '\n',
                      'SHHARK_STATUS_PORT=3335\n',
                      'SHHARK_STATUS_TOKEN=' + 'a' * 64 + '\nSHHARK_STATUS_PORT=3333\n'):
            self.env.write_text(original + extra)
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                preflight.read_settings(self.env)

    def test_tls_port_is_checked_only_when_enabled(self):
        def invoke(args):
            if args[0] == 'ss':
                return 'LISTEN 0 128 192.168.1.10:3334 0.0.0.0:*\n'
            return self.invoke(args)
        report, _ = self.report(invoke)
        self.assertEqual(next(c['status'] for c in report['checks'] if c['check'] == 'listener_port'), 'pass')
        with self.env.open('a') as stream:
            stream.write('TLS_ENABLED=1\n')
        report, _ = self.report(invoke)
        self.assertEqual(next(c['status'] for c in report['checks'] if c['check'] == 'listener_port'), 'warn')

    def test_shhark_status_port_is_checked_only_when_enabled(self):
        def invoke(args):
            if args[0] == 'ss':
                return 'LISTEN 0 128 192.168.1.10:3335 0.0.0.0:*\n'
            return self.invoke(args)
        report, _ = self.report(invoke)
        self.assertEqual(next(c['status'] for c in report['checks']
                             if c['check'] == 'listener_port'), 'pass')
        with self.env.open('a') as stream:
            stream.write('SHHARK_STATUS_TOKEN=' + 'a' * 64 + '\n')
        report, _ = self.report(invoke)
        self.assertEqual(next(c['status'] for c in report['checks']
                             if c['check'] == 'listener_port'), 'warn')


class DeploymentVersionTests(unittest.TestCase):
    def test_running_images_are_allowlisted_and_missing_metadata_is_unknown(self):
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'VERSION').write_text('0.1.2-alpha.1\n')
            instance = Mock(root=root)
            instance.compose.return_value = ['docker', 'compose']
            image = 'sha256:' + 'a' * 64
            expected = 'b' * 40
            def run(args):
                if 'ps' in args:
                    return args[-1]
                if 'container' in args:
                    return json.dumps([{'Image': image, 'State': {'Running': True},
                                        'Config': {'Env': ['SECRET=never-publish']}}])
                return json.dumps([{'Config': {'Labels': {
                    'org.opencontainers.image.revision': expected,
                    'org.opencontainers.image.version': '0.1.2-alpha.1',
                    'private': 'never-publish'}}}])
            instance.run.side_effect = run
            result = deployment_version.report(instance, expected)
            self.assertEqual(len(result['services']), 4)
            self.assertTrue(all(s['matches_expected'] for s in result['services']))
            self.assertNotIn('never-publish', json.dumps(result))
            instance.run.side_effect = lambda args: (args[-1] if 'ps' in args else
                json.dumps([{'Image': image, 'State': {'Running': True}, 'Config': {}}]))
            result = deployment_version.report(instance, expected)
            self.assertTrue(all(s['revision'] is None and s['matches_expected'] is None
                                for s in result['services']))

    def test_source_without_own_git_metadata_never_inherits_parent_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'VERSION').write_text('0.1.2-alpha.1\n')
            value = deployment_version.source(root)
            self.assertIsNone(value['revision'])
            self.assertIsNone(value['dirty'])


class PairingExportTests(unittest.TestCase):
    def test_export_is_private_and_refuses_unexpected_or_mismatched_data(self):
        profile = {'format': 'arkpool-gateway-pairing', 'version': 1, 'host': '192.168.1.10',
                   'tlsPort': 3334, 'plaintextPort': 3333,
                   'caCertificate': '-----BEGIN CERTIFICATE-----\nSYNTHETIC\n-----END CERTIFICATE-----\n'}
        with tempfile.TemporaryDirectory() as directory, patch.object(pairing, 'Upgrader') as factory:
            instance = factory.return_value
            instance.settings = {'LAN_IP': '192.168.1.10', 'LAN_PORT': '3333', 'TLS_ENABLED': '1'}
            instance.compose.return_value = ['docker', '--host', 'unix:///var/run/docker.sock', 'compose']
            instance.run.return_value = json.dumps(profile)
            output = pairing.export(Path(directory))
            self.assertEqual(json.loads(output.read_text()), profile)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(output.parent.stat().st_mode & 0o777, 0o700)
            command = instance.run.call_args.args[0]
            self.assertIn('unix:///var/run/docker.sock', command)
            self.assertEqual(command[-5:], ['-T', 'ingress', 'python3', '/app/tls_identity.py', 'export'])
            for changes in ({'extra': 'must-not-export'}, {'host': '192.168.1.99'}, {'tlsPort': 9999}):
                instance.run.return_value = json.dumps(dict(profile, **changes))
                with self.assertRaises(ValueError):
                    pairing.export(Path(directory))
                self.assertEqual(json.loads(output.read_text()), profile)

    def test_export_when_disabled_never_calls_docker(self):
        with patch.object(pairing, 'Upgrader') as factory:
            factory.return_value.settings = {'TLS_ENABLED': '0'}
            with self.assertRaises(ValueError):
                pairing.export(Path('/unused'))
            factory.return_value.run.assert_not_called()


class ReleaseAllowlistTests(unittest.TestCase):
    def test_current_tracked_tree_matches_release_allowlist(self):
        # The archive fixtures below copy FILES; by themselves they cannot
        # detect a required tracked file missing from the production allowlist.
        if (ROOT / '.git').exists():
            tracked = subprocess.check_output(
                ['git', '-C', str(ROOT), 'ls-files', '-z']).decode().split('\0')
            tracked = set(filter(None, tracked))
        else:
            # Downloaded source archives intentionally contain no Git history.
            tracked = set(json.loads((ROOT / 'SOURCE.json').read_text())['files'])
        self.assertEqual(len(FILES), len(set(FILES)), 'duplicate release entry')
        self.assertEqual(tracked, set(FILES), 'review new tracked files for release packaging')


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'repo'
        self.root.mkdir()
        for name in FILES:
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, target)
        self.git('init', '-q')
        self.git('config', 'user.name', 'Release test')
        self.git('config', 'user.email', 'release-test@example.invalid')
        self.git('add', '.')
        self.git('commit', '-qm', 'fixture')
        self.git('tag', 'v' + (self.root/'VERSION').read_text().strip())

    def git(self, *args):
        return subprocess.check_output(['git','-C',str(self.root),*args], stderr=subprocess.DEVNULL)

    def test_deterministic_and_private_files_excluded(self):
        secret = secrets.token_hex(32)
        (self.root / '.env').write_text(secret)
        private_backup = self.root / '.arkpool-upgrade'
        private_backup.mkdir(mode=0o700)
        (private_backup/'state.json').write_text(secret)
        (self.root/'.arkpool-pairing').mkdir(mode=0o700)
        (self.root/'.arkpool-pairing/gateway.json').write_text(secret)
        build(self.root, self.base/'one')
        (self.root / '.env').write_text('CHANGED_PRIVATE_CONFIGURATION')
        build(self.root, self.base/'two')
        first = next((self.base/'one').glob('*.tar.gz')).read_bytes()
        second = next((self.base/'two').glob('*.tar.gz')).read_bytes()
        self.assertEqual(first, second)
        with tarfile.open(fileobj=io.BytesIO(first),mode='r:gz') as archive:
            names = [m.name.split('/',1)[1] for m in archive.getmembers()]
            self.assertEqual(set(names),set(FILES)|{'SOURCE.json'})
            for member in archive.getmembers():
                self.assertTrue(member.isfile())
                self.assertNotIn(secret.encode(),archive.extractfile(member).read())
        for line in (self.base/'one'/'SHA256SUMS').read_text().splitlines():
            digest,name=line.split('  ',1)
            self.assertEqual(hashlib.sha256((self.base/'one'/name).read_bytes()).hexdigest(),digest)

    def test_dirty_worktree_rejected(self):
        (self.root/'README.md').write_text('changed')
        with self.assertRaises(ValueError):build(self.root,self.base/'out')

    def test_source_archive_includes_mit_license_unchanged(self):
        expected = (self.root/'LICENSE').read_bytes()
        self.assertIn(b'MIT License', expected)
        self.assertIn(b'Copyright (c) 2026 PiHiker', expected)
        self.assertIn('LICENSE', FILES)
        build(self.root, self.base/'licensed')
        archive_path = next((self.base/'licensed').glob('*.tar.gz'))
        with tarfile.open(archive_path, mode='r:gz') as archive:
            member = next(m for m in archive.getmembers() if m.name.endswith('/LICENSE'))
            self.assertEqual(archive.extractfile(member).read(), expected)

    def test_new_tracked_file_cannot_be_silently_omitted(self):
        (self.root/'new_required_module.py').write_text('# synthetic module\n')
        self.git('add', 'new_required_module.py')
        self.git('commit', '-qm', 'new source fixture')
        self.git('tag', '-f', 'v'+(self.root/'VERSION').read_text().strip())
        with self.assertRaisesRegex(ValueError, 'exactly match'):
            build(self.root, self.base/'out')
        self.assertFalse((self.base/'out').exists())

    def test_tracked_private_file_is_rejected_not_automatically_packaged(self):
        (self.root/'.env').write_text('SYNTHETIC_PRIVATE_CONFIGURATION')
        self.git('add', '-f', '.env')
        self.git('commit', '-qm', 'private file fixture')
        self.git('tag', '-f', 'v'+(self.root/'VERSION').read_text().strip())
        with self.assertRaisesRegex(ValueError, 'exactly match'):
            build(self.root, self.base/'out')
        self.assertFalse((self.base/'out').exists())

    def test_missing_tag_rejected(self):
        self.git('tag','-d','v'+(self.root/'VERSION').read_text().strip())
        with self.assertRaises(subprocess.CalledProcessError):build(self.root,self.base/'out')

    def test_output_inside_repo_rejected(self):
        with self.assertRaises(ValueError):build(self.root,self.root/'dist')

    def test_symlink_blob_rejected(self):
        target=self.root/'README.md'
        target.unlink()
        target.symlink_to('/etc/passwd')
        self.git('add','README.md');self.git('commit','-qm','symlink fixture')
        self.git('tag','-f','v'+(self.root/'VERSION').read_text().strip())
        with self.assertRaises(ValueError):build(self.root,self.base/'out')

    def test_existing_destination_not_overwritten(self):
        dest=self.base/'out';dest.mkdir();(dest/'keep').write_text('preserve')
        with self.assertRaises(FileExistsError):build(self.root,dest)
        self.assertEqual((dest/'keep').read_text(),'preserve')

    def test_public_endpoint_is_valid_and_new_defaults_need_no_miner_list(self):
        target = self.root / '.env'
        shutil.copyfile(self.root / '.env.example', target)
        target.chmod(0o600)
        settings = preflight.read_settings(target)
        self.assertEqual(settings['POOL_ONION'], source_screen.PUBLIC_POOL_ONION)
        self.assertEqual(settings['POOL_PORT'], '3333')
        self.assertEqual(settings['MINER_IPS'], 'subnet')
        self.assertEqual(settings['LAN_CIDR'], '192.168.1.0/24')
        self.assertEqual(source_screen.scan(self.root), [])

    def test_shhark_overlay_preserves_explicit_client_ip_opt_in(self):
        overlay = (self.root / 'compose.shhark-status.yaml').read_text()
        self.assertIn('DASHBOARD_CLIENT_IPS: ${DASHBOARD_CLIENT_IPS:-0}', overlay)
        self.assertEqual(overlay.count('\n      DASHBOARD_CLIENT_IPS: '), 1)

    def test_source_screen_allows_only_exact_public_endpoint_in_designated_files(self):
        sample = self.root / '.env.example'
        original = sample.read_text()
        sample.write_text(original + '\n# ' + onion() + '\n')
        self.assertIn('.env.example', source_screen.scan(self.root))
        sample.write_text(original)
        readme = self.root / 'README.md'
        readme.write_text(readme.read_text() + '\n' + source_screen.PUBLIC_POOL_ONION)
        self.assertIn('README.md', source_screen.scan(self.root))

    def test_public_endpoint_exception_does_not_hide_keys(self):
        sample = self.root / '.env.example'
        marker = '-' * 5 + 'BEGIN PRIVATE KEY' + '-' * 5
        sample.write_text(sample.read_text() + '\n# ' + marker + '\n')
        self.assertIn('.env.example', source_screen.scan(self.root))

    def test_source_screen_flags_private_lan_details_outside_public_fixtures(self):
        readme = self.root / 'README.md'
        original = readme.read_text()
        # Split fixtures so the source-policy test does not itself publish the
        # concrete values that it is verifying will be rejected.
        for address in ('10' + '.23.45.67', '172' + '.20.40.60',
                        '192' + '.168.44.55', '10' + '.23.0.0/16'):
            with self.subTest(address=address):
                readme.write_text(original + '\n' + address + '\n')
                self.assertIn('README.md', source_screen.scan(self.root))
        readme.write_text(original)
        self.assertNotIn('README.md', source_screen.scan(self.root))

    def test_source_screen_flags_common_service_credentials(self):
        readme = self.root / 'README.md'
        original = readme.read_text()
        markers = ('glpat-' + 'a' * 24, 'ghp_' + 'b' * 36,
                   'github_pat_' + 'c' * 40, 'sk-or-v1-' + 'd' * 48,
                   'AKIA' + 'E' * 16, 'xoxb-' + 'f' * 24)
        for marker in markers:
            with self.subTest(marker=marker.split('-', 1)[0]):
                readme.write_text(original + '\n' + marker + '\n')
                self.assertIn('README.md', source_screen.scan(self.root))
        readme.write_text(original)


if __name__ == '__main__':
    unittest.main()
