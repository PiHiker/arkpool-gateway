import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import http.client
import threading
import os
import subprocess

import platform_export as export


def settings(tls='0'):
    key = bytes(range(32))
    digest = hashlib.sha3_256(b'.onion checksum' + key + b'\x03').digest()[:2]
    onion = base64.b32encode(key + digest + b'\x03').decode().lower() + '.onion'
    return export.checked_settings({'LAN_IP': '192.168.1.10', 'MINER_IPS': 'lan',
                                    'POOL_ONION': onion, 'TLS_ENABLED': tls})


IMAGE = 'registry.example.invalid/arkpool/gateway:fixture@sha256:' + 'a' * 64


class ExportTests(unittest.TestCase):
    def test_checked_in_community_package_matches_generator(self):
        from scripts.build_umbrel_store import build, ROOT
        compose = json.loads((ROOT/'arkpool-gateway/docker-compose.yml').read_text())
        manifest = json.loads((ROOT/'arkpool-gateway/umbrel-app.yml').read_text())
        image = compose['services']['gateway']['image']
        for name, expected in build(image, manifest['submission']).items():
            self.assertEqual((ROOT/name).read_text(), expected, name)
        self.assertEqual(manifest['port'], 23335)
        self.assertEqual(compose['services']['ingress']['ports'][0]['published'], '23333')

    def test_community_store_has_no_operator_configuration(self):
        from scripts.build_umbrel_store import build
        files = build(IMAGE)
        services = json.loads(files['arkpool-gateway/docker-compose.yml'])['services']
        self.assertEqual(services['gateway']['network_mode'], 'none')
        self.assertEqual(services['gateway']['environment']['MINER_IPS'], 'subnet')
        self.assertEqual(services['ingress']['environment']['MINER_IPS'], 'subnet')
        self.assertNotIn('ports', services['web'])
        self.assertNotIn('PROXY_AUTH_ADD', services['app_proxy']['environment'])
        for service in services.values():
            for port in service.get('ports', []):
                self.assertIn('${APP_ARKPOOL_LAN_IP:', port['host_ip'])
            for volume in service.get('volumes', []):
                self.assertIsInstance(volume, str)
                self.assertIn('${APP_DATA_DIR}/data/', volume)
                self.assertNotIn('docker.sock', volume)
        self.assertNotIn('192.168.1.10', files['arkpool-gateway/docker-compose.yml'])
        manifest = json.loads(files['arkpool-gateway/umbrel-app.yml'])
        self.assertEqual(manifest['storage']['dataRoot'], 'data')
        self.assertEqual(manifest['environment'][0]['services'], ['gateway', 'ingress'])

    def test_community_lan_detection_fails_closed(self):
        from scripts.build_umbrel_store import EXPORTS
        cases = [
            ([{'dev': 'eth0'}], '192.168.1.10', 24, True),
            ([], '192.168.1.10', 24, False),
            ([{'dev': 'eth0'}, {'dev': 'eth1'}], '192.168.1.10', 24, False),
            ([{'dev': 'wg0'}], '192.168.1.10', 24, False),
            ([{'dev': 'eth0'}], '203.0.113.1', 24, False),
            ([{'dev': 'eth0'}], '192.168.1.10', 8, False),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            mock = Path(tmp)/'ip'
            mock.write_text('#!/usr/bin/env python3\nimport os,sys\nprint(os.environ["TEST_ROUTES" if "route" in sys.argv else "TEST_ADDRS"])\n')
            mock.chmod(0o755)
            script = Path(tmp)/'exports.sh'; script.write_text(EXPORTS)
            for routes, address, prefix, success in cases:
                env = dict(os.environ, PATH=tmp+':'+os.environ['PATH'], TEST_ROUTES=json.dumps(routes),
                           TEST_ADDRS=json.dumps([{'addr_info': [{'family': 'inet', 'scope': 'global', 'local': address, 'prefixlen': prefix}]}]))
                result = subprocess.run(['bash', '-ec', 'source "$1"; printf "%s %s" "$APP_ARKPOOL_LAN_IP" "$APP_ARKPOOL_LAN_CIDR"', 'test', str(script)],
                                        capture_output=True, text=True, env=env, timeout=10)
                with self.subTest(routes=routes, address=address, prefix=prefix):
                    self.assertEqual(result.returncode == 0, success)
                    if success:
                        self.assertEqual(result.stdout, '192.168.1.10 192.168.1.0/24')

    def test_route_policy_default_opt_in_and_scope_match_across_adapters(self):
        from platform_umbrel import render as umbrel
        from platform_podman import render as podman
        self.assertEqual(settings()['TOR_ROUTE_POLICY'], 'round-robin')
        self.assertEqual(export.checked_settings(settings())['TOR_ISOLATION'], 'miner')
        s = dict(settings(), TOR_ROUTE_POLICY='latency')
        u = json.loads(umbrel(s, IMAGE)['arkpool-gateway/docker-compose.yml'])['services']
        self.assertEqual(u['gateway']['environment']['TOR_ROUTE_POLICY'], 'latency')
        self.assertNotIn('TOR_ROUTE_POLICY', u['web']['environment'])
        self.assertNotIn('TOR_ROUTE_POLICY', u['ingress']['environment'])
        p = podman(s, IMAGE)
        self.assertIn('Environment=TOR_ROUTE_POLICY=latency\n', p['arkpool-gateway.container'])
        self.assertNotIn('TOR_ROUTE_POLICY=', p['arkpool-ingress.container'])
        with self.assertRaises(ValueError): export.checked_settings(dict(s, TOR_ROUTE_POLICY='invalid'))

    def test_preserves_existing_policy_and_destination(self):
        original = dict(settings(), MINER_IPS='192.168.1.70', POOL_PORT='4444')
        self.assertEqual(export.checked_settings(original), original)

    def test_rejects_unsafe_settings(self):
        for patch in ({'LAN_IP': '0.0.0.0'}, {'MINER_IPS': '*'}, {'POOL_ONION': 'example.com'},
                      {'LAN_PORT': '0'}, {'LAN_PORT': '3333\nExecStart=id'},
                      {'LAN_PORT': '$(id)'}, {'LAN_PORT': '%n'}, {'WALLET_KEY': 'secret'},
                      {'TLS_ENABLED': 'yes'}, {'TLS_ENABLED': '1', 'LAN_TLS_PORT': '3333'}):
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                export.checked_settings(dict(settings(), **patch))

    def test_images_are_immutable_without_shell_syntax(self):
        self.assertEqual(export.checked_image(IMAGE, registry=True), IMAGE)
        self.assertEqual(export.checked_image('sha256:'+'b'*64), 'sha256:'+'b'*64)
        for value in ('latest', 'repo:main', 'registry/repo:tag;id', IMAGE+'\nExecStart=id',
                      'https://'+IMAGE, 'user:password@'+IMAGE, 'sha256:'+'b'*64):
            with self.subTest(value=value), self.assertRaises(ValueError):
                export.checked_image(value, registry=True)

    def test_exports_private_and_never_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)/'export'
            export.write_export(out, {'nested/config': 'private\n'})
            self.assertEqual(out.stat().st_mode & 0o777, 0o700)
            self.assertEqual((out/'nested/config').stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                export.write_export(out, {'nested/config': 'replacement'})
            self.assertEqual((out/'nested/config').read_text(), 'private\n')
            link = Path(tmp)/'link'; link.symlink_to(out)
            with self.assertRaises(ValueError):export.write_export(link, {'file': 'x'})

    def test_bad_paths_rejected_before_creating_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ('../escape', '/absolute'):
                out = Path(tmp)/'export'
                with self.assertRaises(ValueError):export.write_export(out, {name: 'x'})
                self.assertFalse(out.exists())
        with self.assertRaises(ValueError):export.write_export(export.ROOT/'generated', {'file': 'x'})
        with tempfile.TemporaryDirectory() as tmp:
            other = Path(tmp)/'other-repo';other.mkdir();(other/'.git').mkdir()
            (other/'.git/HEAD').write_text('ref: refs/heads/main\n')
            with self.assertRaises(ValueError):export.write_export(other/'output', {'file': 'x'})

    def test_export_is_not_mining_evidence(self):
        report = export.evidence('fixture')
        self.assertFalse(report['ready_for_mining'])
        self.assertFalse(report['containers_started'])
        self.assertEqual(report['accepted_share'], 'not_run')
        self.assertNotIn(settings()['POOL_ONION'], json.dumps(report))


class PodmanTests(unittest.TestCase):
    def render(self, tls='0'):
        from platform_podman import render
        return render(settings(tls), IMAGE)

    def test_gateway_remains_networkless_and_not_in_pod(self):
        files = self.render()
        gateway = files['arkpool-gateway.container']
        self.assertIn('Network=none\n', gateway)
        self.assertNotIn('PublishPort=', gateway)
        for name, text in files.items():
            if name.endswith('.container'):
                for required in ('ConditionUser=root', 'ReadOnly=true', 'DropCapability=all',
                                 'NoNewPrivileges=true', 'User=10001', 'Pull=never'):
                    self.assertIn(required, text)
                self.assertNotIn('Pod=', text)
                self.assertNotIn('docker.sock', text)
                self.assertNotIn('Network=host', text)
                self.assertNotIn('HealthOnFailure=', text)

    def test_socket_and_state_sharing_are_scoped(self):
        files = self.render()
        self.assertIn('tor-a-socks.volume:/run/tor-a:ro,z', files['arkpool-gateway.container'])
        self.assertNotIn('state.volume:', files['arkpool-gateway.container'])
        self.assertNotIn('POOL_ONION=', files['arkpool-ingress.container'])
        self.assertNotIn('tor-a-', files['arkpool-tor-b.container'])
        self.assertIn('Copy=false', files['arkpool-tor-a-state.volume'])
        self.assertNotIn('Requires=arkpool-tor', files['arkpool-gateway.container'])

    def test_tls_and_plaintext_ports_preserve_settings(self):
        from platform_podman import render
        s = dict(settings('1'), LAN_PORT='4333', LAN_TLS_PORT='4334', MINER_IPS='192.168.1.70')
        files = render(s, IMAGE)
        ingress = files['arkpool-ingress.container']
        self.assertIn('PublishPort=192.168.1.10:4333:3333/tcp', ingress)
        self.assertIn('PublishPort=192.168.1.10:4334:3334/tcp', ingress)
        self.assertIn('MINER_IPS=192.168.1.70', ingress)
        self.assertIn('arkpool-tls-identity.volume', files)
        self.assertNotIn('TLS_ENABLED=', self.render()['arkpool-ingress.container'])


class ApplianceUITests(unittest.TestCase):
    def test_private_setup_content_and_tls(self):
        import appliance_ui as ui
        content = ui.page(dict(settings('1'), PRIVATE_TOKEN='must-not-appear')).decode()
        for text in ('192.168.1.10', '3333', '3334', 'not a live mining-health', 'No wallet access or mining controls'):
            self.assertIn(text, content)
        for text in ('must-not-appear', settings()['POOL_ONION'], '<script', '<form'):
            self.assertNotIn(text, content)
        for change in ({'LAN_IP': '<script>'}, {'LAN_IP': '8.8.8.8'},
                       {'LAN_PORT': '3333<script>'}, {'TLS_ENABLED': 'yes'}):
            with self.assertRaises(ValueError):ui.page(dict(settings(), **change))

    def test_http_routes_are_read_only_and_have_security_headers(self):
        import appliance_ui as ui
        server = ui.SetupServer(('127.0.0.1', 0), ui.handler(ui.page(settings())))
        thread = threading.Thread(target=server.serve_forever, daemon=True);thread.start()
        try:
            for method, path, status in [('GET', '/', 200), ('HEAD', '/', 200),
                                         ('GET', '/health', 200), ('GET', '/.env', 404),
                                         ('GET', '/telemetry', 404), ('POST', '/', 405)]:
                c = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=3)
                c.request(method, path, headers={'Host': '<script>untrusted</script>'})
                r = c.getresponse();body = r.read()
                self.assertEqual(r.status, status)
                self.assertNotIn(b'untrusted', body)
                if method != 'POST':
                    self.assertEqual(r.getheader('Cache-Control'), 'no-store')
                    self.assertIn("form-action 'none'", r.getheader('Content-Security-Policy'))
                if path == '/health':self.assertFalse(json.loads(body)['mining_verified'])
                c.close()
        finally:
            server.shutdown();server.server_close();thread.join(timeout=3)


class UmbrelTests(unittest.TestCase):
    def render(self, tls='0'):
        from platform_umbrel import render
        files = render(settings(tls), IMAGE)
        return files, json.loads(files['arkpool-gateway/docker-compose.yml'])['services'], json.loads(files['arkpool-gateway/umbrel-app.yml'])

    def test_hardening_and_isolation(self):
        files, services, manifest = self.render()
        self.assertEqual(services['gateway']['network_mode'], 'none')
        self.assertEqual(services['app_proxy']['environment'], {'APP_HOST': 'arkpool-gateway_web_1', 'APP_PORT': '8080'})
        self.assertEqual(set(services['web']['environment']), {'LAN_IP','LAN_PORT','LAN_TLS_PORT','TLS_ENABLED', 'DASHBOARD_ENABLED', 'DASHBOARD_AUTH', 'DASHBOARD_CLIENT_IPS'})
        self.assertNotIn('ports', services['web'])
        self.assertEqual(services['web']['environment']['DASHBOARD_AUTH'], 'platform')
        self.assertEqual(services['web']['environment']['DASHBOARD_CLIENT_IPS'], '0')
        self.assertEqual(services['gateway']['environment']['DASHBOARD_CLIENT_IPS'], '0')
        self.assertEqual(len(services['web']['volumes']), 2)
        for mount in services['web']['volumes']:
            self.assertTrue(mount['read_only'])
            self.assertIn('/data/runtime/dashboard-', mount['source'])
            self.assertTrue(mount['target'].startswith('/run/arkpool-dashboard/'))
        for role in ('gateway', 'ingress'):
            self.assertEqual(services[role]['environment']['DASHBOARD_SNAPSHOTS'], '1')
            own = [m for m in services[role]['volumes'] if m['target'] == '/run/arkpool-dashboard']
            self.assertEqual(len(own), 1)
            self.assertFalse(own[0]['read_only'])
        for role, service in services.items():
            if role == 'app_proxy':continue
            self.assertEqual(service['image'], IMAGE)
            self.assertEqual(service['user'], '1000:1000')
            self.assertTrue(service['read_only'])
            self.assertEqual(service['cap_drop'], ['ALL'])
            for key in ('build', 'container_name', 'privileged', 'cap_add', 'networks'):
                self.assertNotIn(key, service)
            if role != 'ingress':self.assertNotIn('ports', service)

    def test_lifecycle_grace_matches_service_startup_and_shutdown(self):
        _, services, _ = self.render()
        self.assertEqual(services['gateway']['healthcheck']['start_period'], '10m')
        self.assertEqual(services['ingress']['healthcheck']['start_period'], '30s')
        self.assertEqual(services['web']['healthcheck']['start_period'], '30s')
        for role in ('tor-a', 'tor-b'):
            self.assertEqual(services[role]['stop_grace_period'], '30s')
        for role in ('gateway', 'ingress', 'web'):
            self.assertNotIn('stop_grace_period', services[role])

    def test_state_persists_and_transient_sockets_excluded_from_backup(self):
        files, services, manifest = self.render('1')
        self.assertEqual(manifest['storage'], {'dataRoot': 'data'})
        self.assertEqual(manifest['backupIgnore'], ['data/runtime/*'])
        for service in services.values():
            for mount in service.get('volumes', []):
                self.assertEqual(mount['type'], 'bind')
                relative = mount['source'].split('/data/', 1)[1]
                self.assertIn('arkpool-gateway/data/'+relative+'/.gitkeep', files)
        self.assertNotIn('state', json.dumps(services['gateway']['volumes']))
        self.assertIn('tls-identity', json.dumps(services['ingress']['volumes']))

    def test_listener_ports_and_exact_client_policy(self):
        from platform_umbrel import render
        s = dict(settings('1'), MINER_IPS='192.168.1.70', LAN_PORT='5333', LAN_TLS_PORT='5334')
        files = render(s, IMAGE, ui_port=5335)
        services = json.loads(files['arkpool-gateway/docker-compose.yml'])['services']
        self.assertEqual(services['gateway']['environment']['MINER_IPS'], s['MINER_IPS'])
        self.assertEqual([p['published'] for p in services['ingress']['ports']], ['5333', '5334'])
        self.assertTrue(all(p['host_ip'] == s['LAN_IP'] for p in services['ingress']['ports']))
        for port in (5333, 5334, 0, 40001, 65536):
            with self.assertRaises(ValueError):render(s, IMAGE, ui_port=port)
        with self.assertRaises(ValueError):render(s, 'sha256:'+'a'*64)


class StartOSTests(unittest.TestCase):
    def test_native_package_is_external_and_export_stays_blocked(self):
        import platform_startos as startos
        report = startos.report('0.4')
        self.assertEqual(report['status'], 'external_package')
        self.assertTrue(report['native_package_available'])
        self.assertFalse(report['exporter_available'])
        self.assertFalse(report['ready_for_mining'])
        self.assertEqual(report['minimum_os_version'], '0.4.0.2')
        self.assertEqual(report['package_repository'], startos.PACKAGE_REPOSITORY)
        self.assertIn('networkless_gateway_namespace', report['required_checks'])

        unsupported = startos.report('0.3')
        self.assertEqual(unsupported['status'], 'unsupported')
        self.assertFalse(unsupported['native_package_available'])
        self.assertFalse(unsupported['exporter_available'])
        with self.assertRaises(ValueError):startos.render(settings(), IMAGE)
        with self.assertRaises(ValueError):startos.report('unknown')


if __name__ == '__main__':
    unittest.main()
