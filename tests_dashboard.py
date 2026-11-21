"""Synthetic snapshot/UI checks. No platform credentials, miners or pool access."""
import asyncio
import http.client
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import appliance_ui as ui
import dashboard_status as status


def gateway():
    return {'sessions': [{'route': 'tor-1', 'job_state': 'fresh', 'last_job_age_seconds': 1,
                          'counts': {'accepted': 3, 'rejected': 1}, 'client_ip': '192.168.1.70',
                          'difficulty': 1000, 'accepted_work': 3000, 'username': 'secret'}],
            'tor_isolation': 'miner',
            'account_fingerprints': ['a' * 64],
            'routes': [{'route': name, 'bootstrap_ready': True, 'cooldown_seconds': 0,
                        'connection_attempts': 2, 'connection_successes': 1,
                        'cookie': 'secret'} for name in ('tor-1', 'tor-2')],
            'mining': {'submitted': 5, 'accepted': 3, 'rejected': 1, 'unanswered': 1,
                       'raw_frame': 'secret'}, 'private': 'secret'}


def ingress():
    return {'listener_ready': True, 'tls_enabled': True, 'accepting_new_tls': True,
            'ca_maintenance_due': False, 'server_expires_at': 2e9, 'ca_expires_at': 3e9,
            'private_key': 'secret'}


def envelope(role, now=None):
    now = time.time() if now is None else now
    source = gateway() if role == 'gateway' else ingress()
    return {'schema_version': 1, 'role': role, 'process': 'a'*32,
            'started_at': now - 100, 'sampled_at': now, 'data': status.clean(role, source)}


class SnapshotTests(unittest.TestCase):
    def test_translator_acknowledgments_do_not_invent_per_session_counts(self):
        source = gateway()
        source.update(upstream_protocol='SV2', counter_basis='aggregate_pool_acknowledgments')
        source['sessions'][0]['counts'] = {'accepted': None, 'rejected': None}
        source['sessions'][0].pop('accepted_work')
        result = status.gateway_view(source)
        self.assertIsNone(result['sessions'][0]['accepted'])
        self.assertEqual(result['mining']['accepted'], 3)
        with tempfile.TemporaryDirectory() as tmp:
            value = envelope('gateway'); value['data'] = result
            status.write_snapshot(tmp, value)
            observed = status.read_snapshot(tmp, 'gateway')['data']
            self.assertEqual(observed['upstream_protocol'], 'SV2')
            self.assertIsNone(observed['sessions'][0]['rejected'])
        source['upstream_protocol'] = 'SV1'
        with self.assertRaises(ValueError):
            status.gateway_view(source)

    def test_route_bootstrap_is_not_end_to_end_mining_evidence(self):
        source = gateway()
        result = status.gateway_view(source)
        self.assertEqual(result['routes'][0]['work_state'], 'fresh_jobs')
        self.assertEqual(result['routes'][1]['work_state'], 'unverified')
        source['sessions'][0]['job_state'] = 'stale'
        self.assertEqual(status.gateway_view(source)['routes'][0]['work_state'], 'stale_jobs')
        source['routes'][1]['probe'] = {'samples': 3, 'successes': 3, 'last_success': True,
            'median_ms': 400, 'last_sample_age_seconds': 20}
        self.assertEqual(status.gateway_view(source)['routes'][1]['work_state'], 'subscription_verified')
        source['routes'][0]['bootstrap_ready'] = False
        self.assertEqual(status.gateway_view(source)['routes'][0]['work_state'], 'tor_unready')

    def test_share_outcomes_roundtrip_without_fabricating_pending_on_old_snapshots(self):
        source = gateway()
        self.assertIsNone(status.gateway_view(source)['mining']['pending_submissions'])
        source['mining'].update(pending_submissions=2, unknown_responses=1)
        value = envelope('gateway')
        value['data'] = status.gateway_view(source)
        with tempfile.TemporaryDirectory() as tmp:
            status.write_snapshot(tmp, value)
            result = status.read_snapshot(tmp, 'gateway')
        self.assertEqual(result['state'], 'current')
        self.assertEqual(result['data']['mining']['pending_submissions'], 2)
        self.assertEqual(result['data']['mining']['unknown_responses'], 1)
        self.assertNotIn('secret', json.dumps(result))

    def test_pending_share_gauge_is_a_bounded_integer(self):
        for invalid in (-1, 1025, 0.5, True, '1', [], float('nan')):
            source = gateway(); source['mining']['pending_submissions'] = invalid
            with self.subTest(value=invalid), self.assertRaises(ValueError):
                status.gateway_view(source)

    def test_probe_summary_and_preference_are_allowlisted_with_old_snapshot_compatibility(self):
        source = gateway()
        old = status.gateway_view(source)
        self.assertEqual(old['route_selection']['policy'], 'round-robin')
        self.assertIsNone(old['routes'][0]['probe']['median_ms'])
        source['route_selection'] = {'policy': 'latency', 'preferred_route': 'tor-2', 'reason': 'faster', 'secret': 'secret'}
        source['routes'][1]['probe'] = {'samples': 3, 'successes': 3, 'last_success': True,
            'median_ms': 400, 'last_sample_age_seconds': 20, 'destination': 'secret'}
        result = status.gateway_view(source)
        self.assertEqual(result['route_selection']['preferred_route'], 'tor-2')
        self.assertEqual(result['routes'][1]['probe']['median_ms'], 400)
        self.assertNotIn('secret', json.dumps(result))
        with tempfile.TemporaryDirectory() as tmp:
            value = envelope('gateway'); value['data'] = result
            status.write_snapshot(tmp, value)
            self.assertEqual(status.read_snapshot(tmp, 'gateway')['data']['route_selection'], result['route_selection'])

    def test_tor_isolation_policy_is_allowlisted_and_old_snapshots_are_compatible(self):
        source = gateway()
        self.assertEqual(status.gateway_view(source)['tor_isolation'], 'miner')
        with tempfile.TemporaryDirectory() as tmp:
            status.write_snapshot(tmp, envelope('gateway'))
            self.assertEqual(status.read_snapshot(tmp, 'gateway')['data']['tor_isolation'], 'miner')
        del source['tor_isolation']
        self.assertEqual(status.gateway_view(source)['tor_isolation'], 'unknown')
        for invalid in ('ip', 'Miner', '', True, {}, None):
            source = gateway(); source['tor_isolation'] = invalid
            with self.subTest(value=invalid), self.assertRaises(ValueError):
                status.gateway_view(source)

    def test_admission_summary_is_allowlisted_and_old_snapshots_are_derived(self):
        old = status.gateway_view(gateway())
        self.assertEqual(old['admission']['state'], 'ready')
        source = gateway()
        source['admission'] = {'state': 'cooldown', 'eligible_routes': 0,
            'heartbeat_ready_routes': 2, 'total_routes': 2, 'secret': 'secret'}
        result = status.gateway_view(source)
        self.assertEqual(result['admission']['state'], 'cooldown')
        self.assertNotIn('secret', json.dumps(result))
        for invalid in ([], {'state': 'secret', 'eligible_routes': 0, 'heartbeat_ready_routes': 0, 'total_routes': 2},
                {'state': 'ready', 'eligible_routes': 2, 'heartbeat_ready_routes': 1, 'total_routes': 2},
                {'state': 'ready', 'eligible_routes': 0, 'heartbeat_ready_routes': 2, 'total_routes': 2},
                {'state': 'cooldown', 'eligible_routes': 0, 'heartbeat_ready_routes': 0, 'total_routes': 2}):
            source = gateway(); source['admission'] = invalid
            with self.subTest(value=invalid), self.assertRaises(ValueError):
                status.gateway_view(source)

    def test_per_route_activity_is_allowlisted_with_old_snapshot_compatibility(self):
        old = status.gateway_view(gateway())
        self.assertEqual(old['routes'][0]['active_sessions'], 1)
        self.assertEqual(old['routes'][0]['mining']['accepted'], 0)
        source = gateway()
        source['routes'][0].update(active_sessions=1,
            mining={'jobs': 9, 'submitted': 3, 'accepted': 2, 'rejected': 1,
                    'pending_submissions': 0, 'private': 'secret'})
        result = status.gateway_view(source)
        self.assertEqual(result['routes'][0]['mining']['accepted'], 2)
        self.assertNotIn('secret', json.dumps(result))
        for field, value in (('active_sessions', 9), ('active_sessions', 2),
                             ('active_sessions', True), ('mining', [])):
            source = gateway(); source['routes'][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                status.gateway_view(source)

    def test_invalid_probe_stats_and_unknown_selection_are_refused(self):
        for probe in ([], 'private', {'samples': 6}, {'samples': True},
                      {'samples': 1, 'successes': 2}, {'median_ms': float('nan')},
                      {'samples': 3, 'successes': 3, 'last_success': True, 'median_ms': -1, 'last_sample_age_seconds': 0},
                      {'samples': 1, 'successes': 0, 'last_success': False, 'last_sample_age_seconds': 901}):
            source = gateway(); source['routes'][0]['probe'] = probe
            with self.subTest(probe=probe), self.assertRaises(ValueError): status.gateway_view(source)
        for selection in ([], {'policy': 'latency', 'preferred_route': 'secret', 'reason': 'faster'},
                          {'policy': 'latency', 'preferred_route': None, 'reason': 'secret'}):
            source = gateway(); source['route_selection'] = selection
            with self.assertRaises(ValueError): status.gateway_view(source)

    def test_allowlist_drops_all_unrecognized_fields(self):
        for role, source in [('gateway', gateway()), ('ingress', ingress())]:
            result = status.clean(role, source)
            self.assertNotIn('secret', json.dumps(result))
            self.assertNotIn('private', json.dumps(result))
        self.assertEqual(status.gateway_view(gateway())['active_sessions'], 1)

    def test_account_fingerprints_are_hash_only_bounded_and_backward_compatible(self):
        source = gateway()
        self.assertEqual(status.gateway_view(source)['account_fingerprints'], ['a' * 64])
        old = gateway(); del old['account_fingerprints']
        self.assertEqual(status.gateway_view(old)['account_fingerprints'], [])
        for invalid in (['A' * 64], ['a' * 63], ['a' * 64, 'a' * 64],
                        ['b' * 64, 'a' * 64], ['a' * 64] * 9, 'a' * 64):
            source = gateway(); source['account_fingerprints'] = invalid
            with self.subTest(value=invalid), self.assertRaises(ValueError):
                status.gateway_view(source)

    def test_difficulty_weighted_work_is_allowlisted_without_fabricating_old_values(self):
        result = status.gateway_view(gateway())['sessions'][0]
        self.assertEqual(result['difficulty'], 1000)
        self.assertEqual(result['accepted_work'], 3000)
        old = gateway(); del old['sessions'][0]['difficulty']; del old['sessions'][0]['accepted_work']
        result = status.gateway_view(old)['sessions'][0]
        self.assertIsNone(result['difficulty'])
        self.assertIsNone(result['accepted_work'])
        for field, value in (('difficulty', 0), ('accepted_work', -1), ('accepted_work', 0)):
            source = gateway(); source['sessions'][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                status.gateway_view(source)

    def test_client_ips_are_private_validated_and_opt_in_at_both_boundaries(self):
        source = gateway()
        self.assertNotIn('client_ip', status.gateway_view(source)['sessions'][0])
        self.assertEqual(status.gateway_view(source, True)['sessions'][0]['client_ip'], '192.168.1.70')
        for invalid in ('8.8.8.8', '192.168.1.070', 'secret', None):
            source = gateway(); source['sessions'][0]['client_ip'] = invalid
            with self.subTest(value=invalid), self.assertRaises((ValueError, TypeError)):
                status.gateway_view(source, True)
        with tempfile.TemporaryDirectory() as tmp:
            value = envelope('gateway')
            value['data'] = status.clean('gateway', gateway(), True)
            status.write_snapshot(tmp, value)
            self.assertNotIn('client_ip', status.read_snapshot(tmp, 'gateway')['data']['sessions'][0])
            self.assertEqual(status.read_snapshot(tmp, 'gateway', include_client_ips=True)
                             ['data']['sessions'][0]['client_ip'], '192.168.1.70')

    def test_bad_types_numbers_and_labels_are_rejected(self):
        for value in (True, -1, float('inf'), float('nan'), '4', 10**18):
            source = gateway(); source['mining']['accepted'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                status.gateway_view(source)
        for state in ('secret', '<script>', {}, None):
            source = gateway(); source['sessions'][0]['job_state'] = state
            with self.subTest(state=state), self.assertRaises(ValueError):
                status.gateway_view(source)
        source = gateway(); source['routes'][1]['route'] = 'tor-1'
        with self.assertRaises(ValueError): status.gateway_view(source)
        source = gateway(); source['sessions'] *= 9
        with self.assertRaises(ValueError): status.gateway_view(source)

    def test_atomic_private_snapshot_and_redaction_on_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            value = envelope('gateway')
            value['data']['password'] = 'secret'
            value['data']['sessions'][0]['username'] = 'secret'
            status.write_snapshot(tmp, value)
            self.assertEqual((Path(tmp)/'status.json').stat().st_mode & 0o777, 0o600)
            self.assertEqual(len(list(Path(tmp).iterdir())), 1)
            result = status.read_snapshot(tmp, 'gateway')
            self.assertEqual(result['state'], 'current')
            self.assertEqual(result['data']['mining']['accepted'], 3)
            self.assertNotIn('secret', json.dumps(result))

    def test_stale_future_missing_and_wrong_role_hide_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(status.read_snapshot(tmp, 'gateway')['state'], 'unavailable')
            for offset in (-31, 3):
                status.write_snapshot(tmp, envelope('gateway', 1000 + offset))
                self.assertEqual(status.read_snapshot(tmp, 'gateway', 1000), {'state': 'stale', 'data': None})
            status.write_snapshot(tmp, envelope('ingress'))
            self.assertEqual(status.read_snapshot(tmp, 'gateway')['state'], 'unavailable')

    def test_malformed_oversized_nonregular_and_symlink_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)/'status.json'
            for content in ('bad json', '['*40, 'x'*(status.MAX_BYTES+1), '{"schema_version":9}'):
                target.write_text(content)
                self.assertEqual(status.read_snapshot(tmp, 'gateway')['state'], 'unavailable')
            target.unlink()
            os.mkfifo(target)
            self.assertEqual(status.read_snapshot(tmp, 'gateway')['state'], 'unavailable')
            target.unlink()
            other = Path(tmp)/'other'; other.write_text(json.dumps(envelope('gateway')))
            target.symlink_to(other)
            self.assertEqual(status.read_snapshot(tmp, 'gateway')['state'], 'unavailable')
            linked = Path(tmp)/'linked'; linked.symlink_to(tmp)
            with self.assertRaises(OSError): status.write_snapshot(linked, envelope('gateway'))

    def test_writer_replaces_symlink_not_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            other = Path(tmp)/'private'; other.write_text('unchanged')
            (Path(tmp)/'status.json').symlink_to(other)
            status.write_snapshot(tmp, envelope('gateway'))
            self.assertEqual(other.read_text(), 'unchanged')
            self.assertFalse((Path(tmp)/'status.json').is_symlink())

    def test_ingress_status_is_independent_and_optional_tls(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp)/'ingress').mkdir()
            status.write_snapshot(Path(tmp)/'ingress', envelope('ingress'))
            result = status.dashboard(tmp)
            self.assertEqual(result['gateway']['state'], 'unavailable')
            self.assertEqual(result['ingress']['state'], 'current')
        self.assertEqual(status.ingress_view({'listener_ready': True, 'tls_enabled': False}),
                         {'listener_ready': True, 'tls_enabled': False})

    def test_process_marker_changes_without_lifetime_counter_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            value = envelope('gateway'); status.write_snapshot(tmp, value)
            first = status.read_snapshot(tmp, 'gateway')
            value['process'] = 'b'*32; value['data']['mining']['accepted'] = 0
            status.write_snapshot(tmp, value)
            second = status.read_snapshot(tmp, 'gateway')
            self.assertNotEqual(first['process'], second['process'])
            self.assertEqual(second['data']['mining']['accepted'], 0)


class PublisherTests(unittest.IsolatedAsyncioTestCase):
    async def test_disabled_by_default(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(status.start_publisher('gateway', gateway))

    async def test_write_failure_does_not_stop_publisher(self):
        with patch.object(status, 'write_snapshot', side_effect=OSError('secret')) as write:
            task = asyncio.create_task(status.publish('gateway', gateway, interval=.01))
            try:
                await asyncio.sleep(.1)
                self.assertFalse(task.done())
                self.assertGreater(write.call_count, 1)
            finally:
                task.cancel(); await asyncio.gather(task, return_exceptions=True)

    async def test_slow_writer_does_not_block_event_loop_or_queue_writes(self):
        entered, release = threading.Event(), threading.Event()
        def slow(*_):
            entered.set(); release.wait(2)
        with patch.object(status, 'write_snapshot', side_effect=slow) as write:
            task = asyncio.create_task(status.publish('gateway', gateway, interval=.001))
            try:
                await asyncio.wait_for(asyncio.to_thread(entered.wait, 1), 1.5)
                await asyncio.sleep(.02)
                self.assertEqual(write.call_count, 1)
                self.assertFalse(task.done())
            finally:
                release.set(); task.cancel(); await asyncio.gather(task, return_exceptions=True)


class UITests(unittest.TestCase):
    def test_compact_layout_keeps_setup_accessible_without_javascript(self):
        from html.parser import HTMLParser
        class Structure(HTMLParser):
            def __init__(self, content):
                super().__init__(); self.elements = []; self.feed(content)
            def handle_starttag(self, tag, attrs):
                self.elements.append((tag, dict(attrs)))
        env = {'LAN_IP': '192.168.1.10', 'DASHBOARD_ENABLED': '1', 'DASHBOARD_AUTH': 'platform'}
        content = ui.page(env).decode()
        elements = Structure(content).elements
        details = [attrs for tag, attrs in elements if tag == 'details']
        self.assertEqual(details, [{'id': 'miner-setup'}])
        self.assertTrue(any(tag == 'summary' for tag, _ in elements))
        self.assertTrue(any(tag == 'div' and attrs.get('role') == 'region' and
                            attrs.get('tabindex') == '0' for tag, attrs in elements))
        self.assertIn('192.168.1.10', content)
        self.assertIn('Accepted responses are not payments', content)
        self.assertIn('Before you switch', content)
        self.assertNotIn('your administrator', content)
        self.assertIn('hide your public IP address from ArkPool', content)
        self.assertGreaterEqual(content.count('href="https://arkpool.org"'), 2)
        setup = Structure(ui.page({'LAN_IP': '192.168.1.10'}).decode()).elements
        self.assertEqual([attrs for tag, attrs in setup if tag == 'details'],
                         [{'id': 'miner-setup', 'open': None}])

    def test_setup_separates_v2_and_legacy_without_guessing_connection_details(self):
        env={'LAN_IP':'192.168.1.10','DASHBOARD_ENABLED':'1','DASHBOARD_AUTH':'platform'}
        page=ui.page(env).decode()
        self.assertIn('Native Stratum V2',page)
        self.assertIn('V2 connection details are not configured',page)
        self.assertIn('V1 · legacy',page)
        self.assertNotIn('Bitaxe',page)
        env.update(V2_LAN_IP='192.168.1.20',V2_LAN_PORT='4336',V2_AUTHORITY_PUBKEY='1'*48)
        page=ui.page(env).decode()
        self.assertIn('192.168.1.20',page)
        self.assertIn('require authentication',page)
        with self.assertRaises(ValueError):ui.page(dict(env,V2_LAN_IP='8.8.8.8'))
        with self.assertRaises(ValueError):ui.page(dict(env,V2_AUTHORITY_PUBKEY='<script>'))

    def test_dashboard_requires_explicit_platform_auth_and_no_controls(self):
        env = {'LAN_IP': '192.168.1.10', 'DASHBOARD_ENABLED': '1'}
        with self.assertRaises(ValueError): ui.page(env)
        page = ui.page(dict(env, DASHBOARD_AUTH='platform')).decode()
        self.assertIn('Gateway overview', page)
        self.assertIn('id="status" class="status-pill neutral"', page)
        self.assertIn('id="status-detail" class="status-detail"', page)
        self.assertIn('No wallet access', page)
        self.assertNotIn('<form', page)
        self.assertIn('/dashboard.js', page)
        self.assertNotIn('https://cdn', page)
        self.assertNotIn('Miner IP', page)
        self.assertIn('Accepted work', page)
        self.assertIn('different miners compare fairly', page)
        private_page = ui.page(dict(env, DASHBOARD_AUTH='platform', DASHBOARD_CLIENT_IPS='1')).decode()
        self.assertIn('Miner IP', private_page)
        self.assertIn('data-client-ips="1"', private_page)

    def test_http_is_readonly_no_cache_no_cross_origin_no_arbitrary_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            server = ui.SetupServer(('127.0.0.1', 0), ui.handler(b'fixture', Path(tmp)))
            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
            try:
                for method, path, code in [('GET', '/api/status', 200), ('HEAD', '/api/status', 200),
                                          ('POST', '/api/status', 405), ('GET', '/dashboard.js', 200),
                                          ('GET', '/api/status?file=.env', 404), ('GET', '/.env', 404),
                                          ('GET', '/../../etc/passwd', 404), ('GET', '/health', 200)]:
                    conn = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=2)
                    conn.request(method, path, headers={'Origin': 'https://example.invalid'})
                    response = conn.getresponse(); body = response.read()
                    self.assertEqual(response.status, code)
                    self.assertIsNone(response.getheader('Access-Control-Allow-Origin'))
                    if method != 'POST':
                        self.assertEqual(response.getheader('Cache-Control'), 'no-store')
                        self.assertIn("script-src 'self'", response.getheader('Content-Security-Policy'))
                    if path == '/health': self.assertFalse(json.loads(body)['mining_verified'])
                    if method == 'GET' and path == '/api/status':
                        self.assertEqual(json.loads(body)['gateway']['state'], 'unavailable')
                    conn.close()
            finally:
                server.shutdown(); server.server_close(); thread.join(timeout=3)

    def test_slow_header_cannot_block_other_status_requests(self):
        import socket
        with tempfile.TemporaryDirectory() as tmp:
            handler = ui.handler(b'fixture', Path(tmp))
            handler.header_timeout_seconds = .1
            server = ui.SetupServer(('127.0.0.1', 0), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
            slow = socket.create_connection(('127.0.0.1', server.server_port), timeout=1)
            try:
                slow.sendall(b'G')
                conn = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=1)
                conn.request('GET', '/health')
                response = conn.getresponse(); response.read()
                self.assertEqual(response.status, 200)
                conn.close()
                time.sleep(.15)
                self.assertEqual(slow.recv(1), b'')
            finally:
                slow.close()
                server.shutdown(); server.server_close(); thread.join(timeout=3)

    def test_shhark_status_api_requires_exact_bearer_and_has_no_ui(self):
        with tempfile.TemporaryDirectory() as tmp:
            token = 'a' * 64
            server = ui.SetupServer(('127.0.0.1', 0), ui.handler(b'', Path(tmp), token, True))
            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
            try:
                for authorization, code in ((None, 401), ('Bearer ' + 'b' * 64, 401),
                                             ('Bearer ' + token, 200)):
                    headers = {} if authorization is None else {'Authorization': authorization}
                    conn = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=2)
                    conn.request('GET', '/api/status', headers=headers)
                    response = conn.getresponse(); response.read()
                    self.assertEqual(response.status, code)
                    conn.close()
                conn = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=2)
                for path in ('/', '/dashboard.js'):
                    conn = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=2)
                    conn.request('GET', path)
                    response = conn.getresponse(); response.read()
                    self.assertEqual(response.status, 404)
                    conn.close()
            finally:
                server.shutdown(); server.server_close(); thread.join(timeout=3)


if __name__ == '__main__':
    unittest.main()
