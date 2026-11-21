"""Offline transport tests. No hashing, real pool, Tor exit, or wallet access."""
import asyncio
import base64
import contextlib
from dataclasses import replace
import hashlib
import io
import ipaddress
import json
import os
import socket
from pathlib import Path
import struct
import tempfile
import time
import unittest
from unittest import mock

import gateway
import ingress
import tor_health
import tor_supervisor
import route_quality as quality


def example_onion():
    public = bytes(range(32))
    checksum = hashlib.sha3_256(b".onion checksum" + public + b"\x03").digest()[:2]
    return base64.b32encode(public + checksum + b"\x03").decode().lower() + ".onion"


class TorControlTests(unittest.TestCase):
    def test_torrc_cancels_dormancy_at_startup(self):
        directives = [
            line.split('#', 1)[0].split()
            for line in Path(__file__).with_name('torrc').read_text().splitlines()
        ]
        self.assertEqual(
            [parts for parts in directives if parts and parts[0] == 'DormantCanceledByStartup'],
            [['DormantCanceledByStartup', '1']],
        )

    def test_existing_loopback_control_is_unchanged(self):
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(tor_health.socket, 'create_connection') as tcp:
            tor_health.control_connection()
            tcp.assert_called_once_with(('127.0.0.1', 9051), timeout=2)

    def test_unix_control_uses_only_fixed_private_socket(self):
        with mock.patch.dict(os.environ, {'TOR_CONTROL_UNIX':'1'}, clear=True), \
                mock.patch.object(tor_health.socket, 'socket') as unix, \
                mock.patch.object(tor_health.socket, 'create_connection') as tcp:
            tor_health.control_connection()
            unix.assert_called_once_with(socket.AF_UNIX, socket.SOCK_STREAM)
            unix.return_value.connect.assert_called_once_with('/var/lib/tor/control.sock')
            unix.return_value.settimeout.assert_called_once_with(2)
            tcp.assert_not_called()

    def test_unix_failure_closes_and_never_falls_back_to_tcp(self):
        with mock.patch.dict(os.environ, {'TOR_CONTROL_UNIX':'1'}, clear=True), \
                mock.patch.object(tor_health.socket, 'socket') as unix, \
                mock.patch.object(tor_health.socket, 'create_connection') as tcp:
            unix.return_value.connect.side_effect = OSError('unavailable')
            with self.assertRaises(OSError):
                tor_health.control_connection()
            unix.return_value.close.assert_called_once()
            tcp.assert_not_called()

    def test_invalid_control_mode_fails_closed(self):
        for value in ('', 'true', '2', '/tmp/control.sock'):
            with mock.patch.dict(os.environ, {'TOR_CONTROL_UNIX':value}, clear=True), self.assertRaises(ValueError):
                tor_health.control_connection()

    def test_invalid_cookie_never_opens_control_connection(self):
        for cookie in (b'', b'x' * 31, b'x' * 33):
            with self.subTest(length=len(cookie)), \
                    mock.patch.object(Path, 'read_bytes', return_value=cookie), \
                    mock.patch.object(tor_health, 'control_connection') as connect:
                self.assertFalse(tor_health.ready())
                connect.assert_not_called()

    def test_readiness_requires_authenticated_complete_bootstrap(self):
        responses = (
            (b'250 OK\r\n250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done\r\n250-network-liveness=up\r\n250 OK\r\n', True),
            (b'250 OK\r\n250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done\r\n250-network-liveness=down\r\n250 OK\r\n', False),
            (b'250 OK\r\n250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done\r\n', False),
            (b'250 OK\r\n250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=99 TAG=loading\r\n', False),
            (b'515 Authentication failed\r\n250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done\r\n', False),
            (b'250 OK\r\n', False),
            (b'', False),
        )
        for response, expected in responses:
            with self.subTest(expected=expected, response=response), \
                    mock.patch.object(Path, 'read_bytes', return_value=b'x' * 32), \
                    mock.patch.object(tor_health, 'control_connection') as connect:
                connection = connect.return_value.__enter__.return_value
                connection.recv.side_effect = [response, b'']
                self.assertEqual(tor_health.ready(), expected)
                connection.sendall.assert_called_once_with(
                    b'AUTHENTICATE ' + (b'x' * 32).hex().encode() +
                    b'\r\nGETINFO status/bootstrap-phase network-liveness\r\nQUIT\r\n')

    def test_control_timeout_and_missing_cookie_fail_closed(self):
        with mock.patch.object(Path, 'read_bytes', side_effect=FileNotFoundError), \
                mock.patch.object(tor_health, 'control_connection') as connect:
            self.assertFalse(tor_health.ready())
            connect.assert_not_called()
        with mock.patch.object(Path, 'read_bytes', return_value=b'x' * 32), \
                mock.patch.object(tor_health, 'control_connection') as connect:
            connect.return_value.__enter__.return_value.recv.side_effect = TimeoutError
            self.assertFalse(tor_health.ready())
            connect.return_value.__exit__.assert_called_once()


class TorSupervisorTests(unittest.TestCase):
    def test_unix_supervisor_disables_tcp_control(self):
        for mode in ('0', '1'):
            with self.subTest(mode=mode), \
                    mock.patch.dict(os.environ, {'TOR_CONTROL_UNIX': mode}, clear=True), \
                    mock.patch.object(tor_supervisor, 'HEARTBEAT'), \
                    mock.patch.object(tor_supervisor.signal, 'signal'), \
                    mock.patch.object(tor_supervisor.subprocess, 'Popen') as spawn:
                spawn.return_value.poll.return_value = 0
                self.assertEqual(tor_supervisor.main(), 1)
                expected = ['tor', '-f', '/app/torrc']
                if mode == '1':
                    expected += ['--ControlPort', '0', '--ControlSocket', '/var/lib/tor/control.sock']
                self.assertEqual(spawn.call_args.args[0], expected)

    def test_invalid_mode_never_launches_tor(self):
        with mock.patch.dict(os.environ, {'TOR_CONTROL_UNIX': 'invalid'}, clear=True), \
                mock.patch.object(tor_supervisor, 'HEARTBEAT') as heartbeat, \
                mock.patch.object(tor_supervisor.subprocess, 'Popen') as spawn:
            with self.assertRaises(ValueError):
                tor_supervisor.main()
            heartbeat.unlink.assert_called_once_with(missing_ok=True)
            spawn.assert_not_called()

    def test_bootstrap_and_post_bootstrap_watchdogs_stop_only_child(self):
        for initially_ready, clock in ((False, [0, 601]), (True, [0, 1, 182])):
            stopped = mock.Mock()
            stopped.is_set.return_value = False
            with self.subTest(initially_ready=initially_ready), \
                    mock.patch.dict(os.environ, {'TOR_CONTROL_UNIX': '1'}, clear=True), \
                    mock.patch.object(tor_supervisor, 'HEARTBEAT') as heartbeat, \
                    mock.patch.object(tor_supervisor, 'ready', side_effect=([True, False] if initially_ready else [False])), \
                    mock.patch.object(tor_supervisor.signal, 'signal'), \
                    mock.patch.object(tor_supervisor.threading, 'Event', return_value=stopped), \
                    mock.patch.object(tor_supervisor.time, 'monotonic', side_effect=clock), \
                    mock.patch.object(tor_supervisor.subprocess, 'Popen') as spawn, \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                child = spawn.return_value
                child.poll.return_value = None
                self.assertEqual(tor_supervisor.main(), 1)
                child.terminate.assert_called_once()
                child.wait.assert_called_once_with(timeout=tor_supervisor.CHILD_STOP_TIMEOUT)
                child.kill.assert_not_called()
                heartbeat.unlink.assert_called_with(missing_ok=True)
                self.assertIn('Tor readiness stalled; restarting container', output.getvalue())

    def test_unresponsive_child_is_killed_after_shutdown_deadline(self):
        stopped = mock.Mock()
        stopped.is_set.return_value = False
        with mock.patch.dict(os.environ, {'TOR_CONTROL_UNIX': '1'}, clear=True), \
                mock.patch.object(tor_supervisor, 'HEARTBEAT'), \
                mock.patch.object(tor_supervisor, 'ready', return_value=False), \
                mock.patch.object(tor_supervisor.signal, 'signal'), \
                mock.patch.object(tor_supervisor.threading, 'Event', return_value=stopped), \
                mock.patch.object(tor_supervisor.time, 'monotonic', side_effect=[0, 601]), \
                mock.patch.object(tor_supervisor.subprocess, 'Popen') as spawn, \
                contextlib.redirect_stdout(io.StringIO()):
            child = spawn.return_value
            child.poll.return_value = None
            child.wait.side_effect = [tor_supervisor.subprocess.TimeoutExpired(
                'tor', tor_supervisor.CHILD_STOP_TIMEOUT), 0]
            self.assertEqual(tor_supervisor.main(), 1)
            child.terminate.assert_called_once()
            child.kill.assert_called_once()
            self.assertEqual(child.wait.call_args_list, [
                mock.call(timeout=tor_supervisor.CHILD_STOP_TIMEOUT), mock.call()])

    def test_signal_wakes_supervisor_and_uses_one_cleanup_path(self):
        handlers = {}
        state = {'stopped': False}
        stopped = mock.Mock()
        stopped.is_set.side_effect = lambda: state['stopped']
        stopped.set.side_effect = lambda: state.__setitem__('stopped', True)

        def register(sig, handler):
            handlers[sig] = handler

        def interrupt(_timeout):
            handlers[tor_supervisor.signal.SIGTERM]()
            return True

        stopped.wait.side_effect = interrupt
        with mock.patch.dict(os.environ, {'TOR_CONTROL_UNIX': '1'}, clear=True), \
                mock.patch.object(tor_supervisor, 'HEARTBEAT'), \
                mock.patch.object(tor_supervisor, 'ready', return_value=False), \
                mock.patch.object(tor_supervisor.signal, 'signal', side_effect=register), \
                mock.patch.object(tor_supervisor.threading, 'Event', return_value=stopped), \
                mock.patch.object(tor_supervisor.time, 'monotonic', side_effect=[0, 1]), \
                mock.patch.object(tor_supervisor.subprocess, 'Popen') as spawn:
            child = spawn.return_value
            child.poll.return_value = None
            self.assertEqual(tor_supervisor.main(), 0)
            stopped.wait.assert_called_once_with(tor_supervisor.CHECK_INTERVAL)
            child.terminate.assert_called_once()
            child.wait.assert_called_once_with(timeout=tor_supervisor.CHILD_STOP_TIMEOUT)


class ConfigurationTests(unittest.TestCase):
    def config(self, **changes):
        values = dict(LAN_IP="192.168.1.10", MINER_IPS="192.168.1.70", POOL_ONION=example_onion())
        values.update(changes)
        return gateway.Config.load(values)

    def test_three_fields_are_sufficient_and_no_wallet_secret_is_needed(self):
        self.assertEqual(self.config().port, 3333)
        self.assertEqual(self.config().miners, frozenset({"192.168.1.70"}))

    def test_production_selfcheck_uses_no_external_state(self):
        self.assertTrue(gateway.selfcheck())

    def test_bind_must_be_rfc1918_not_wildcard_loopback_or_public(self):
        for address in ("0.0.0.0", "127.0.0.1", "203.0.113.1", "100.64.0.1", "169.254.1.2", "172.32.0.1", "::1", "192.168.001.1"):
            with self.subTest(address=address), self.assertRaises(ValueError):
                self.config(LAN_IP=address)

    def test_exact_private_miner_allowlist(self):
        for value in ("", "0.0.0.0/0", "192.168.1.0/24", "192.168.1.10", "example.org", "127.0.0.1"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.config(MINER_IPS=value)
        self.assertEqual(len(self.config(MINER_IPS="192.168.1.70,192.168.1.71").miners), 2)

    def test_miner_allowlist_is_bounded(self):
        miners = ",".join(f"192.168.1.{number}" for number in range(1, 18))
        with self.assertRaises(ValueError):
            self.config(MINER_IPS=miners)

    def test_lan_mode_allows_only_rfc1918_sources_in_both_services(self):
        policy = self.config(MINER_IPS="lan").miners
        self.assertEqual(policy, ingress.allowed_miners(dict(LAN_IP="192.168.1.10", MINER_IPS="lan")))
        for source in ("10.0.0.1", "10.255.255.254", "172.16.0.1", "172.31.255.254", "192.168.1.70"):
            self.assertTrue(gateway.miner_allowed(source, policy), source)
        for source in ("8.8.8.8", "172.15.255.254", "172.32.0.1", "127.0.0.1",
                       "169.254.1.2", "100.64.0.1", "0.0.0.0", "224.0.0.1",
                       "255.255.255.255", "::1", "fc00::1", "::ffff:192.168.1.70", "invalid"):
            self.assertFalse(gateway.miner_allowed(source, policy), source)

    def test_lan_mode_cannot_be_mixed_or_enable_a_wildcard(self):
        for value in ("LAN", "lan,192.168.1.70", "*", "private", "0.0.0.0/0"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.config(MINER_IPS=value)

    def test_subnet_mode_requires_explicit_private_cidr_containing_listener(self):
        policy = self.config(MINER_IPS="subnet", LAN_CIDR="192.168.1.0/24").miners
        self.assertEqual(policy, frozenset({"subnet:192.168.1.0/24"}))
        self.assertEqual(policy, ingress.allowed_miners(dict(
            LAN_IP="192.168.1.10", MINER_IPS="subnet", LAN_CIDR="192.168.1.0/24")))
        self.assertTrue(gateway.miner_allowed("192.168.1.70", policy))
        for source in ("10.0.0.1", "192.168.1.070", "::ffff:192.168.1.70", "invalid"):
            self.assertFalse(gateway.miner_allowed(source, policy), source)

        for cidr in ("", "192.168.1.10/24", "10.1.0.0/24", "192.168.1.10/32",
                     "0.0.0.0/0", "100.64.0.0/10", "2001:db8::/64"):
            with self.subTest(cidr=cidr), self.assertRaises(ValueError):
                self.config(MINER_IPS="subnet", LAN_CIDR=cidr)

    def test_existing_exact_ip_policy_is_not_broadened(self):
        policy = self.config().miners
        self.assertTrue(gateway.miner_allowed("192.168.1.70", policy))
        self.assertFalse(gateway.miner_allowed("192.168.1.71", policy))
        self.assertFalse(gateway.miner_allowed("10.0.0.1", policy))

    def test_optional_account_pins_require_exact_allowed_sources_and_hashes(self):
        fingerprint = 'a' * 64
        config = self.config(MINER_ACCOUNT_PINS='192.168.1.70=' + fingerprint)
        self.assertEqual(config.account_pins, (('192.168.1.70', fingerprint),))
        invalid = (
            dict(MINER_ACCOUNT_PINS='192.168.1.71=' + fingerprint),
            dict(MINER_ACCOUNT_PINS='192.168.1.70=' + fingerprint.upper()),
            dict(MINER_ACCOUNT_PINS='192.168.1.70=' + fingerprint[:-1]),
            dict(MINER_ACCOUNT_PINS='192.168.1.70=' + fingerprint +
                 ',192.168.1.70=' + fingerprint),
            dict(MINER_IPS='lan', MINER_ACCOUNT_PINS='192.168.1.70=' + fingerprint),
            dict(MINER_IPS='subnet', LAN_CIDR='192.168.1.0/24',
                 MINER_ACCOUNT_PINS='192.168.1.70=' + fingerprint),
        )
        for values in invalid:
            with self.subTest(values=values), self.assertRaises(ValueError):
                self.config(**values)

    def test_only_checksum_valid_v3_onions(self):
        good = example_onion()
        bad_checksum = ("b" if good[0] != "b" else "c") + good[1:]
        for name in ("pool.example.org", "127.0.0.1", "a" * 16 + ".onion", "a" * 56 + ".onion", bad_checksum,
                     good.upper(), "socks5h://" + good, good + ":3333", good + "\n"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.config(POOL_ONION=name)

    def test_invalid_ports_rejected(self):
        for port in ("0", "65536", "abc", "-1"):
            with self.assertRaises(ValueError):
                self.config(POOL_PORT=port)

    def test_route_preference_is_opt_in_and_strict(self):
        self.assertEqual(self.config().route_policy, 'round-robin')
        self.assertEqual(self.config(TOR_ROUTE_POLICY='latency').route_policy, 'latency')
        for value in ('', 'fastest', 'Latency', 'true'):
            with self.assertRaises(ValueError): self.config(TOR_ROUTE_POLICY=value)

    def test_tor_stream_isolation_policy_is_explicit_and_strict(self):
        self.assertEqual(self.config().tor_isolation, 'miner')
        for value in ('miner', 'session', 'shared'):
            self.assertEqual(self.config(TOR_ISOLATION=value).tor_isolation, value)
        for value in ('', 'ip', 'Miner', 'true'):
            with self.assertRaises(ValueError):
                self.config(TOR_ISOLATION=value)

    def test_dashboard_client_ips_are_private_by_default_and_strictly_opt_in(self):
        self.assertFalse(self.config().dashboard_client_ips)
        self.assertTrue(self.config(DASHBOARD_CLIENT_IPS='1').dashboard_client_ips)
        for value in ('', 'true', 'yes', '2'):
            with self.assertRaises(ValueError):
                self.config(DASHBOARD_CLIENT_IPS=value)

    def test_health_refuses_missing_stale_future_or_malformed_tor_heartbeat(self):
        with tempfile.TemporaryDirectory() as directory:
            heartbeat = Path(directory) / "ready"
            with mock.patch.object(gateway.time, "time", return_value=1000):
                self.assertFalse(gateway.tor_recently_ready(heartbeat))
                for text, expected in (("1000", True), ("975", True), ("900", False), ("1001", False), ("invalid", False)):
                    heartbeat.write_text(text)
                    self.assertEqual(gateway.tor_recently_ready(heartbeat), expected)

    def test_bridge_requires_at_least_one_tor_route(self):
        with self.assertRaises(ValueError):
            gateway.Bridge(self.config(), ())

    def test_route_cooldown_backoff_bounded_and_success_resets(self):
        a, b = gateway.TOR_ROUTES
        bridge = gateway.Bridge(self.config())
        with mock.patch.object(gateway, 'tor_recently_ready', return_value=True), mock.patch.object(gateway.time, 'monotonic', return_value=100):
            bridge.route_failed(a)
            self.assertEqual(bridge.route_candidates(), [b])
            for _ in range(10):
                bridge.route_failed(a)
            self.assertEqual(bridge.route_cooldowns[a], 220)
            bridge.route_failed(b)
            self.assertEqual(bridge.route_candidates(), [])
        with mock.patch.object(gateway, 'tor_recently_ready', return_value=True), mock.patch.object(gateway.time, 'monotonic', return_value=221):
            self.assertEqual(set(bridge.route_candidates()), {a, b})
            bridge.route_succeeded(a)
            self.assertNotIn(a, bridge.route_failures)
            self.assertNotIn(a, bridge.route_cooldowns)

    def test_single_route_failure_is_not_counted_as_a_retry(self):
        async def exercise():
            bridge = gateway.Bridge(self.config(), (gateway.TOR_ROUTES[0],))
            with mock.patch.object(gateway, 'tor_recently_ready', return_value=True), \
                    mock.patch.object(gateway, 'socks_connect', mock.AsyncMock(side_effect=OSError('offline'))):
                with self.assertRaises(OSError):
                    await bridge.open_upstream("192.168.1.70")
            self.assertEqual(bridge.route_attempts[gateway.TOR_ROUTES[0]], 1)
            self.assertEqual(bridge.route_retries, 0)
        asyncio.run(exercise())

    def test_health_is_unready_while_every_route_is_cooling_down(self):
        async def check(now, bridge):
            writer = mock.Mock()
            writer.drain = mock.AsyncMock()
            writer.wait_closed = mock.AsyncMock()
            with mock.patch.object(gateway, 'tor_recently_ready', return_value=True), \
                    mock.patch.object(gateway.time, 'monotonic', return_value=now):
                await gateway.health_connection(None, writer, bridge)
            return writer.write.call_args.args[0]

        bridge = gateway.Bridge(self.config())
        bridge.route_cooldowns = {route: 120 for route in bridge.routes}
        with mock.patch.object(gateway, 'tor_recently_ready', return_value=True), \
                mock.patch.object(gateway.time, 'monotonic', return_value=100):
            self.assertEqual(bridge.admission_snapshot(), {'state': 'cooldown', 'eligible_routes': 0,
                'heartbeat_ready_routes': 2, 'total_routes': 2})
        self.assertEqual(asyncio.run(check(100, bridge)), b'unready\n')
        self.assertEqual(asyncio.run(check(121, bridge)), b'ok\n')


class TransportTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.socks_path = str(Path(self.directory.name) / "socks")
        self.ready_path = Path(self.directory.name) / "ready"
        self.ready_path.write_text(str(time.time()), encoding="ascii")
        self.destinations, self.frames = [], []
        self.socks_auth = []
        self.route_hits = []
        self.mode = "echo"
        self.pool_frame = None
        self.fake_tasks = set()
        self.extra_socks = []
        self.socks = await asyncio.start_unix_server(
            lambda reader, writer: self.fake_tor_named("a", reader, writer), self.socks_path)
        # Loopback is exclusively an offline test fixture. Config.load refuses
        # it for real deployments; Docker --network none contains these tests.
        self.bridge = gateway.Bridge(
            gateway.Config("192.168.1.10", frozenset({"127.0.0.1"}), example_onion(), 3333),
            (gateway.TorRoute(self.socks_path, self.ready_path),))
        self.gateway_path = str(Path(self.directory.name) / "gateway.sock")
        self.backend = await asyncio.start_unix_server(self.bridge.handle, self.gateway_path, limit=gateway.MAX_LINE)
        self.ingress = ingress.Ingress(frozenset({"127.0.0.1"}), self.gateway_path)
        self.server = await asyncio.start_server(self.ingress.handle, "127.0.0.1", 0, limit=gateway.MAX_LINE)
        self.port = self.server.sockets[0].getsockname()[1]
        self.clients = []

    async def asyncTearDown(self):
        for writer in self.clients:
            await gateway.close(writer)
        self.server.close()
        self.backend.close()
        self.socks.close()
        for server in self.extra_socks:
            server.close()
        await self.server.wait_closed()
        await self.backend.wait_closed()
        await self.socks.wait_closed()
        for server in self.extra_socks:
            await server.wait_closed()
        await self.ingress.shutdown()
        await self.bridge.shutdown()
        tasks = list(self.fake_tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self.directory.cleanup()

    async def test_job_watchdog_closes_stale_session_and_reconnects_other_route(self):
        await self.add_second_route()
        self.pool_frame = b'{"method":"mining.notify","params":[]}\n'
        with mock.patch.object(gateway, 'JOB_STALE_SECONDS', .08), mock.patch.object(gateway, 'JOB_WATCH_INTERVAL', .01):
            reader, _ = await self.connect()
            self.assertEqual(await asyncio.wait_for(reader.readline(), 1), self.pool_frame)
            self.assertEqual(await asyncio.wait_for(reader.read(), 1), b'')
            self.assertEqual(self.bridge.job_recoveries, 1)
            reader, _ = await self.connect()
            self.assertEqual(await asyncio.wait_for(reader.readline(), 1), self.pool_frame)
            self.assertEqual(self.route_hits[-1], 'b')

    async def connect(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        self.clients.append(writer)
        return reader, writer

    async def fake_tor(self, reader, writer):
        task = asyncio.current_task()
        self.fake_tasks.add(task)
        try:
            self.assertEqual(await reader.readexactly(3), b"\x05\x01\x02")
            if self.mode == "auth_refused":
                writer.write(b"\x05\xff")
                await writer.drain()
                return
            writer.write(b"\x05\x02")
            await writer.drain()
            version, username_length = await reader.readexactly(2)
            self.assertEqual(version, 1)
            username = await reader.readexactly(username_length)
            password_length = (await reader.readexactly(1))[0]
            password = await reader.readexactly(password_length)
            self.socks_auth.append((username, password))
            if self.mode == "auth_login_refused":
                writer.write(b"\x01\x01")
                await writer.drain()
                return
            writer.write(b"\x01\x00")
            await writer.drain()
            self.assertEqual(await reader.readexactly(4), b"\x05\x01\x00\x03")
            length = (await reader.readexactly(1))[0]
            hostname = (await reader.readexactly(length)).decode("ascii")
            port = struct.unpack("!H", await reader.readexactly(2))[0]
            self.destinations.append((hostname, port))
            if self.mode == "refused":
                writer.write(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                return
            if self.mode == "truncated":
                writer.write(b"\x05\x00")
                await writer.drain()
                return
            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            if self.mode == 'early_close':
                await writer.drain()
                return
            if self.pool_frame is not None:
                writer.write(self.pool_frame)
            elif self.mode == "redirect":
                writer.write(b'{"method":"client.reconnect","params":["bad.example",3333]}\n')
            else:
                writer.write(b'{"id":null,"method":"mining.set_difficulty","params":[1]}\n')
            await writer.drain()
            if self.mode == "jobs":
                for _ in range(35):
                    await asyncio.sleep(0.02)
                    writer.write(b'{"method":"mining.notify","params":[]}\n')
                    await writer.drain()
            while line := await reader.readline():
                self.frames.append(line)
                if self.mode == 'subscribe' and json.loads(line).get('method') == 'mining.subscribe':
                    writer.write(b'{"id":43,"result":[[["mining.notify","fixture"]],"",3],"error":null}\n')
                else:
                    writer.write(line)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            await gateway.close(writer)
            self.fake_tasks.discard(task)

    async def fake_tor_named(self, name, reader, writer):
        self.route_hits.append(name)
        await self.fake_tor(reader, writer)

    async def add_second_route(self):
        path = str(Path(self.directory.name) / "socks-b")
        ready = Path(self.directory.name) / "ready-b"
        ready.write_text(str(time.time()), encoding="ascii")
        server = await asyncio.start_unix_server(
            lambda reader, writer: self.fake_tor_named("b", reader, writer), path)
        self.extra_socks.append(server)
        self.bridge.routes = (
            gateway.TorRoute(self.socks_path, self.ready_path),
            gateway.TorRoute(path, ready),
        )
        return path, ready

    async def test_remote_domain_socks_and_exact_username_passthrough(self):
        reader, writer = await self.connect()
        self.assertIn(b"mining.set_difficulty", await asyncio.wait_for(reader.readline(), 2))
        frame = b'{"id":1, "method":"mining.authorize", "params":["PRIVATE_ARK_ADDRESS","x"]}\n'
        writer.write(frame)
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readline(), 2), frame)
        self.assertEqual(self.destinations, [(example_onion(), 3333)])
        self.assertEqual(self.frames, [frame])

    def test_per_miner_tor_isolation_is_stable_and_private(self):
        first = self.bridge.isolation_auth("192.168.1.70")
        self.assertEqual(first, self.bridge.isolation_auth("192.168.1.70"))
        self.assertNotEqual(first, self.bridge.isolation_auth("192.168.1.71"))
        self.assertNotIn(b"192.168.1.70", first)

        self.bridge.config = replace(self.bridge.config, tor_isolation='session')
        self.assertNotEqual(self.bridge.isolation_auth("192.168.1.70"),
                            self.bridge.isolation_auth("192.168.1.70"))
        self.bridge.config = replace(self.bridge.config, tor_isolation='shared')
        self.assertEqual(self.bridge.isolation_auth("192.168.1.70"),
                         self.bridge.isolation_auth("192.168.1.71"))
        route = self.bridge.routes[0]
        first_probe = self.bridge.isolation_auth(route, purpose='probe')
        self.assertEqual(first_probe, self.bridge.isolation_auth(route, purpose='probe'))
        self.assertNotEqual(first_probe, first)
        other = gateway.TorRoute('/tmp/other-socks', '/tmp/other-ready')
        separate = gateway.Bridge(self.bridge.config, routes=(route, other))
        self.assertNotEqual(separate.isolation_auth(route, purpose='probe'),
                            separate.isolation_auth(other, purpose='probe'))
        with self.assertRaises(ValueError):
            self.bridge.isolation_auth(other, purpose='probe')

    async def test_upstream_redirect_is_never_forwarded(self):
        self.mode = "redirect"
        reader, _ = await self.connect()
        self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"")
        self.assertEqual(self.bridge.failed, 1)

    async def test_miner_cannot_request_redirect(self):
        reader, writer = await self.connect()
        self.assertIn(b"mining.set_difficulty", await asyncio.wait_for(reader.readline(), 2))
        writer.write(b'{"id":1,"method":"client.reconnect","params":["bad.example",3333]}\n')
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"")
        self.assertEqual(self.frames, [])

    async def test_ambiguous_redirects_rejected_in_both_directions(self):
        frames = (
            b'{"method":"client.reconnect","method":"mining.notify"}\n',
            b'{"method":"mining.notify","method":"client.reconnect"}\n',
            b'{"Method":"client.reconnect"}\n',
            b'{"method":"mining.notify","METHOD":"client.reconnect"}\n',
            b'{"method":"client.reconnect\\u0000suffix"}\n',
            b'{"method\\u0000suffix":"client.reconnect"}\n',
            b'{"method":"mining.notify","\\u006dethod":"client.reconnect"}\n',
        )
        for frame in frames:
            with self.subTest(direction="pool", frame=frame):
                self.pool_frame = frame
                reader, _ = await self.connect()
                self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"")
            with self.subTest(direction="miner", frame=frame):
                self.pool_frame = None
                reader, writer = await self.connect()
                await asyncio.wait_for(reader.readline(), 2)
                writer.write(frame)
                await writer.drain()
                self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"")
        self.assertEqual(self.frames, [])

    async def test_quiet_miner_survives_jobs_then_idle_session_closes(self):
        self.mode = "jobs"
        with mock.patch.object(gateway, "IDLE_TIMEOUT", 0.25):
            reader, _ = await self.connect()
            self.assertIn(b"mining.set_difficulty", await asyncio.wait_for(reader.readline(), 2))
            # Pool-only activity over multiple idle windows must survive BOTH
            # forwarding layers; no miner submissions or synthetic keepalives.
            for _ in range(35):
                self.assertIn(b"mining.notify", await asyncio.wait_for(reader.readline(), 2))
            self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"")

    async def test_malformed_and_oversize_frames_close_without_logging(self):
        for frame in (b"not-json-PRIVATE\n", b"[]\n", b"\xff\n",
                      b"x" * (gateway.MAX_LINE + 1) + b"\n"):
            output = io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                reader, writer = await self.connect()
                await asyncio.wait_for(reader.readline(), 2)
                writer.write(frame)
                await writer.drain()
                self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"")
            self.assertEqual(output.getvalue(), "")
        self.assertEqual(self.frames, [])

    async def test_unknown_lan_client_cannot_reach_tor(self):
        self.bridge.config = gateway.Config("192.168.1.10", frozenset({"192.168.1.70"}), example_onion(), 3333)
        reader, _ = await self.connect()
        self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"")
        self.assertEqual(self.destinations, [])

    async def test_ingress_refuses_unlisted_client_before_unix_connect(self):
        self.ingress.miners = frozenset({"192.168.1.70"})
        reader, _ = await self.connect()
        self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"")
        self.assertEqual(self.bridge.opened, 0)

    async def test_lan_ingress_checks_actual_peer_before_connect(self):
        listener = ingress.Ingress(frozenset({"lan"}), self.gateway_path)
        for source, allowed in (("10.0.0.1", True), ("172.16.0.1", True),
                                ("192.168.1.71", True), ("8.8.8.8", False),
                                ("127.0.0.1", False), ("100.64.0.1", False),
                                ("::ffff:192.168.1.71", False)):
            writer = mock.Mock()
            writer.get_extra_info.return_value = (source, 12345)
            writer.wait_closed = mock.AsyncMock()
            with mock.patch.object(asyncio, "open_unix_connection", side_effect=OSError) as dial:
                await listener.handle(mock.Mock(), writer)
                self.assertEqual(dial.call_count, int(allowed), source)
            writer.close.assert_called()

    async def test_lan_gateway_rechecks_source_envelope(self):
        self.bridge.config = gateway.Config("192.168.1.10", frozenset({"lan"}), example_onion(), 3333)
        for source, allowed in (("10.0.0.1", True), ("172.31.0.1", True),
                                ("192.168.1.71", True), ("8.8.8.8", False),
                                ("127.0.0.1", False), ("169.254.1.2", False),
                                ("100.64.0.1", False)):
            before = self.bridge.opened
            reader, writer = await asyncio.open_unix_connection(self.gateway_path)
            self.clients.append(writer)
            writer.write(ipaddress.IPv4Address(source).packed)
            await writer.drain()
            response = await asyncio.wait_for(reader.readline(), 2)
            self.assertEqual(bool(response), allowed, source)
            self.assertEqual(self.bridge.opened - before, int(allowed), source)
            await gateway.close(writer)

    async def test_missing_gateway_socket_fails_closed(self):
        self.ingress.upstream_path += "-missing"
        reader, _ = await self.connect()
        self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"")
        self.assertEqual(self.destinations, [])

    async def test_deep_miner_frame_never_reaches_pool(self):
        reader, writer = await self.connect()
        await asyncio.wait_for(reader.readline(), 2)
        frame = b'{"params":' + b'[' * gateway.MAX_JSON_DEPTH + b'0' + b']' * gateway.MAX_JSON_DEPTH + b'}\n'
        writer.write(frame)
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.read(), 2), b'')
        self.assertEqual(self.frames, [])

    async def test_deep_pool_frame_is_blocked_and_next_session_works(self):
        await self.add_second_route()
        self.pool_frame = b'{"result":' + b'[' * gateway.MAX_JSON_DEPTH + b'0' + b']' * gateway.MAX_JSON_DEPTH + b'}\n'
        reader, _ = await self.connect()
        self.assertEqual(await asyncio.wait_for(reader.read(), 2), b'')
        self.pool_frame = None
        reader, writer = await self.connect()
        self.assertIn(b'mining.set_difficulty', await asyncio.wait_for(reader.readline(), 2))
        frame = b'{"id":1,"method":"mining.authorize","params":["ARK_SYNTHETIC","x"]}\n'
        writer.write(frame)
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readline(), 2), frame)
        self.assertEqual(self.frames, [frame])

    async def test_partial_trusted_envelope_is_not_forwarded(self):
        reader, writer = await asyncio.open_unix_connection(self.gateway_path)
        writer.write(b"\x7f\x00")
        await writer.drain()
        writer.write_eof()
        self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"")
        await gateway.close(writer)
        self.assertEqual(self.destinations, [])

    async def test_tor_failure_closes_session_and_never_dials_a_tcp_fallback(self):
        self.socks.close()
        await self.socks.wait_closed()
        Path(self.socks_path).unlink(missing_ok=True)
        reader, _ = await self.connect()
        with mock.patch.object(asyncio, "open_connection", side_effect=AssertionError("direct TCP forbidden")):
            self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"")
        self.assertEqual(self.bridge.opened, 0)

    async def test_bad_socks_responses_fail_closed(self):
        for mode in ("auth_refused", "auth_login_refused", "refused", "truncated"):
            self.mode = mode
            reader, _ = await self.connect()
            self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"")

    async def test_per_source_connection_limit_and_reconnect_after_close(self):
        for _ in range(gateway.MAX_CONNECTIONS_PER_SOURCE):
            reader, _ = await self.connect()
            await asyncio.wait_for(reader.readline(), 2)
        reader, _ = await self.connect()
        self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"")
        self.assertEqual(len(self.destinations), gateway.MAX_CONNECTIONS_PER_SOURCE)
        for writer in self.clients:
            await gateway.close(writer)
        for _ in range(100):
            if not self.bridge.active and not self.ingress.active:
                break
            await asyncio.sleep(0.01)
        reader, _ = await self.connect()
        self.assertIn(b"mining.set_difficulty", await asyncio.wait_for(reader.readline(), 2))

    async def test_global_limit_is_fair_across_source_envelopes(self):
        self.bridge.config = gateway.Config(
            "192.168.1.10", frozenset({"lan"}), example_onion(), 3333)

        async def connect_source(source):
            reader, writer = await asyncio.open_unix_connection(self.gateway_path)
            self.clients.append(writer)
            writer.write(ipaddress.IPv4Address(source).packed)
            await writer.drain()
            return reader

        for source in ("192.168.1.70", "192.168.1.71", "192.168.1.72", "192.168.1.73"):
            for _ in range(gateway.MAX_CONNECTIONS_PER_SOURCE):
                reader = await connect_source(source)
                self.assertIn(b"mining.set_difficulty", await asyncio.wait_for(reader.readline(), 2))

        refused = await connect_source("192.168.1.74")
        try:
            refusal = await asyncio.wait_for(refused.read(), 2)
        except ConnectionResetError:
            refusal = b""
        self.assertEqual(refusal, b"")
        self.assertEqual(len(self.destinations), gateway.MAX_CONNECTIONS)

    async def test_unauthorized_session_releases_reserved_slot_promptly(self):
        with mock.patch.object(gateway, 'AUTHORIZATION_TIMEOUT', .05):
            reader, _ = await self.connect()
            self.assertIn(b'mining.set_difficulty', await asyncio.wait_for(reader.readline(), 2))
            self.assertEqual(await asyncio.wait_for(reader.read(), 1), b'')
        for _ in range(100):
            if not self.bridge.active and not self.ingress.active:
                break
            await asyncio.sleep(.01)
        self.assertFalse(self.bridge.active)
        self.assertFalse(self.ingress.active)

    async def test_pending_shares_settle_on_disconnect_shutdown_and_bad_pool_frame(self):
        for reason in ('disconnect', 'shutdown', 'bad_frame'):
            with self.subTest(reason=reason):
                reader, writer = await self.connect()
                await asyncio.wait_for(reader.readline(), 2)
                payload = b'{"id":7,"method":"mining.submit","params":["UNCHANGED_TEST_IDENTITY"]}\n'
                writer.write(payload)
                await writer.drain()
                self.assertEqual(await asyncio.wait_for(reader.readline(), 2), payload)
                self.assertEqual(self.bridge.snapshot()['mining']['pending_submissions'], 1)
                if reason == 'disconnect':
                    await gateway.close(writer)
                elif reason == 'shutdown':
                    await self.bridge.shutdown()
                else:
                    # The echoing fake pool sends a forbidden redirect; no real upstream.
                    writer.write(b'{"method":"client.reconnect","params":[]}\n')
                    await writer.drain()
                    self.assertEqual(await asyncio.wait_for(reader.read(), 2), b'')
                for _ in range(200):
                    if not self.bridge.active:
                        break
                    await asyncio.sleep(.005)
                self.assertFalse(self.bridge.active)
                self.assertFalse(self.bridge.sessions)
                observed = self.bridge.snapshot()['mining']
                self.assertEqual(observed['submitted'], observed['unanswered'])
                self.assertEqual(observed['pending_submissions'], 0)
                self.assertEqual(observed.get('accepted', 0), 0)
                self.assertEqual(observed.get('rejected', 0), 0)
                self.assertEqual(self.frames.count(payload), observed['submitted'])

    async def test_new_sessions_round_robin_across_ready_tor_routes(self):
        await self.add_second_route()
        first, _ = await self.connect()
        second, _ = await self.connect()
        await asyncio.wait_for(first.readline(), 2)
        await asyncio.wait_for(second.readline(), 2)
        self.assertEqual(self.route_hits[-2:], ["a", "b"])

    async def test_failed_preferred_tor_route_fails_over_without_tcp_fallback(self):
        await self.add_second_route()
        self.socks.close()
        await self.socks.wait_closed()
        Path(self.socks_path).unlink(missing_ok=True)
        reader, _ = await self.connect()
        self.assertIn(b"mining.set_difficulty", await asyncio.wait_for(reader.readline(), 2))
        self.assertEqual(self.route_hits[-1:], ["b"])
        self.assertEqual(self.bridge.route_retries, 1)

    async def test_pool_stream_close_marks_route_failed_after_socks_success(self):
        self.mode = 'early_close'
        reader, _ = await self.connect()
        self.assertEqual(await asyncio.wait_for(reader.read(), 2), b'')
        self.assertIn(self.bridge.routes[0], self.bridge.route_cooldowns)

    async def test_latency_preference_only_affects_new_sessions(self):
        await self.add_second_route()
        self.bridge.config = replace(self.bridge.config, route_policy='latency')
        first, first_writer = await self.connect()
        await asyncio.wait_for(first.readline(), 2)
        for route, ms in zip(self.bridge.routes, (1200, 400)):
            for _ in range(3): self.bridge.route_quality.record(route, ms)
        second, _ = await self.connect()
        await asyncio.wait_for(second.readline(), 2)
        self.assertEqual(self.route_hits[-2:], ['a', 'b'])
        self.assertEqual([s.route for s in self.bridge.sessions.values()], ['tor-1', 'tor-2'])
        original = b'{"id":6,"method":"mining.submit","params":["UNCHANGED_TEST_IDENTITY"]}\n'
        first_writer.write(original); await first_writer.drain()
        self.assertEqual(await asyncio.wait_for(first.readline(), 2), original)
        self.assertEqual(self.bridge.closed, 0)

    async def test_measured_preferred_path_failure_uses_other_path(self):
        await self.add_second_route()
        self.bridge.config = replace(self.bridge.config, route_policy='latency')
        for route, ms in zip(self.bridge.routes, (200, 1000)):
            for _ in range(3): self.bridge.route_quality.record(route, ms)
        self.socks.close(); await self.socks.wait_closed()
        Path(self.socks_path).unlink(missing_ok=True)
        reader, _ = await self.connect()
        self.assertIn(b'mining.set_difficulty', await asyncio.wait_for(reader.readline(), 2))
        self.assertEqual(self.route_hits[-1], 'b')
        self.assertEqual(self.bridge.route_retries, 1)
        self.assertIn(self.bridge.routes[0], self.bridge.route_cooldowns)

    async def test_real_unix_probe_subscribes_without_mining_side_effects(self):
        self.mode = 'subscribe'
        self.bridge.config = replace(self.bridge.config, route_policy='latency')
        before = (self.bridge.opened, self.bridge.closed, dict(self.bridge.mining_totals))
        with mock.patch.object(asyncio, 'open_connection', side_effect=AssertionError('No TCP fallback')):
            await self.bridge.probe_route(self.bridge.routes[0])
        self.assertEqual(self.frames, [quality.SUBSCRIBE])
        self.assertEqual(self.destinations, [(example_onion(), 3333)])
        self.assertEqual(self.bridge.route_quality.snapshot(self.bridge.routes[0])['successes'], 1)
        self.assertEqual(before, (self.bridge.opened, self.bridge.closed, dict(self.bridge.mining_totals)))
        self.assertEqual(self.bridge.route_attempts, {})
        self.assertEqual(self.bridge.route_successes, {})
        self.assertEqual(self.bridge.sessions, {})

    async def test_failed_probe_does_not_close_miner_or_set_route_cooldown(self):
        reader, writer = await self.connect()
        await asyncio.wait_for(reader.readline(), 2)
        await self.bridge.probe_route(self.bridge.routes[0])  # Echo is not a valid subscription.
        sample = self.bridge.route_quality.snapshot(self.bridge.routes[0])
        self.assertEqual((sample['samples'], sample['successes'], sample['last_success']), (1, 0, False))
        self.assertEqual(self.bridge.route_cooldowns, {})
        payload = b'{"id":7,"method":"mining.submit","params":["SYNTHETIC"]}\n'
        writer.write(payload); await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readline(), 2), payload)
        self.assertEqual(self.bridge.closed, 0)


class RouteQualityTests(unittest.TestCase):
    def setUp(self):
        self.q = quality.RouteQuality()
        self.routes = gateway.TOR_ROUTES

    def populate(self, a, b):
        for route, values in zip(self.routes, (a, b)):
            for n, ms in enumerate(values): self.q.record(route, ms, now=100+n)

    def preference(self):
        return self.q.preference(self.routes, now=110)

    def test_minimum_samples_and_all_expired_remain_unbiased(self):
        self.populate([200, 200], [1200, 1200])
        self.assertEqual(self.preference(), (None, 'warming_up'))
        self.populate([200]*3, [1200]*3)
        self.assertEqual(self.preference(), (self.routes[0], 'faster'))
        self.assertEqual(self.q.preference(self.routes, now=1100), (None, 'warming_up'))
        self.assertIsNone(self.q.snapshot(self.routes[0], now=1100)['median_ms'])

    def test_tiny_or_only_percentage_differences_do_not_choose_a_winner(self):
        for a, b in ((768, 779), (100, 150), (1000, 1150)):
            self.q = quality.RouteQuality(); self.populate([a]*3, [b]*3)
            self.assertEqual(self.preference(), (None, 'similar'))

    def test_median_ignores_single_outlier_and_significant_advantage_wins(self):
        self.populate([400, 400, 19000], [1000]*3)
        self.assertEqual(self.preference(), (self.routes[0], 'faster'))
        self.assertEqual(self.q.snapshot(self.routes[0], now=110)['median_ms'], 400)

    def test_reliability_outranks_speed_and_failed_latest_probe_cannot_win(self):
        self.populate([100, 100, None], [1000]*3)
        self.assertEqual(self.preference(), (self.routes[1], 'more_reliable'))
        self.q = quality.RouteQuality()
        self.populate([100, 100, 100, None], [1000]*4)
        self.assertEqual(self.preference(), (self.routes[1], 'more_reliable'))
        self.q = quality.RouteQuality()
        self.populate([None]*3, [None]*3)
        self.assertEqual(self.preference(), (None, 'insufficient_successes'))

    def test_old_success_recovers_only_with_fresh_samples(self):
        self.populate([100]*3, [1000]*3)
        for n in range(5): self.q.record(self.routes[0], None, now=105+n)
        self.assertEqual(self.preference(), (self.routes[1], 'more_reliable'))
        for n in range(5): self.q.record(self.routes[0], 100, now=105+n)
        self.assertEqual(self.preference(), (self.routes[0], 'faster'))
        self.assertEqual(len(self.q.samples[self.routes[0]]), 5)

    def test_invalid_timings_refused_and_future_samples_unused(self):
        for value in (-1, True, '3', float('nan'), float('inf'), 20001):
            with self.assertRaises(ValueError): self.q.record(self.routes[0], value)
        self.q.record(self.routes[0], 100, now=120)
        self.assertEqual(self.q.snapshot(self.routes[0], now=110)['samples'], 0)

    def test_readiness_and_cooldown_override_measurements(self):
        config = gateway.Config('192.168.1.10', frozenset({'lan'}), example_onion(), 3333, 'latency')
        bridge = gateway.Bridge(config)
        bridge.route_quality = self.q
        self.populate([100]*3, [1000]*3)
        with mock.patch.object(gateway.time, 'monotonic', return_value=110), \
                mock.patch.object(gateway, 'tor_recently_ready', return_value=True):
            self.assertEqual(bridge.route_candidates(), list(self.routes))
            bridge.route_cooldowns[self.routes[0]] = 120
            self.assertEqual(bridge.route_candidates(), [self.routes[1]])
            bridge.route_cooldowns[self.routes[1]] = 120
            self.assertEqual(bridge.route_candidates(), [])
        self.assertEqual(self.q.preference([], now=110), (None, 'no_ready'))
        self.assertEqual(self.q.preference([self.routes[1]], now=110), (self.routes[1], 'single_ready'))

    def test_disabled_policy_ignores_scores_and_snapshot_does_not_advance_cursor(self):
        bridge = gateway.Bridge(gateway.Config('192.168.1.10', frozenset({'lan'}), example_onion(), 3333))
        bridge.route_quality = self.q
        self.populate([100]*3, [1000]*3)
        with mock.patch.object(gateway.time, 'monotonic', return_value=110), \
                mock.patch.object(gateway, 'tor_recently_ready', return_value=True):
            bridge.snapshot(); bridge.snapshot()
            self.assertEqual(bridge.route_cursor, 0)
            self.assertEqual(bridge.route_candidates(), list(self.routes))
            self.assertEqual(bridge.route_candidates(), list(reversed(self.routes)))


class RouteProbeTests(unittest.IsolatedAsyncioTestCase):
    async def exercise(self, lines, timeout=1):
        reader = asyncio.StreamReader(limit=gateway.MAX_LINE)
        if lines is not None:
            reader.feed_data(lines); reader.feed_eof()
        writer = mock.Mock(); writer.drain = mock.AsyncMock()
        connect = mock.AsyncMock(return_value=(reader, writer))
        closer = mock.AsyncMock()
        try:
            return await asyncio.wait_for(quality.subscription_probe(connect, gateway.validate_frame, closer), timeout)
        finally:
            self.assertEqual(writer.write.call_args_list, [mock.call(quality.SUBSCRIBE)])
            closer.assert_awaited_once_with(writer)

    async def test_subscription_validation_and_frame_limit(self):
        good = b'{"id":43,"result":[[],"1234",4],"error":null}\n'
        elapsed = await self.exercise(b'{"method":"mining.set_difficulty","params":[1]}\n'+good)
        self.assertGreaterEqual(elapsed, 0)
        self.assertGreaterEqual(await self.exercise(b'{"id":43,"result":[[],"",3],"error":null}\n'), 0)
        for frame in (b'', b'[]\n', b'{"id":43,"result":true}\n',
                      b'{"id":43,"result":[[],"xyz",4]}\n',
                      b'{"id":43,"result":[[],"1234",true]}\n',
                      b'{"id":43,"result":[[],"1234",4],"error":[1,"private"]}\n',
                      b'{"method":"client.reconnect","params":["bad.example",3]}\n',
                      b'{"id":43,"id":43,"result":[[],"1234",4]}\n',
                      b'{"params":'+b'['*40+b'0'+b']'*40+b'}\n',
                      b'x'*(gateway.MAX_LINE+1)+b'\n',
                      b'{"id":0,"result":null}\n'*8+good):
            with self.subTest(frame=frame[:60]), self.assertRaises(ValueError): await self.exercise(frame)

    async def test_total_timeout_and_cancellation_always_close(self):
        with self.assertRaises(asyncio.TimeoutError): await self.exercise(None, timeout=.02)
        task = asyncio.create_task(self.exercise(None))
        await asyncio.sleep(.01); task.cancel()
        with self.assertRaises(asyncio.CancelledError): await task

    async def test_probe_start_is_disabled_by_default_and_shutdown_cleans_up(self):
        bridge = gateway.Bridge(gateway.Config('192.168.1.10', frozenset({'lan'}), example_onion(), 3333))
        self.assertIsNone(bridge.start_probes())
        bridge.config = replace(bridge.config, route_policy='latency')
        with mock.patch.object(gateway, 'tor_recently_ready', return_value=False), \
                mock.patch.object(bridge, 'probe_route', new_callable=mock.AsyncMock) as probe:
            task = bridge.start_probes()
            self.assertIs(task, bridge.start_probes())
            await asyncio.sleep(.01)
            probe.assert_not_awaited()
            await bridge.shutdown()
            self.assertTrue(task.cancelled())

    async def test_scheduler_bounds_warmup_then_slows_down_and_is_sequential(self):
        bridge = gateway.Bridge(gateway.Config('192.168.1.10', frozenset({'lan'}), example_onion(), 3333, 'latency'))
        now, calls, active = [100.0], [], [0]
        async def probe(route):
            active[0] += 1; self.assertEqual(active[0], 1)
            calls.append((route, now[0])); active[0] -= 1
        async def advance(_):
            now[0] += 5
            if now[0] > 450: raise asyncio.CancelledError()
        with mock.patch.object(bridge, 'probe_route', side_effect=probe), \
                mock.patch.object(bridge, 'ready_routes', return_value=list(bridge.routes)), \
                mock.patch.object(gateway.time, 'monotonic', side_effect=lambda: now[0]), \
                mock.patch.object(gateway.secrets, 'randbelow', return_value=0), \
                mock.patch.object(gateway.asyncio, 'sleep', side_effect=advance):
            with self.assertRaises(asyncio.CancelledError): await bridge.probe_routes()
        self.assertEqual([at for r, at in calls if r==bridge.routes[0]], [100, 115, 130, 400])


class MemoryWriter:
    def __init__(self, blocked=False):
        self.frames = []
        self.blocked = blocked

    def write(self, frame):
        self.frames.append(frame)

    async def drain(self):
        if self.blocked:
            await asyncio.Event().wait()


class ForwardingTests(unittest.IsolatedAsyncioTestCase):
    def test_excessive_nesting_rejected_before_json_decoder(self):
        for opening, closing in ((b'[', b']'), (b'{"x":', b'}')):
            for depth in (gateway.MAX_JSON_DEPTH, 2000):
                frame = b'{"params":' + opening * depth + b'0' + closing * depth + b'}\n'
                self.assertLess(len(frame), gateway.MAX_LINE)
                with self.subTest(container=opening, depth=depth):
                    with mock.patch.object(gateway.json, 'loads') as decoder:
                        with self.assertRaisesRegex(ValueError, 'nesting limit'):
                            gateway.validate_frame(frame)
                        decoder.assert_not_called()

    async def test_nesting_boundary_remains_byte_exact(self):
        frame = b'{ "result":' + b'[' * (gateway.MAX_JSON_DEPTH - 1) + b'0' + b']' * (gateway.MAX_JSON_DEPTH - 1) + b' }\n'
        reader, writer = asyncio.StreamReader(), MemoryWriter()
        reader.feed_data(frame)
        reader.feed_eof()
        await gateway.forward(reader, writer)
        self.assertEqual(writer.frames, [frame])

    async def test_quoted_delimiters_and_escapes_do_not_count_as_nesting(self):
        frame = (json.dumps({'method': 'mining.authorize', 'params': [
            '[{' * 100, '}]' * 100, 'quote"brackets[{', 'slash\\', 'slash\\"[{',
        ]}) + '\n').encode()
        reader, writer = asyncio.StreamReader(), MemoryWriter()
        reader.feed_data(frame)
        reader.feed_eof()
        await gateway.forward(reader, writer)
        self.assertEqual(writer.frames, [frame])

    async def test_valid_frames_remain_byte_exact(self):
        frame = b'{ "id":1, "method":"mining.authorize", "params":["ARK_SYNTHETIC_\\u0041","x"] }\n'
        reader, writer = asyncio.StreamReader(), MemoryWriter()
        reader.feed_data(frame)
        reader.feed_eof()
        await gateway.forward(reader, writer)
        self.assertEqual(writer.frames, [frame])

    async def test_nonstandard_and_ambiguous_json_rejected(self):
        for frame in (
            b'\n', b'[]\n', b'{"method":null}\n',
            b'{"id":1,"id":2}\n', b'{"params":[NaN]}\n',
            b'{"params":[{"x":1,"X":2}]}\n',
            '{"method":"mining.notify"}\n'.encode("utf-16"),
        ):
            with self.subTest(frame=frame):
                reader, writer = asyncio.StreamReader(), MemoryWriter()
                reader.feed_data(frame)
                reader.feed_eof()
                with self.assertRaises(ValueError):
                    await gateway.forward(reader, writer)
                self.assertEqual(writer.frames, [])

    async def exercise_timeout(self, function, reader, writer, activity):
        task = asyncio.create_task(function(reader, writer, activity))
        try:
            # Sustained other-direction activity cannot extend a frame or write
            # deadline. This is independent from the session idle policy.
            for _ in range(15):
                activity.touch()
                await asyncio.sleep(0.02)
            with self.assertRaises(asyncio.TimeoutError):
                await asyncio.wait_for(asyncio.shield(task), 1)
            self.assertTrue(task.done())  # Not the outer test timeout.
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def test_partial_frame_deadline_survives_opposite_activity(self):
        reader, writer = asyncio.StreamReader(), MemoryWriter()
        reader.feed_data(b'{"method":')
        with mock.patch.object(gateway, "FRAME_TIMEOUT", 0.08):
            await self.exercise_timeout(gateway.forward, reader, writer, gateway.SessionActivity())
        self.assertEqual(writer.frames, [])

    async def test_blocked_writes_still_timeout_in_both_layers(self):
        for function in (gateway.forward, ingress.copy_stream):
            with self.subTest(layer=function.__module__):
                reader, writer = asyncio.StreamReader(), MemoryWriter(blocked=True)
                reader.feed_data(b'{"id":1,"result":true}\n')
                with mock.patch.object(gateway, "WRITE_TIMEOUT", 0.08), mock.patch.object(ingress, "WRITE_TIMEOUT", 0.08):
                    await self.exercise_timeout(function, reader, writer, gateway.SessionActivity())

    async def test_cancellation_releases_pending_read_in_both_layers(self):
        for function in (gateway.forward, ingress.copy_stream):
            reader = asyncio.StreamReader()
            task = asyncio.create_task(function(reader, MemoryWriter()))
            await asyncio.sleep(0.02)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            # No orphan reader is left waiting on the same stream.
            reader.feed_data(b'x')
            self.assertEqual(await reader.read(1), b'x')


class TelemetryTests(unittest.TestCase):
    def setUp(self):
        self.now = 10.0
        self.totals = gateway.Counter()
        self.s = gateway.MiningSession(self.totals, 'tor-1', lambda: self.now)

    def assert_share_balance(self):
        snapshot = self.s.snapshot()
        settled = sum(self.totals[key] for key in ('accepted', 'rejected', 'unanswered',
                                                  'untracked', 'unknown_responses'))
        self.assertEqual(self.totals['submitted'], settled + snapshot['pending_submissions'])

    def test_disconnect_accounts_for_pending_shares_once_without_rejecting_or_replaying(self):
        for ident, method in ((1, 'mining.submit'), (2, 'mining.submit'), (3, 'mining.authorize')):
            self.s.observe({'id': ident, 'method': method}, False)
        self.s.observe({'id': 1, 'result': True}, True)
        self.assert_share_balance()
        self.s.finish()
        self.s.finish()
        self.s.observe({'id': 2, 'result': True}, True)  # Closed sessions cannot gain responses.
        self.s.observe({'id': 4, 'method': 'mining.submit'}, False)
        self.assertEqual(self.totals['accepted'], 1)
        self.assertEqual(self.totals['unanswered'], 1)
        self.assertEqual(self.totals['rejected'], 0)
        self.assertEqual(self.s.pending, {})
        self.assert_share_balance()

    def test_colliding_ids_account_for_both_shares_and_remain_ambiguous_after_response(self):
        for method in ('mining.submit', 'mining.submit'):
            self.s.observe({'id': 1, 'method': method}, False)
            self.assert_share_balance()
        self.s.observe({'id': 1, 'result': True}, True)
        self.s.observe({'id': 1, 'method': 'mining.submit'}, False)
        self.s.observe({'id': 1, 'result': True}, True)  # May belong to either older request.
        self.assertEqual(self.totals['accepted'], 0)
        self.assertEqual(self.totals['untracked'], 3)
        self.assert_share_balance()
        self.s.finish()
        self.assertEqual(self.totals['unanswered'], 0)
        self.assert_share_balance()

    def test_nonshare_collisions_and_overflow_never_inflate_share_counts(self):
        for methods in (('mining.submit', 'mining.subscribe'),
                        ('mining.authorize', 'mining.submit')):
            self.setUp()
            for method in methods:
                self.s.observe({'id': 1, 'method': method}, False)
            self.s.observe({'id': 1, 'result': True}, True)
            self.assertEqual(self.totals['untracked'], 1)
            self.assertEqual(self.totals['accepted'], 0)
            self.assert_share_balance()
        self.setUp()
        for ident in range(150):
            self.s.observe({'id': ident, 'method': 'mining.subscribe'}, False)
        self.assertEqual(len(self.s.pending), 128)
        self.assertEqual(self.totals['untracked'], 0)
        self.s.observe({'id': 150, 'method': 'mining.submit'}, False)
        self.assertEqual(self.totals['untracked'], 1)
        self.assert_share_balance()

    def test_expired_unknown_and_uncorrelatable_shares_have_distinct_outcomes(self):
        self.s.observe({'id': 1, 'method': 'mining.submit'}, False)
        self.s.observe({'id': 1, 'result': {'unexpected': True}}, True)
        self.s.observe({'id': 2, 'method': 'mining.submit'}, False)
        for ident in (None, True, [], 'x' * 129):
            self.s.observe({'id': ident, 'method': 'mining.submit'}, False)
        self.assert_share_balance()
        self.now += 301
        self.s.snapshot()
        self.s.observe({'id': 2, 'result': True}, True)
        self.s.finish()
        self.assertEqual(self.totals['unknown_responses'], 1)
        self.assertEqual(self.totals['unanswered'], 1)
        self.assertEqual(self.totals['untracked'], 4)
        self.assertEqual(self.totals['accepted'], 0)
        self.assertEqual(self.totals['rejected'], 0)
        self.assert_share_balance()

    def test_ambiguous_tombstones_expire_within_the_bounded_tracking_window(self):
        self.s.observe({'id': 1, 'method': 'mining.submit'}, False)
        self.s.observe({'id': 1, 'method': 'mining.submit'}, False)
        self.s.observe({'id': 1, 'result': True}, True)
        self.assertEqual(len(self.s.pending), 1)
        self.now += 301
        self.s.snapshot()
        self.assertEqual(self.s.pending, {})
        self.assertEqual(self.totals['untracked'], 2)
        self.assert_share_balance()

    def test_correlated_accept_reject_and_latency_without_private_data(self):
        self.s.observe({'id': 1, 'method': 'mining.submit', 'params': ['PRIVATE_IDENTITY']}, False)
        self.now += .2
        self.s.observe({'id': 1, 'result': True, 'error': None}, True)
        self.s.observe({'id': 2, 'method': 'mining.submit'}, False)
        self.s.observe({'id': 2, 'result': False, 'error': [20, 'PRIVATE_ERROR']}, True)
        self.s.observe({'id': 3, 'result': True}, True)
        self.assertEqual(self.totals['accepted'], 1)
        self.assertEqual(self.totals['rejected'], 1)
        self.assertEqual(self.s.ack_max_ms, 200)
        self.assertNotIn('PRIVATE', json.dumps(self.s.snapshot()))

    def test_authorized_ark_identity_becomes_only_a_validated_fingerprint(self):
        address = 'ark1' + 'qurswpc8qurswpc8qurswpc8qurswpc8qurswpc8qurswpc8qursmr9erd'
        expected = '020ae34b41201a618b21cdac2b965aa93a0f68adfb8e59b5c5ce4a0b853595f3'
        self.assertEqual(gateway.ark_account_fingerprint(address), expected)
        self.s.observe({'id': 7, 'method': 'mining.authorize', 'params': [address, 'x']}, False)
        self.assertIsNone(self.s.account_fingerprint)
        self.s.observe({'id': 7, 'result': True, 'error': None}, True)
        self.assertEqual(self.s.account_fingerprint, expected)
        self.assertNotIn(address, json.dumps(vars(self.s), default=str))

    def test_optional_account_pin_rejects_other_authorize_and_submit_identities(self):
        address = 'ark1' + 'qurswpc8qurswpc8qurswpc8qurswpc8qurswpc8qurswpc8qursmr9erd'
        expected = gateway.ark_account_fingerprint(address)
        session = gateway.MiningSession(self.totals, 'tor-1', lambda: self.now,
                                        expected_account_fingerprint=expected)
        session.observe({'id': 1, 'method': 'mining.authorize',
                         'params': [address, 'password']}, False)
        session.observe({'id': 2, 'method': 'mining.submit',
                         'params': [address, 'job', 'nonce']}, False)
        for invalid in (address[:-1] + 'q', address + '.worker', None):
            for method in ('mining.authorize', 'mining.submit'):
                with self.subTest(method=method, invalid=invalid), self.assertRaises(ValueError):
                    session.observe({'id': 3, 'method': method,
                                     'params': [invalid]}, False)

    def test_malformed_failed_and_ambiguous_authorizations_never_publish_identity(self):
        address = 'ark1' + 'qurswpc8qurswpc8qurswpc8qurswpc8qurswpc8qurswpc8qursmr9erd'
        for invalid in (address.upper(), address[:-1] + 'q', address + '.worker', 'ark1short', None):
            self.assertIsNone(gateway.ark_account_fingerprint(invalid))
        self.s.observe({'id': 1, 'method': 'mining.authorize', 'params': [address, 'x']}, False)
        self.s.observe({'id': 1, 'result': False, 'error': [20, 'no']}, True)
        self.assertIsNone(self.s.account_fingerprint)
        self.s.observe({'id': 2, 'method': 'mining.authorize', 'params': [address, 'x']}, False)
        self.s.observe({'id': 2, 'method': 'mining.subscribe'}, False)
        self.s.observe({'id': 2, 'result': True, 'error': None}, True)
        self.assertIsNone(self.s.account_fingerprint)
        self.assertEqual(self.s.pending_accounts, {})

    def test_accepted_work_uses_difficulty_at_submission_not_response_time(self):
        self.s.observe({'id': None, 'method': 'mining.set_difficulty', 'params': [32768]}, True)
        self.s.observe({'id': 1, 'method': 'mining.submit'}, False)
        self.s.observe({'id': None, 'method': 'mining.set_difficulty', 'params': [1000]}, True)
        self.s.observe({'id': 1, 'result': True, 'error': None}, True)
        snapshot = self.s.snapshot()
        self.assertEqual(snapshot['difficulty'], 1000)
        self.assertEqual(snapshot['accepted_work'], 32768)
        self.assertEqual(self.totals['accepted_difficulty'], 32768)

    def test_missing_or_invalid_difficulty_never_fabricates_accepted_work(self):
        for invalid in (0, -1, True, '1000', float('nan'), float('inf'), 10**16, 10**1000):
            self.s.observe({'id': None, 'method': 'mining.set_difficulty', 'params': [invalid]}, True)
        self.s.observe({'id': 1, 'method': 'mining.submit'}, False)
        self.s.observe({'id': 1, 'result': True, 'error': None}, True)
        self.assertIsNone(self.s.snapshot()['difficulty'])
        self.assertIsNone(self.s.snapshot()['accepted_work'])

    def test_client_ip_is_retained_only_when_explicitly_supplied_for_dashboard(self):
        self.assertNotIn('client_ip', self.s.snapshot())
        session = gateway.MiningSession(self.totals, 'tor-1', lambda: self.now,
                                        client_ip='192.168.1.70')
        self.assertEqual(session.snapshot()['client_ip'], '192.168.1.70')

    def test_route_totals_receive_the_same_sanitized_events(self):
        route_totals = gateway.Counter()
        session = gateway.MiningSession(self.totals, 'tor-1', lambda: self.now,
                                        route_totals=route_totals)
        session.observe({'method': 'mining.notify', 'params': ['PRIVATE_JOB']}, True)
        session.observe({'id': 1, 'method': 'mining.submit', 'params': ['PRIVATE_USER']}, False)
        session.observe({'id': 1, 'result': True, 'error': None}, True)
        self.assertEqual(route_totals, {'jobs': 1, 'submitted': 1, 'accepted': 1})
        self.assertNotIn('PRIVATE', json.dumps(route_totals))

    def test_duplicate_id_and_wrong_type_never_count_acceptance(self):
        self.s.observe({'id': 1, 'method': 'mining.submit'}, False)
        self.s.observe({'id': '1', 'result': True}, True)
        self.s.observe({'id': 1, 'method': 'mining.subscribe'}, False)
        self.s.observe({'id': 1, 'result': True}, True)
        self.assertEqual(self.totals['accepted'], 0)
        self.assertEqual(self.totals['ambiguous_ids'], 1)

    def test_pending_is_bounded_and_unanswered_is_not_rejected(self):
        for n in range(200):
            self.s.observe({'id': n, 'method': 'mining.submit'}, False)
        self.assertEqual(len(self.s.pending), 128)
        self.now += 301
        self.s.snapshot()
        self.assertEqual(len(self.s.pending), 0)
        self.assertEqual(self.totals['unanswered'], 128)
        self.assertEqual(self.totals['rejected'], 0)

    def test_jobs_and_authorization_are_separate_from_acceptance(self):
        self.s.observe({'id': 1, 'method': 'mining.authorize'}, False)
        self.s.observe({'id': 1, 'result': True}, True)
        self.s.observe({'method': 'mining.notify', 'params': []}, True)
        self.now += 2
        self.assertEqual(self.s.snapshot()['last_job_age_seconds'], 2)
        self.assertEqual(self.totals['jobs'], 1)
        self.assertEqual(self.totals['accepted'], 0)


class JobWatchTests(unittest.IsolatedAsyncioTestCase):
    def bridge(self):
        return gateway.Bridge(gateway.Config('192.168.1.10', frozenset({'lan'}), example_onion(), 3333))

    def test_cooldown_hourly_budget_and_expiry(self):
        b = self.bridge()
        self.assertTrue(b.reserve_recovery(100))
        self.assertFalse(b.reserve_recovery(101))
        self.assertTrue(b.reserve_recovery(160))
        self.assertTrue(b.reserve_recovery(220))
        self.assertFalse(b.reserve_recovery(400))
        self.assertTrue(b.reserve_recovery(3701))

    def test_only_authorized_or_working_sessions_become_stale(self):
        s = gateway.MiningSession(gateway.Counter(), 'tor-1', lambda: 1000)
        self.assertFalse(s.job_stale())
        s.authorized = 1
        self.assertTrue(s.job_stale())
        s.observe({'method': 'mining.notify'}, True)
        self.assertFalse(s.job_stale())
        self.assertIsNone(s.last_accepted)

    async def test_stale_session_releases_only_with_alternate_and_budget(self):
        b = self.bridge()
        s = gateway.MiningSession(b.mining_totals, 'tor-1')
        s.authorized = time.monotonic() - 301
        with mock.patch.object(gateway, 'JOB_WATCH_INTERVAL', .005), mock.patch.object(gateway, 'tor_recently_ready', return_value=True):
            await asyncio.wait_for(b.watch_jobs(s, b.routes[0]), .2)
        self.assertEqual(b.job_recoveries, 1)
        self.assertIn(b.routes[0], b.route_cooldowns)

    async def test_no_alternate_budget_exhaustion_and_fresh_jobs_do_not_close(self):
        for state in ('no_alternate', 'budget', 'fresh'):
            b = self.bridge()
            s = gateway.MiningSession(b.mining_totals, 'tor-1')
            s.last_job = time.monotonic() - (0 if state == 'fresh' else 301)
            if state == 'budget':
                b.recovery_times = [time.monotonic()] * 3
            with mock.patch.object(gateway, 'JOB_WATCH_INTERVAL', .005), mock.patch.object(gateway, 'tor_recently_ready', return_value=state != 'no_alternate'):
                task = asyncio.create_task(b.watch_jobs(s, b.routes[0]))
                await asyncio.sleep(.025)
                self.assertFalse(task.done())
                self.assertEqual(s.recovery_blocked, state != 'fresh')
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            self.assertEqual(b.job_recoveries, 0)


class ShutdownDrainTests(unittest.IsolatedAsyncioTestCase):
    def bridge(self):
        return gateway.Bridge(gateway.Config('192.168.1.10', frozenset({'lan'}), example_onion(), 3333))

    async def test_gateway_drain_settles_an_inflight_share_without_replay(self):
        bridge = self.bridge()
        session = gateway.MiningSession(bridge.mining_totals, 'tor-1')
        bridge.sessions[object()] = session
        session.observe({'id': 1, 'method': 'mining.submit'}, False)

        async def acknowledge():
            await asyncio.sleep(.01)
            session.observe({'id': 1, 'result': True, 'error': None}, True)

        task = asyncio.create_task(acknowledge())
        with mock.patch.object(gateway, 'SHUTDOWN_DRAIN_POLL', .001):
            self.assertEqual(await bridge.drain_pending(.1), (1, 0))
        await task
        self.assertEqual(bridge.mining_totals['accepted'], 1)
        self.assertEqual(bridge.mining_totals['submitted'], 1)

    async def test_gateway_drain_is_bounded_when_reply_never_arrives(self):
        bridge = self.bridge()
        session = gateway.MiningSession(bridge.mining_totals, 'tor-1')
        bridge.sessions[object()] = session
        session.observe({'id': 1, 'method': 'mining.submit'}, False)
        with mock.patch.object(gateway, 'SHUTDOWN_DRAIN_POLL', .001):
            self.assertEqual(await bridge.drain_pending(.01), (1, 1))

    async def test_ingress_drain_keeps_existing_stream_task_briefly(self):
        listener = ingress.Ingress(frozenset({'127.0.0.1'}))

        async def existing_stream():
            try:
                await asyncio.sleep(.01)
            finally:
                listener.active.discard(asyncio.current_task())

        listener.active.add(asyncio.create_task(existing_stream()))
        with mock.patch.object(ingress, 'SHUTDOWN_DRAIN_POLL', .001):
            self.assertEqual(await listener.drain(.1), 0)


if __name__ == "__main__":
    unittest.main()
