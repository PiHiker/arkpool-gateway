"""Offline TLS, trust-bootstrap and admission-limit tests; synthetic identities only."""
import asyncio
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import unittest
from unittest import mock

import gateway
import ingress
import tests as fixtures
import tls_identity as tls


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        tls.ensure_identity(self.root, '192.168.1.10')

    def test_restart_preserves_identity_and_exports_only_public_pairing_fields(self):
        original = {p.name: p.read_bytes() for p in (self.root/'identity').iterdir()}
        tls.ensure_identity(self.root, '192.168.1.10')
        self.assertEqual(original, {p.name: p.read_bytes() for p in (self.root/'identity').iterdir()})
        profile = tls.pairing_profile(self.root, '192.168.1.10', 3334, 3333)
        self.assertEqual(set(profile), {'format', 'version', 'host', 'tlsPort', 'plaintextPort', 'caCertificate'})
        self.assertNotIn('PRIVATE KEY', json.dumps(profile))
        self.assertEqual(profile['caCertificate'].encode(), original['ca.pem'])
        self.assertLess(len(profile['caCertificate']), 3000)
        self.assertTrue(all(p.stat().st_mode & 0o077 == 0 for p in (self.root/'identity').iterdir()))

    def test_changed_address_does_not_silently_replace_trust(self):
        original = (self.root/'identity/ca.pem').read_bytes()
        with self.assertRaises(subprocess.CalledProcessError):
            tls.ensure_identity(self.root, '192.168.1.11')
        self.assertEqual((self.root/'identity/ca.pem').read_bytes(), original)

    def test_invalid_or_missing_identity_fails_without_regeneration(self):
        original = (self.root/'identity/ca.pem').read_bytes()
        (self.root/'identity/server.key').unlink()
        with self.assertRaises(OSError):
            tls.ensure_identity(self.root, '192.168.1.10')
        self.assertEqual((self.root/'identity/ca.pem').read_bytes(), original)

    def test_symlink_and_world_readable_private_key_are_rejected(self):
        key = self.root/'identity/server.key'
        key.chmod(0o644)
        with self.assertRaises(ValueError):
            tls.ensure_identity(self.root, '192.168.1.10')
        key.chmod(0o600)
        key.rename(key.with_suffix('.original'))
        key.symlink_to(key.with_suffix('.original'))
        with self.assertRaises(ValueError):
            tls.ensure_identity(self.root, '192.168.1.10')

    def test_leaf_renewal_preserves_the_paired_ca_and_server_key(self):
        ca, key, leaf = [(self.root/'identity'/n).read_bytes() for n in ('ca.pem', 'server.key', 'server.pem')]
        original = tls.openssl
        def expiring(*args):
            if args[0] == 'x509' and '-checkend' in args and str(args[2]).endswith('/server.pem'):
                raise subprocess.CalledProcessError(1, ['openssl'])
            return original(*args)
        with mock.patch.object(tls, 'openssl', side_effect=expiring):
            tls.ensure_identity(self.root, '192.168.1.10')
        self.assertEqual((self.root/'identity/ca.pem').read_bytes(), ca)
        self.assertEqual((self.root/'identity/server.key').read_bytes(), key)
        self.assertNotEqual((self.root/'identity/server.pem').read_bytes(), leaf)

    def test_invalid_pairing_ports_are_rejected(self):
        for ports in ((3333, 3333), (0, 3333), (65536, 3333), (True, 3333)):
            with self.subTest(ports=ports), self.assertRaises(ValueError):
                tls.pairing_profile(self.root, '192.168.1.10', *ports)

    def test_status_is_dates_only_and_live_refresh_refuses_changed_ca(self):
        status = tls.certificate_status(self.root)
        self.assertEqual(set(status), {'ca_expires_at', 'server_expires_at', 'ca_maintenance_due'})
        self.assertGreater(status['ca_expires_at'], status['server_expires_at'])
        with self.assertRaises(ValueError):
            tls.refresh_identity(self.root, '192.168.1.10', b'wrong digest')
        context, checked = tls.refresh_identity(self.root, '192.168.1.10', tls.ca_digest(self.root))
        self.assertIsInstance(context, ssl.SSLContext)
        self.assertEqual(status, checked)


class TLSTransportTests(unittest.IsolatedAsyncioTestCase):
    # Reuse the fake Tor/backend fixture without duplicating its plaintext tests.
    fake_tor = fixtures.TransportTests.fake_tor
    fake_tor_named = fixtures.TransportTests.fake_tor_named
    connect = fixtures.TransportTests.connect

    @classmethod
    def setUpClass(cls):
        cls.identity = tempfile.TemporaryDirectory()
        cls.context = tls.ensure_identity(Path(cls.identity.name), '192.168.1.10')
        cls.client_context = ssl.create_default_context(cafile=str(Path(cls.identity.name)/'identity/ca.pem'))

    @classmethod
    def tearDownClass(cls):
        cls.identity.cleanup()

    async def asyncSetUp(self):
        self.loop_errors = []
        asyncio.get_running_loop().set_exception_handler(lambda _loop, context: self.loop_errors.append(context))
        await fixtures.TransportTests.asyncSetUp(self)
        self.tls_socket = socket.create_server(('127.0.0.1', 0))
        self.tls_socket.setblocking(False)
        self.tls_port = self.tls_socket.getsockname()[1]
        self.accept_task = asyncio.create_task(ingress.accept_tls(self.ingress, self.tls_socket, self.context))

    async def asyncTearDown(self):
        self.accept_task.cancel()
        self.tls_socket.close()
        await asyncio.gather(self.accept_task, return_exceptions=True)
        await fixtures.TransportTests.asyncTearDown(self)
        await asyncio.sleep(0)
        self.assertEqual(self.loop_errors, [])

    async def connect_tls(self, context=None, hostname='192.168.1.10'):
        reader, writer = await asyncio.wait_for(asyncio.open_connection(
            '127.0.0.1', self.tls_port, ssl=context or self.client_context,
            server_hostname=hostname, ssl_handshake_timeout=1), 2)
        self.clients.append(writer)
        return reader, writer

    async def runtime(self):
        self.accept_task.cancel()
        await asyncio.gather(self.accept_task, return_exceptions=True)
        runtime = ingress.TLSRuntime(Path(self.identity.name), '192.168.1.10', self.context)
        self.accept_task = asyncio.create_task(ingress.accept_tls(self.ingress, self.tls_socket, runtime))
        return runtime

    async def test_live_renewal_changes_new_handshakes_and_preserves_existing_session(self):
        runtime = await self.runtime()
        reader, writer = await self.connect_tls()
        await asyncio.wait_for(reader.readline(), 1)
        old_cert = writer.get_extra_info('ssl_object').getpeercert(binary_form=True)
        old_ca = tls.ca_digest(Path(self.identity.name))
        original = tls.openssl
        def expiring(*args):
            if args[0] == 'x509' and '-checkend' in args and str(args[2]).endswith('/server.pem'):
                raise subprocess.CalledProcessError(1, ['openssl'])
            return original(*args)
        with mock.patch.object(tls, 'openssl', side_effect=expiring):
            self.assertTrue(await runtime.refresh())
        new_reader, new_writer = await self.connect_tls()
        await asyncio.wait_for(new_reader.readline(), 1)
        self.assertNotEqual(old_cert, new_writer.get_extra_info('ssl_object').getpeercert(binary_form=True))
        self.assertEqual(old_ca, tls.ca_digest(Path(self.identity.name)))
        frame = b'{"id":42,"method":"mining.submit","params":["SYNTHETIC"]}\n'
        writer.write(frame)
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readline(), 1), frame)

    async def test_failed_maintenance_refuses_new_tls_but_recovers_without_ca_change(self):
        runtime = await self.runtime()
        with mock.patch.object(ingress, 'refresh_identity', side_effect=ValueError('private error')):
            self.assertFalse(await runtime.refresh())
        self.assertEqual(runtime.status['state'], 'maintenance_required')
        with self.assertRaises((OSError, asyncio.TimeoutError)):
            await self.connect_tls()
        self.assertTrue(await runtime.refresh())
        reader, _ = await self.connect_tls()
        self.assertIn(b'mining.set_difficulty', await asyncio.wait_for(reader.readline(), 1))
        runtime.status['server_expires_at'] = 0
        self.assertFalse(runtime.available())

    async def test_tls_and_plaintext_forward_same_bytes_with_actual_peer_envelope(self):
        frame = b'{ "id":1,"method":"mining.authorize","params":["ARK_SYNTHETIC","x"] }\n'
        for connect in (self.connect_tls, self.connect):
            reader, writer = await connect()
            self.assertIn(b'mining.set_difficulty', await asyncio.wait_for(reader.readline(), 2))
            writer.write(frame)
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.readline(), 2), frame)
        self.assertEqual(self.frames, [frame, frame])

    async def test_wrong_ca_and_wrong_hostname_never_reach_pool(self):
        for context, hostname in ((ssl.create_default_context(), '192.168.1.10'),
                                  (self.client_context, '192.168.1.11')):
            with self.assertRaises(ssl.SSLCertVerificationError):
                await self.connect_tls(context, hostname)
        self.assertEqual(self.destinations, [])

    async def test_source_policy_is_enforced_before_handshake(self):
        self.ingress.miners = frozenset({'192.168.1.70'})
        with self.assertRaises((OSError, asyncio.TimeoutError)):
            await self.connect_tls()
        self.assertEqual(self.destinations, [])
        self.assertEqual(len(self.ingress.active), 0)

    async def test_plaintext_on_tls_port_is_rejected_without_forwarding(self):
        reader, writer = await asyncio.open_connection('127.0.0.1', self.tls_port)
        self.clients.append(writer)
        writer.write(b'{"id":1,"method":"mining.subscribe","params":[]}\n')
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.read(), 2), b'')
        self.assertEqual(self.destinations, [])

    async def test_handshake_slots_are_bounded_shared_and_recovered_after_timeout(self):
        with mock.patch.object(ingress, 'TLS_HANDSHAKE_TIMEOUT', 0.3), mock.patch.object(ingress, 'MAX_CONNECTIONS', 2):
            for _ in range(2):
                _, writer = await asyncio.open_connection('127.0.0.1', self.tls_port)
                self.clients.append(writer)
            await asyncio.sleep(0.03)
            self.assertEqual(len(self.ingress.active), 2)
            reader, _ = await self.connect()
            self.assertEqual(await asyncio.wait_for(reader.read(), 1), b'')
            with self.assertRaises(OSError):
                await self.connect_tls()
            self.assertEqual(self.destinations, [])
            await asyncio.sleep(0.4)
            self.assertEqual(len(self.ingress.active), 0)
            reader, _ = await self.connect_tls()
            self.assertIn(b'mining.set_difficulty', await asyncio.wait_for(reader.readline(), 2))

    async def test_pending_handshakes_obey_per_source_limit(self):
        self.ingress.miners = frozenset({'127.0.0.1', '127.0.0.2'})

        async def pending(source):
            reader, writer = await asyncio.open_connection(
                '127.0.0.1', self.tls_port, local_addr=(source, 0))
            self.clients.append(writer)
            return reader

        for _ in range(gateway.MAX_CONNECTIONS_PER_SOURCE):
            await pending('127.0.0.1')
        await asyncio.sleep(0.03)
        self.assertEqual(self.ingress.active_sources['127.0.0.1'],
                         gateway.MAX_CONNECTIONS_PER_SOURCE)

        refused = await pending('127.0.0.1')
        self.assertEqual(await asyncio.wait_for(refused.read(), 1), b'')

        await pending('127.0.0.2')
        await asyncio.sleep(0.03)
        self.assertEqual(self.ingress.active_sources['127.0.0.2'], 1)
        self.assertEqual(len(self.ingress.active),
                         gateway.MAX_CONNECTIONS_PER_SOURCE + 1)

    async def test_invalid_encrypted_frame_is_blocked_and_next_session_recovers(self):
        reader, writer = await self.connect_tls()
        await asyncio.wait_for(reader.readline(), 2)
        writer.write(b'{"method":"client.reconnect","params":[]}\n')
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.read(), 2), b'')
        self.assertEqual(self.frames, [])
        reader, _ = await self.connect_tls()
        self.assertIn(b'mining.set_difficulty', await asyncio.wait_for(reader.readline(), 2))


if __name__ == '__main__':
    unittest.main()
