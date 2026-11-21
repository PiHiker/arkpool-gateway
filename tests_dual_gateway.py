"""Offline dual-runtime contracts; no real pool, credentials or mining claims."""
import asyncio
import base64
from collections import Counter
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import stat
import tempfile
import time
import tomllib
import unittest
from unittest.mock import AsyncMock, patch

import dashboard_status
from dual_gateway import DualGateway, translator_toml, write_private_config
from gateway import MiningSession
from translator_runtime import bounded_lines, bootstrap, drain_bootstrap


def config(owner=False):
    public = bytes(range(32))
    checksum = hashlib.sha3_256(b'.onion checksum' + public + b'\x03').digest()[:2]
    result = dict(pool_onion=base64.b32encode(public + checksum + b'\x03').decode().lower()+'.onion',
                  pool_port=4444, authority_pubkey='A'*43)
    if owner:
        result['ark_identity'] = 'ark1qqqqqqqq6wkmzn'  # Synthetic checksum fixture, no wallet.
    return result


async def until(predicate, timeout=3):
    async with asyncio.timeout(timeout):
        while not predicate():
            await asyncio.sleep(.01)


class ConfigTests(unittest.TestCase):
    def test_generated_config_keeps_exact_owner_and_only_loopback_destinations(self):
        fixture = config(True)
        value = tomllib.loads(translator_toml(fixture))
        self.assertEqual(value['upstreams'], [dict(address='127.0.0.1', port=34256,
                         authority_pubkey=fixture['authority_pubkey'], user_identity=fixture['ark_identity'])])
        self.assertEqual(value['downstream_address'], '127.0.0.1')
        self.assertEqual(value['min_supported_version'], 2)
        self.assertEqual(value['max_supported_version'], 2)
        self.assertTrue(value['downstream_difficulty_config']['enable_vardiff'])
        self.assertNotIn('monitoring_address', value)
        self.assertNotIn('miner_telemetry', value)
        for changed in ({}, {**fixture, 'ark_identity': fixture['ark_identity']+'.worker'},
                        {**fixture, 'pool_onion': 'example.com'}, config()):
            with self.assertRaises(ValueError):
                translator_toml(changed)

    def test_private_config_modes_and_symlink_directory_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = write_private_config(root/'private', config(True))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            (root/'alias').symlink_to(root/'private')
            with self.assertRaises(ValueError):
                write_private_config(root/'alias', config(True))


class RuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.env = patch.dict(os.environ, LAN_IP='192.168.1.10', MINER_IPS='lan', DASHBOARD_SNAPSHOTS='0')
        self.env.start()
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        (self.root/'ipc').mkdir()
        (self.root/'tmp').mkdir()
        self.stop = asyncio.Event()
        self.tasks = []
        self.writers = []
        self.servers = []

    async def asyncTearDown(self):
        self.stop.set()
        for writer in self.writers:
            writer.close()
        for server in self.servers:
            server.close()
            await server.wait_closed()
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        self.directory.cleanup()
        self.env.stop()

    def gateway(self, owner=False):
        return DualGateway(config(owner), self.root/'ipc', self.root/'tmp', self.root)

    async def start(self, gateway):
        task = asyncio.create_task(gateway.serve(self.stop))
        self.tasks.append(task)
        await until(lambda: gateway.health_socket.exists())
        return task

    async def connect(self, socket_name, address='192.168.1.70'):
        reader, writer = await asyncio.open_unix_connection(self.root/'ipc'/socket_name)
        self.writers.append(writer)
        writer.write(ipaddress.IPv4Address(address).packed)
        await writer.drain()
        return reader, writer

    async def test_native_only_health_and_v1_rejection_without_translator_spawn(self):
        gateway = self.gateway()
        with patch('dual_gateway.tor_recently_ready', return_value=True), \
             patch('dual_gateway.asyncio.create_subprocess_exec', side_effect=AssertionError('must not spawn')):
            await self.start(gateway)
            reader, writer = await asyncio.open_unix_connection(gateway.health_socket)
            self.writers.append(writer)
            self.assertEqual(await reader.read(), b'ok\n')
            reader, _ = await self.connect('gateway.sock')
            try:
                self.assertEqual(await reader.read(), b'')
            except ConnectionResetError:
                pass  # Explicit close may reset already-written unsupported V1 bytes.
            self.assertTrue(gateway.ready())
        with patch('dual_gateway.tor_recently_ready', return_value=False):
            self.assertFalse(gateway.ready())

    async def test_combined_admission_limit_and_per_source_limit(self):
        gateway = self.gateway(True)
        hold = asyncio.Event()
        async def remain(*_):
            await hold.wait()
        async def supervise():
            await asyncio.Event().wait()
        with patch.object(gateway, 'translator_available', return_value=True), \
             patch.object(gateway, 'translate', side_effect=remain), \
             patch.object(gateway.native, 'handle', side_effect=remain), \
             patch.object(gateway, 'supervise', side_effect=supervise):
            await self.start(gateway)
            for index in range(8):
                await self.connect('native.sock' if index % 2 else 'gateway.sock', '192.168.1.'+str(70+index//2))
            await until(lambda: gateway.active == 8 and sum(gateway.sources.values()) == 8)
            reader, _ = await self.connect('native.sock', '192.168.1.90')
            try:
                self.assertEqual(await reader.read(), b'')
            except ConnectionResetError:
                pass
            self.assertEqual(gateway.active, 8)
            hold.set()
            await until(lambda: gateway.active == 0)
            hold.clear()
            await self.connect('native.sock')
            await self.connect('gateway.sock')
            await until(lambda: gateway.sources['192.168.1.70'] == 2)
            reader, _ = await self.connect('native.sock')
            self.assertEqual(await reader.read(), b'')
            await until(lambda: gateway.active == 2)

    async def test_disallowed_source_never_reaches_native_or_translator(self):
        gateway = self.gateway()
        with patch.object(gateway.native, 'handle', new=AsyncMock()) as native:
            await self.start(gateway)
            reader, _ = await self.connect('native.sock', '203.0.113.1')
            self.assertEqual(await reader.read(), b'')
            native.assert_not_awaited()

    async def test_native_stream_survives_repeated_translator_exits(self):
        gateway = self.gateway(True)
        # Each synthetic child briefly publishes readiness, then exits. This
        # exercises process retry and cleanup without invoking SRI or a pool.
        (self.root/'translator_runtime.py').write_text('''import asyncio, os
from pathlib import Path
async def echo(r,w):
 try:
  await r.readexactly(4)
  while line:=await r.readline():
   w.write(line); await w.drain()
 finally:
  w.close()
async def main():
 assert os.environ['TRANSLATOR_KEEPALIVE']=='1'
 p=Path(os.environ['TRANSLATOR_SOCKET'])
 s=await asyncio.start_unix_server(echo,str(p))
 print('private-oversized-fixture-'*7000,flush=True)
 print('Translator Tor path A',flush=True)
 print('Translator authenticated V2 job ready',flush=True)
 await asyncio.sleep(.3)
 os._exit(1)
asyncio.run(main())
''')
        async def echo(reader, writer):
            try:
                while data := await reader.read(1024):
                    writer.write(data)
                    await writer.drain()
            finally:
                writer.close()
        peer = self.root/'echo.sock'
        self.servers.append(await asyncio.start_unix_server(echo, str(peer)))
        async def connect(_source):
            reader, writer = await asyncio.open_unix_connection(peer)
            return reader, writer, 1
        with patch.object(gateway.native, 'connect', side_effect=connect), \
             patch('dual_gateway.RETRY_MAX', .05), patch('dual_gateway.tor_recently_ready', return_value=True):
            await self.start(gateway)
            await until(gateway.translator_available)
            old_v1, v1_writer = await self.connect('gateway.sock', '192.168.1.72')
            v1_writer.write(b'{"id":1,"method":"mining.subscribe","params":[]}\n')
            await v1_writer.drain()
            self.assertIn(b'mining.subscribe', await old_v1.readline())
            reader, writer = await self.connect('native.sock')
            writer.write(b'noise-fixture-1')
            await writer.drain()
            self.assertEqual(await reader.readexactly(15), b'noise-fixture-1')
            await until(lambda: gateway.connections['tor-1'] >= 2)
            self.assertEqual(await asyncio.wait_for(old_v1.read(), 1), b'')
            writer.write(b'noise-fixture-2')
            await writer.drain()
            self.assertEqual(await reader.readexactly(15), b'noise-fixture-2')
            self.assertEqual(gateway.native.active, 1)
            self.stop.set()
            await asyncio.wait_for(self.tasks[0], 2)
            self.assertFalse(gateway.child_socket.exists())
            self.assertFalse((self.root/'tmp'/'arkpool-translator'/'translator.toml').exists())

    async def test_supervisor_shutdown_kills_grandchildren(self):
        gateway = self.gateway(True)
        (self.root/'translator_runtime.py').write_text('''import os, subprocess, sys, time
from pathlib import Path
p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'])
Path(os.environ['TRANSLATOR_SOCKET']+'.pid').write_text(str(p.pid))
time.sleep(60)
''')
        await self.start(gateway)
        pid_file = Path(str(gateway.child_socket)+'.pid')
        await until(pid_file.exists)
        child_pid = int(pid_file.read_text())
        self.stop.set()
        await asyncio.wait_for(self.tasks[0], 3)
        def stopped():
            try:
                return Path('/proc') .joinpath(str(child_pid), 'stat').read_text().split()[2] == 'Z'
            except FileNotFoundError:
                return True
        await until(stopped)

    async def test_upstream_loss_revokes_readiness_and_settles_pending(self):
        gateway = self.gateway(True)
        gateway.observe('Translator Tor path A')
        gateway.observe('Translator authenticated V2 job ready')
        for _ in range(3):
            gateway.observe('SubmitSharesExtended: valid share, forwarding')
        gateway.observe('Received: SubmitSharesSuccess(channel_id=1, last_sequence_number=2, new_submits_accepted_count=1, new_shares_sum=40)')
        held = asyncio.create_task(asyncio.Event().wait())
        self.tasks.append(held)
        gateway.v1_clients.add(held)
        gateway.observe('Translator upstream unavailable; V2 restart required')
        await asyncio.sleep(0)
        self.assertFalse(gateway.child_ready)
        self.assertTrue(gateway.restart_requested)
        self.assertTrue(held.cancelled())
        gateway.settle_pending()
        self.assertEqual(gateway.counts['accepted'], 1)
        self.assertEqual(gateway.counts['unanswered'], 2)
        self.assertEqual(gateway.pending, 0)

    async def test_snapshot_never_promotes_local_v1_success_to_pool_acceptance(self):
        gateway = self.gateway(True)
        gateway.observe('Translator Tor path B')
        gateway.observe('Translator authenticated V2 job ready')
        session = MiningSession(Counter(), 'tor-2', client_ip='192.168.1.70')
        session.counts['accepted'] = 7  # Local SRI successes are not pool acknowledgments.
        gateway.sessions[1] = session
        gateway.native.sessions[2] = dict(route='A', client_ip='192.168.1.71', started_at_monotonic=time.monotonic())
        result = dashboard_status.gateway_view(gateway.snapshot())
        self.assertEqual(result['active_sessions'], 2)
        self.assertEqual(result['mining']['accepted'], 0)
        self.assertTrue(all(row['accepted'] is None for row in result['sessions']))
        self.assertEqual(result['sessions'][1]['job_state'], 'encrypted')
        self.assertNotIn(config(True)['ark_identity'], str(result))
        self.assertNotIn('192.168.1.', str(result))
        gateway.observe('Received: SubmitSharesSuccess(channel_id=1, last_sequence_number=2, new_submits_accepted_count=3, new_shares_sum=40)')
        result = dashboard_status.gateway_view(gateway.snapshot())
        self.assertEqual(result['mining']['accepted'], 3)
        self.assertEqual([r['active_sessions'] for r in result['routes']], [1, 1])

    async def test_oversized_child_logs_are_discarded_without_stalling_later_records(self):
        reader = asyncio.StreamReader()
        reader.feed_data(b'secret-'*20000+b'\nsmall-safe-record\n')
        reader.feed_eof()
        self.assertEqual([line async for line in bounded_lines(reader)], [b'small-safe-record\n'])

    async def test_readiness_client_is_retained_only_in_appliance_mode(self):
        original_connect = asyncio.open_connection
        for keepalive in (False, True):
            with self.subTest(keepalive=keepalive):
                requests = []
                closed = asyncio.Event()
                peers = []
                async def server(reader, writer):
                    peers.append(writer)
                    try:
                        for _ in range(3):
                            requests.append(json.loads(await reader.readline()))
                        writer.write(b'{"id":3,"result":true,"error":null}\n'
                                     b'{"method":"mining.notify","params":[]}\n')
                        await writer.drain()
                        self.assertEqual(await reader.read(), b'')
                        closed.set()
                    finally:
                        writer.close()
                listener = await asyncio.start_server(server, '127.0.0.1', 0)
                self.servers.append(listener)
                port = listener.sockets[0].getsockname()[1]
                async def connect(*_args, **_kwargs):
                    return await original_connect('127.0.0.1', port)
                with patch('translator_runtime.asyncio.open_connection', side_effect=connect):
                    retained = await bootstrap('exact-synthetic-owner', keepalive)
                self.assertEqual([r['method'] for r in requests],
                                 ['mining.configure', 'mining.subscribe', 'mining.authorize'])
                self.assertEqual(requests[2]['params'][0], 'exact-synthetic-owner')
                if keepalive:
                    self.assertFalse(closed.is_set())
                    self.assertIsNotNone(retained)
                    reader, writer = retained
                    self.writers.append(writer)
                    drainer = asyncio.create_task(drain_bootstrap(reader))
                    self.tasks.append(drainer)
                    peers[0].write(b'{"method":"mining.notify","params":[]}\n')
                    await peers[0].drain()
                    await asyncio.sleep(.02)
                    self.assertFalse(drainer.done())
                    writer.close()
                    await asyncio.wait_for(drainer, 1)
                else:
                    self.assertIsNone(retained)
                await asyncio.wait_for(closed.wait(), 1)

    async def test_readiness_drainer_rejects_malformed_or_oversized_frames(self):
        for line in (b'not-json\n', b'x'*70000+b'\n'):
            reader = asyncio.StreamReader()
            reader.feed_data(line)
            reader.feed_eof()
            with self.assertRaises(ValueError):
                await drain_bootstrap(reader)

    async def test_readiness_connection_loss_revokes_translation(self):
        gateway = self.gateway(True)
        gateway.child_ready = True
        held = asyncio.create_task(asyncio.Event().wait())
        self.tasks.append(held)
        gateway.v1_clients.add(held)
        gateway.observe('Translator readiness lost; V2 restart required')
        await asyncio.sleep(0)
        self.assertTrue(held.cancelled())
        self.assertFalse(gateway.child_ready)
        self.assertTrue(gateway.restart_requested)
        self.assertFalse(gateway.snapshot()['translation_ready'])


if __name__ == '__main__':
    unittest.main()
