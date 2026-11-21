import asyncio,ipaddress,tempfile,unittest
from pathlib import Path
from native_relay import Relay

class RelayTests(unittest.IsolatedAsyncioTestCase):
    async def test_binary_preserved_and_source_enforced(self):
        with tempfile.TemporaryDirectory() as tmp:
            upstream_seen=[]
            async def echo(r,w):
                b=await r.read(4096);upstream_seen.append(b);w.write(b);await w.drain();w.close();await w.wait_closed()
            upstream=await asyncio.start_unix_server(echo,path=tmp+'/up')
            relay=Relay(frozenset({'192.168.1.70'}),'unused',3336)
            async def connect(source):
                reader,writer=await asyncio.open_unix_connection(tmp+'/up')
                return reader,writer,0
            relay.connect=connect
            server=await asyncio.start_unix_server(relay.handle,path=tmp+'/relay')
            async with upstream,server:
                r,w=await asyncio.open_unix_connection(tmp+'/relay')
                payload=bytes(range(256))*4
                w.write(ipaddress.IPv4Address('192.168.1.70').packed+payload);await w.drain()
                self.assertEqual(await asyncio.wait_for(r.readexactly(len(payload)),2),payload)
                w.close();await w.wait_closed()
                r,w=await asyncio.open_unix_connection(tmp+'/relay')
                w.write(ipaddress.IPv4Address('192.168.1.71').packed);await w.drain()
                self.assertEqual(await asyncio.wait_for(r.read(),2),b'')
                w.close();await w.wait_closed()
                self.assertEqual(upstream_seen,[payload])
    async def test_no_tor_fails_closed(self):
        relay=Relay(frozenset(),'unused',3336)
        with self.assertRaises(OSError):await relay.connect()



from unittest.mock import patch
import native_relay

class RaceTests(unittest.IsolatedAsyncioTestCase):
    async def test_failed_route_cools_down_and_next_dial_uses_other_route(self):
        from types import SimpleNamespace
        routes=[SimpleNamespace(socks_path='bad',ready_path='x'),
                SimpleNamespace(socks_path='good',ready_path='x')]
        attempts=[]
        class Writer:
            def close(self):pass
            async def wait_closed(self):pass
        async def dial(_host,_port,path,_auth):
            attempts.append(path)
            return object(),Writer()
        relay=Relay(frozenset(),'unused',1)
        relay.route_failed(0)
        with patch.object(native_relay,'TOR_ROUTES',routes), \
             patch.object(native_relay,'tor_recently_ready',return_value=True), \
             patch.object(native_relay,'socks_connect',side_effect=dial):
            _reader,_writer,route=await relay.connect()
        self.assertEqual(route,1)
        self.assertEqual(attempts,['good'])

    async def test_slow_first_route_does_not_delay_fast_second(self):
        cancelled = asyncio.Event()
        class Writer:
            closed = False
            def close(self): self.closed = True
            async def wait_closed(self): pass
        writer = Writer()
        async def dial(host,port,path,auth):
            if path == 'slow':
                try: await asyncio.sleep(10)
                finally: cancelled.set()
            return object(),writer
        from types import SimpleNamespace
        routes=[SimpleNamespace(socks_path='slow',ready_path='x'),SimpleNamespace(socks_path='fast',ready_path='x')]
        with patch.object(native_relay,'TOR_ROUTES',routes),patch.object(native_relay,'tor_recently_ready',return_value=True),patch.object(native_relay,'socks_connect',side_effect=dial):
            result=await asyncio.wait_for(Relay(frozenset(),'unused',1).connect(),.5)
            self.assertIs(result[1],writer)
            self.assertTrue(cancelled.is_set())
            self.assertFalse(writer.closed)

    async def test_losing_successful_socket_closed(self):
        from types import SimpleNamespace
        class Writer:
            closed=False
            def close(self): self.closed=True
            async def wait_closed(self): pass
        writers=[Writer(),Writer()]
        async def dial(host,port,path,auth):return object(),writers[int(path)]
        routes=[SimpleNamespace(socks_path=str(i),ready_path='x') for i in range(2)]
        with patch.object(native_relay,'TOR_ROUTES',routes),patch.object(native_relay,'tor_recently_ready',return_value=True),patch.object(native_relay,'socks_connect',side_effect=dial):
            result=await Relay(frozenset(),'unused',1).connect()
            self.assertFalse(result[1].closed)
            self.assertEqual(sum(w.closed for w in writers),1)

    async def test_both_routes_timeout_without_direct_fallback(self):
        from types import SimpleNamespace
        async def dial(*args):await asyncio.sleep(10)
        routes=[SimpleNamespace(socks_path='slow',ready_path='x')]
        with patch.object(native_relay,'TOR_ROUTES',routes),patch.object(native_relay,'tor_recently_ready',return_value=True),patch.object(native_relay,'socks_connect',side_effect=dial),patch.object(native_relay,'CONNECT_TIMEOUT',.02):
            with self.assertRaises(OSError):await asyncio.wait_for(Relay(frozenset(),'unused',1).connect(),.5)

class IsolationTests(unittest.TestCase):
    def test_per_miner_opaque_credentials(self):
        relay=Relay(frozenset(),'unused',3336)
        a=relay.isolation_auth('192.168.1.70');b=relay.isolation_auth('192.168.1.71')
        self.assertEqual(a,relay.isolation_auth('192.168.1.70'))
        self.assertNotEqual(a,b)
        self.assertNotIn(b'192.168', b''.join(a))
        self.assertNotEqual(a,Relay(frozenset(),'unused',3336).isolation_auth('192.168.1.70'))

class PolicyTests(unittest.IsolatedAsyncioTestCase):
    async def test_v1_upstream_setting_fails_before_listen(self):
        with patch.dict('os.environ', {'UPSTREAM_PROTOCOL':'SV1'}, clear=True):
            with self.assertRaises(ValueError): await native_relay.main()

    async def test_legacy_endpoint_is_never_used_as_fallback(self):
        with patch.dict('os.environ', {'POOL_PORT':'3333','POOL_ONION':'legacy'}, clear=True):
            with self.assertRaises(KeyError): await native_relay.main()

class UpstreamSilenceTests(unittest.IsolatedAsyncioTestCase):
    async def test_outgoing_activity_cannot_hide_silent_pool(self):
        reader = asyncio.StreamReader()
        activity = native_relay.SessionActivity()
        class Writer:
            def write(self, data): raise AssertionError('silent pool wrote data')
            async def drain(self): pass
        async def outgoing():
            while True:
                activity.touch()
                await asyncio.sleep(.005)
        sender = asyncio.create_task(outgoing())
        try:
            with patch.object(native_relay, 'UPSTREAM_SILENCE_TIMEOUT', .05):
                with self.assertRaises(asyncio.TimeoutError):
                    await asyncio.wait_for(native_relay.pump(reader, Writer(), activity, 1, 'pool_to_miner'), .5)
        finally:
            sender.cancel()
            await asyncio.gather(sender, return_exceptions=True)

    async def test_pool_bytes_reset_deadline_without_miner_submissions(self):
        reader = asyncio.StreamReader()
        received = bytearray()
        class Writer:
            def write(self, data): received.extend(data)
            async def drain(self): pass
        with patch.object(native_relay, 'UPSTREAM_SILENCE_TIMEOUT', .15):
            task = asyncio.create_task(native_relay.pump(reader, Writer(), native_relay.SessionActivity(), 1, 'pool_to_miner'))
            try:
                for _ in range(6):
                    reader.feed_data(b'\x00\xff')
                    await asyncio.sleep(.04)
                reader.feed_eof()
                await asyncio.wait_for(task, .5)
                self.assertEqual(received, b'\x00\xff' * 6)
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    async def test_silent_session_closes_and_releases_capacity(self):
        with tempfile.TemporaryDirectory() as tmp:
            peer_closed = asyncio.Event()
            async def silent(reader, writer):
                try:
                    while await reader.read(4096): pass
                finally:
                    writer.close()
                    await writer.wait_closed()
                    peer_closed.set()
            upstream = await asyncio.start_unix_server(silent, path=tmp+'/up')
            relay = Relay(frozenset({'192.168.1.70'}), 'unused', 3336)
            async def connect(source):
                r, w = await asyncio.open_unix_connection(tmp+'/up')
                return r, w, 0
            relay.connect = connect
            server = await asyncio.start_unix_server(relay.handle, path=tmp+'/relay')
            with patch.object(native_relay, 'UPSTREAM_SILENCE_TIMEOUT', .05):
                async with upstream, server:
                    reader, writer = await asyncio.open_unix_connection(tmp+'/relay')
                    writer.write(ipaddress.IPv4Address('192.168.1.70').packed+b'noise-handshake')
                    await writer.drain()
                    self.assertEqual(await asyncio.wait_for(reader.read(), 1), b'')
                    writer.close()
                    await writer.wait_closed()
                    await asyncio.wait_for(peer_closed.wait(), 1)
                    for _ in range(20):
                        if relay.active == 0: break
                        await asyncio.sleep(.01)
                    self.assertEqual(relay.active, 0)
                    self.assertEqual(relay.sessions, {})
                    self.assertEqual(dict(relay.sources), {})
                    self.assertIn(0, relay.route_cooldowns)

if __name__=='__main__':unittest.main()
