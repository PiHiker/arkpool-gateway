"""Synthetic identity, source-admission and pool-acknowledgment checks."""
import asyncio
import ipaddress
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, patch

import dashboard_status
from translator_runtime import (MinerBridge, validate_request, safe_log, ShareProgress,
                                log_output, read_request, watch_share_progress)
from ingress import SessionActivity
from translator_observer import fresh_state, update, snapshot


class IdentityTests(unittest.TestCase):
    def test_logs_keep_acknowledgments_without_identity_or_job_payloads(self):
        self.assertIsNone(safe_log('Sending user_identity: private-account'))
        self.assertEqual(safe_log('Received: NewExtendedMiningJob coinbase_tx_prefix=secret'),
                         'Received: NewExtendedMiningJob')
        self.assertNotIn('secret', safe_log('ERROR private-account secret'))
        message = 'Received: SubmitSharesSuccess(channel_id=1, last_sequence_number=2, new_submits_accepted_count=1, new_shares_sum=32769)'
        self.assertEqual(safe_log(message), message)

    def test_owner_identity_is_exact_on_authorization_and_submission(self):
        owner = 'ark1syntheticidentity'
        for method in ('mining.authorize', 'mining.submit'):
            raw = (json.dumps({'id': 1, 'method': method, 'params': [owner, 'x']})+'\n').encode()
            self.assertEqual(validate_request(raw, owner), raw)
            for params in ([], None, ['another-owner', 'x'], [owner+'.worker', 'x']):
                with self.subTest(method=method, params=params), self.assertRaises(ValueError):
                    validate_request((json.dumps({'method': method, 'params': params})+'\n').encode(), owner)

    def test_malformed_and_unbounded_frames_are_rejected(self):
        for raw in (b'{}', b'[]\n', b'not json\n', b'x'*65537+b'\n'):
            with self.subTest(raw=raw[:20]), self.assertRaises(ValueError):
                validate_request(raw, 'fixture')


class FrameDeadlineTests(unittest.IsolatedAsyncioTestCase):
    async def test_reverse_activity_cannot_extend_partial_request_deadline(self):
        reader = asyncio.StreamReader()
        reader.feed_data(b'{"method":')
        activity = SessionActivity()

        async def keep_reverse_direction_active():
            while True:
                activity.touch()
                await asyncio.sleep(.005)

        keepalive = asyncio.create_task(keep_reverse_direction_active())
        try:
            with patch('translator_runtime.FRAME_TIMEOUT', .05):
                with self.assertRaises(asyncio.TimeoutError):
                    await asyncio.wait_for(read_request(reader, activity), .5)
        finally:
            keepalive.cancel()
            await asyncio.gather(keepalive, return_exceptions=True)


SUBMISSION = 'SubmitSharesExtended: valid share, forwarding'


def accepted(count):
    return ('Received: SubmitSharesSuccess(channel_id=1, last_sequence_number=7, '
            f'new_submits_accepted_count={count}, new_shares_sum=32769)')


class ShareProgressTests(unittest.TestCase):
    def setUp(self):
        self.now = 0
        self.progress = ShareProgress(lambda: self.now)

    def test_quiet_miner_does_not_trigger_recovery(self):
        self.now = 100000
        self.progress.observe('Received: NewExtendedMiningJob')
        self.assertFalse(self.progress.stalled())

    def test_more_submissions_jobs_and_local_replies_do_not_hide_stall(self):
        self.progress.observe(SUBMISSION)
        self.now = 119
        for message in (SUBMISSION, 'Received: NewExtendedMiningJob',
                        'Received: SetNewPrevHash', 'mining.submit result=true', accepted(0)):
            self.progress.observe(message)
        self.assertFalse(self.progress.stalled())
        self.now = 120
        self.assertTrue(self.progress.stalled())

    def test_batched_acknowledgments_clear_pending_wait(self):
        for _ in range(3):
            self.progress.observe(SUBMISSION)
        self.now = 119
        self.progress.observe(accepted(3))
        self.now = 1000
        self.assertEqual(self.progress.pending, 0)
        self.assertFalse(self.progress.stalled())
        self.progress.observe(SUBMISSION)
        self.now = 1119
        self.assertFalse(self.progress.stalled())
        self.now = 1120
        self.assertTrue(self.progress.stalled())

    def test_partial_pool_progress_renews_remaining_response_deadline(self):
        self.progress.observe(SUBMISSION)
        self.progress.observe(SUBMISSION)
        self.now = 100
        self.progress.observe(accepted(1))
        self.now = 219
        self.assertFalse(self.progress.stalled())
        self.now = 220
        self.assertTrue(self.progress.stalled())

    def test_rejection_is_a_response_but_not_credit_for_future_submissions(self):
        self.progress.observe(SUBMISSION)
        self.progress.observe('Received: SubmitSharesError(')
        self.progress.observe(accepted(8))
        self.now = 1000
        self.progress.observe(SUBMISSION)
        self.assertEqual(self.progress.pending, 1)
        self.now = 1120
        self.assertTrue(self.progress.stalled())

    def test_malformed_acknowledgment_does_not_extend_deadline(self):
        self.progress.observe(SUBMISSION)
        self.now = 100
        for message in (accepted(-1), accepted('not-a-number'), accepted('9'*100)):
            self.progress.observe(message)
        self.now = 120
        self.assertTrue(self.progress.stalled())


class ShareWatchdogTests(unittest.IsolatedAsyncioTestCase):
    async def test_runtime_closes_admission_and_child_after_missing_pool_reply(self):
        from translator_runtime import main

        class Child:
            def __init__(self):
                self.stdout = asyncio.StreamReader()
                self.stdout.feed_data((SUBMISSION + '\n').encode())
                self.returncode = None
                self.exited = asyncio.Event()
                self.terminations = 0

            async def wait(self):
                await self.exited.wait()
                return self.returncode

            def terminate(self):
                self.terminations += 1
                self.returncode = -15
                self.stdout.feed_eof()
                self.exited.set()

        child = Child()

        async def quick_watchdog(progress):
            await watch_share_progress(progress, timeout=.02, poll_seconds=.001)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'config.toml').write_text(
                '[[upstreams]]\naddress="127.0.0.1"\nport=34256\nuser_identity="synthetic-owner"\n')
            with patch.dict(os.environ, LAN_IP='192.168.1.10', MINER_IPS='lan',
                            UPSTREAM_PROTOCOL='SV2', TRANSLATOR_KEEPALIVE='0',
                            SV2_POOL_ONION='synthetic', SV2_POOL_PORT='4444',
                            TRANSLATOR_CONFIG=str(root/'config.toml'),
                            TRANSLATOR_SOCKET=str(root/'miner.sock')), \
                 patch('translator_runtime.onion_hostname', return_value='synthetic'), \
                 patch('translator_runtime.asyncio.create_subprocess_exec', new=AsyncMock(return_value=child)), \
                 patch('translator_runtime.bootstrap', new=AsyncMock(return_value=None)), \
                 patch('translator_runtime.watch_share_progress', side_effect=quick_watchdog), \
                 patch('builtins.print') as output:
                with self.assertRaises(SystemExit):
                    await main()
                self.assertEqual(child.terminations, 1)
                self.assertTrue(any('share responses stalled' in str(call) for call in output.call_args_list))
                with self.assertRaises(OSError):
                    await asyncio.open_unix_connection(root/'miner.sock')

    async def test_filtered_child_logs_drive_watchdog_without_exposing_payload(self):
        now = [0]
        progress = ShareProgress(lambda: now[0])
        reader = asyncio.StreamReader()
        reader.feed_data((SUBMISSION + ' private payload\n').encode())
        logger = asyncio.create_task(log_output(reader, progress))
        watchdog = asyncio.create_task(watch_share_progress(progress, poll_seconds=.001))
        with patch('builtins.print') as output:
            await asyncio.sleep(.01)
            self.assertEqual(progress.pending, 1)
            now[0] = 120
            await asyncio.wait_for(watchdog, 1)
            reader.feed_eof()
            await logger
            self.assertEqual(output.call_args.args[0], SUBMISSION)

    async def test_healthy_responses_keep_watchdog_waiting_and_cancellable(self):
        progress = ShareProgress()
        progress.observe(SUBMISSION)
        progress.observe(accepted(1))
        watchdog = asyncio.create_task(watch_share_progress(progress, timeout=.01, poll_seconds=.001))
        await asyncio.sleep(.03)
        self.assertFalse(watchdog.done())
        watchdog.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await watchdog


class AdmissionTests(unittest.IsolatedAsyncioTestCase):
    async def test_later_sessions_reach_backend_until_shared_eight_session_limit(self):
        for existing, expected_dials in ((4, 1), (7, 1), (8, 0)):
            with patch.dict(os.environ, LAN_IP='192.168.1.10', MINER_IPS='192.168.1.70'):
                bridge = MinerBridge('fixture')
            bridge.active = existing
            with tempfile.TemporaryDirectory() as tmp:
                path = str(Path(tmp)/'ingress.sock')
                server = await asyncio.start_unix_server(bridge.handle, path)
                try:
                    with patch('translator_runtime.asyncio.open_connection', side_effect=OSError('synthetic backend')) as dial:
                        reader, writer = await asyncio.open_unix_connection(path)
                        writer.write(ipaddress.IPv4Address('192.168.1.70').packed)
                        try:
                            await writer.drain()
                            await asyncio.wait_for(reader.read(), 1)
                        except ConnectionResetError:
                            pass
                        await asyncio.sleep(0)
                        self.assertEqual(dial.call_count, expected_dials)
                        writer.close()
                        try:
                            await writer.wait_closed()
                        except ConnectionResetError:
                            pass
                    self.assertEqual(bridge.active, existing)
                finally:
                    server.close(); await server.wait_closed()

    async def test_disallowed_source_never_connects_to_translator(self):
        with patch.dict(os.environ, LAN_IP='192.168.1.10', MINER_IPS='192.168.1.70'):
            bridge = MinerBridge('fixture')
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp)/'ingress.sock')
            server = await asyncio.start_unix_server(bridge.handle, path)
            try:
                reader, writer = await asyncio.open_unix_connection(path)
                with patch('translator_runtime.asyncio.open_connection', side_effect=AssertionError('forbidden dial')):
                    writer.write(ipaddress.IPv4Address('192.168.1.71').packed)
                    await writer.drain()
                    self.assertEqual(await asyncio.wait_for(reader.read(), 1), b'')
                writer.close(); await writer.wait_closed()
                await asyncio.sleep(0)
                self.assertEqual(bridge.active, 0)
            finally:
                server.close(); await server.wait_closed()


class ObserverTests(unittest.TestCase):
    def test_pool_acknowledgments_are_distinct_from_local_submissions(self):
        stamp = '2026-11-16T16:00:00.000000000Z'
        state = fresh_state(stamp)
        for message in ('Translator Tor path B', 'Translator authenticated V2 job ready',
                        'Downstream 1 registered successfully', 'Received mining.authorize from Sv1 downstream 1',
                        'Downstream: 1 disconnected', 'Downstream 2 registered successfully',
                        'Received mining.authorize from Sv1 downstream 2',
                        'Received: NewExtendedMiningJob(channel_id=1)',
                        'SubmitSharesExtended: valid share, forwarding it to upstream | channel_id: 1'):
            update(state, stamp+' '+message)
        self.assertEqual(state['submitted'], 1)
        self.assertEqual(state['accepted'], 0)
        update(state, stamp+' Received: SubmitSharesSuccess(channel_id=1, last_sequence_number=1, new_submits_accepted_count=1, new_shares_sum=32769)')
        self.assertEqual(state['accepted'], 1)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root/'ready').write_text(str(time.time()))
            config = dict(tor_roots=[tmp, tmp], client_ip='192.168.1.70', account_fingerprint='a'*64)
            value = snapshot(state, config, time.time())
            dashboard_status.write_snapshot(root, value)
            result = dashboard_status.read_snapshot(root, 'gateway')['data']
            self.assertEqual(result['upstream_protocol'], 'SV2')
            self.assertEqual(result['active_sessions'], 1)
            self.assertEqual(result['mining']['accepted'], 1)
            self.assertIsNone(result['sessions'][0]['accepted'])
            self.assertIsNone(result['sessions'][0]['rejected'])


if __name__ == '__main__':
    unittest.main()
