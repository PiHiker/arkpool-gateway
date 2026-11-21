"""Offline appliance configuration, admission and honest telemetry checks."""
import asyncio
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import appliance_ui
import dashboard_status
import ingress
import v2_config
import dual_gateway
from tests import example_onion
from tests_dashboard import gateway, envelope


def config():
    return dict(pool_onion=example_onion(), pool_port=3336, authority_pubkey='A'*64)


class ConfigTests(unittest.TestCase):
    def test_health_and_unknown_cli_arguments_never_start_the_gateway(self):
        with patch('dual_gateway.asyncio.run') as run:
            for ready in (True, False):
                with patch('gateway.healthcheck', return_value=ready) as check:
                    self.assertEqual(dual_gateway.cli(['healthcheck']), 0 if ready else 1)
                    check.assert_called_once_with()
            for args in (['typo'], ['healthcheck','extra'], ['serve','extra']):
                self.assertEqual(dual_gateway.cli(args),2)
            run.assert_not_called()

    def test_native_only_and_exact_owner(self):
        self.assertEqual(v2_config.validate(config())['ark_identity'], '')
        owner = 'ark1' + 'qurswpc8qurswpc8qurswpc8qurswpc8qurswpc8qurswpc8qursmr9erd'
        self.assertEqual(v2_config.validate(dict(config(), ark_identity=owner))['ark_identity'], owner)
        for bad in (owner+'.worker', owner.upper(), None, 't'+owner):
            with self.subTest(owner=bad), self.assertRaises(ValueError):
                v2_config.validate(dict(config(), ark_identity=bad))

    def test_rejects_ambiguous_and_unbounded_config(self):
        for field, value in (('pool_port', True), ('pool_port', '3336'), ('pool_port', 0),
                             ('pool_port', 65536), ('pool_onion', 'localhost'),
                             ('pool_onion', None), ('authority_pubkey', 'A'*129),
                             ('authority_pubkey', '0'*64), ('extra', 'secret')):
            with self.subTest(field=field), self.assertRaises(ValueError):
                v2_config.validate(dict(config(), **{field:value}))
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)/'config.json'
            for raw in ('{"pool_port":3336,"pool_port":3337}', ' '*16385):
                p.write_text(raw)
                with self.assertRaises(ValueError): v2_config.read(p)
            p.write_text(json.dumps(config()))
            self.assertEqual(v2_config.read(p)['pool_port'],3336)
            symlink=Path(temp)/'link'; symlink.symlink_to(p)
            with self.assertRaises(OSError): v2_config.read(symlink)
            fifo=Path(temp)/'fifo';os.mkfifo(fifo)
            with self.assertRaises(ValueError): v2_config.read(fifo)

    def test_native_only_setup_does_not_claim_available_translator(self):
        page=appliance_ui.page(dict(LAN_IP='192.168.1.10',V1_UPSTREAM_PROTOCOL='SV2',V1_TRANSLATION_ENABLED='0'))
        self.assertIn(b'V1 compatibility is disabled',page)


class TelemetryTests(unittest.TestCase):
    def native(self):
        source=gateway()
        source.update(upstream_protocol='SV2',counter_basis='encrypted_unavailable',translation_enabled=False)
        row=source['sessions'][0]
        row.update(miner_protocol='SV2',job_state='encrypted',last_job_age_seconds=None,
                   counts={'accepted':None,'rejected':None},difficulty=None,accepted_work=None,uptime_seconds=42)
        return source

    def test_native_encryption_preserves_unknown_counters_through_disk(self):
        result=dashboard_status.gateway_view(self.native())
        self.assertIsNone(result['mining']['accepted'])
        self.assertIsNone(result['sessions'][0]['accepted'])
        self.assertTrue(all(r['mining']['accepted'] is None for r in result['routes']))
        self.assertTrue(all(r['mining']['pending_submissions'] is None for r in result['routes']))
        with tempfile.TemporaryDirectory() as temp:
            value=envelope('gateway');value['data']=result
            dashboard_status.write_snapshot(temp,value)
            observed=dashboard_status.read_snapshot(temp,'gateway')
            self.assertEqual(observed['state'],'current')
            self.assertEqual(observed['data']['sessions'][0]['miner_protocol'],'SV2')
            self.assertEqual(observed['data']['sessions'][0]['uptime_seconds'],42)
            self.assertIsNone(observed['data']['mining']['accepted'])
            self.assertTrue(all(r['mining']['accepted'] is None for r in observed['data']['routes']))

    def test_native_relay_cannot_claim_jobs_or_acceptances(self):
        for field,value in [('job_state','fresh'),('last_job_age_seconds',1),('counts',{'accepted':0}),('difficulty',1)]:
            source=self.native();source['sessions'][0][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):dashboard_status.gateway_view(source)

    def test_mixed_session_counters_are_only_translator_totals(self):
        source=self.native();source.update(counter_basis='aggregate_pool_acknowledgments',translation_enabled=True)
        row=gateway()['sessions'][0];row.update(counts={'accepted':None,'rejected':None},accepted_work=None)
        source['sessions'].append(row)
        result=dashboard_status.gateway_view(source)
        self.assertEqual(result['active_sessions'],2)
        self.assertEqual(result['mining']['accepted'],3)
        self.assertTrue(all(r['accepted'] is None for r in result['sessions']))

    def test_translation_readiness_is_not_inferred_from_tor_bootstrap(self):
        source=self.native();source.update(counter_basis='aggregate_pool_acknowledgments',translation_enabled=True,translation_ready=False)
        result=dashboard_status.gateway_view(source)
        self.assertFalse(result['translation_ready'])
        self.assertTrue(all(r['bootstrap_ready'] for r in result['routes']))
        with tempfile.TemporaryDirectory() as temp:
            value=envelope('gateway');value['data']=result
            dashboard_status.write_snapshot(temp,value)
            self.assertFalse(dashboard_status.read_snapshot(temp,'gateway')['data']['translation_ready'])


class IngressTests(unittest.IsolatedAsyncioTestCase):
    async def test_invalid_native_port_fails_before_any_listener_opens(self):
        for value in ('3333','3334','0','65536','foo','1.5'):
            with patch.dict(os.environ,LAN_V2_PORT=value),patch('ingress.asyncio.start_server') as listen:
                with self.assertRaises(ValueError):await ingress.serve(frozenset({'lan'}))
                listen.assert_not_called()

    async def test_combined_source_budget_and_release(self):
        legacy=ingress.Ingress(frozenset({'lan'}))
        native=ingress.Ingress(legacy.miners,ingress.NATIVE_UPSTREAM_PATH)
        native.active=legacy.active;native.active_sources=legacy.active_sources
        source='192.168.1.70'
        self.assertTrue(legacy.reserve_source(source))
        self.assertTrue(native.reserve_source(source))
        self.assertFalse(legacy.reserve_source(source))
        native.release_source(source)
        self.assertTrue(legacy.reserve_source(source))
        legacy.active.update(range(8))
        self.assertFalse(native.reserve_source('192.168.1.71'))


if __name__=='__main__':unittest.main()
