import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import miner_status as m


def bounded_fetch_fixture(config):
    if config['label'] == 'Slow miner':
        time.sleep(2)
    return {'label': config['label'], 'available': True, 'connected': False,
            'authenticated': False, 'fallback': False, 'fallback_enabled': False,
            'trial_endpoint': False, 'mining_target_verified': False,
            'protocol': 'unknown', 'primary_protocol': 'unknown',
            'upstream_protocol': 'unknown', 'hashrate_ghs': 0, 'accepted': 0,
            'rejected': 0, 'uptime_seconds': 0, 'job_age_seconds': None}

class MinerStatusTests(unittest.TestCase):
    def test_one_trickling_miner_cannot_block_other_results(self):
        started = time.monotonic()
        rows = m.fetch_all([{'label': 'Slow miner'}, {'label': 'Fast miner'}],
                           timeout=.1, max_workers=2, fetcher=bounded_fetch_fixture)
        self.assertLess(time.monotonic() - started, 1)
        self.assertEqual(rows[0], {'label': 'Slow miner', 'available': False})
        self.assertTrue(rows[1]['available'])

    def test_local_routes_are_bounded_fresh_and_fail_closed(self):
        now=time.time()
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'status.json'
            self.assertIsNone(m.read_local_routes(tmp))
            value=dict(schema_version=1,sampled_at=now,sessions=[dict(session=1,route='A',client_ip='192.168.1.3')])
            p.write_text(json.dumps(value))
            self.assertEqual(m.read_local_routes(tmp),value['sessions'])
            value['sampled_at']=now-31;p.write_text(json.dumps(value))
            self.assertIsNone(m.read_local_routes(tmp))
            p.write_text('x'*65537);self.assertIsNone(m.read_local_routes(tmp))
            p.unlink();p.symlink_to(Path(tmp)/'absent')
            self.assertIsNone(m.read_local_routes(tmp))

    def sample(self):
        config={'label':'Test miner','authority_key':'public-test-key','expected_gateway':'192.168.1.2','expected_port':3336}
        pool={'id':0,'stratumProtocol':'SV2','stratumURL':'192.168.1.2','stratumPort':3336,'stratumV2RequireAuth':True,'stratumV2AuthorityPubkey':'public-test-key'}
        info={'pools':[pool,{'id':1,'stratumProtocol':'SV1','stratumURL':'192.168.1.3'}], 'primaryPoolIndex':0,'secondaryPoolIndex':3,'isUsingFallbackStratum':0,'poolConnectionSecurity':'noise','connectionDiagnostics':{'poolConnected':True,'lastWorkAgeSeconds':2},'hashRate_1m':1000,'sharesAccepted':2,'sharesRejected':0,'uptimeSeconds':60}
        return info, config
    def test_upstream_badge_requires_end_to_end_evidence_and_known_endpoint(self):
        info,c=self.sample();self.assertEqual(m.observe(info,c)['upstream_protocol'],'SV2')
        info['pools'][0]['stratumURL']='192.168.1.99'
        self.assertEqual(m.observe(info,c)['upstream_protocol'],'unknown')
        info,c=self.sample();info['pools'][0]['stratumV2RequireAuth']=False
        self.assertEqual(m.observe(info,c)['upstream_protocol'],'unknown')
    def test_actual_fallback_is_v1_even_when_primary_v2(self):
        info,c=self.sample();info.update(secondaryPoolIndex=1,isUsingFallbackStratum=1,poolConnectionSecurity='plaintext')
        row=m.observe(info,c)
        self.assertEqual(row['protocol'],'SV1');self.assertEqual(row['primary_protocol'],'SV2');self.assertFalse(row['authenticated']);self.assertTrue(row['fallback'])
    def test_auth_requires_noise_required_auth_and_exact_pin(self):
        info,c=self.sample();self.assertTrue(m.observe(info,c)['authenticated'])
        info['pools'][0]['stratumV2AuthorityPubkey']='wrong';self.assertFalse(m.observe(info,c)['authenticated'])
        info['pools'][0]['stratumV2AuthorityPubkey']='public-test-key';info['pools'][0]['stratumV2RequireAuth']=False;self.assertFalse(m.observe(info,c)['authenticated'])
    def test_disconnected_is_unknown_not_configured_protocol(self):
        info,c=self.sample();info['connectionDiagnostics']['poolConnected']=False
        row=m.observe(info,c);self.assertEqual(row['protocol'],'unknown');self.assertFalse(row['authenticated'])
    def test_stale_missing_and_secrets_hidden(self):
        info,c=self.sample();row=m.observe(info,c);row['password']='secret';row['stratumUser']='private identity'
        payload={'schema_version':1,'sampled_at':100,'miners':[row],'private':'secret'}
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp)/'miners';d.mkdir();(d/'status.json').write_text(json.dumps(payload))
            current=m.read_snapshot(tmp,110);self.assertEqual(current['state'],'current');self.assertNotIn('secret',json.dumps(current));self.assertNotIn('private identity',json.dumps(current))
            self.assertEqual(m.read_snapshot(tmp,131),{'state':'stale','data':None})
            self.assertEqual(m.read_snapshot(tmp,99),{'state':'stale','data':None})
        self.assertEqual(m.read_snapshot('/nonexistent')['state'],'unavailable')
    def test_public_destinations_and_redirects_refused(self):
        _,c=self.sample();c.update(url='http://8.8.8.8',username='test',password='test')
        with self.assertRaises(ValueError):m.validate_config([c])
        c['url']='http://192.168.1.3';self.assertEqual(m.validate_config([c]),[c])
        with self.assertRaises(ValueError):m.NoRedirect().redirect_request(None,None,None,None,None,None)
    def test_failed_fetch_does_not_return_previous_counters(self):
        _,c=self.sample();c.update(url='http://192.168.1.3',username='test',password='test')
        with patch('urllib.request.build_opener',side_effect=OSError('private secret')):
            self.assertEqual(m.fetch(c),{'label':'Test miner','available':False})

    def test_miner_ip_explicit_opt_in_and_private_validation(self):
        info,c=self.sample();row=m.observe(info,c);row.update(miner_ip='192.168.1.3',miner_number=3)
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'miners';p.mkdir()
            (p/'status.json').write_text(json.dumps(dict(schema_version=1,sampled_at=100,miners=[row])))
            hidden=m.read_snapshot(tmp,110)
            self.assertNotIn('miner_ip',hidden['data']['miners'][0])
            shown=m.read_snapshot(tmp,110,include_miner_ips=True)
            self.assertEqual(shown['data']['miners'][0]['miner_ip'],'192.168.1.3')
            self.assertEqual(shown['data']['miners'][0]['miner_number'],3)
        for ip in ('8.8.8.8','127.0.0.1','192.168.1.3<script>','::1','192.168.01.3'):
            with self.assertRaises(ValueError):m.private_miner_ip(ip)
        config=dict(kind='snapshot-file',label='Example',physical_id='example',display_ip='192.168.1.3')
        self.assertEqual(m.validate_config([config]),[config])
        with self.assertRaises(ValueError):m.validate_config([dict(config,display_ip='8.8.8.8')])

    def joined_fixture(self):
        row={'label':'Miner 3','available':True,'connected':True,'protocol':'SV1','upstream_protocol':'unknown','authenticated':False,'mining_target_verified':True,'trial_endpoint':True}
        snapshot={'state':'current','data':{'miners':[row]}}
        gateway={'state':'current','data':{'upstream_protocol':'SV2','counter_basis':'aggregate_pool_acknowledgments','account_fingerprints':['a'*64],
            'routes':[{'route':'tor-1','bootstrap_ready':True}], 'sessions':[{'client_ip':'192.168.1.3','miner_protocol':'SV1','job_state':'fresh','last_job_age_seconds':2,'route':'tor-1'}]}}
        bindings=[{'label':'Miner 3','client_ip':'192.168.1.3','gateway_host':'192.168.1.2','gateway_port':3333,'account_fingerprint':'a'*64}]
        return snapshot,gateway,bindings

    def test_translator_badge_requires_exact_bound_current_authenticated_job_evidence(self):
        snapshot,gateway,bindings=self.joined_fixture()
        row=m.join_gateway_evidence(snapshot,gateway,bindings,'192.168.1.2',3333)['data']['miners'][0]
        self.assertEqual(row['upstream_protocol'],'SV2');self.assertEqual(row['protocol'],'SV1');self.assertFalse(row['authenticated'])
        self.assertEqual(row['upstream_evidence'],'matched_translator')
        self.assertEqual(row['tor_route'],'A')
        self.assertEqual(snapshot['data']['miners'][0]['upstream_protocol'],'unknown')
        self.assertNotIn('192.168.',json.dumps(row));self.assertNotIn('account_fingerprints',row)

    def test_translated_route_tracks_matching_sessions_without_guessing(self):
        for routes, expected in [(['tor-2'], 'B'), (['tor-2', 'tor-2'], 'B'),
                                 (['tor-1', 'tor-2'], 'unknown')]:
            snapshot,gateway,bindings=self.joined_fixture()
            source=gateway['data']['sessions'][0]
            gateway['data']['routes']=[{'route':r,'bootstrap_ready':True} for r in set(routes)]
            gateway['data']['sessions']=[dict(source,route=r) for r in routes]
            # A different source using the other client must not affect this miner.
            gateway['data']['sessions'].append(dict(source,client_ip='192.168.1.4',route='tor-1'))
            with self.subTest(routes=routes):
                row=m.join_gateway_evidence(snapshot,gateway,bindings,'192.168.1.2',3333)['data']['miners'][0]
                self.assertEqual(row['tor_route'],expected)
                self.assertEqual(row['upstream_protocol'],'SV2')
                self.assertFalse(row['authenticated'])
                self.assertNotIn('tor_route',snapshot['data']['miners'][0])

    def test_translator_badge_stale_unready_or_unverified_stays_unknown(self):
        for case in ['miner_stale','gateway_stale','not_ready','not_verified','stale_job','tor_unready','wrong_protocol','wrong_basis']:
            snapshot,gateway,bindings=self.joined_fixture()
            if case=='miner_stale':snapshot['state']='stale'
            if case=='gateway_stale':gateway['state']='stale'
            if case=='not_ready':gateway['data']['translation_ready']=False
            if case=='not_verified':gateway['data']['account_fingerprints']=[]
            if case=='stale_job':gateway['data']['sessions'][0]['last_job_age_seconds']=181
            if case=='tor_unready':gateway['data']['routes'][0]['bootstrap_ready']=False
            if case=='wrong_protocol':gateway['data']['upstream_protocol']='SV1'
            if case=='wrong_basis':gateway['data']['counter_basis']='encrypted_unavailable'
            with self.subTest(case=case):
                row=m.join_gateway_evidence(snapshot,gateway,bindings,'192.168.1.2',3333)['data']['miners'][0]
                self.assertEqual(row['upstream_protocol'],'unknown')
                self.assertEqual(row.get('tor_route','unknown'),'unknown')

    def test_translator_badge_mismatched_identity_target_or_gateway_stays_unknown(self):
        for case in ['label','source','target','gateway','port','account']:
            snapshot,gateway,bindings=self.joined_fixture()
            if case=='label':bindings[0]['label']='Other miner'
            if case=='source':bindings[0]['client_ip']='192.168.1.4'
            if case=='target':snapshot['data']['miners'][0]['mining_target_verified']=False
            if case=='gateway':bindings[0]['gateway_host']='192.168.1.5'
            if case=='port':bindings[0]['gateway_port']=3334
            if case=='account':bindings[0]['account_fingerprint']='b'*64
            with self.subTest(case=case):
                row=m.join_gateway_evidence(snapshot,gateway,bindings,'192.168.1.2',3333)['data']['miners'][0]
                self.assertEqual(row['upstream_protocol'],'unknown')
                self.assertEqual(row.get('tor_route','unknown'),'unknown')
        with self.assertRaises(ValueError):m.gateway_bindings(bindings+bindings)
        with self.assertRaises(ValueError):m.gateway_bindings([{**bindings[0],'client_ip':'8.8.8.8'}])

if __name__=='__main__':unittest.main()
