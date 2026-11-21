import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from hashrate_history import History, aggregate, clean_points, MAX_BYTES
import miner_status as miner

FULL = dict(total_ghs=3000, known_ghs=3000, observed=2, expected=2)
PARTIAL = dict(total_ghs=None, known_ghs=1000, observed=1, expected=2)


class HistoryTests(unittest.TestCase):
    def test_first_actual_sample_per_quarter_hour_no_invented_backfill(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'history.json';history = History(path, now=9001)
            history.sample(FULL, 9001)
            first = path.read_bytes()
            history.sample(PARTIAL, 9011)
            self.assertEqual(path.read_bytes(), first)
            history.sample(PARTIAL, 10804)
            self.assertEqual([p['sampled_at'] for p in history.points], [9001, 10804])
            self.assertIsNone(history.points[-1]['total_ghs'])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertLess(path.stat().st_size, MAX_BYTES)

    def test_retention_96_max_and_strict_expiry(self):
        with tempfile.TemporaryDirectory() as folder:
            history = History(Path(folder)/'history.json', now=0)
            for i in range(110): history.sample(FULL, i*900+1)
            self.assertEqual(len(history.points), 96)
            self.assertTrue(all(p['sampled_at'] > 109*900+1-86400 for p in history.points))
            self.assertEqual(clean_points([dict(sampled_at=1000, **FULL)], 87400), [])

    def test_restart_scope_change_and_backward_clock(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'history.json';history=History(path,now=9001,scope='one')
            history.sample(FULL,9001)
            restored=History(path,now=9010,scope='one');restored.sample(PARTIAL,9010)
            self.assertEqual(restored.points,history.points)
            self.assertEqual(History(path,now=9010,scope='two').points,[])
            restored.sample(PARTIAL,8001)
            self.assertEqual([p['sampled_at'] for p in restored.points],[8001])

    def test_corrupt_oversize_symlink_and_nonfinite_not_loaded(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'history.json';path.write_bytes(b'x'*(MAX_BYTES+1))
            self.assertEqual(History(path,now=1).points,[])
            path.unlink();target=Path(folder)/'elsewhere';target.write_text('private');path.symlink_to(target)
            self.assertEqual(History(path,now=1).points,[])
            self.assertEqual(target.read_text(),'private')
            for value in (float('nan'),float('inf'),-1,True):
                with self.assertRaises(ValueError): clean_points([dict(sampled_at=value,**FULL)],100)

    def test_physical_dedup_missing_wrong_pool_and_actual_zero(self):
        configs=[{'physical_id':'one','url':'http://192.168.1.10'}, {'physical_id':'two','url':'http://192.168.1.11'}]
        rows=[{'available':True,'mining_target_verified':True,'hashrate_ghs':1000},
              {'available':True,'mining_target_verified':True,'hashrate_ghs':2000}]
        self.assertEqual(aggregate(rows,configs),FULL)
        # Two transport sessions from one physical device never add a second rate.
        self.assertEqual(aggregate([rows[0],rows[0]],[configs[0],configs[0]])['total_ghs'],1000)
        rows[1]['mining_target_verified']=False
        self.assertEqual(aggregate(rows,configs),PARTIAL)
        rows[1]={'available':False};self.assertEqual(aggregate(rows,configs),PARTIAL)
        rows[0]['hashrate_ghs']=0
        self.assertEqual(aggregate(rows,configs)['known_ghs'],0)
        rows[0]={'available':False};self.assertIsNone(aggregate(rows,configs)['known_ghs'])


class MinerSeriesTests(unittest.TestCase):
    def test_individual_series_missing_zero_and_validation(self):
        from hashrate_history import observation, miner_series
        rows=[dict(miner_number=1, available=True, mining_target_verified=True, hashrate_ghs=0),
              dict(miner_number=3, available=False)]
        series=miner_series(rows)
        self.assertEqual(series, {'1':0, '3':None})
        value=dict(total_ghs=None, known_ghs=0, observed=1, expected=2, miners=series)
        self.assertEqual(observation(value)['miners'],series)
        for bad in ({'9':0}, {'1':float('nan')}, {'1':True}, {'1':2,'3':None}, {'1':0}):
            with self.assertRaises(ValueError): observation(dict(value,miners=bad))

    def test_contact_expiry_restart_and_return_same_number(self):
        from hashrate_history import Presence
        config=[dict(physical_id='one'),dict(physical_id='two')]
        up=[dict(label='One',available=True),dict(label='Two',available=True)]
        down=[dict(label='One',available=False),up[1]]
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'contacts.json'
            roster=Presence(path,'scope',2,now=100)
            rows,_=roster.visible(up,config,now=100)
            self.assertEqual([r['miner_number'] for r in rows],[1,2])
            roster=Presence(path,'scope',2,now=200)
            rows,_=roster.visible(down,config,now=86499)
            self.assertEqual([r['miner_number'] for r in rows],[1,2])
            rows,active=roster.visible(down,config,now=86500)
            self.assertEqual([r['miner_number'] for r in rows],[2])
            self.assertEqual(active,[config[1]])
            roster=Presence(path,'scope',2,now=86501)
            rows,_=roster.visible(up,config,now=86502)
            self.assertEqual([r['miner_number'] for r in rows],[1,2])
            self.assertEqual(path.stat().st_mode & 0o777,0o600)
            self.assertLess(path.stat().st_size,1024)
            self.assertNotIn('label',path.read_text())

    def test_unseen_grace_empty_table_and_original_source_contact(self):
        from hashrate_history import Presence, observation
        with tempfile.TemporaryDirectory() as folder:
            roster=Presence(Path(folder)/'contacts.json','scope',1,now=1000)
            config=[dict(physical_id='one')]
            down=[dict(label='One',available=False)]
            self.assertEqual(roster.visible(down,config,now=87400),([],[]))
            empty=aggregate([],[])
            self.assertEqual(empty,dict(total_ghs=None,known_ghs=None,observed=0,expected=0))
            data=miner.clean(dict(schema_version=1,sampled_at=87400,miners=[],hashrate=empty,hashrate_history=[],history_available=True))
            self.assertEqual(data['miners'],[])
            roster.visible([dict(label='One',available=True,source_age_seconds=100)],config,now=90000)
            self.assertEqual(roster.contacts['1'],89900)
            self.assertEqual(roster.visible(down,config,now=176300),([],[]))

    def test_history_preserves_old_totals_without_invented_individual_rates(self):
        with tempfile.TemporaryDirectory() as folder:
            history=History(Path(folder)/'history.json',now=9001)
            history.sample(FULL,9001)
            current=dict(FULL,miners={'1':1000,'2':2000})
            history.sample(current,9011)
            self.assertNotIn('miners',history.points[0])
            history.sample(current,9901)
            self.assertEqual(history.points[1]['miners'],current['miners'])
            self.assertEqual(History(history.path,now=9910).points,history.points)

    def test_maximum_eight_miners_96_points_remain_bounded(self):
        from hashrate_history import atomic_write
        with tempfile.TemporaryDirectory() as folder:
            history=History(Path(folder)/'history.json',now=0)
            value=dict(total_ghs=8e13,known_ghs=8e13,observed=8,expected=8,miners={str(i):1e13 for i in range(1,9)})
            for i in range(96): history.sample(value,i*900+1)
            self.assertLess(history.path.stat().st_size,MAX_BYTES)
            atomic_write(Path(folder)/'status.json',dict(hashrate_history=history.points))

    def test_contact_ledger_rejects_symlink_and_clock_rollback(self):
        from hashrate_history import Presence
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'contacts.json';target=Path(folder)/'target'
            target.write_text('private');path.symlink_to(target)
            roster=Presence(path,'scope',1,now=100)
            with self.assertRaises(ValueError):roster.visible([dict(available=False)],[{}],now=101)
            self.assertEqual(target.read_text(),'private')
            path.unlink();roster.visible([dict(available=True)],[{}],now=200)
            roster.visible([dict(available=False)],[{}],now=150)
            self.assertEqual(roster.contacts['1'],150)


class SummaryTests(unittest.TestCase):
    def config(self):
        return dict(kind='summary-api',physical_id='miner3',label='Test miner',url='http://192.168.1.3:8080',expected_gateway='192.168.1.2',expected_port=3333)

    def payload(self):
        return {'SUMMARY':[{'GHS 1m':20000,'Accepted':100,'Rejected':2,'Elapsed':1000}]}, {'POOLS':[{'Stratum Active':True,'Status':'Alive','URL':'stratum+tcp://192.168.1.2:3333','User':'private identity'}, {'Stratum Active':False,'Status':'Dead','URL':'stratum+tcp://192.168.1.4:4333'}]}

    def test_summary_is_actual_rate_and_private_target_evidence(self):
        row=miner.observe_summary(*self.payload(),self.config())
        self.assertEqual(row['hashrate_ghs'],20000);self.assertTrue(row['mining_target_verified'])
        self.assertNotIn('private identity',json.dumps(row));self.assertNotIn('192.168.',json.dumps(row))
        summary,pools=self.payload();pools['POOLS'][0]['URL']='stratum+tcp://192.168.1.4:4333'
        self.assertFalse(miner.observe_summary(summary,pools,self.config())['mining_target_verified'])
        pools['POOLS'][1]['Stratum Active']=True
        self.assertFalse(miner.observe_summary(summary,pools,self.config())['mining_target_verified'])
        del summary['SUMMARY'][0]['GHS 1m']
        with self.assertRaises(KeyError): miner.observe_summary(summary,pools,self.config())

    def test_external_snapshot_freshness_no_paths_and_redaction(self):
        c={'kind':'snapshot-file','label':'Miner 3','physical_id':'physical-3'}
        self.assertEqual(miner.validate_config([c]),[c])
        for extra in ({'path':'/private'}, {'url':'http://192.168.1.3'}):
            with self.assertRaises(ValueError): miner.validate_config([{**c,**extra}])
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ,{'MINER_STATUS_ROOT':folder}):
            row=miner.observe_summary(*self.payload(),self.config());row['secret']='private'
            path=Path(folder)/'external-physical-3.json'
            path.write_text(json.dumps({'schema_version':1,'sampled_at':100,'miner':row}))
            result=miner.fetch_snapshot(c,120)
            self.assertEqual(result['source_age_seconds'],20)
            self.assertEqual(result['label'],'Miner 3');self.assertNotIn('secret',result)
            for now in (99,131):
                with self.assertRaises(ValueError): miner.fetch_snapshot(c,now)
            self.assertEqual(aggregate([result],[c])['total_ghs'],20000)
            self.assertEqual(aggregate([result],[c])['oldest_source_age_seconds'],20)
            extended={**c,'max_age_seconds':150};miner.validate_config([extended])
            self.assertEqual(miner.fetch_snapshot(extended,240)['source_age_seconds'],140)
            with self.assertRaises(ValueError): miner.fetch_snapshot(extended,251)
            with self.assertRaises(ValueError): miner.validate_config([{**c,'max_age_seconds':301}])
            target=Path(folder)/'other';path.rename(target);path.symlink_to(target)
            with self.assertRaises(OSError): miner.fetch_snapshot(c,120)

    def test_private_origin_port_commands_and_device_duplicates(self):
        self.assertEqual(miner.validate_config([self.config()]),[self.config()])
        for url in ('http://8.8.8.8:8080','http://192.168.1.3:22','http://192.168.1.3:8080/other','http://user@192.168.1.3:8080'):
            with self.assertRaises(ValueError): miner.validate_config([{**self.config(),'url':url}])
        with self.assertRaises(ValueError): miner.validate_config([self.config(),self.config()])
        with self.assertRaises(ValueError): miner.summary_request(self.config(),'restart')
        with patch('miner_status.summary_request',side_effect=OSError('private response')):
            self.assertFalse(miner.fetch(self.config())['available'])

if __name__=='__main__':unittest.main()
