import json
from pathlib import Path
import tempfile
import time
import unittest
import native_status as n
import miner_status as m

class NativeStatusTests(unittest.TestCase):
    def test_only_route_metadata_survives(self):
        value={'schema_version':1,'sampled_at':100,'sessions':[{'session':1,'client_ip':'192.168.1.70','route':'B','payload':'secret'}],'private':'secret'}
        data=n.clean(value,110)
        self.assertNotIn('secret',json.dumps(data));self.assertEqual(data['sessions'][0]['route'],'B')
        self.assertEqual(n.clean(value,96)['sessions'][0]['route'],'B')
        with self.assertRaises(ValueError):n.clean(value,94)
        with self.assertRaises(ValueError):n.clean(value,131)
        value['sessions'][0]['client_ip']='8.8.8.8'
        with self.assertRaises(ValueError):n.clean(value,110)
    def test_ambiguous_or_other_endpoint_never_guesses_a_route(self):
        row={'available':True,'connected':True,'trial_endpoint':True};cfg=[{'url':'http://192.168.1.70'}]
        routes=[{'client_ip':'192.168.1.70','route':'B'}]
        self.assertEqual(m.attach_routes([dict(row)],cfg,routes)[0]['tor_route'],'B')
        self.assertEqual(m.attach_routes([dict(row)],cfg,routes*2)[0]['tor_route'],'unknown')
        row['trial_endpoint']=False
        self.assertEqual(m.attach_routes([row],cfg,routes)[0]['tor_route'],'unknown')
    def test_bad_tokens_and_public_client_are_refused(self):
        with self.assertRaises(ValueError):n.handler('/unused','bad','192.168.1.10')
        with self.assertRaises(ValueError):n.handler('/unused','a'*64,'8.8.8.8')
    def test_status_http_requires_token_and_allows_no_control(self):
        import http.client,threading
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as root:
            Path(root,'status.json').write_text(json.dumps({'schema_version':1,'sampled_at':time.time(),'sessions':[]}))
            # Exact-peer boundary is preserved; localhost is only a synthetic test fixture.
            with patch.object(n,'private_ip',return_value='127.0.0.1'):
                server=n.Server(('127.0.0.1',0),n.handler(root,'a'*64,'127.0.0.1'))
            t=threading.Thread(target=server.serve_forever,daemon=True);t.start()
            try:
                for method,path,token,expected in [('GET','/api/routes','','403'),('GET','/api/routes','a'*64,'200'),('GET','/api/routes?x=1','a'*64,'404'),('POST','/api/routes','a'*64,'405')]:
                    c=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=2);c.request(method,path,headers={'Authorization':'Bearer '+token});r=c.getresponse();self.assertEqual(str(r.status),expected);r.read();c.close()
            finally:server.shutdown();server.server_close();t.join(2)

if __name__=='__main__':unittest.main()
