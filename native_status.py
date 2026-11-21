"""Optional read-only native-relay route metadata; no mining payloads or keys."""
import hmac
from bounded_http import BoundedHTTPServer, DeadlineHTTPRequestHandler
import ipaddress
import json
import os
from pathlib import Path
import time

PRIVATE = tuple(ipaddress.ip_network(x) for x in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))


def private_ip(value):
    address=ipaddress.IPv4Address(value)
    if str(address)!=value or not any(address in network for network in PRIVATE):
        raise ValueError('private IPv4 required')
    return value


def clean(value, now=None):
    now=time.time() if now is None else now
    stamp=value['sampled_at']
    if type(stamp) not in (int,float) or not -5 <= now-stamp <= 30:
        raise ValueError('stale native route data')
    if value.get('schema_version') != 1 or not isinstance(value['sessions'],list) or len(value['sessions'])>8:
        raise ValueError('invalid native route snapshot')
    sessions=[]
    for s in value['sessions']:
        if s['route'] not in ('A','B') or type(s['session']) is not int or not 1 <= s['session'] <= 10**15:
            raise ValueError('invalid native route')
        row={'route':s['route'],'session':s['session']}
        if 'client_ip' in s:row['client_ip']=private_ip(s['client_ip'])
        sessions.append(row)
    if len({s['session'] for s in sessions})!=len(sessions):raise ValueError('duplicate session')
    return {'schema_version':1,'sampled_at':stamp,'sessions':sessions}


def read(root):
    with (Path(root)/'status.json').open('rb') as f:raw=f.read(16385)
    if len(raw)>16384:raise ValueError('oversize route snapshot')
    return clean(json.loads(raw))


def handler(root, token, client_ip):
    if len(token)!=64 or any(c not in '0123456789abcdef' for c in token):raise ValueError('invalid status token')
    private_ip(client_ip)
    class Routes(DeadlineHTTPRequestHandler):
        header_timeout_seconds=3
        response_timeout_seconds=3
        def log_message(self,*args):pass
        def do_GET(self):
            self.response_ready()
            if self.client_address[0] != client_ip or not hmac.compare_digest(self.headers.get('Authorization','').encode(),('Bearer '+token).encode()):
                code,body=403,b'Forbidden\n'
            elif self.path!='/api/routes':code,body=404,b'Not found\n'
            else:
                try:code,body=200,json.dumps(read(root),allow_nan=False).encode()
                except (OSError,ValueError,KeyError,TypeError):code,body=503,b'Unavailable\n'
            self.send_response(code);self.send_header('Content-Length',str(len(body)))
            self.send_header('Content-Type','application/json' if code==200 else 'text/plain')
            self.send_header('Cache-Control','no-store');self.send_header('Connection','close')
            self.end_headers();self.wfile.write(body);self.close_connection=True
        def do_POST(self):
            self.response_ready()
            self.send_response(405);self.send_header('Content-Length','0');self.send_header('Connection','close');self.end_headers();self.close_connection=True
    return Routes


class Server(BoundedHTTPServer):
    request_queue_size=4
    max_workers=2


if __name__=='__main__':
    token=Path(os.environ['NATIVE_STATUS_TOKEN_FILE']).read_text().strip()
    Server(('0.0.0.0',8080),handler('/run/native-status',token,os.environ['NATIVE_STATUS_CLIENT'])).serve_forever()
