"""Build a generic community-store tree from public defaults and an image digest.

Never reads deployment settings. Output must be a new directory outside Git.
"""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from platform_umbrel import render

# This runs on the Umbrel host, before Compose. No network packets are sent.
# Refuse ambiguous/public interfaces instead of binding every host interface.
EXPORTS = r'''_arkpool_network="$(python3 - <<'PY'
import ipaddress, json, subprocess
def query(*args):
    return json.loads(subprocess.check_output(['ip', '-j', '-4', *args], timeout=5))
routes = query('route', 'show', 'default')
devices = {row.get('dev') for row in routes if row.get('dev')}
if len(devices) != 1:
    raise SystemExit('ArkPool requires one unambiguous default LAN interface')
device = devices.pop()
if device.startswith(('docker', 'br-', 'wg', 'tun', 'tailscale', 'zt')):
    raise SystemExit('ArkPool refuses a VPN or container interface as its LAN')
allowed = [ipaddress.ip_network(value) for value in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')]
addresses = []
for row in query('address', 'show', 'dev', device):
    for address in row.get('addr_info', []):
        if address.get('family') != 'inet' or address.get('scope') != 'global':
            continue
        value = ipaddress.ip_interface(str(address['local']) + '/' + str(address['prefixlen']))
        if any(value.ip in network and value.network.subnet_of(network) for network in allowed):
            addresses.append(value)
if len(addresses) != 1:
    raise SystemExit('ArkPool requires one RFC1918 address on its default LAN interface')
print(str(addresses[0].ip) + ' ' + str(addresses[0].network))
PY
)" || return 1
read -r APP_ARKPOOL_LAN_IP APP_ARKPOOL_LAN_CIDR <<< "${_arkpool_network}"
export APP_ARKPOOL_LAN_IP APP_ARKPOOL_LAN_CIDR
unset _arkpool_network
'''

PRE_START = r'''#!/usr/bin/env bash
set -euo pipefail
APP_DIR="${APP_DATA_DIR:-$(readlink -f "$(dirname "${BASH_SOURCE[0]}")/..")}"
DATA_DIR="${APP_DATA_ROOT:-${APP_DIR}/data}"
# Umbrel creates bind directories with mode 0755. Tor requires private socket
# parents; normalize only this app's known directories, never existing files.
for relative in tor-a-state tor-b-state runtime runtime/tor-a-socks runtime/tor-b-socks runtime/gateway-socket runtime/dashboard-gateway runtime/dashboard-ingress; do
    target="${DATA_DIR}/${relative}"
    if [ -L "${target}" ]; then
        echo 'ArkPool refuses a symlink in its private runtime directories' >&2
        exit 1
    fi
    install -d -m 0700 -o 1000 -g 1000 "${target}"
done
'''


def build(image, submission=''):
    # Only the reviewed public example supplies pool defaults, never a local .env.
    public = {}
    for line in (ROOT / '.env.example').read_text().splitlines():
        if line.strip() and not line.lstrip().startswith('#') and '=' in line:
            key, value = line.split('=', 1)
            public[key] = value
    public.update(LAN_IP='192.168.1.10', LAN_CIDR='192.168.1.0/24',
                  MINER_IPS='subnet', LAN_PORT='23333', TLS_ENABLED='0',
                  LAN_TLS_PORT='23334', TOR_ROUTE_POLICY='round-robin', TOR_ISOLATION='miner')
    files = render(public, image, ui_port=23335)
    del files['INSTALL.txt']
    compose = json.loads(files['arkpool-gateway/docker-compose.yml'])
    for service in compose['services'].values():
        if 'volumes' in service:
            service['volumes'] = [volume['source'].replace('${APP_DATA_DIR:?Umbrel app data required}', '${APP_DATA_DIR}')
                                  + ':' + volume['target'] + (':ro' if volume.get('read_only') else '')
                                  for volume in service['volumes']]
        env = service.get('environment', {})
        if 'LAN_IP' in env:
            env['LAN_IP'] = '${APP_ARKPOOL_LAN_IP:?Private LAN detection required}'
        if 'LAN_CIDR' in env:
            env['LAN_CIDR'] = '${APP_ARKPOOL_LAN_CIDR:?Private subnet detection required}'
        for port in service.get('ports', []):
            port['host_ip'] = '${APP_ARKPOOL_LAN_IP:?Private LAN detection required}'
    manifest = json.loads(files['arkpool-gateway/umbrel-app.yml'])
    manifest.update(manifestVersion=2.0, version=manifest['version'] + '.umbrel.1', description=(
        'Alpha community package. Open the authenticated dashboard for miner setup and live status. '
        'Use your complete mainnet Ark receive address as the miner username and x as password. '
        'Never provide wallet keys. Stratum V1 is available on private LAN port 23333 without TLS; '
        'upstream mining uses two independent Tor clients. Reserve the Umbrel LAN address and '
        'keep this port off the Internet. By default only miners in the same LAN subnet can connect. '
        'For routed private miners, select the explicit lan policy in app settings and maintain '
        'appropriate firewall restrictions. Counters describe this running process, not payments. '
        'This package is for fresh installations; importing an earlier operator-specific export '
        'requires a separately reviewed migration.'),
        environment=[{'name': 'MINER_IPS', 'services': ['gateway', 'ingress'],
                      'default': 'subnet', 'options': ['subnet', 'lan'],
                      'note': 'subnet permits the detected LAN subnet; lan permits all RFC1918 sources. Keep firewall restrictions.'}],
        repo='https://gitlab.com/arkpool/arkpool-gateway', submission=submission,
        icon='https://arkpool.org/favicon.svg')
    files['arkpool-gateway/docker-compose.yml'] = json.dumps(compose, indent=2) + '\n'
    files['arkpool-gateway/umbrel-app.yml'] = json.dumps(manifest, indent=2) + '\n'
    files['arkpool-gateway/exports.sh'] = EXPORTS
    files['arkpool-gateway/hooks/pre-start'] = PRE_START
    files['umbrel-app-store.yml'] = 'id: arkpool\nname: ArkPool Community Store\n'
    return files


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--submission', required=True, help='Actual package review merge-request URL')
    args = parser.parse_args()
    destination = args.output.resolve()
    if destination == ROOT or ROOT in destination.parents or destination.exists():
        parser.error('output must be a new directory outside the source checkout')
    import re
    if not re.fullmatch(r'https://gitlab.com/arkpool/arkpool-gateway/-/merge_requests/[1-9][0-9]*', args.submission):
        parser.error('an actual ArkPool gateway merge-request URL is required')
    files = build(args.image, args.submission)
    destination.mkdir(parents=True, mode=0o755)
    for name, content in files.items():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        target.chmod(0o755 if '/hooks/' in name else 0o644)
    print('Generated generic store candidate; native install and image verification still required.')
