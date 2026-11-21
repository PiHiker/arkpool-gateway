"""Read-only local setup checks. No pool/miner traffic; no private values printed."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
sys.dont_write_bytecode = True
from gateway import Config

ROOT = Path(__file__).resolve().parent
KEYS = {'LAN_IP', 'LAN_CIDR', 'MINER_IPS', 'POOL_ONION', 'POOL_PORT', 'LAN_PORT',
        'LAN_TLS_PORT', 'TLS_ENABLED', 'TOR_ROUTE_POLICY', 'TOR_ISOLATION',
        'SHHARK_STATUS_TOKEN', 'SHHARK_STATUS_PORT', 'DASHBOARD_CLIENT_IPS',
        'MINER_ACCOUNT_PINS'}
OVERLAP_INTERFACES = re.compile(r'^(docker\d*|br-[0-9a-f]+|wg\d*|tailscale\d*|tun\d*|zt[a-z0-9]+)$')


def read_settings(path):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(fd) as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or info.st_size > 4096):
            raise ValueError('private regular file required')
        values = {}
        for line in stream.read(4097).splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            key, sep, value = line.partition('=')
            if (not sep or key not in KEYS or key in values or not value
                    or any(c in value for c in '$`"\'\\#\x00') or value != value.strip()):
                raise ValueError('literal settings required')
            values[key] = value
    Config.load(values)
    port = values.get('LAN_PORT', '3333')
    if not port.isdecimal() or not 1 <= int(port) <= 65535:
        raise ValueError('invalid listener port')
    values['LAN_PORT'] = port
    tls_enabled = values.get('TLS_ENABLED', '0')
    if tls_enabled not in ('0', '1'):
        raise ValueError('invalid TLS setting')
    tls_port = values.get('LAN_TLS_PORT', '3334')
    if not tls_port.isdecimal() or not 1 <= int(tls_port) <= 65535 or (tls_enabled == '1' and int(tls_port) == int(port)):
        raise ValueError('invalid or conflicting TLS listener port')
    values['TLS_ENABLED'] = tls_enabled
    values['LAN_TLS_PORT'] = tls_port
    token = values.get('SHHARK_STATUS_TOKEN')
    if token is not None and not re.fullmatch(r'[0-9a-f]{64}', token):
        raise ValueError('invalid Shhark status token')
    if 'SHHARK_STATUS_PORT' in values and token is None:
        raise ValueError('Shhark status token required with status port')
    if token is not None or 'SHHARK_STATUS_PORT' in values:
        status_port = values.get('SHHARK_STATUS_PORT', '3335')
        if (not status_port.isdecimal() or not 1 <= int(status_port) <= 65535
                or int(status_port) in (int(port), int(tls_port))):
            raise ValueError('invalid or conflicting Shhark status port')
        values['SHHARK_STATUS_PORT'] = status_port
    return values


def command(args):
    try:
        env = dict(os.environ)
        for name in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH'):
            env.pop(name, None)
        result = subprocess.run(args, capture_output=True, text=True, timeout=12, cwd=ROOT, env=env)
        return result.stdout if result.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def address_inventory(output):
    interfaces = json.loads(output or 'null')
    if not isinstance(interfaces, list):
        raise ValueError('invalid interface inventory')
    rows = []
    for interface in interfaces:
        if not isinstance(interface, dict) or not isinstance(interface.get('ifname'), str):
            raise ValueError('invalid interface inventory')
        for address in interface.get('addr_info', []):
            if not isinstance(address, dict) or address.get('family', 'inet') != 'inet':
                continue
            local, prefix = address.get('local'), address.get('prefixlen')
            if not isinstance(local, str) or type(prefix) is not int:
                raise ValueError('invalid interface address')
            rows.append((interface['ifname'], ipaddress.ip_network(f'{local}/{prefix}', strict=False), local))
    return rows


def listener_network(settings, invoke=command):
    rows = address_inventory(invoke(['ip', '-j', '-4', 'address', 'show']))
    matches = [(name, network) for name, network, local in rows if local == settings['LAN_IP']]
    if len(matches) != 1:
        raise ValueError('listener address must identify exactly one interface network')
    return matches[0], rows


def suggested_lan_cidr(root=ROOT, invoke=command):
    settings = read_settings(root / '.env')
    (_name, network), _rows = listener_network(settings, invoke)
    return str(network)


def run(root=ROOT, invoke=command):
    checks = []
    def add(name, status, detail):
        checks.append({'check': name, 'status': status, 'detail': detail})
    add('platform', 'pass' if sys.platform.startswith('linux') else 'fail', 'Linux host required.')
    try:
        version = (root / 'VERSION').read_text().strip()
        if not re.fullmatch(r'\d+\.\d+\.\d+-alpha\.\d+', version):
            raise ValueError()
        add('version', 'pass', version)
    except (OSError, ValueError):
        add('version', 'fail', 'Version file missing or invalid.')
    try:
        settings = read_settings(root / '.env')
        add('configuration', 'pass', 'Private literal configuration valid; values suppressed.')
    except (OSError, ValueError, UnicodeError):
        settings = None
        add('configuration', 'fail', 'Provide a regular mode-0600 .env with valid literal settings; values suppressed.')
    docker = ['docker', '--host', 'unix:///var/run/docker.sock']
    data = invoke(docker + ['version', '--format', '{{json .Server}}'])
    try:
        good = json.loads(data).get('Os') == 'linux' if data else False
    except (ValueError, AttributeError):
        good = False
    add('docker_local', 'pass' if good else 'fail', 'Accessible local Linux Docker daemon required.')
    compose = invoke(docker + ['compose', 'version', '--short'])
    add('compose_v2', 'pass' if compose and re.match(r'^v?2\.', compose.strip()) else 'fail', 'Docker Compose v2 required.')
    if settings:
        try:
            (listener_name, detected_network), rows = listener_network(settings, invoke)
            add('listener_address', 'pass', 'Listener address is assigned to exactly one local interface.')
            if settings.get('MINER_IPS', 'lan') == 'subnet':
                allowed = ipaddress.ip_network(settings['LAN_CIDR'], strict=True)
                exact = allowed == detected_network
                add('lan_cidr', 'pass' if exact else 'warn',
                    'Configured LAN_CIDR matches the listener interface.' if exact else
                    'Configured LAN_CIDR differs from the listener interface; run preflight --show-lan-cidr and review intentional routing.')
                overlap = any(name != listener_name and OVERLAP_INTERFACES.fullmatch(name)
                              and allowed.overlaps(network) for name, network, _local in rows)
                add('network_overlap', 'warn' if overlap else 'pass',
                    'Allowed miner range overlaps a Docker or VPN interface; use exact miner IPs or a narrower non-overlapping range.' if overlap else
                    'No overlap with detected Docker or VPN interface ranges.')
        except (ValueError, TypeError, AttributeError, KeyError):
            add('listener_address', 'fail', 'Unable to inspect local IPv4 addresses; check iproute2 availability.')
        output = invoke(['ss', '-H', '-ltn'])
        if output is None:
            add('listener_port', 'fail', 'Unable to inspect TCP listeners.')
        else:
            occupied = False
            ports = {settings['LAN_PORT']}
            if settings['TLS_ENABLED'] == '1':
                ports.add(settings['LAN_TLS_PORT'])
            if 'SHHARK_STATUS_TOKEN' in settings:
                ports.add(settings['SHHARK_STATUS_PORT'])
            for line in output.splitlines():
                fields = line.split()
                if len(fields) >= 4:
                    address, _, port = fields[3].rpartition(':')
                    if port in ports and address.strip('[]') in (settings['LAN_IP'], '0.0.0.0', '*', '::'):
                        occupied = True
            add('listener_port', 'warn' if occupied else 'pass',
                'Port occupied: verify existing deployment ownership; do not stop it automatically.' if occupied else 'No conflicting listener observed; this is not a port reservation.')
    try:
        free = shutil.disk_usage(root).free
        add('disk_headroom', 'pass' if free >= 2 * 1024**3 else 'warn', '2 GiB free recommended for setup; not a sizing guarantee.')
        memory = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
        kib = int(memory['MemAvailable'].split()[0])
        add('memory_headroom', 'pass' if kib >= 1024**2 else 'warn', '1 GiB available recommended for setup; review other workloads.')
    except (OSError, ValueError, KeyError):
        add('resources', 'warn', 'Resource headroom could not be measured.')
    add('external_validation', 'manual', 'Operator must confirm placement, reservations, firewall reachability, source-IP preservation, both Tor paths, identity and accepted shares.')
    failed = any(x['status'] == 'fail' for x in checks)
    warned = any(x['status'] == 'warn' for x in checks)
    return {'schema_version': 1, 'scope': 'local_setup_only', 'mutations_performed': False,
            'ready_for_mining': False, 'result': 'blocked' if failed else 'review' if warned else 'local_checks_passed',
            'checks': checks}, 1 if failed else 2 if warned else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--show-lan-cidr', action='store_true',
                        help='print the detected LAN_CIDR assignment; does not edit .env')
    args = parser.parse_args()
    if args.show_lan_cidr:
        try:
            print('LAN_CIDR=' + suggested_lan_cidr())
            return 0
        except (OSError, ValueError, UnicodeError):
            print('Unable to derive LAN_CIDR from the configured LAN_IP.', file=sys.stderr)
            return 1
    result, code = run()
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        for item in result['checks']:
            print(f"{item['status'].upper():6} {item['check']}: {item['detail']}")
        print('Local checks only; no containers started and no pool or miner contacted.')
    return code


if __name__ == '__main__':
    sys.exit(main())
