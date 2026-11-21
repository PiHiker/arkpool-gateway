"""Experimental Umbrel app-directory export, never an App Store submission."""
import json
from platform_export import ROOT, checked_image, checked_settings

APP_ID = 'arkpool-gateway'


def render(values, image, ui_port=3335):
    s = checked_settings(values)
    image = checked_image(image, registry=True)
    used = {int(s['LAN_PORT'])}
    if s['TLS_ENABLED'] == '1':
        used.add(int(s['LAN_TLS_PORT']))
    if not isinstance(ui_port, int) or not 1024 <= ui_port <= 65535 or ui_port in used or 40000 <= ui_port <= 49999:
        raise ValueError('nonconflicting nonreserved browser port required')
    def runtime(program, memory='192m'):
        return {'image': image, 'user': '1000:1000', 'command': ['python3', '/app/'+program],
                'init': True, 'restart': 'on-failure', 'read_only': True,
                'cap_drop': ['ALL'], 'security_opt': ['no-new-privileges:true'],
                'pids_limit': 64, 'cpus': 0.5, 'mem_limit': memory,
                'tmpfs': ['/tmp:rw,noexec,nosuid,size=8m,mode=1777'],
                'logging': {'driver': 'json-file', 'options': {'max-size': '2m', 'max-file': '2'}}}
    directories = set()
    def mount(name, target, readonly=False):
        directories.add(name)
        return {'type': 'bind', 'source': '${APP_DATA_DIR:?Umbrel app data required}/data/'+name,
                'target': target, 'read_only': readonly}
    def health(script, start_period='30s'):
        return {'test': ['CMD', 'python3', '/app/'+script, 'healthcheck'],
                'interval': '15s', 'timeout': '5s', 'retries': 4, 'start_period': start_period}
    services = {}
    for name in ('tor-a', 'tor-b'):
        services[name] = dict(runtime('tor_supervisor.py'), volumes=[
            mount(name+'-state', '/var/lib/tor'), mount('runtime/'+name+'-socks', '/run/tor-socks')],
            stop_grace_period='30s')
    services['gateway'] = dict(runtime('gateway.py'), network_mode='none',
        environment={k: s[k] for k in ('LAN_IP', 'LAN_CIDR', 'MINER_IPS', 'POOL_ONION', 'POOL_PORT', 'TOR_ROUTE_POLICY', 'TOR_ISOLATION')},
        depends_on={k: {'condition': 'service_started'} for k in ('tor-a', 'tor-b')},
        healthcheck=health('gateway.py', '10m'), volumes=[mount('runtime/gateway-socket', '/run/arkpool'),
            mount('runtime/tor-a-socks', '/run/tor-a', True),
            mount('runtime/tor-b-socks', '/run/tor-b', True)])
    services['gateway']['environment'].update(DASHBOARD_SNAPSHOTS='1', DASHBOARD_CLIENT_IPS='0')
    services['gateway']['volumes'].append(mount('runtime/dashboard-gateway', '/run/arkpool-dashboard'))
    ports = [{'target': 3333, 'published': s['LAN_PORT'], 'host_ip': s['LAN_IP'], 'protocol': 'tcp'}]
    env = {k: s[k] for k in ('LAN_IP', 'LAN_CIDR', 'MINER_IPS')}
    volumes = [mount('runtime/gateway-socket', '/run/arkpool', True)]
    if s['TLS_ENABLED'] == '1':
        env.update({k: s[k] for k in ('TLS_ENABLED', 'LAN_PORT', 'LAN_TLS_PORT')})
        ports.append({'target': 3334, 'published': s['LAN_TLS_PORT'], 'host_ip': s['LAN_IP'], 'protocol': 'tcp'})
        volumes.append(mount('tls-identity', '/var/lib/arkpool-tls'))
    services['ingress'] = dict(runtime('ingress.py', '64m'), environment=env, ports=ports,
        volumes=volumes, healthcheck=health('ingress.py'),
        depends_on={'gateway': {'condition': 'service_healthy'}})
    services['ingress']['environment']['DASHBOARD_SNAPSHOTS'] = '1'
    services['ingress']['volumes'].append(mount('runtime/dashboard-ingress', '/run/arkpool-dashboard'))
    services['web'] = dict(runtime('appliance_ui.py', '64m'),
        environment={k: s[k] for k in ('LAN_IP', 'LAN_PORT', 'LAN_TLS_PORT', 'TLS_ENABLED')},
        healthcheck=health('appliance_ui.py'))
    services['web']['environment'].update(
        DASHBOARD_ENABLED='1', DASHBOARD_AUTH='platform', DASHBOARD_CLIENT_IPS='0')
    services['web']['volumes'] = [mount('runtime/dashboard-gateway', '/run/arkpool-dashboard/gateway', True),
                                mount('runtime/dashboard-ingress', '/run/arkpool-dashboard/ingress', True)]
    # Umbrel manages this proxy; do not add an image or bypass its authentication.
    services['app_proxy'] = {'environment': {'APP_HOST': APP_ID+'_web_1', 'APP_PORT': '8080'}}
    manifest = {'manifestVersion': 1, 'id': APP_ID, 'storage': {'dataRoot': 'data'},
        'category': 'bitcoin', 'name': 'ArkPool Gateway', 'version': (ROOT/'VERSION').read_text().strip(),
        'tagline': 'Private Bitcoin mining over Tor with Ark payouts',
        'description': 'Experimental package for operator testing, not a supported App Store release. '
            'Open the app for your miner connection settings. Supply your own compatible Ark receive '
            'address only in the miner, never wallet keys. Two independent Tor clients carry upstream '
            'traffic; the gateway has no network interface. Keep mining ports private and verify actual '
            'source-IP preservation. The authenticated read-only dashboard shows sessions, '
            'job freshness, share responses and Tor/TLS status. Counters reset with the gateway '
            'process; accepted responses are not proof of payment.',
        'releaseNotes': '', 'developer': 'ArkPool', 'website': 'https://arkpool.org',
        'dependencies': [], 'repo': 'https://gitlab.com/arkpool/arkpool-gateway',
        'support': 'https://gitlab.com/arkpool/arkpool-gateway/-/issues',
        'port': ui_port, 'gallery': [], 'path': '', 'defaultUsername': '', 'defaultPassword': '',
        'submitter': 'ArkPool', 'submission': '', 'backupIgnore': ['data/runtime/*']}
    files = {APP_ID+'/docker-compose.yml': json.dumps({'services': services}, indent=2)+'\n',
             APP_ID+'/umbrel-app.yml': json.dumps(manifest, indent=2)+'\n'}
    for directory in sorted(directories):
        files[APP_ID+'/data/'+directory+'/.gitkeep'] = ''
    files['INSTALL.txt'] = (
        'EXPERIMENTAL operator-specific Umbrel package, not a published App Store app.\n'
        'JSON syntax in .yml files is valid YAML. Read docs/PLATFORMS.md first.\n'
        'Requires a publicly pullable, reviewed tagged multi-architecture image digest\n'
        'containing appliance_ui.py; verify amd64 AND arm64 before store distribution.\n'
        'Generated files contain your LAN/pool configuration: keep them private.\n'
        'The UI port is not reserved globally; check the chosen Umbrel before install.\n'
        'Umbrel must preserve gateway network_mode:none and actual ingress source IP.\n'
        'The UI reads only separate read-only status snapshots; no transport sockets or keys.\n'
        'Keep Umbrel authentication enabled. UI health alone does not prove mining.\n'
        'Tor and optional TLS identities persist under app data, including after restart.\n'
        'Tor gets a 30-second stop grace so it can flush state before forced teardown.\n'
        'Client IP display is explicitly disabled in both status producer and UI.\n'
        'Only transient socket/heartbeat/status directories are excluded from backups.\n'
        'Do not use gateway.sh upgrade on this layout or install over an existing app.\n'
        'Do not mount the engine socket, use host networking, or substitute shared Tor.\n'
        'Native install/update/restore/LAN/mining tests remain required on an appliance.\n')
    return files
