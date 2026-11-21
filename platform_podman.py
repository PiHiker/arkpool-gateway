"""Rootful Podman Quadlets; no shared pod, engine socket or Compose dependency."""
from platform_export import checked_image, checked_settings


def render(values, image):
    s = checked_settings(values)
    image = checked_image(image)
    files = {}
    volumes = ('gateway-socket', 'tor-a-state', 'tor-a-socks', 'tor-b-state', 'tor-b-socks')
    if s['TLS_ENABLED'] == '1':
        volumes += ('tls-identity',)
    for name in volumes:
        files[f'arkpool-{name}.volume'] = ('[Volume]\n'
            f'VolumeName=arkpool-{name}\nUser=10001\nGroup=10001\nCopy=false\n')
    for name in ('miner-lan', 'tor-egress'):
        files[f'arkpool-{name}.network'] = f'[Network]\nNetworkName=arkpool-{name}\nDriver=bridge\n'
    for role in ('tor-a', 'tor-b', 'gateway', 'ingress'):
        tor = role.startswith('tor-')
        program = 'tor_supervisor.py' if tor else role + '.py'
        deps = ('arkpool-tor-a.service arkpool-tor-b.service' if role == 'gateway' else
                'arkpool-gateway.service' if role == 'ingress' else '')
        lines = ['[Unit]', 'Description=ArkPool ' + role, 'ConditionUser=root',
                 'Wants=network-online.target', 'After=network-online.target']
        if deps:
            # Wants rather than Requires: restarting one Tor must not stop its peers.
            lines += ['Wants=' + deps, 'After=' + deps]
        lines += ['[Container]', 'Image=' + image, 'Pull=never',
                  'ContainerName=arkpool-' + role, 'Exec=python3 /app/' + program,
                  'User=10001', 'Group=10001', 'RunInit=true', 'ReadOnly=true',
                  'ReadOnlyTmpfs=false', 'DropCapability=all', 'NoNewPrivileges=true',
                  'PidsLimit=64', 'Tmpfs=/tmp:rw,noexec,nosuid,size=8m,mode=1777',
                  'LogDriver=journald', 'PodmanArgs=--http-proxy=false',
                  'Network=' + ('none' if role == 'gateway' else
                    'arkpool-tor-egress.network' if tor else 'arkpool-miner-lan.network')]
        mounts = ([f'{role}-state:/var/lib/tor:rw,Z', f'{role}-socks:/run/tor-socks:rw,z'] if tor else
                  ['gateway-socket:/run/arkpool:rw,z', 'tor-a-socks:/run/tor-a:ro,z',
                   'tor-b-socks:/run/tor-b:ro,z'] if role == 'gateway' else
                  ['gateway-socket:/run/arkpool:ro,z'])
        env = {} if tor else {k: s[k] for k in ('LAN_IP', 'LAN_CIDR', 'MINER_IPS')}
        if role == 'gateway':
            env.update({k: s[k] for k in ('POOL_ONION', 'POOL_PORT', 'TOR_ROUTE_POLICY', 'TOR_ISOLATION')})
        if role == 'ingress':
            lines += [f'PublishPort={s["LAN_IP"]}:{s["LAN_PORT"]}:3333/tcp']
            if s['TLS_ENABLED'] == '1':
                env.update({k: s[k] for k in ('TLS_ENABLED', 'LAN_PORT', 'LAN_TLS_PORT')})
                lines += [f'PublishPort={s["LAN_IP"]}:{s["LAN_TLS_PORT"]}:3334/tcp']
                mounts += ['tls-identity:/var/lib/arkpool-tls:rw,Z']
        lines += ['Environment=' + k + '=' + v for k, v in sorted(env.items())]
        lines += ['Volume=arkpool-' + m.replace(':', '.volume:', 1) for m in mounts]
        health = 'tor_health.py' if tor else role + '.py healthcheck'
        lines += ['HealthCmd=python3 /app/' + health, 'HealthInterval=15s',
                  'HealthTimeout=5s', 'HealthRetries=4', 'HealthStartPeriod=10m',
                  '[Service]', 'Restart=on-failure', 'RestartSec=5s',
                  'TimeoutStartSec=900', 'MemoryMax=' + ('64M' if role == 'ingress' else '192M'),
                  'CPUQuota=' + ('25%' if role == 'ingress' else '50%'),
                  '[Install]', 'WantedBy=multi-user.target']
        files[f'arkpool-{role}.container'] = '\n'.join(lines) + '\n'
    files['INSTALL.txt'] = (
        'EXPERIMENTAL: new rootful Linux Podman 5.4+ / systemd deployment only.\n'
        'Export does not install units, pull images, migrate state or change miners.\n'
        'Read docs/PLATFORMS.md in the source tree before installation.\n'
        'Use a separate approved host/port and preload the exact reviewed image.\n'
        'Validate with the local Quadlet generator in dry-run mode first.\n'
        'Install only the generated .container/.network/.volume files into\n'
        '/etc/containers/systemd with mode 0600, after checking name/port conflicts.\n'
        'Then systemctl daemon-reload and systemctl start arkpool-ingress.service.\n'
        'Do not use systemctl --user, --pod, rootless networking or Compose here.\n'
        'No health-triggered restart is added to the gateway; Tor supervises itself.\n'
        'Verify actual LAN peer IP, Tor paths, fresh jobs and accepted shares separately.\n'
        'Stop via systemctl stop arkpool-ingress.service arkpool-gateway.service\n'
        'arkpool-tor-a.service arkpool-tor-b.service; retain all volume units/data.\n'
        'Existing Docker upgrades/rollback helper is NOT a Podman migration tool.\n')
    return files
