"""Offline platform exports. Never start containers or alter an existing install."""
import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re

from gateway import Config
from preflight import KEYS, read_settings

ROOT = Path(__file__).resolve().parent
IMAGE = re.compile(r'[a-z0-9][a-z0-9.-]*(?::[0-9]{1,5})?/'
                   r'[a-z0-9][a-z0-9/._-]*:[A-Za-z0-9_][A-Za-z0-9_.-]*'
                   r'@sha256:[a-f0-9]{64}')
LOCAL_IMAGE = re.compile(r'sha256:[a-f0-9]{64}')


def checked_settings(values):
    """Reject directives/expansion before generating any platform syntax."""
    if set(values) - KEYS or any(not isinstance(v, str) or
            (not v and k != 'LAN_CIDR') or
            (v and not re.fullmatch(r'[A-Za-z0-9.,:/_-]+', v)) for k, v in values.items()):
        raise ValueError('literal gateway settings required')
    Config.load(values)
    result = dict(values)
    result.setdefault('LAN_CIDR', '')
    result.setdefault('TOR_ROUTE_POLICY', 'round-robin')
    result.setdefault('TOR_ISOLATION', 'miner')
    for name, default in (('LAN_PORT', '3333'), ('POOL_PORT', '3333'),
                          ('LAN_TLS_PORT', '3334')):
        value = result.setdefault(name, default)
        if not value.isdecimal() or not 1 <= int(value) <= 65535:
            raise ValueError('invalid port')
        result[name] = str(int(value))
    if result.setdefault('TLS_ENABLED', '0') not in ('0', '1'):
        raise ValueError('invalid TLS mode')
    if result['TLS_ENABLED'] == '1' and result['LAN_TLS_PORT'] == result['LAN_PORT']:
        raise ValueError('conflicting ports')
    return result


def checked_image(image, registry=False):
    if not IMAGE.fullmatch(image) and not (not registry and LOCAL_IMAGE.fullmatch(image)):
        raise ValueError('immutable image ID or tagged registry digest required')
    return image


def write_export(destination, files):
    """New private directory only; generated deployment data must stay outside Git."""
    destination = Path(destination).absolute()
    resolved = destination.resolve()
    if (destination.is_symlink() or resolved == ROOT or ROOT in resolved.parents
            or any((parent/'.git').is_file() or (parent/'.git/HEAD').is_file()
                   for parent in resolved.parents)):
        raise ValueError('new external output directory required')
    for name, content in files.items():
        path = PurePosixPath(name)
        if path.is_absolute() or '..' in path.parts or not path.parts or not isinstance(content, str):
            raise ValueError('invalid export file')
    old = os.umask(0o077)
    try:
        destination.mkdir(mode=0o700, parents=False, exist_ok=False)
        for name, content in sorted(files.items()):
            target = destination / name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with target.open('x', encoding='utf-8') as stream:
                stream.write(content)
    finally:
        os.umask(old)


def evidence(platform):
    return {'schema_version': 1, 'platform': platform, 'status': 'experimental',
            'containers_started': False, 'ready_for_mining': False,
            'runtime_test': 'not_run', 'lan_source_preservation': 'not_run',
            'tor_failover': 'not_run', 'accepted_share': 'not_run',
            'payout_reconciliation': 'not_run'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('platform', choices=('podman', 'umbrel', 'startos'))
    parser.add_argument('--settings', type=Path, required=True)
    parser.add_argument('--image', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--ui-port', type=int, default=3335, help='Umbrel browser port (default 3335)')
    args = parser.parse_args()
    if args.platform == 'startos':
        from platform_startos import REASON
        parser.exit(1, REASON+'\n')
    try:
        settings = checked_settings(read_settings(args.settings))
        image = checked_image(args.image, registry=args.platform == 'umbrel')
        # Imports are local and selected from fixed choices, never user paths.
        if args.platform == 'podman':
            from platform_podman import render
        elif args.platform == 'umbrel':
            from platform_umbrel import render
        else:
            from platform_startos import render
        files = render(settings, image, ui_port=args.ui_port) if args.platform == 'umbrel' else render(settings, image)
        files['acceptance.json'] = json.dumps(evidence(args.platform), indent=2) + '\n'
        write_export(args.output, files)
    except (OSError, ValueError, ImportError):
        parser.exit(1, 'Export blocked: verify platform availability, private literal settings, '
                    'immutable image and a new external directory. No deployment was performed.\n')
    print(json.dumps({'platform': args.platform, 'files_written': len(files),
                      'status': 'experimental', 'containers_started': False,
                      'ready_for_mining': False}))


if __name__ == '__main__':
    main()
