"""Read-only, allowlisted source and running-image identity; no registry requests."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

REVISION = re.compile(r'[0-9a-f]{40}(?:[0-9a-f]{24})?')
IMAGE = re.compile(r'sha256:[0-9a-f]{64}')
VERSION = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.]+)?')


def source(root):
    version = (root / 'VERSION').read_text().strip()
    if not VERSION.fullmatch(version):
        raise ValueError('invalid source version')
    revision, dirty = None, None
    try:
        result = subprocess.run(['git', '-C', str(root), 'rev-parse', '--show-toplevel'],
                                capture_output=True, text=True, timeout=5, check=True)
        if Path(result.stdout.strip()).resolve() == root.resolve():
            result = subprocess.run(['git', '-C', str(root), 'rev-parse', 'HEAD'],
                                    capture_output=True, text=True, timeout=5, check=True)
            value = result.stdout.strip()
            if REVISION.fullmatch(value):
                revision = value
                result = subprocess.run(['git', '-C', str(root), 'status', '--porcelain',
                                         '--untracked-files=normal'], capture_output=True,
                                        text=True, timeout=5, check=True)
                dirty = bool(result.stdout.strip())
    except (OSError, subprocess.SubprocessError):
        pass
    return {'version': version, 'revision': revision, 'dirty': dirty}


def report(instance, expected=None):
    checkout = source(instance.root)
    expected = expected or (checkout['revision'] if checkout['dirty'] is False else None)
    if expected is not None and not REVISION.fullmatch(expected):
        raise ValueError('invalid expected revision')
    services = []
    for name in ('gateway', 'ingress', 'tor-a', 'tor-b'):
        ids = instance.run(instance.compose() + ['ps', '-a', '-q', name]).split()
        row = {'service': name, 'available': False, 'matches_expected': None}
        if len(ids) == 1:
            container = json.loads(instance.run(['docker', '--host', 'unix:///var/run/docker.sock',
                                                  'container', 'inspect', ids[0]]))[0]
            image = container.get('Image', '')
            if not IMAGE.fullmatch(image):
                raise ValueError('invalid running image identity')
            data = json.loads(instance.run(['docker', '--host', 'unix:///var/run/docker.sock',
                                           'image', 'inspect', image]))[0]
            labels = data.get('Config', {}).get('Labels') or {}
            revision = labels.get('org.opencontainers.image.revision', '')
            version = labels.get('org.opencontainers.image.version', '')
            revision = revision if REVISION.fullmatch(revision) else None
            version = version if VERSION.fullmatch(version) else None
            row.update(available=True, image_id=image, version=version, revision=revision,
                       running=container.get('State', {}).get('Running') is True,
                       matches_expected=(revision == expected if revision and expected else None))
        services.append(row)
    return {'schema_version': 1, 'checkout': checkout, 'expected_revision': expected,
            'services': services, 'scope': 'source_identity_not_mining_health'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--build-revision', action='store_true')
    parser.add_argument('--expected-revision')
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    if args.build_revision:
        info = source(root)
        print(info['revision'] if info['dirty'] is False else 'unknown')
        return
    from upgrade import Upgrader
    value = report(Upgrader(root), args.expected_revision)
    print(json.dumps(value, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Deployment identity unavailable; private details suppressed.', file=sys.stderr)
        sys.exit(1)
