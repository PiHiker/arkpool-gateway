"""Deterministic alpha source archives from a clean, version-tagged Git commit."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile

FILES = (
    'dual_gateway.py', 'v2_config.py', 'tests_dual_gateway.py', 'tests_v2_appliance.py',
    'Dockerfile.translator', 'translator_runtime.py', 'translator_observer.py',
    'tests_translator.py', 'patches/sri-exact-ark-identity.patch',
    'tests_translator_dependencies.py', 'patches/sri-security-dependencies.patch',
    'scripts/verify-translator-dependencies.sh', 'docs/V1_TO_V2.md',
    'umbrel-app-store.yml',
    'arkpool-gateway/data/runtime/dashboard-gateway/.gitkeep',
    'arkpool-gateway/data/runtime/dashboard-ingress/.gitkeep',
    'arkpool-gateway/data/runtime/gateway-socket/.gitkeep',
    'arkpool-gateway/data/runtime/tor-a-socks/.gitkeep',
    'arkpool-gateway/data/runtime/tor-b-socks/.gitkeep',
    'arkpool-gateway/data/tor-a-state/.gitkeep',
    'arkpool-gateway/data/tor-b-state/.gitkeep',
    'arkpool-gateway/docker-compose.yml',
    'arkpool-gateway/exports.sh',
    'arkpool-gateway/hooks/pre-start',
    'arkpool-gateway/umbrel-app.yml',
    'scripts/build_umbrel_store.py',
    'scripts/publish_image_index.py',
    'platform_export.py', 'tests_platforms.py', 'platform_podman.py',
    'native_status.py', 'tests_native_status.py', 'bounded_http.py',
    'appliance_ui.py', 'native_relay.py', 'tests_native_relay.py', 'docs/NATIVE_V2.md',
    'dashboard_status.py', 'dashboard.js', 'tests_dashboard.py',
    'miner_status.py', 'hashrate_history.py', 'tests_hashrate_history.py', 'protocol.js', 'tests_miner_status.py', 'docs/PROTOCOL_DASHBOARD.md',
    'platform_umbrel.py',
    'platform_startos.py', 'scripts/check_platform_generators.py', 'docs/PLATFORMS.md',
    'runtime_packages.py', 'tests_packages.py', 'tor_repository.py',
    '.dockerignore', '.env.example', '.gitignore', '.forgejo/workflows/ci.yml',
    'MAINTAINING.md', 'README.md', 'SECURITY.md', 'LICENSE', 'VERSION', 'CHANGELOG.md',
    'Dockerfile', 'compose.yaml', 'compose.shhark-status.yaml', 'gateway.py', 'route_quality.py', 'gateway.sh', 'ingress.py',
    'preflight.py', 'tests.py', 'tests_release.py', 'tor_health.py',
    'tor_supervisor.py', 'torrc', 'scripts/check.py', 'scripts/build_release.py',
    'docs/INSTALLATION.md', 'docs/TESTING.md', 'docs/RELEASING.md',
    'docs/LATEST_DEVELOPMENT.md', 'docs/MIGRATING_TO_V2.md',
    'docs/acceptance.example.json',
    'upgrade.py', 'tests_upgrade.py', 'deployment_version.py',
    '.gitlab-ci.yml', 'scripts/check_public_source.py', 'docs/GITLAB.md',
    'docs/UPGRADING.md',
    'tls_identity.py', 'pairing.py', 'tests_tls.py', 'compose.tls.yaml',
)


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args], stderr=subprocess.DEVNULL)


def build(root, destination):
    root = root.resolve()
    destination = destination.resolve()
    if destination == root or root in destination.parents:
        raise ValueError('Output must be outside the repository')
    if git(root, 'status', '--porcelain', '--untracked-files=normal').strip():
        raise ValueError('Clean Git worktree required')
    revision = git(root, 'rev-parse', 'HEAD').decode().strip()
    version = git(root, 'show', 'HEAD:VERSION').decode().strip()
    if not re.fullmatch(r'\d+\.\d+\.\d+-alpha\.\d+', version):
        raise ValueError('An explicit alpha version is required while release gates remain open')
    if git(root, 'rev-parse', f'refs/tags/v{version}^{{commit}}').decode().strip() != revision:
        raise ValueError('Version tag must point at HEAD')
    timestamp = int(git(root, 'show', '-s', '--format=%ct', 'HEAD'))
    tree = {}
    for entry in git(root, 'ls-tree', '-r', '-z', 'HEAD').split(b'\0'):
        if entry:
            attrs, path = entry.split(b'\t', 1)
            tree[path.decode()] = attrs.decode().split()
    # New tracked files require an explicit packaging decision, never automatic
    # inclusion (which could ship secrets) or silent omission of needed code.
    if len(FILES) != len(set(FILES)) or set(tree) != set(FILES):
        raise ValueError('Tracked files must exactly match the release allowlist')
    sources, modes = {}, {}
    for name in FILES:
        attrs = tree.get(name)
        if not attrs or attrs[0] not in ('100644', '100755') or attrs[1] != 'blob':
            raise ValueError('Release requires every allowlisted file as a regular Git blob')
        sources[name] = git(root, 'show', f'HEAD:{name}')
        modes[name] = int(attrs[0][-3:], 8)
    manifest = {'schema_version': 1, 'version': version, 'source_revision': revision,
                'release_status': 'alpha', 'runtime_image_reproducible': False,
                'files': {k: hashlib.sha256(v).hexdigest() for k,v in sorted(sources.items())}}
    metadata = (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode()
    sources['SOURCE.json'] = metadata
    modes['SOURCE.json'] = 0o644
    prefix = f'arkpool-gateway-{version}'
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode='wb', filename='', mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w', format=tarfile.PAX_FORMAT) as archive:
            for name, data in sorted(sources.items()):
                item = tarfile.TarInfo(f'{prefix}/{name}')
                item.size, item.mode, item.mtime = len(data), modes[name], timestamp
                item.uid = item.gid = 0
                item.uname = item.gname = ''
                archive.addfile(item, io.BytesIO(data))
    artifacts = {prefix + '.tar.gz': output.getvalue(), prefix + '.manifest.json': metadata}
    destination.mkdir(parents=True, exist_ok=False)
    for name, data in artifacts.items():
        with (destination / name).open('xb') as stream:
            stream.write(data)
    with (destination / 'SHA256SUMS').open('x') as stream:
        for name, data in sorted(artifacts.items()):
            stream.write(f'{hashlib.sha256(data).hexdigest()}  {name}\n')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = build(Path(__file__).resolve().parents[1], args.output_dir)
    except (OSError, ValueError, subprocess.SubprocessError):
        parser.exit(1, 'Release blocked: require clean tagged alpha source, an exact tracked-file allowlist, regular files, and a new external output directory.\n')
    print(json.dumps({'version': result['version'], 'source_revision': result['source_revision'], 'release_status': 'alpha'}))


if __name__ == '__main__':
    main()
