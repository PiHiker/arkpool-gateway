"""Fail a build/check if runtime security packages are stale.

The default check is offline and enforces reviewed minimums. The explicit
``--check-upgradable`` mode additionally requires fresh APT indexes and rejects
any pending package update. Debian versions include backports; keep revisions.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

MINIMUM = {
    'tor': '0.4.9.17',
    'libpcre2-8-0': '10.46-1~deb13u3',
    # Python's TLS server and the certificate helper both use this OpenSSL
    # source package. Check the shared library as well as the CLI so a partial
    # package state cannot satisfy the runtime floor.
    'openssl': '3.5.7-1~deb13u3',
    'libssl3t64': '3.5.7-1~deb13u3',
}
PACKAGE = re.compile(r'^[a-z0-9][a-z0-9+.-]*(?::[a-z0-9]+)?$')


def check(run=subprocess.run, os_release=None):
    release = Path('/etc/os-release').read_text() if os_release is None else os_release
    fields = dict(line.split('=', 1) for line in release.splitlines() if '=' in line)
    if fields.get('ID', '').strip('"') != 'debian' or fields.get('VERSION_ID', '').strip('"') != '13':
        raise ValueError('unsupported_runtime_distribution')
    versions = {}
    for package, minimum in MINIMUM.items():
        result = run(['dpkg-query', '-W', '-f=${Version}', package],
                     capture_output=True, text=True, timeout=10, check=True)
        version = result.stdout.strip()
        if not version or run(['dpkg', '--compare-versions', version, 'ge', minimum],
                              capture_output=True, timeout=10).returncode != 0:
            raise ValueError('runtime_security_floor_not_met')
        versions[package] = version
    return versions


def pending_updates(run=subprocess.run):
    result = run(['apt', 'list', '--upgradable'], capture_output=True, text=True,
                 timeout=60, check=True)
    pending = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line or line == 'Listing...':
            continue
        package, separator, _details = line.partition('/')
        if not separator or not PACKAGE.fullmatch(package):
            raise ValueError('invalid package update output')
        pending.append(package)
    return tuple(sorted(set(pending)))


def validate_current_report(text):
    report = json.loads(text)
    if (not isinstance(report, dict) or report.get('security_floors_met') is not True
            or report.get('pending_updates_checked') is not True
            or report.get('pending_update_count') != 0):
        raise ValueError('runtime package currency was not verified')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--check-upgradable', action='store_true',
                        help='also fail if refreshed APT metadata reports any pending update')
    modes.add_argument('--validate-report', action='store_true',
                       help='validate a current-package JSON report from standard input')
    args = parser.parse_args()
    try:
        if args.validate_report:
            validate_current_report(sys.stdin.read())
            sys.exit(0)
        versions = check()
        pending = pending_updates() if args.check_upgradable else ()
        if pending:
            raise ValueError('pending runtime package updates')
        print(json.dumps({'security_floors_met': True, 'packages': versions,
                          'pending_updates_checked': args.check_upgradable,
                          'pending_update_count': len(pending),
                          'comprehensive_vulnerability_scan': False}))
    except (OSError, ValueError, subprocess.SubprocessError):
        print('Runtime security check failed: use a reviewed Debian 13 image with current security packages.', file=sys.stderr)
        sys.exit(1)
