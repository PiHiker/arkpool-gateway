"""Exercise the real Podman Quadlet generator; never start services or containers."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from platform_export import write_export
from platform_podman import render
from tests_platforms import settings, IMAGE


def check(generator):
    for tls in ('0', '1'):
        with tempfile.TemporaryDirectory(prefix='arkpool-quadlet-check-') as temporary:
            source = Path(temporary)/'units'
            write_export(source, render(settings(tls), IMAGE))
            result = subprocess.run([str(generator), '-dryrun', '-no-kmsg-log'],
                env=dict(os.environ, QUADLET_UNIT_DIRS=str(source)), capture_output=True,
                text=True, timeout=30, check=True)
            out = result.stdout
            for role in ('gateway', 'ingress', 'tor-a', 'tor-b'):
                marker = f'---arkpool-{role}.service---'
                if marker not in out:
                    raise ValueError('missing service')
                block = out.split(marker, 1)[1].split('\n---', 1)[0]
                if '--cap-drop all' not in block or '--read-only' not in block:
                    raise ValueError('missing security flags')
                if '--user 10001:10001' not in block or '--http-proxy=false' not in block:
                    raise ValueError('missing runtime isolation')
                if role == 'gateway' and ('--network none' not in block or '--publish' in block):
                    raise ValueError('gateway network isolation changed')
                if '--pod ' in block or '--network host' in block:
                    raise ValueError('shared network namespace')
    print('PASS: real Quadlet generator, plaintext/TLS profiles; no runtime or mining test claimed.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--quadlet-generator', type=Path, required=True)
    args = parser.parse_args()
    try:
        check(args.quadlet_generator)
    except (OSError, ValueError, subprocess.SubprocessError):
        parser.exit(1, 'Platform generator check failed or unavailable; no test skipped as a pass.\n')
