"""One repeatable offline test entry point; no live miners or Docker required."""
import os
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
for filename in ('tests.py', 'tests_tls.py', 'tests_release.py', 'tests_upgrade.py', 'tests_packages.py', 'tests_platforms.py', 'tests_dashboard.py', 'tests_native_relay.py', 'tests_native_status.py', 'tests_miner_status.py', 'tests_hashrate_history.py', 'tests_translator.py', 'tests_translator_dependencies.py', 'tests_dual_gateway.py', 'tests_v2_appliance.py'):
    subprocess.run([sys.executable, '-B', str(root / filename)], cwd=root, env=env, check=True)
subprocess.run(['sh', '-n', str(root / 'gateway.sh')], check=True)
print('PASS: transport, preflight, packaging, upgrade, platform, and shell syntax checks')
