"""Export public pairing data via the local Docker socket; never fetch over LAN."""
import json
from pathlib import Path
import sys

from upgrade import Upgrader, private_dir, atomic


def export(root):
    instance = Upgrader(root)
    if instance.settings.get('TLS_ENABLED') != '1':
        raise ValueError('TLS is not enabled')
    profile = json.loads(instance.run(instance.compose() + ['exec', '-T', 'ingress', 'python3', '/app/tls_identity.py', 'export']))
    # Only this small public schema may leave the container.
    expected = {'format', 'version', 'host', 'tlsPort', 'plaintextPort', 'caCertificate'}
    if (set(profile) != expected or profile['format'] != 'arkpool-gateway-pairing' or profile['version'] != 1
            or profile['host'] != instance.settings['LAN_IP']
            or profile['tlsPort'] != int(instance.settings.get('LAN_TLS_PORT', '3334'))
            or profile['plaintextPort'] != int(instance.settings['LAN_PORT'])
            or not isinstance(profile['caCertificate'], str) or len(profile['caCertificate']) > 3000
            or not profile['caCertificate'].startswith('-----BEGIN CERTIFICATE-----\n')
            or not profile['caCertificate'].endswith('-----END CERTIFICATE-----\n')):
        raise ValueError('invalid public pairing profile')
    directory = Path(root)/'.arkpool-pairing'
    private_dir(directory)
    atomic(directory/'gateway.json', profile)
    return directory/'gateway.json'


if __name__ == '__main__':
    try:
        if len(sys.argv) != 1:
            raise ValueError('no arguments expected')
        export(Path(__file__).resolve().parent)
        print('Pairing file saved: .arkpool-pairing/gateway.json')
        print('Copy it through your trusted admin connection, then import it on the miner Pool page.')
    except Exception:
        print('Pairing export failed. Enable TLS_ENABLED=1 and start the TLS-capable gateway first; live settings were not changed.', file=sys.stderr)
        sys.exit(1)
