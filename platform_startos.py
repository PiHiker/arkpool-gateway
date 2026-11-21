"""Report StartOS support; never emit a weakened native package from this tree."""
import argparse
import json
import sys

PACKAGE_REPOSITORY = 'https://gitlab.com/arkpool/arkpool-gateway-startos'
EXTERNAL_REASON = (
    'The reviewed native StartOS 0.4 package is maintained and released separately at '
    f'{PACKAGE_REPOSITORY}. This compatibility reporter does not generate or install an '
    '.s9pk; use the native package instructions and verify its release checksum.'
)
UNSUPPORTED_REASON = (
    'StartOS 0.3 is unsupported. Do not weaken the gateway isolation, add host privileges, '
    'or add a direct pool fallback to make an older package install.'
)


def report(version='0.4'):
    if version not in ('0.3', '0.4'):
        raise ValueError('unreviewed StartOS version')
    external = version == '0.4'
    return {'schema_version': 1, 'platform': 'startos', 'version_family': version,
            'status': 'external_package' if external else 'unsupported',
            'native_package_available': external, 'exporter_available': False,
            'containers_started': False, 'ready_for_mining': False,
            'reason': EXTERNAL_REASON if external else UNSUPPORTED_REASON,
            'package_repository': PACKAGE_REPOSITORY if external else None,
            'minimum_os_version': '0.4.0.2' if external else None,
            'required_checks': ['networkless_gateway_namespace', 'private_socket_mounts',
                'independent_tor_state', 'raw_tcp_source_preservation', 'nonroot_readonly_capability_drop',
                'no_public_listener', 'settings_preserving_upgrade_restore', 'real_mining_recovery'],
            'references': ['https://docs.start9.com/packaging/0.4.0.x/main.html',
                           'https://docs.start9.com/packaging/0.4.0.x/interfaces.html',
                           'https://docs.start9.com/0.3.5.x/developer-docs/packaging']}


def render(_settings, _image):
    raise ValueError(EXTERNAL_REASON)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version-family', choices=('0.3', '0.4'), default='0.4')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args()
    result = report(args.version_family)
    print(json.dumps(result, indent=2) if args.json else result['reason'])
    # This command is an exporter gate, not a package installer. Keep its non-zero
    # exit status so automation cannot mistake an external package for generated output.
    return 1


if __name__ == '__main__':
    sys.exit(main())
