"""Prepare a scoped, fingerprint-verified Tor Project APT source for image builds."""
import argparse
from pathlib import Path
import subprocess
import tempfile
import urllib.request

FINGERPRINT = 'A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89'
KEY_URL = f'https://deb.torproject.org/torproject.org/{FINGERPRINT}.asc'
KEYRING = '/usr/share/keyrings/arkpool-tor-archive.gpg'
SOURCE = ("Types: deb\nURIs: https://deb.torproject.org/torproject.org/\n"
          "Suites: trixie\nComponents: main\nArchitectures: amd64 arm64\n"
          f"Signed-By: {KEYRING}\n")
PREFERENCES = ("Package: tor tor-geoipdb\nPin: origin deb.torproject.org\nPin-Priority: 700\n\n"
               "Package: *\nPin: origin deb.torproject.org\nPin-Priority: -1\n")


def verify_fingerprint(listing):
    """Reject missing, different, duplicate or additional primary keys."""
    primary = []
    waiting = False
    for line in listing.splitlines():
        fields = line.split(':')
        if fields[0] == 'pub':
            if waiting:
                raise ValueError('missing primary fingerprint')
            waiting = True
        elif fields[0] == 'fpr' and waiting:
            if len(fields) < 10:
                raise ValueError('invalid primary fingerprint')
            primary.append(fields[9])
            waiting = False
    if waiting or primary != [FINGERPRINT]:
        raise ValueError('unexpected Tor archive signing key')


def prepare(destination):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    with urllib.request.urlopen(KEY_URL, timeout=30) as response:
        key = response.read(262145)
    if not key or len(key) > 262144:
        raise ValueError('invalid archive key size')
    with tempfile.TemporaryDirectory() as directory:
        command = ['gpg', '--no-options', '--homedir', directory, '--batch']
        result = subprocess.run(command + ['--with-colons', '--show-keys'], input=key,
                                capture_output=True, check=True, timeout=15)
        verify_fingerprint(result.stdout.decode('utf-8'))
        result = subprocess.run(command + ['--dearmor'], input=key,
                                capture_output=True, check=True, timeout=15)
    (destination / 'keyring.gpg').write_bytes(result.stdout)
    (destination / 'tor.sources').write_text(SOURCE)
    (destination / 'tor.pref').write_text(PREFERENCES)
    for file in destination.iterdir():
        file.chmod(0o644)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output_directory', type=Path)
    prepare(parser.parse_args().output_directory)
