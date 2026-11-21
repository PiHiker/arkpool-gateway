"""Local gateway identity. Only the public CA is exported for miner pairing."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import ssl
import stat
import subprocess
import sys
import tempfile
import time

from gateway import private_ipv4

STATE = Path('/var/lib/arkpool-tls')
RENEW_SECONDS = 30 * 86400


def openssl(*args):
    return subprocess.check_output(['openssl', *map(str, args)], stderr=subprocess.DEVNULL, timeout=30)


def private_file(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.geteuid():
        raise ValueError('unsafe TLS identity file')


def sign_server(directory, host, ca, ca_key, server_key):
    extensions = directory / 'server.ext'
    extensions.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n'
                          'extendedKeyUsage=serverAuth\nsubjectAltName=IP:' + host + '\n')
    openssl('req', '-new', '-key', server_key, '-subj', '/CN=ArkPool Gateway', '-out', directory/'server.csr')
    openssl('x509', '-req', '-in', directory/'server.csr', '-CA', ca, '-CAkey', ca_key,
            '-set_serial', '0x' + os.urandom(16).hex(), '-days', '825', '-sha256',
            '-extfile', extensions, '-out', directory/'server.pem')


def validate_identity(directory, host):
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.geteuid():
        raise ValueError('unsafe TLS identity directory')
    for name in ('ca.pem', 'ca.key', 'server.pem', 'server.key'):
        private_file(directory/name)
    # Check identity and SAN independently of expiry so a leaf can be renewed.
    openssl('verify', '-no_check_time', '-CAfile', directory/'ca.pem', '-purpose', 'sslserver',
            '-verify_ip', host, directory/'server.pem')
    if openssl('x509', '-in', directory/'ca.pem', '-pubkey', '-noout') != openssl('pkey', '-in', directory/'ca.key', '-pubout'):
        raise ValueError('TLS authority key mismatch')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(directory/'server.pem', directory/'server.key')
    return context


def ensure_identity(root, host):
    private_ipv4(host)
    root = Path(root)
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError('private TLS volume required')
    old_mask = os.umask(0o077)
    try:
        fd = os.open(root/'identity.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            identity = root/'identity'
            if not os.path.lexists(identity):
                with tempfile.TemporaryDirectory(prefix='.create-', dir=root) as temp:
                    directory = Path(temp)/'identity'
                    directory.mkdir(mode=0o700)
                    openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '3650',
                            '-subj', '/CN=ArkPool Local Gateway CA', '-keyout', directory/'ca.key', '-out', directory/'ca.pem',
                            '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0',
                            '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
                    openssl('genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', directory/'server.key')
                    sign_server(directory, host, directory/'ca.pem', directory/'ca.key', directory/'server.key')
                    validate_identity(directory, host)
                    (directory/'server.csr').unlink()
                    (directory/'server.ext').unlink()
                    directory.rename(identity)
            if identity.is_symlink() or not identity.is_dir():
                raise ValueError('unsafe TLS identity directory')
            validate_identity(identity, host)
            # Never silently replace the trusted CA. Expiring CA needs re-pairing.
            openssl('x509', '-in', identity/'ca.pem', '-noout', '-checkend', RENEW_SECONDS)
            try:
                openssl('x509', '-in', identity/'server.pem', '-noout', '-checkend', RENEW_SECONDS)
            except subprocess.CalledProcessError:
                with tempfile.TemporaryDirectory(prefix='.renew-', dir=root) as temp:
                    directory = Path(temp)
                    sign_server(directory, host, identity/'ca.pem', identity/'ca.key', identity/'server.key')
                    os.replace(directory/'server.pem', identity/'server.pem')
            openssl('verify', '-CAfile', identity/'ca.pem', '-purpose', 'sslserver',
                    '-verify_ip', host, identity/'server.pem')
            return validate_identity(identity, host)
    finally:
        os.umask(old_mask)


def ca_digest(root):
    path = Path(root)/'identity/ca.pem'
    private_file(path)
    return hashlib.sha256(path.read_bytes()).digest()


def certificate_status(root):
    identity = Path(root)/'identity'
    result = {}
    for name in ('ca', 'server'):
        path = identity/(name + '.pem')
        private_file(path)
        date = openssl('x509', '-in', path, '-enddate', '-noout').decode('ascii').strip()
        result[name + '_expires_at'] = ssl.cert_time_to_seconds(date.split('=', 1)[1])
    result['ca_maintenance_due'] = result['ca_expires_at'] - time.time() < 60 * 86400
    return result


def refresh_identity(root, host, expected_ca):
    # Never adopt a different CA during unattended maintenance.
    if ca_digest(root) != expected_ca:
        raise ValueError('CA changed; operator review required')
    context = ensure_identity(root, host)
    if ca_digest(root) != expected_ca:
        raise ValueError('CA changed during maintenance')
    return context, certificate_status(root)


def pairing_profile(root, host, tls_port, plaintext_port):
    private_ipv4(host)
    if not all(type(p) is int and 1 <= p <= 65535 for p in (tls_port, plaintext_port)) or tls_port == plaintext_port:
        raise ValueError('invalid pairing ports')
    identity = Path(root)/'identity'
    validate_identity(identity, host)
    certificate = (identity/'ca.pem').read_text('ascii')
    return {'format': 'arkpool-gateway-pairing', 'version': 1, 'host': host,
            'tlsPort': tls_port, 'plaintextPort': plaintext_port, 'caCertificate': certificate}


if __name__ == '__main__':
    try:
        if sys.argv[1:] != ['export']:
            raise ValueError('unsupported action')
        print(json.dumps(pairing_profile(STATE, os.environ['LAN_IP'], int(os.environ.get('LAN_TLS_PORT', '3334')),
                                        int(os.environ.get('LAN_PORT', '3333')))))
    except Exception:
        print('Pairing export failed; verify the running TLS listener and configuration.', file=sys.stderr)
        sys.exit(1)
