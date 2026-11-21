"""Private, bounded appliance V2 configuration; no inferred legacy destination."""
import json
import os
from pathlib import Path
import stat
from gateway import onion_hostname, ark_account_fingerprint


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate configuration key')
        result[key] = value
    return result


def validate(value):
    required = {'pool_onion', 'pool_port', 'authority_pubkey'}
    if not isinstance(value, dict) or not required <= value.keys() or value.keys() - required - {'ark_identity'}:
        raise ValueError('invalid V2 configuration fields')
    if not isinstance(value['pool_onion'], str):
        raise ValueError('onion hostname required')
    onion_hostname(value['pool_onion'])
    if type(value['pool_port']) is not int or not 1 <= value['pool_port'] <= 65535:
        raise ValueError('invalid V2 port')
    key = value['authority_pubkey']
    if not isinstance(key, str) or not 32 <= len(key) <= 128 or any(c not in '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz' for c in key):
        raise ValueError('invalid authority key encoding')
    identity = value.get('ark_identity', '')
    if identity != '' and ark_account_fingerprint(identity) is None:
        raise ValueError('exact mainnet Ark identity required')
    return dict(value, ark_identity=identity)


def read(path):
    fd = os.open(Path(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError('regular V2 configuration required')
        raw = stream.read(16385)
    if len(raw) > 16384:
        raise ValueError('V2 configuration too large')
    return validate(json.loads(raw, object_pairs_hook=unique_object))
