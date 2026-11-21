"""Publish a verified OCI index using ephemeral GitLab CI registry credentials."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import urllib.parse
import urllib.request
import urllib.error

INDEX = 'application/vnd.oci.image.index.v1+json'
MANIFEST = 'application/vnd.oci.image.manifest.v1+json'


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != 'https':
            raise ValueError('refusing non-HTTPS registry redirect')
        redirected = super().redirect_request(request, fp, code, msg, headers, newurl)
        if redirected and urllib.parse.urlsplit(request.full_url).netloc != urllib.parse.urlsplit(newurl).netloc:
            redirected.remove_header('Authorization')
        return redirected


def descriptor(body, digest, config, arch, revision):
    if digest != 'sha256:' + hashlib.sha256(body).hexdigest():
        raise ValueError('image manifest digest mismatch')
    manifest = json.loads(body)
    if manifest.get('schemaVersion') != 2 or manifest.get('mediaType') != MANIFEST:
        raise ValueError('expected a native OCI image manifest')
    if config.get('architecture') != arch or config.get('os') != 'linux':
        raise ValueError('native image architecture mismatch')
    if config.get('config', {}).get('Labels', {}).get('org.opencontainers.image.revision') != revision:
        raise ValueError('image source revision mismatch')
    return {'mediaType': MANIFEST, 'digest': digest, 'size': len(body),
            'platform': {'architecture': arch, 'os': 'linux'}}


def main():
    opener = urllib.request.build_opener(SafeRedirect())
    registry = os.environ['CI_REGISTRY']
    image = os.environ['CI_REGISTRY_IMAGE']
    revision = os.environ['CI_COMMIT_SHA']
    if registry != 'registry.gitlab.com' or image != registry + '/arkpool/arkpool-gateway':
        raise ValueError('unexpected publication destination')
    if not re.fullmatch('[0-9a-f]{40}', revision):
        raise ValueError('invalid source revision')
    variant = os.environ.get('IMAGE_VARIANT', '')
    if variant not in ('', 'translator'):
        raise ValueError('invalid image variant')
    suffix = '-' + variant if variant else ''
    repository = image.split('/', 1)[1]
    query = urllib.parse.urlencode({'service': 'container_registry',
                                   'scope': 'repository:' + repository + ':pull,push'})
    credential = base64.b64encode((os.environ['CI_REGISTRY_USER'] + ':' + os.environ['CI_REGISTRY_PASSWORD']).encode()).decode()
    request = urllib.request.Request('https://gitlab.com/jwt/auth?' + query,
                                     headers={'Authorization': 'Basic ' + credential})
    with opener.open(request, timeout=30) as response:
        token = json.load(response)['token']
    headers = {'Authorization': 'Bearer ' + token, 'Accept': INDEX + ', ' + MANIFEST}

    def get(path):
        request = urllib.request.Request('https://' + registry + '/v2/' + repository + path, headers=headers)
        with opener.open(request, timeout=60) as response:
            body = response.read(4 * 1024 * 1024 + 1)
            if len(body) > 4 * 1024 * 1024:
                raise ValueError('registry metadata exceeds bound')
            return body

    descriptors = []
    for arch in ('amd64', 'arm64'):
        digest = Path('digest' + suffix + '-' + arch + '.txt').read_text().strip()
        if not re.fullmatch('sha256:[0-9a-f]{64}', digest):
            raise ValueError('invalid architecture digest artifact')
        body = get('/manifests/' + digest)
        config_digest = json.loads(body)['config']['digest']
        if not re.fullmatch('sha256:[0-9a-f]{64}', config_digest):
            raise ValueError('invalid configuration digest')
        config_body = get('/blobs/' + config_digest)
        if 'sha256:' + hashlib.sha256(config_body).hexdigest() != config_digest:
            raise ValueError('configuration digest mismatch')
        descriptors.append(descriptor(body, digest, json.loads(config_body), arch, revision))
    body = json.dumps({'schemaVersion': 2, 'mediaType': INDEX, 'manifests': descriptors}, separators=(',', ':')).encode()
    digest = 'sha256:' + hashlib.sha256(body).hexdigest()
    path = '/manifests/sha-' + revision + suffix
    try:
        previous = get(path)
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
    else:
        if previous != body:
            raise ValueError('refusing to replace an existing commit tag')
    request = urllib.request.Request('https://' + registry + '/v2/' + repository + path,
                                     data=body, method='PUT', headers={**headers, 'Content-Type': INDEX})
    with opener.open(request, timeout=60) as response:
        if response.status != 201 or response.headers.get('Docker-Content-Digest') != digest:
            raise ValueError('registry publication digest mismatch')
    if get('/manifests/' + digest) != body:
        raise ValueError('published index readback mismatch')
    Path('image' + suffix + '-digest.txt').write_text(digest + '\n')
    print('Published verified amd64/arm64 OCI index: ' + digest)


if __name__ == '__main__':
    main()
