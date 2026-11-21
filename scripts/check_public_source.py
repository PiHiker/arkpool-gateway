"""Conservative current-source screen; NOT proof that Git history is public-safe."""
from pathlib import Path
import ipaddress
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_release import FILES

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_POOL_ONION = 'sj2uz24t77burdvmljhr6sjfp2ceyikmjz3gegvsokcsxzvauhq6paid.onion'
PUBLIC_ENDPOINT_FILES = {'.env.example', 'scripts/check_public_source.py',
                         'arkpool-gateway/docker-compose.yml'}
ONION_RULE = re.compile(r'\b[a-z2-7]{56}\.onion\b')
PRIVATE_IPV4_RULE = re.compile(
    r'(?<![0-9.])(?:10|172|192)(?:\.[0-9]{1,3}){3}(?:/[0-9]{1,2})?(?![0-9./])')
DOCUMENTATION_LAN = ipaddress.ip_network('192.168.1.0/24')
PUBLIC_PRIVATE_LITERALS = {
    # Network-policy constants and deliberate boundary-test fixtures.
    '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '10.1.0.0/24',
    '10.0.0.1', '10.255.255.254', '172.16.0.1', '172.31.0.1',
    '172.31.255.254',
}
RULES = (
    re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----'),
    re.compile(r'\bnsec1[023456789acdefghjklmnpqrstuvwxyz]{40,}\b'),
    re.compile(r'\b(?:npub1|ark1)[023456789acdefghjklmnpqrstuvwxyz]{40,}\b'),
    re.compile(r'\bglpat-[A-Za-z0-9_-]{20,}\b'),
    re.compile(r'\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b'),
    re.compile(r'\bsk-or-v1-[A-Za-z0-9_-]{32,}\b'),
    re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
    re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{10,}\b'),
    ONION_RULE,
)


def unexpected_private_ipv4(content):
    """Flag concrete RFC1918 data outside explicit public fixtures."""
    for match in PRIVATE_IPV4_RULE.finditer(content):
        literal = match.group()
        if literal in PUBLIC_PRIVATE_LITERALS:
            continue
        try:
            value = ipaddress.ip_interface(literal) if '/' in literal else ipaddress.ip_address(literal)
        except ValueError:
            continue
        address = value.ip if isinstance(value, ipaddress.IPv4Interface) else value
        if address.is_private and address not in DOCUMENTATION_LAN:
            return True
    return False


def scan(root=ROOT):
    flagged = []
    for name in FILES:
        path = root/name
        if path.is_symlink() or not path.is_file():
            flagged.append(name)
            continue
        content = path.read_text(encoding='utf-8')
        # Only the exact owner-approved public endpoint in these specific files
        # is intentional. Other onions and all other sensitive patterns fail.
        if any(not (rule is ONION_RULE and name in PUBLIC_ENDPOINT_FILES
                    and match.group() == PUBLIC_POOL_ONION)
               for rule in RULES for match in rule.finditer(content)):
            flagged.append(name)
        elif unexpected_private_ipv4(content):
            flagged.append(name)
    return flagged


if __name__ == '__main__':
    findings = scan()
    if findings:
        print('Source review required in allowlisted files: ' + ', '.join(findings))
        sys.exit(1)
    print('PASS: allowlisted source screen. Git history, metadata and licensing still require review.')
