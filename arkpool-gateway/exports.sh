_arkpool_network="$(python3 - <<'PY'
import ipaddress, json, subprocess
def query(*args):
    return json.loads(subprocess.check_output(['ip', '-j', '-4', *args], timeout=5))
routes = query('route', 'show', 'default')
devices = {row.get('dev') for row in routes if row.get('dev')}
if len(devices) != 1:
    raise SystemExit('ArkPool requires one unambiguous default LAN interface')
device = devices.pop()
if device.startswith(('docker', 'br-', 'wg', 'tun', 'tailscale', 'zt')):
    raise SystemExit('ArkPool refuses a VPN or container interface as its LAN')
allowed = [ipaddress.ip_network(value) for value in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')]
addresses = []
for row in query('address', 'show', 'dev', device):
    for address in row.get('addr_info', []):
        if address.get('family') != 'inet' or address.get('scope') != 'global':
            continue
        value = ipaddress.ip_interface(str(address['local']) + '/' + str(address['prefixlen']))
        if any(value.ip in network and value.network.subnet_of(network) for network in allowed):
            addresses.append(value)
if len(addresses) != 1:
    raise SystemExit('ArkPool requires one RFC1918 address on its default LAN interface')
print(str(addresses[0].ip) + ' ' + str(addresses[0].network))
PY
)" || return 1
read -r APP_ARKPOOL_LAN_IP APP_ARKPOOL_LAN_CIDR <<< "${_arkpool_network}"
export APP_ARKPOOL_LAN_IP APP_ARKPOOL_LAN_CIDR
unset _arkpool_network
