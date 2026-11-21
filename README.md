# ArkPool Gateway

This GitHub copy tracks the [upstream GitLab project](https://gitlab.com/arkpool/arkpool-gateway). Please submit issues and merge requests there.

[![GitLab CI](https://gitlab.com/arkpool/arkpool-gateway/badges/main/pipeline.svg)](https://gitlab.com/arkpool/arkpool-gateway/-/pipelines)
[![License: MIT](https://gitlab.com/arkpool/arkpool-gateway/-/badges/custom.svg?key_text=license&value_text=MIT&value_color=007ec6)](LICENSE)
[![Status: alpha](https://gitlab.com/arkpool/arkpool-gateway/-/badges/custom.svg?key_text=status&value_text=alpha&value_color=orange)](docs/TESTING.md)
[![Upstream: Tor only](https://gitlab.com/arkpool/arkpool-gateway/-/badges/custom.svg?key_text=upstream&value_text=Tor%20only&value_color=7d4698)](SECURITY.md)
[![Payments: Ark](https://gitlab.com/arkpool/arkpool-gateway/-/badges/custom.svg?key_text=payments&value_text=Ark&value_color=007ec6)](#how-it-works)

### Privacy-focused Bitcoin mining over Tor. Payouts over Ark.

ArkPool Gateway connects miners to ArkPool through two independent Tor clients.
The established listener supports Stratum V1; an explicit native V2 path supports
compatible miners with end-to-end encrypted, authenticated pool connections.
It runs on your home network, keeps upstream mining traffic on Tor,
and never holds wallet keys or makes payments.

Current source version: **0.1.2-alpha.1**. See the [changelog](CHANGELOG.md),
[testing record](docs/TESTING.md), and [upgrade guide](docs/UPGRADING.md).

[arkpool.org](https://arkpool.org) ·
[Security](SECURITY.md) ·
[Installation](docs/INSTALLATION.md) ·
[Platform status](docs/PLATFORMS.md) ·
[Umbrel package](https://gitlab.com/arkpool/arkpool-gateway-umbrel) ·
[StartOS package](https://gitlab.com/arkpool/arkpool-gateway-startos)

## Latest development

Follow [latest-development setup](docs/LATEST_DEVELOPMENT.md).
It resolves `main` to an exact commit, uses the appropriate platform package,
and verifies the running versions. A named release remains a separate choice.

## What it does

- Sends pool connections only through Tor; there is no clearnet fallback.
- Uses two Tor clients with bounded failover and optional faster-path preference.
- Separates miners into Tor streams by default without logging their source IPs.
- Restricts new installations to one explicit private subnet by default.
- Runs the gateway networkless and connects it to Tor through Unix sockets.
- Preserves your Ark receive address byte-for-byte as the Stratum username.
- Provides private, sanitized job/share/route telemetry and an optional dashboard.

The pool schedules eligible Ark payouts hourly under its current accounting and
payout policy. An accepted share is not proof of payment. The gateway does not
create wallets, claim funds, or verify pool accounting.

## Prefer V2 for supported miners

For an existing installation, follow the [V2 migration checklist](docs/MIGRATING_TO_V2.md).

Use [the native V2 path](docs/NATIVE_V2.md) with a verified receiver authority key.
V2 deployments keep **V2-only upstream**: reconnects and upgrades must not silently
restore V1 or clearnet fallback. Existing V1 installations are not automatically
migrated. V1-only miners use the optional [exact-owner translator](docs/V1_TO_V2.md)
to join a V2 upstream. Appliance candidates combine both incoming protocols in
the shared V2 runtime; consult their own qualification records before deployment.
V1 miners do not need V2 firmware when their gateway includes the translator.
The standard image does not include that binary; the translator image and V2
appliance packages do. V1 compatibility also requires the owner's exact Ark
identity in gateway configuration. Native V2 miners use the separate V2 listener.
Preserve working mining and payout identities
during an explicitly approved migration.

### See both protocol connections

The optional [protocol dashboard](docs/PROTOCOL_DASHBOARD.md) separates
**Miner → gateway** from **Gateway → ArkPool**, with V2 preference and
verified-authentication badges in one unified session table. It uses actual connection evidence; stale or
unavailable observations become Unknown. A short warning explains V1-only
operation. Native miner counters remain separate from V1 gateway counters.

## How it works

```text
                                    ┌─ Tor A ─┐
Miner ── private LAN ── Ingress ── Gateway ┤         ├── ArkPool onion endpoint
                                    └─ Tor B ─┘
```

Ingress verifies the miner's actual source address and forwards it over a private
Unix socket. The networkless gateway verifies the policy again, validates bounded
Stratum messages, and opens only authenticated SOCKS connections to the configured
v3 onion. A healthy session stays on its route; failover occurs when the miner
reconnects.

Both Tor clients share the same host and Internet connection. Tor improves network
privacy but cannot eliminate timing correlation or protect a compromised host.

## Why Tor?

A miner connected directly to a public pool creates a long-lived link between
the household's public IP address and its mining activity. Routing the upstream
connection to ArkPool's onion service through Tor removes that direct network
link: the pool does not receive the miner's home IP, while the ISP sees Tor
traffic rather than a direct connection to the pool.

Hiding the home IP has practical benefits. It prevents the pool from trivially
storing a residential IP beside a payout identity, and makes coarse location,
ISP and household-level profiling less direct. A passive observer on the normal
Internet path cannot simply read the destination and identify ArkPool use, while
IP-based targeting or blocking has no miner-to-pool address pair to act on. It
also avoids giving the pool a stable network identifier when the miner changes
devices or the household changes providers. These protections reduce exposed
metadata; they do not make the payout identity itself anonymous.

The miner itself does not need to support Tor. It speaks ordinary Stratum to the
gateway on the private LAN; the gateway validates that traffic and carries only
the upstream leg over Tor. Optional local TLS protects the LAN leg when the local
network is not fully trusted. There is deliberately no clearnet fallback: if Tor
is unavailable, mining through this gateway stops instead of silently exposing a
direct pool connection.

Two Tor clients provide route redundancy and let a reconnect use the other path.
They do not create two independent Internet connections or make the system
anonymous against every observer. Tor does not hide the payout address from the
pool, conceal share timing, prevent end-to-end traffic correlation, secure a
compromised miner or host, or prove that a share was paid. Keep the gateway and
miner private, preserve wallet separation, and treat Tor as one layer of network
privacy rather than a complete anonymity guarantee.

## Quick start

The recommended installation is an always-on Linux host or VM with Docker Engine,
Docker Compose v2, Python 3.10+, at least 1 GiB available memory, and 2 GiB free
disk space. Podman and Umbrel exports remain experimental. StartOS 0.4 users
should use the separately maintained
[native package](https://gitlab.com/arkpool/arkpool-gateway-startos); this repository
does not generate or install an `.s9pk`. Start with Docker unless you specifically
need a platform package.

You also need:

- A Stratum V1 miner such as a Bitaxe 403, 601, or 601a.
- A reserved private IPv4 address for the gateway host.
- The actual private subnet containing that address.
- Your own compatible mainnet Ark receive address beginning with `ark1`.

### Get your Ark payout address

Never provide the gateway with a seed phrase, wallet private key, or wallet
backup. If you need an address, follow the [ArkPool wallet guide](https://arkpool.org/#wallet)
and Second's [Bark wallet documentation](https://second.tech/docs/built-with-bark#mobile-wallets).

### 1. Configure

From a reviewed checkout or checksum-verified source archive:

```sh
test ! -e .env && test ! -L .env && (umask 077; cp .env.example .env)
```

Edit only the private `.env`. Replace the examples with the gateway host's real
address and subnet:

```dotenv
LAN_IP=192.168.1.10
MINER_IPS=subnet
LAN_CIDR=192.168.1.0/24
```

Do not silently assume `/24`; confirm the subnet on the chosen host. Existing
installations using `MINER_IPS=lan` or exact miner addresses remain compatible.
The `lan` option deliberately permits all RFC1918 sources and is wider than the
new default.

Leave the prefilled pool onion and port unchanged. They are public defaults; no
invitation or endpoint handoff is required.

### 2. Check and start

```sh
./gateway.sh preflight
./gateway.sh preflight --show-lan-cidr
./gateway.sh up
./gateway.sh status
```

Preflight is read-only. Exit `0` means local checks passed, `1` means blocked,
and `2` means operator review is required. It does not prove mining, share
acceptance, or payment. The CIDR command prints the exact interface-derived
`LAN_CIDR=` line without editing `.env`; normal preflight warns about mismatches
and Docker/VPN overlaps. Initial Tor bootstrap can take several minutes. The
shipped Tor configuration explicitly cancels dormant mode at process startup so
a retained dormant state cannot prevent the supervised clients from bootstrapping.

### 3. Configure the miner

| Miner setting | Value |
| --- | --- |
| Pool host | The gateway's `LAN_IP` |
| Port | `3333`, unless you changed `LAN_PORT` |
| Username | Your complete compatible mainnet `ark1...` receive address |
| Password | `x` |
| Protocol | Stratum V1 |
| TLS | Off for the default private-LAN listener |

For a single URL field, use `stratum+tcp://LAN_IP:3333` with your real address.
Do not put the onion hostname directly in the miner. Disable any clearnet fallback
pool if all mining must remain on Tor.

Confirm fresh jobs, hashing, and a new accepted share. Verify payout eligibility
separately with the pool or your wallet; do not claim or redeem funds as a test.

## Optional settings

### Umbrel community package

The [separate Umbrel project](https://gitlab.com/arkpool/arkpool-gateway-umbrel)
contains the published alpha community store, installation instructions and
package changelog. It requires umbrelOS 2.0 and uses private-LAN Stratum port
23333 and dashboard port 23335. It is not an official Umbrel App Store listing.

The [platform guide](docs/PLATFORMS.md#generic-community-store-candidate) distinguishes
the maintained V2 package from the legacy V1 generators in this repository. Use
the separate project's current instructions for V2. The community
package is for fresh installs; do not overwrite an existing private operator
export. Its native lifecycle and accepted-share evidence are recorded separately
from outstanding ARM appliance, forced-recovery and payment checks.

### Check the running build

`./gateway.sh version` shows the source version. Use
`./gateway.sh version --json` for each running service's immutable image ID,
embedded source revision and version. Older or unlabelled images report an
unknown revision. Add `--expected-revision FULL_COMMIT_SHA` to compare with a
reviewed commit. This check does not contact GitLab or certify mining health.

### Local TLS

Set `TLS_ENABLED=1` before first startup to add a verified TLS listener on port
3334 while retaining plaintext port 3333. Then run `./gateway.sh pairing` and
import the public profile into compatible firmware through a trusted admin path.
Private keys stay on the gateway. Existing deployments must follow the
[reviewed TLS migration](docs/UPGRADING.md#adding-optional-tls).

### Faster initial route

Set `TOR_ROUTE_POLICY=latency` to let new connections prefer a reliably faster
Tor path using bounded subscription-only probes. It never moves a healthy session,
authorizes a worker, or submits a share. Round-robin remains the default.
Each route keeps a separate process-local probe identity, isolated from miner
credentials and reused only while that gateway process is running.

### Tor stream isolation

`TOR_ISOLATION=miner` is the default. Each miner gets a process-local opaque
SOCKS credential, and Tor's `IsolateSOCKSAuth` keeps different credentials on
separate streams. Optional `session` mode uses a fresh token per connection;
`shared` deliberately reduces isolation. Tokens contain no source address and
are never saved or logged.

### Shhark pool-stat integration

The optional `compose.shhark-status.yaml` overlay gives a separate Shhark host
read-only access to sanitized gateway status. It does not expose the dashboard
page or any control API. Generate a private token with `openssl rand -hex 32`,
store the same value as `SHHARK_STATUS_TOKEN` in the gateway's private `.env`,
and start the existing deployment with the overlay:

```sh
docker compose -f compose.yaml -f compose.shhark-status.yaml up -d
```

The status service binds only to `LAN_IP` on port `3335` by default. Allow that
port through the gateway host firewall only from the Shhark host; never forward
it from the Internet. Configure Shhark with the matching private URL and token:

```dotenv
SHHARK_ARKPOOL_STATUS_URL=http://192.168.1.10:3335/api/status
SHHARK_ARKPOOL_STATUS_TOKEN=<the same private 64-character token>
```

Use the gateway's actual private address. Recreate Shhark's network API and Tor
gateway services as described in its self-hosting guide. The gateway publishes
only schema-filtered process status and account fingerprints; the full Ark
address, raw Stratum messages, wallet keys, and mining controls never cross this
interface. If `DASHBOARD_CLIENT_IPS=1` is explicitly enabled, Shhark also receives
canonical RFC1918 miner addresses so its authenticated local view can identify
sessions. They remain omitted by default. Removing the overlay leaves the default
four-service topology.

## Everyday commands

| Task | Command |
| --- | --- |
| Service status | `./gateway.sh status` |
| Private job/share/route telemetry | `./gateway.sh telemetry` |
| TLS certificate status | `./gateway.sh tls-status` |
| Runtime package minimums | `./gateway.sh security-check` |
| Current package-index audit | `./gateway.sh security-audit` |
| Recent logs | `./gateway.sh logs` |
| Restart existing images | `./gateway.sh restart` |
| Stop this deployment | `./gateway.sh stop` |

Run the security commands from current reviewed source. Both include running
optional services such as the dashboard and authenticated status listener, and
use the host checkout's security requirements rather than an older image's
bundled checker. These commands check packages; they do not upgrade services.

### Private mining telemetry

Telemetry is available only through local Docker administration and a private
Unix socket. It reports bounded process-scoped job, route, connection, submission,
and correlated response counters without usernames, client IPs, destinations, or
raw messages. When an active miner successfully authorizes with a checksum-valid
Ark address, sanitized dashboard status may include only its SHA-256 account
fingerprint so an authenticated local consumer can open matching pool statistics.
The address itself is never retained, displayed, or logged. Counters reset when
the process restarts. Pending, unanswered,
untracked, and unclear outcomes are not rejects; accepted responses are neither
backend reconciliation nor payment proof. When the pool supplies a valid
`mining.set_difficulty`, telemetry can sum the difficulty captured when each
correlated share was submitted. This accepted-work value compares unlike share
difficulties; it is not hashrate, earnings, or payout proof. Missing difficulty
is shown as unavailable rather than estimated. A quiet share counter alone is
not a fault signal.

Plan updates and restarts around a brief miner reconnect. Preserve Tor volumes,
private configuration, current image IDs, and a tested rollback path. For existing
installations, use [the settings-preserving upgrade workflow](docs/UPGRADING.md).

## Installation

Follow the [installation guide](docs/INSTALLATION.md) for setup, verification, and handoff.

## Security boundary

Keep the listener private and never port-forward it from the Internet. Private
addressing is not authentication, NAT can hide a client's original source, and
the default LAN listener is plaintext. Use firewall restrictions and verify source
preservation. All containers run non-root, read-only, capability-dropped, and
without a Docker socket. Read [SECURITY.md](SECURITY.md) before deployment.

Reports and issues must not include `.env`, Tor state, wallet data, payout
addresses, private IPs, credentials, raw Stratum messages, or signing keys.

## Development and releases

```sh
python3 -B scripts/check.py
docker build --target test -t arkpool-gateway:test .
docker run --rm --network none --read-only --tmpfs /tmp \
  --cap-drop ALL --security-opt no-new-privileges:true arkpool-gateway:test
```

The production image intentionally excludes the test suite. Release tooling,
artifact verification, remaining alpha gates, and platform limitations are in:

- [Release tooling](docs/RELEASING.md)
- [Developer testing](docs/TESTING.md)
- [GitLab workflow](docs/GITLAB.md)
- [Podman, Umbrel, and StartOS](docs/PLATFORMS.md)

## Acknowledgments

Thanks to the [Second team](https://second.tech/) and Bark contributors for the
Ark ecosystem and developer tooling, and to the [Tor Project](https://www.torproject.org/),
its contributors, and volunteer relay operators for the privacy network that
makes Tor-only pool access possible.

ArkPool is independent and is not affiliated with or endorsed by Second or the
Tor Project. Dependencies retain their own licenses and notices.

## License

ArkPool Gateway code and documentation are available under the [MIT License](LICENSE),
copyright (c) 2026 PiHiker. The project remains alpha; an open-source license
does not mean every recovery, platform, accounting, or payout gate is complete.

### V1 miners on V2 upstream

The [optional V1-to-V2 translator](docs/V1_TO_V2.md) keeps compatible V1 miners
on their existing firmware while using authenticated V2 over Tor upstream.
Its separate image, exact owner identity and migration checks are required;
the standard Compose deployment does not silently migrate itself.

The optional [miner dashboard](docs/PROTOCOL_DASHBOARD.md#total-reported-hashrate)
includes total and individual reported hashrates in a lightweight 24-hour chart.
It retains at most 96 actual observations at 15-minute intervals. Missing readings
are gaps. Miners disappear after 24 hours without valid telemetry and return
automatically when contacted again. Enable `DASHBOARD_CLIENT_IPS=1` on the private
web service to identify miners by LAN IP in the table and chart legend.

The dashboard starts with a fleet overview and hashrate history, followed by
miner rows with separate local and upstream protocol badges. Gateway diagnostics
and connection settings expand on demand. Copy controls use only the displayed
connection values; browser restrictions fall back to selecting text. The page
adds no mining controls or external assets.
