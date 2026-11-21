# V1 miners with V2-only upstream

`translator_runtime.py` supports a V1 miner through an operator-configured SRI
translator. The miner keeps its existing V1 firmware; the translator authenticates
ArkPool with its Noise authority key and sends V2 through the two Tor Unix
sockets. A native V2 miner instead uses `native_relay.py` directly.

Translated V1 sessions must send the exact configured owner authorization within
60 seconds. A partial request has its own ten-minute assembly deadline that
cannot be extended by jobs flowing in the opposite direction. Each source is
limited to two concurrent sessions.

Exact-IP V1 deployments may optionally set `MINER_ACCOUNT_PINS` to comma-separated
`private-ip=sha256` mappings. The hash covers the complete, lowercase,
checksum-valid Ark username. The bridge rejects an authorize or submit identity
that does not match before forwarding it. Keep the mapping private; subnet and
broad LAN policies cannot use account pins.

## Implementation and limits

The optional `Dockerfile.translator` builds SRI `translator_sv2` from commit
`6b07996536449e588280c67f5d21d496b52afd56`, with the checked-in identity-preservation
patch. Builds disable SRI's default monitoring/ASIC telemetry feature; this
removes its unused TLS, HTTP monitoring and protobuf dependency chain. Gateway
snapshots and the separate read-only dashboard remain available.
A separate checked-in lockfile patch pins Tokio 1.53.3 and anyhow 1.0.103
for their published RustSec advisories. The build verifies its runtime dependency
graph before compiling. These build changes require a new image and separate
miner qualification; running gateways are not changed by a source update.
SRI's MIT/Apache notices are retained in the image. Firmware licenses and
hardware qualification remain separate. Translation is implemented and has
pool-confirmed accepted-share evidence from an authorized V1-miner trial.
It requires a translator-enabled build and explicit owner configuration; existing
default V1 Compose installations are not migrated automatically. The V2 StartOS
and Umbrel packages include the translator, with their own installation and
miner-qualification records. A candidate label describes release qualification,
not a requirement for the miner itself to support V2.

This integration serves **one exact owner identity per translator**. Every V1
`mining.authorize` and `mining.submit` identity must match that configuration;
a worker suffix or a different address is rejected. It does not redirect arbitrary
miners into the configured account. Do not normalize, generate or replace an
operator's payout identity. Multiple owners require separate isolated instances.

The networkless gateway permits only loopback TCP to SRI and Unix sockets to
Tor. Ingress carries its verified IPv4 peer over the private Unix socket.
Both ingress and runtime enforce the miner policy. V2 failure retries V2; there
is no V1 receiver, direct Internet path or alternate payout account in the
translator. A separately configured miner-level backup is an independent policy.

## Build and configuration

Build the reviewed Gateway runtime first, then the optional translator image:

```sh
docker build --target runtime -t arkpool-gateway:reviewed .
docker build -f Dockerfile.translator \
  --build-arg GATEWAY_IMAGE=arkpool-gateway:reviewed \
  -t arkpool-gateway:translator-reviewed .
```

Record the source revision and resulting image digest. The ordinary published
Gateway image includes Python support but does **not** include the SRI binary;
do not switch an installation merely by changing its command.

Mount a private SRI configuration at `/config/translator.toml`. Required settings:

- Downstream: `127.0.0.1:34255`; upstream: only `127.0.0.1:34256`.
- Protocol min/max: `2`; `aggregate_channels=true`; `verify_payout=false` for
  normal ArkPool account mining. Pool accounting is not a Bitcoin coinbase-address
  verification scheme.
- `downstream_extranonce2_size=2`: the tested receiver's four-byte allowance also
  contains the translator's two-byte allocation prefix.
- Empty supported/required extension lists; required receiver authority key;
  the exact owner-provided Ark identity as `user_identity`.
- Difficulty settings: actual nominal hashrate, six shares/minute,
  `enable_vardiff=false`, `job_keepalive_interval_secs=60`.

Set `LAN_IP`, `MINER_IPS`, `SV2_POOL_ONION`, `SV2_POOL_PORT` and
`UPSTREAM_PROTOCOL=SV2`. Preserve private socket, Tor-state and TLS-identity
volumes. Use a non-root user, read-only root filesystem, dropped capabilities,
bounded memory/PIDs, and `network_mode: none`. The bootstrap connection opens
the authenticated aggregate channel before publishing the ingress socket;
it submits no shares. Configure container restart on failure.

After a separate candidate passes an authorized miner trial, persist the V2
socket selection in the installation's normal lifecycle configuration. A code
rollback is not permission to restore V1 upstream. Keep saved miner settings and
a reviewed recovery procedure; do not reboot the miner to verify a gateway change.

## Missing share responses

The translator monitors sanitized SRI events for forwarded shares and upstream
responses. When shares are awaiting replies and no acceptance or rejection
advances for 120 seconds, it closes translated admission and exits for its
existing supervisor to reconnect over V2/Tor. New submissions, jobs and
miner-local acknowledgments do not extend that deadline. Idle miners with no
outstanding replies do not trigger this check. Batched acceptances and explicit
rejections count as upstream responses; rejection is not accepted work.

This closes a gap in bidirectional socket inactivity checks, where continuing
outgoing submissions can keep an unresponsive upstream session open. The check
depends on the pinned SRI log format and is not independent pool accounting.
No outstanding share is replayed and its final credit may remain unknown.
Native V2 sessions, Tor clients, guard state and payout identity are unchanged.

## Counters and qualification

### Combined appliance runtime

StartOS and Umbrel V2 candidates use `python3 /app/dual_gateway.py` from an
image containing the pinned SRI binary. They require a private configuration
file selected by `GATEWAY_V2_CONFIG`, containing exactly these fields:

| Field | Value |
| --- | --- |
| `pool_onion` | Operator-verified, checksum-valid v3 receiver hostname |
| `pool_port` | Receiver's V2 port as an integer |
| `authority_pubkey` | Receiver's verified Base58 Noise authority public key |
| `ark_identity` | Optional exact mainnet Ark receive address for V1 translation |

Missing or invalid configuration prevents startup. There is no legacy endpoint
default. Without `ark_identity`, native V2 remains available and V1 connections
are refused. The web service receives only the public authority key and a
translation-availability flag, never the private configuration or owner identity.

Ingress uses `LAN_V2_PORT` for the separate native listener and shares its
connection budget with V1/TLS. The runtime independently enforces eight total
connections and two per source across both protocols. Native sessions retain
their own Tor streams; V1 sessions share the authenticated owner channel.
Translator recovery leaves native sessions running and never selects V1 upstream.
The appliance translator uses variable difficulty with a 100 GH/s starting
minimum; the fixed-difficulty V1-miner trial settings above are not appliance defaults.
It retains and drains an internal readiness connection to prevent an idle
translator from advertising zero aggregate hashrate. That connection submits
no shares and is excluded from actual miner-session counts. Loss of readiness
closes translated sessions and retries V2; native sessions stay connected.

Native traffic is encrypted: gateway-only telemetry cannot prove authentication,
job freshness or accepted shares. Its rows and totals remain unavailable for
those values. Mixed dashboards label pool-confirmed totals as translator totals.
Per-session source and uptime come from admitted connections, not guessed SRI IDs.

Use each package's provisioning and migration instructions; preserving the
configuration, Tor state, client policy, TLS identity and platform authentication
is required. Native appliance installation, real-miner acceptance and recovery
must be recorded separately from source and container tests.

### Share observations

The SRI translator may return a local V1 success before ArkPool acknowledges
that share. Only `SubmitSharesSuccess` from the V2 receiver counts as a
pool-confirmed acceptance. The optional `translator_observer.py` reads local
Docker logs and writes bounded, redacted dashboard snapshots. It requires a
trusted host service; never mount the Docker socket in the web container.
Configure `TRANSLATOR_CONTAINER` and `TRANSLATOR_STATUS_STATE_ROOT`, with private
`observer-config.json` containing the single owner's client IP, account hash
and Tor heartbeat directories. Keep observer state across service restarts.

The aggregate upstream supplies totals, not an accurate allocation of accepted
shares to individual V1 sessions. The dashboard shows unavailable per-session
counts as a dash and displays pool-confirmed totals separately.

On 2026-11-16, an owner-authorized V1-miner trial preserved its custom firmware,
identity, power profile and existing LAN gateway address. Both mining connections
used V1 into the translator and authenticated V2 over Tor upstream. Explicit
receiver acknowledgments confirmed accepted shares. This is evidence for that
hardware/receiver combination, not independent payout reconciliation or universal
firmware qualification. StartOS and Umbrel need their own packaging and live tests.

Validation: 151 SRI library tests passed for the pinned source and identity patch;
`python3 -B tests_translator.py` exercises exact identity handling, rejected
sources, bounded frames, log redaction and the distinction between local submits
and pool acknowledgments. Keep source checks, container tests and live evidence
separate in release records.
