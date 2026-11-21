# Native Stratum V2 over Tor

`native_relay.py` provides a V2-only upstream path for miners that implement
Stratum V2 and authenticate the receiver's Noise authority key. It passes
binary bytes unchanged; authentication and encryption run end-to-end between
the miner and ArkPool. It does not translate V1 mining messages.

## Connection policy

Prefer native V2 on compatible miners. Keep V1 miner compatibility as a separate
incoming transport; a V1-only miner requires a validated V1-to-V2 translator
before using a V2-only upstream. Do not point a V1 miner at the native listener
and call that translation. See the separate [V1-to-V2 translator](V1_TO_V2.md) for its configuration and limits.

The native service requires explicit `SV2_POOL_ONION` and `SV2_POOL_PORT` settings.
It never reads the legacy `POOL_PORT` as a fallback. `UPSTREAM_PROTOCOL`, when
set, must be `SV2`. Failure to reach Tor or authenticate the receiver must stop
upstream work and retry V2, never select a V1 receiver or direct Internet route.
The miner must require authority verification with the receiver's public key;
turn off its automatic V1 fallback when enforcing this policy.

A deployment that adopts V2 must retain its native entrypoint, explicit V2
receiver settings and downgrade policy across restarts and upgrades. Do not
replace it with the legacy default Compose command during an image update.
Rolling back code is not authorization to restore V1 upstream. An incompatible
rollback must fail closed and require operator intervention. This source adds
an opt-in native transport; it does not silently migrate existing V1 deployments.

## Deployment contract

Use the existing isolated architecture:

- The gateway has `network_mode: none`, a read-only filesystem, non-root user,
  dropped capabilities and no engine socket.
- The ingress shares the private gateway Unix socket and prepends the actual
  IPv4 source. Both processes enforce the same miner allowlist.
- The native gateway command is `python3 /app/native_relay.py`. Use dedicated
  Unix socket/state volumes and a distinct listener when migrating from V1.
- Both Tor clients retain independent state and use Unix SOCKS sockets with
  `OnionTrafficOnly` and `IsolateSOCKSAuth`. No direct TCP or DNS fallback exists.
- The two ready Tor routes are raced with a seven-second dial budget; unused
  sockets are closed. A SOCKS connection is provisional until upstream bytes
  arrive. An early upstream close places that route in bounded exponential
  cooldown so the miner's next V2 reconnect can use the other ready route. A
  miner's full Noise handshake may take additional time.
- Connections are bounded to eight globally and two per source. Opaque,
  process-local per-miner SOCKS credentials separate Tor streams.
- Ten minutes without upstream bytes closes only the affected native session,
  even if the miner continues sending. Incoming pool bytes reset this deadline;
  they do not prove fresh jobs or accepted shares. The miner can reconnect over
  the existing V2/Tor route selection. This does not rotate Tor identities,
  restart containers, replay shares or select routes by share latency.
- Preserve the exact payout identity in miner settings. No wallet operation is
  part of setup or verification.

A raw relay cannot decrypt mining counters. Use explicit miner observations or
authenticated receiver telemetry for protocol, jobs and accepted shares. Never
infer accepted work from bytes transferred or a connected TCP socket. Logs
contain only bounded session numbers, durations, route indexes, byte counts and
closure reasons; no payout identity or raw encrypted payload is recorded.

## Observed operation and limits

On 2026-11-16, two operator-owned Bitaxes (403 and 601) using compatible custom
firmware mined concurrently through the native path. Both verified the pool
certificate, negotiated extended V2 channels, received jobs and acknowledged
accepted shares with no observed rejects during the recorded window. This
supports those tested firmware/receiver combinations, not every stock firmware.

Several upstream disconnects recovered on V2. The relay recorded an upstream
EOF; receiver-versus-Tor attribution remains unresolved. Long-term reliability,
independent payout reconciliation and unattended migrations still need validation.
V1 translation has separate qualification evidence and deployment requirements. The operator adopted this native path for live mining; that
local decision does not turn these observations into a universal release claim.

Run `python3 -B tests_native_relay.py` for offline binary forwarding, source
policy, route racing, timeout cleanup and isolation checks. Never force Tor
failures against active miners without separate authorization.
