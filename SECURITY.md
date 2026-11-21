# Security boundary

## Runtime security maintenance

New images use Debian 13 with security updates. Build and CI fail unless Tor is
at least **0.4.9.16**, PCRE2 is at least `10.46-1~deb13u3`, and both the
OpenSSL command-line package and shared library are at least
`3.5.7-1~deb13u3`. Debian revisions are retained for backported fixes. These
floors address the reviewed
[Tor security release](https://forum.torproject.org/t/security-release-0-4-9-16/22372),
[PCRE2 advisory](https://security-tracker.debian.org/tracker/CVE-2026-103111),
and [Debian OpenSSL security status](https://security-tracker.debian.org/tracker/source-package/openssl).
They are not a comprehensive or continuously updated vulnerability scan.

The production image uses a digest-pinned Debian base, applies all updates
available from freshly downloaded package indexes, then installs only the
explicit runtime package set. The build fails if an update still remains
pending or if any configured package repository fails to refresh. This prevents
APT from silently accepting partial indexes and selecting Tor from an unintended
fallback origin. Full test modules are copied only into the Dockerfile `test` target;
the final runtime contains the production self-check but not the test suite.
GitLab builds both targets and runs them without network access after the build.

Tor Project's official stable Debian 13 repository supplies Tor because Debian's
security repository can lag upstream. The build verifies archive-key fingerprint
`A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89` before creating a scoped `Signed-By`
keyring. APT permits only `tor` and `tor-geoipdb` from that origin; all other
packages from it are pinned out. No global trusted key, unsigned-package bypass,
nightly repository or host repository change is used. The image supports the
upstream repository's amd64/arm64 architectures. Key preparation tools stay in
a separate build stage. See [Tor's installation guide](https://support.torproject.org/little-t-tor/getting-started/installing/).

Run `./gateway.sh security-check` from a current, reviewed source checkout to
check the four required services and every running optional Compose service.
The host sends its current checker on standard input, so an older image cannot
pass using superseded security floors. Missing required services, failed service
discovery, unsupported runtimes, and unavailable package metadata fail the check.
Run `./gateway.sh security-audit` to compare disposable copies of the deployed
images with current repositories. It mounts no configuration, socket, identity,
or state, includes running optional services, and uses the host's current checker.
It makes repository requests and is not a comprehensive CVE
or application-security scanner.
Transport-only upgrades deliberately leave Tor containers unchanged. A green
source pipeline or a new gateway image does not update existing Tor clients:
follow [the maintenance procedure](docs/UPGRADING.md#tor-and-os-security-updates).

## Network and application boundaries

Alternative-platform exports preserve these boundaries; they do not certify the
platform's actual networking. Rootful Podman and Umbrel profiles are experimental;
rootless Podman is not supported. Native StartOS 0.4 packaging is maintained in a
[separate public repository](https://gitlab.com/arkpool/arkpool-gateway-startos)
with its own security policy, release checks and minimum OS version; the exporter
in this repository deliberately does not emit an `.s9pk`. See
[platform limitations](docs/PLATFORMS.md). The optional appliance dashboard has
no engine, transport, Tor-state, TLS-key or wallet mounts and no write/control
API. It reads only two dedicated read-only sanitized snapshot directories. Its
health endpoint describes only the UI, never mining readiness. Umbrel login
protects every browser/API route; only private Stratum ports are published directly.

An optional `miner_status.py` collector can add native-miner observations. It
uses only bounded GET requests to explicitly configured numeric RFC1918 miner
origins; redirects and environment proxies are disabled. This collector has
network access and private miner-management credentials, so it is a separate
trust boundary from the networkless mining gateway. Those credentials must be
mounted read-only only into the collector, never the web service or source tree.
Read-only polling describes the collector's behavior, not the credentials'
authority: on HTTP-only miner APIs the same credentials may permit pool,
firmware, restart, or other management changes. Keep collector traffic on an
isolated trusted management LAN; LAN interception can expose full miner control.
The web service gets one additional read-only sanitized snapshot volume, hides
readings older than 30 seconds, and exposes no write/restart API. V2 upstream
badges require verified end-to-end Noise through the expected native endpoint;
V1 translation needs independent upstream evidence and is not inferred here.

The UI does **not** implement its own authentication. `DASHBOARD_AUTH=platform`
is an adapter assertion, not an access-control mechanism: never expose its raw
HTTP port. The native StartOS package uses its OS HTTPS proxy with Basic auth;
missing credentials mean no dashboard interface, not an anonymous fallback.
Keep StartOS credentials in its SDK-only store, outside every app subcontainer.

`DASHBOARD_SNAPSHOTS=1` opts the producers in; the default Docker topology is
unchanged. Each producer atomically replaces a mode-0600, bounded status file in
its own volume. The UI revalidates an explicit allowlist and hides snapshots older
than 30 seconds. It exposes no usernames, payout destinations, raw protocol data
or Tor identities. Client addresses are omitted by default. The explicit
`DASHBOARD_CLIENT_IPS=1` opt-in permits only canonical RFC1918 addresses and must
be set on both the gateway snapshot producer and authenticated UI; never enable
it on an externally reachable dashboard. Counters describe one process, not
payment or lifetime history. Difficulty-weighted accepted work uses only a
validated pool difficulty captured at submission time and a correlated accepted
response. Missing or ambiguous difficulty remains unavailable; the value is not
hashrate, earnings, backend reconciliation, or payment proof. Filesystem writes
run off the mining event loop with at most one pending write; missing/failed
snapshots make the dashboard unavailable, not the mining transport. The UI has
no mining restart/watchdog authority. After a successful correlated authorization,
a checksum-valid Ark username may contribute only its SHA-256 account fingerprint
to sanitized status. The full address is not retained or shown. This pseudonymous
fingerprint remains linkable, so keep the dashboard authenticated and private even
though it cannot spend funds.

The optional Shhark status overlay runs a separate status-only HTTP service. It
requires a 256-bit bearer token on every status read, binds to the configured
private `LAN_IP`, serves no dashboard page, and mounts only the two sanitized
snapshot volumes read-only. The token is not wallet material, but it grants
access to linkable mining metadata: keep it out of source control and logs, use
an exact host-firewall allowance for the Shhark host, and never port-forward the
status port. The client-IP opt-in applies to this overlay as well and exposes only
validated RFC1918 addresses to the authenticated Shhark service. TLS is not
provided by this LAN-only overlay; use a private trusted network or an
authenticated encrypted tunnel where LAN interception is in scope.

- Only the configured RFC1918 host address publishes Stratum ports. New installs
  use `MINER_IPS=subnet` with an explicit `LAN_CIDR`: both listener and bridge
  allow sources only inside that RFC1918 subnet. Public, loopback, link-local,
  CGNAT and IPv6 sources are refused. An optional list of up to 16 exact private
  miner IPv4 addresses is tighter; explicit `MINER_IPS=lan` retains the wider
  10/8, 172.16/12 and 192.168/16 behavior for existing or routed deployments.
  Exact-IP deployments may optionally pin each V1 miner source to the SHA-256
  fingerprint of its complete checksum-valid Ark username with
  `MINER_ACCOUNT_PINS`. Keep that mapping only in the private `.env`; never
  commit payout identities or their source-IP mapping. A mismatch closes the
  session before the authorize or submit message reaches the pool.
  Private addressing is not authentication. Routed private networks/VPNs can
  reach the listener if permitted by the host firewall, and source NAT can hide
  an external client behind a private address. Never publicly port-forward this
  service; keep firewall restrictions and verify source preservation.
- The bridge has Docker networking disabled (`network_mode: none`). Its only
  upstream connections are AF_UNIX SOCKS sockets shared with Tor. A separate LAN
  listener publishes the TCP port and forwards to the bridge's private Unix socket.
  It prefixes the actual peer IPv4 address as four bytes; the bridge rechecks the
  client policy. This envelope is trusted only on that socket, which is shared only
  with the listener. Miner-provided source headers are not trusted.
- TLS is optional and off by default. With `TLS_ENABLED=1`, the separate Compose
  overlay publishes a TLS listener (default 3334), retaining plaintext (3333).
  TLS requires version 1.2 or newer. Source policy and the shared eight-connection
  limit apply before the handshake, which has a five-second deadline. After a
  successful handshake, each source may use at most two sessions. No TLS
  bytes are forwarded to the networkless bridge before handshake success.
- The ingress generates a per-installation CA and server key in its private
  `tls-identity` volume (mode-0600 files, mode-0700 directories). Only ingress
  mounts that volume. The server certificate includes the configured private
  IPv4 address. Restarts reuse the identity; expiring leaf certificates renew
  on startup or six-hour maintenance checks within 30 days of expiry without
  changing the CA or server key. The CA lasts ten years; the leaf lasts 825 days.
  Live renewal replaces the context for new handshakes, not established sessions.
  Expiry is checked at admission; maintenance failure blocks new TLS sessions and
  retries in five minutes. A 60-day CA warning is available through private local
  status. An address mismatch, corrupt key, changed or near-expired CA fails closed
  and requires operator maintenance; do not delete the volume to fix it blindly.
- Pairing exports only the public CA, host and ports through the local Docker
  administration path. Obtain the file over a trusted admin connection: a file
  cannot authenticate itself, and unauthenticated LAN auto-discovery is not used
  to establish trust. This is server-authenticated TLS, not miner client-certificate
  authentication. IP restrictions still apply. An explicitly configured plaintext
  fallback permits an attacker who blocks TLS to force an unencrypted connection.
  TLS ends at ingress; Tor protects the onward network hop. The gateway remains
  trusted to read messages. Mining TLS does not encrypt the miner's web interface.
- The LAN listener uses a normal Docker bridge network for port publishing, so
  it is inside the trust boundary. Its code only connects to the gateway's Unix
  socket, but a compromised listener could use its network access. It has no
  pool configuration, Tor control credentials, or wallet keys mounted.
- Each Tor client has external networking but no published port. Its SOCKS
  socket is shared only with the non-root gateway and uses `OnionTrafficOnly`.
  The clients have separate state and socket volumes on the same Docker host.
- Each SOCKS listener explicitly uses `IsolateSOCKSAuth`. The default gateway
  policy derives a process-local opaque credential per miner source, so miners
  do not intentionally share streams. Source addresses are not embedded in the
  credentials, persisted, or logged. Subscription probes use a stable,
  process-local credential per Tor route, separate from every miner credential.
  Optional per-session mode increases circuit churn; explicit shared mode reduces
  isolation. These controls do not defeat end-to-end timing correlation.
- Optional `TOR_ROUTE_POLICY=latency` adds bounded subscription-only probes to
  the same configured onion through those Unix sockets. Default round-robin runs
  no probes. One probe at a time has a 20-second deadline plus bounded cleanup,
  with at most eight bounded, validated response frames. No authorization,
  submissions, wallet access, alternate destination, DNS/TCP fallback, control
  socket, new-identity request or guard rotation is added. Results are capped at
  five per path in process memory and expire after 15 minutes. Probe failures do
  not close miners or alter mining/recovery counters. Preference affects only
  new upstream dials; local readiness, real-connection cooldowns and failover
  remain authoritative. A SOCKS dial alone does not clear failure state: the
  legacy bridge waits for a validated pool frame, while native V2 waits for
  upstream encrypted bytes. An upstream-side close cools that route before the
  miner reconnects; encrypted sessions are never replayed onto another route.
  Tests generate a small amount of identifiable protocol traffic and cannot
  establish anonymity, future circuit speed or payment.
- The destination must be a checksum-valid v3 onion hostname. URLs, IP literals,
  clearnet domains, v2 onions, and invalid checksums are rejected before listen.
- Messages are bounded to 16 KiB and 32 nested JSON objects/arrays (including the
  root object). Nesting is checked before recursive JSON decoding in both
  directions; string contents do not count and accepted wire bytes are unchanged.
  This bounds parser depth independently of message size and stops unusually
  deep frames from reaching a miner or pool. Connection count is bounded to eight
  globally and two per source, so two permitted LAN addresses cannot consume every slot,
  initial Tor dial to 30 seconds per route, session inactivity to ten minutes, and blocked writes
  to 30 seconds. Complete valid messages in either direction refresh gateway
  activity; ingress shares its byte-activity timer across both directions. A V1
  session must complete pool authorization within 60 seconds or release its slot.
  Once a frame starts, its independent ten-minute assembly deadline cannot be
  extended by other traffic. A quiet miner is not disconnected while jobs arrive.
- Only UTF-8 JSON objects are accepted; batches and blank keepalives are not
  supported. Duplicate or case-aliased object keys, null-containing keys,
  noncanonical `method` keys, non-string/null-containing method values, and
  nonstandard JSON constants are rejected. These checks prevent known parser
  differences from bypassing the `client.reconnect` prohibition. They do not
  establish compatibility with every miner parser; validate supported firmware.
- The configured Ark username is forwarded byte-for-byte. No identity rewrite,
  payment operation, accounting shortcut, or synthetic mining exists here.
- All four containers are non-root, read-only, resource-limited, drop all Linux
  capabilities, and cannot gain new privileges. None mounts a Docker socket.
- Only each Tor container sees its own persistent Tor state/control credentials. The
  bridge mounts the SOCKS directories read-only. Data volumes are not handoff
  artifacts and must not be shared or reused between unrelated homes.
- Aggregate logs never include source IPs, onion names, Ark addresses, passwords,
  JSON frames, or underlying exception text. Tor's own logs are suppressed.
- The legacy V1 runtime's orderly shutdown stops admission first and allows at most five seconds for
  already-forwarded share replies. It never replays mining submissions; any
  response still missing at cancellation remains an unanswered observation.
  The combined V2 runtime closes sessions on shutdown without that reply-drain
  window. Plan its upgrades for miner reconnection; an in-flight acceptance may
  remain unknown. Translator recovery preserves existing native V2 sessions.
- Health checks distinguish local availability from proof of remote mining.
  A supervised Tor process exits after prolonged failed bootstrap/readiness;
  Docker restarts it without deleting guard state or enabling fallback.
  Container stop signals wake the supervisor immediately. It gives the Tor
  child seven seconds to exit before killing a stuck child, keeping cleanup
  bounded inside Compose's normal stop window without changing retained state.
  Readiness requires both bootstrap completion and Tor's authenticated network
  liveness signal. Neither is an end-to-end onion or accepted-share check.
  The dashboard distinguishes fresh/stale jobs and subscription-only evidence
  from a locally ready but unverified pool path. A separate job watchdog may
  close a session after five minutes without jobs following authorization/work,
  only with a ready alternate path. Its process-local budget is three closures
  per hour, at least a minute apart. It never uses a share gap as a fault signal,
  replays shares, restarts containers, or rotates identity/state. Telemetry is
  available only through Docker administration and a private local Unix socket.

This does not protect a compromised Docker host, insecure home LAN, malicious
pool accounting, miner firmware configured with a clearnet fallback, or all
traffic-analysis attacks. Trustless payout verification is not implemented.
The package does not change host firewall rules or router configuration. Keep
the host firewall restrictive; do not expose or forward the listener publicly.
