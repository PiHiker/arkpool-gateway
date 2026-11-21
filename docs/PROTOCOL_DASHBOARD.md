# Protocol badges and read-only miner observations

A protocol setting is not proof of the active connection. The dashboard keeps
four concepts separate: local mining protocol, upstream mining protocol,
authentication and preferred configuration.

| Display | Evidence |
| --- | --- |
| Miner → gateway: V1/V2 | Active pool slot, connected state and compatible transport security |
| Gateway → ArkPool: V2 | Native V2 miner verified the configured pool authority through the expected native relay endpoint |
| Authenticated | Required Noise authentication and exact authority-key match |
| V2 preferred | Current primary settings of all monitored miners select V2 |
| V1 fallback active | The miner explicitly reports its secondary pool is active |
| Unknown / Unavailable | Disconnected, stale, malformed or missing observations |

The unified session table labels both legs V1 for the existing JSON gateway,
and places those connections alongside native V2 miners. Each row labels its
counter source: gateway session or miner uptime. Miner counts are not added to
the legacy gateway history. Desktop rows use the full page width without an
inner horizontal scrollbar; narrow screens stack each session's fields. A translator must supply separate verified upstream
telemetry before a future V1 → V2 row may claim upstream V2. Do not infer it
from a configured preference, an open TCP socket or a successful Tor bootstrap.

The V1-only warning applies when all monitored miner readings are available,
there is at least one active connection, and every active monitored connection
uses V1. Missing readings produce an availability warning instead. A browser
that stops receiving fresh snapshots hides old badges and counters after 30s.

## Generic labels and adapter support

Session labels are neutral by default. `DASHBOARD_MINER_NAMES=1` explicitly opts
into installation-provided labels (and already-authorized client addresses for
legacy sessions). Device models and personal names are not baked into the UI.
The session table is protocol-oriented; it does not require a particular brand.
The optional collector understands the Bitaxe `/api/system/info` schema and a
read-only `summary-api` adapter with fixed `summary` and `pools` commands. Other
device APIs need a supported adapter; never claim their hashrate
or authentication from an incompatible response. Legacy gateway observations
remain available independently of that collector.

## Opt-in deployment

The existing platform authentication and private-network restrictions remain
mandatory. Do not expose the raw appliance web port to the Internet. This
addition neither configures a miner nor enables protocol downgrade.

1. Configure a separate read-only collector using `python3 /app/miner_status.py`.
   Keep it non-root, read-only, capability-free, without an engine socket and
   with bounded resources/logs. It needs private LAN access only to the explicitly
   configured miners. It has no access to Tor state or mining gateway sockets.
2. Supply `MINER_STATUS_CONFIG` as a protected file mounted read-only into that
   collector alone. Each entry contains `label`, numeric private `url`, management
   `username`/`password`, `expected_gateway`, `expected_port` and the public
   `authority_key`. Use the already-verified miner credentials and receiver key;
   never put real configuration in Git or images. Existing HTTP-only Bitaxe APIs
   require a trusted private network; these API credentials are not protected by
   the miner's separate V2 Noise session. Treat them as full management
   credentials even though this collector issues only bounded reads: the same
   login may authorize pool, firmware, restart, or other configuration changes.
   Use an isolated trusted management LAN rather than a shared or untrusted Wi-Fi
   segment.
3. Give the collector its own writable snapshot directory, owned by its UID,
   with `MINER_STATUS_ROOT` pointing to it (default `/run/miner-status`). Initialize
   the directory ownership before starting a non-root container. Use a persistent bind directory or volume to retain history across collector
   restarts. Bounded allowlisted `status.json`, `hashrate-history.json`, and `miner-contacts.json` files are written; no response payload or credential logs.
4. Mount that directory read-only into the web service as
   `/run/arkpool-dashboard/miners`. Set `MINER_STATUS_ENABLED=1` on the web service.
   Only the collector receives credentials. Preserve the existing authentication
   wrapper, token policy, network bindings and status volumes.
5. Verify `/api/miners` follows the existing browser access policy, shows current
   observations, hides stale data, and cannot return raw miner credentials,
   payout addresses or raw API objects. The separate token-protected Shhark
   status-only service does not expose this optional route.

The observer polls every ten seconds, uses a four-second socket timeout and a
six-second total deadline in a disposable worker process for each miner, refuses
redirects/proxies/public hosts, and bounds body sizes and field values. A failed
or trickling miner read produces an unavailable row without delaying responsive
miners or recycling old counters.

## Validation

`python3 -B tests_miner_status.py` covers actual V1 fallback, authority mismatches,
disconnection, upstream-evidence requirements, stale snapshots, redaction,
private origins, redirects and read failures. `tests_dashboard.py` covers the
existing HTTP/snapshot behavior. Browser verification covered the two-path
badges, the V1-only warning and an unavailable state without altering miner
configuration. Successful miner responses do not prove payout reconciliation.

Tor path counts are grouped by transport in one panel. Native V2 and translated
V1 connections can share the same pair of Tor clients on one gateway host.
Separate deployments can also use separate clients with the same A/B labels.
Session Tor badges show only `A` or `B`; adjacent columns show protocols. A/B name
Tor clients, not stable Tor circuit IDs. Missing native route telemetry displays
Unavailable rather than a zero count.

The optional native route reader uses an exact private source IP and a
64-character bearer token in a private file. It exposes only bounded connection
metadata; it has no mining-control socket. Snapshots expire after 30 seconds,
with at most five seconds of future clock tolerance. The collector uses
`NATIVE_ROUTES_CONFIG` for its private URL/token file; credentials never reach
the browser. Include `native_status.py` alongside the collector.

For native setup cards, configure `V2_LAN_IP`, `V2_LAN_PORT`, and
`V2_AUTHORITY_PUBKEY` together. Set `V1_UPSTREAM_PROTOCOL=SV2` only after the
V1 listener has been connected to a verified translator. Runtime protocol
badges come from the current snapshot, independently of setup-card settings.
Translated aggregate channels expose pool-confirmed totals; per-session share
counts are unavailable and shown as a dash rather than copied to every miner.

## Total reported hashrate

The top chart sums actual one-minute hashrate readings from configured physical
miners whose active pool matches the expected gateway. A connected flag alone
does not supply hashrate. Each physical miner contributes once, regardless of
how many gateway connections it opens. Connection rows are labeled separately.
If a configured miner is unavailable or on another pool, the total is unknown;
the dashboard shows the known subtotal and reporting count as **Partial**.

The existing collector records the first actual observation in each UTC
15-minute interval, at most 96 observations. It deletes observations at or before
24 hours ago. The chart never reconstructs earlier history, averages an interval
it did not measure, or substitutes zeros for missing readings. Partial samples and skipped intervals break the green total line. An amber
series shows the known subtotal explicitly as partial; a single real sample
remains visible while history starts. Gateway connections are collapsed below
the physical-miner table. History persists through collector
restarts in its existing private status volume; changing the configured miner
set or gateway target resets it. A clock rollback discards future observations.

The chart uses inline SVG and the existing authenticated `/api/miners` response.
It adds no port, public endpoint, service, external script or browser storage.
Each private history/status file is bounded to 64 KiB and written atomically with
mode 0600; symlink and nonregular files are rejected. Raw API responses, pool
addresses, payout identities and management credentials are excluded. This is
reported device hashrate, not proof of pool acceptance or payout.

For the generic `summary-api` adapter, configure `kind: "summary-api"`, `label`,
`physical_id`, numeric private HTTP `url`, `expected_gateway` and `expected_port`
in the existing private miner configuration. Only ports 80 and 8080 are accepted.
The adapter sends only fixed read-only `summary` and `pools` JSON commands to
`/api`, refuses redirects and proxies, and requires a single active pool matching
the configured gateway before including its rate. Never configure one physical
device more than once. This API is unencrypted; use the existing trusted LAN.

`tests_hashrate_history.py` covers interval retention, restart recovery, clock
rollback, missing telemetry, physical-miner deduplication, bounded files and
read-only adapter validation.

For an intentionally isolated management network, preserve its firewall policy.
An existing trusted monitor can instead export a sanitized observation into the
collector's existing private status volume as `external-PHYSICAL_ID.json`.
Configure `kind: "snapshot-file"`, `physical_id`, `label`, and optionally an explicit
`max_age_seconds` (30 by default, at most 300); arbitrary paths
and URLs are refused. The file schema is `schema_version: 1`, original
`sampled_at` Unix time, and a `miner` object matching the sanitized collector
row schema. The exporter must verify the expected active pool before setting
`mining_target_verified`; never copy raw API data. Publish atomically with mode
0600 and the collector UID. Future observations or those beyond the configured freshness limit are
unavailable. The UI displays the original source age and the oldest source in
the total; history retains that age alongside the actual observation. Match the
explicit limit to the existing monitor cadence plus a small delivery margin. Export timestamps must reflect measurement time, not copy time.
Use an existing trusted monitoring/transport mechanism; this adapter adds no
listener, credentials or permission to access quarantined miner APIs.

## Verified upstream badges for V1 miners

A V1 miner cannot itself verify the translator's upstream protocol. Optionally
mount a private JSON array as `TRANSLATED_MINER_BINDINGS` into the existing web
service only. Each entry contains a unique sanitized `label`, exact private
`client_ip`, `gateway_host`, integer `gateway_port`, and the independently
verified gateway `account_fingerprint` (64 lowercase hexadecimal characters).
The fingerprint must match this gateway snapshot; the binding never changes
payout configuration. The host/port must match
that web instance's `LAN_IP`/`LAN_PORT`, and the label must belong to the collector
whose expected target was independently configured and verified. The source IP
must match that physical miner in this gateway's authorized-session observations.

The web service joins only current snapshots, exact-target-verified V1 miners,
a V2 aggregate translator with verified account identity, fresh jobs on the
bound source and a ready Tor path. Explicit translator unready, stale jobs or
mismatched bindings leave upstream Unknown. Legacy observers must already have
seen the authenticated V2-job marker before publishing their snapshot. Binding
addresses stay private and are not added to the miner API. The local badge remains
V1 and the miner never gains a Noise-authenticated label from gateway evidence.

The same verified sessions supply the miner row's Tor A/B badge. All matching
sessions must agree on one Tor client; a split between clients remains Unknown.
Other miners' sessions do not determine this row's path. Stale or unverified
evidence never supplies a route badge. A/B identify clients, not circuit IDs.


## Individual hashrates, LAN addresses and inactive miners

The chart includes a separate color for each monitored physical miner alongside
complete totals and partial subtotals. The legend shows current rates; hover a
sample for its time and rate. Individual observations begin when this collector
version is installed. Earlier total-only samples remain intact, without invented
per-miner history. Every series keeps the same 15-minute / 24-hour limits.

Select a miner in the legend to view only its history on its own vertical scale.
Select it again, or select Total, to restore the combined view. Distinct outlined
markers help separate similar rates; the selected view survives live refreshes.
The headline total remains the current total in either view.

Shaded intervals identify missing or partial observations within recorded history.
Their tooltips distinguish missing readings from partial totals. Shading does not
fill in a hashrate value or connect measured lines across missing samples.

Enable `DASHBOARD_CLIENT_IPS=1` on the private web service to replace numbered
miner labels with their LAN addresses in both the table and chart. Without that
opt-in the API strips addresses and neutral labels remain. API-backed adapters
use their explicitly configured numeric RFC1918 origin. For a `snapshot-file`
adapter, add optional `display_ip` with the independently verified management IP
in its private collector entry. This is display metadata only: it does not add
network access or probe that address. Missing addresses retain a neutral label;
no source address is guessed from shared translator connections. Do not enable
address display on a publicly accessible dashboard.

A valid management observation refreshes the last-contact timestamp, even when
the miner is disconnected from its pool. External snapshots use their original
measurement time, not the time the file was read. An unavailable miner stays
visible with gaps for less than 24 hours, then its row and individual series are
hidden. Remaining miners keep their identities, colors and numbers. The collector
continues its existing bounded checks; contact restores the miner automatically.
New configurations receive a 24-hour discovery grace period. No failed readings
are reused as current rates and an empty roster reports no known total.

The small mode-0600 contact ledger survives collector restarts and contains only
numbered contact timestamps plus the existing configuration-scope fingerprint.
Only that small ledger changes with live contact times; the larger history still
records one observation per interval. Files remain capped at 64 KiB and eight
miners. Existing configuration, management requests, ports and access restrictions
are unchanged. Hiding an inactive row never deletes its configuration or restarts
its miner.


## V1 badge help

V1 badges open a keyboard-accessible, dismissible popout explaining V2 encryption,
authentication and compatible-firmware setup. It links to the existing connection
settings without changing them. The text distinguishes the miner link from the
upstream gateway link and retains V1-to-V2 translation for V1-only miners.
It makes no hashrate, block or payout promise and adds no remote content or controls.

## Fleet overview and layout

The overview reports complete measured hashrate, connected miners verified against
the configured target, upstream protocol evidence, and observed active Tor path
labels. A/B identify Tor clients, not independent internet connections or stable
circuit IDs. A missing route observation cannot prove backup availability.

Measured total segments have a subtle shaded area; gaps and partial readings
remain distinct. Selecting a miner retains its own chart scale. Miner rows become
cards on narrow screens. Gateway process counters remain separate in expandable
diagnostics and do not become fleet-wide accepted-share totals.

Connection settings offer copy buttons when JavaScript is enabled. If clipboard
access is unavailable, the exact value is selected for manual copying. No miner
configuration is written.

A measured job age over 180 seconds displays **Waiting for work** and raises
the fleet attention indicator. An adapter without job-age telemetry shows
**Unavailable** in that column; missing telemetry does not prove stale work.
Expanded gateway-connection details stay open across normal polling.

## Local native route observations

When the native relay and collector share a host, mount only the relay’s
sanitized status volume read-only into the collector and set `NATIVE_ROUTES_ROOT`
to that directory. Remove `NATIVE_ROUTES_CONFIG`; configuring both sources fails
startup. No route HTTP listener or bearer token is required for this local path.
Missing, malformed, oversized or stale files produce unavailable route evidence.
Do not mount the mining socket or Tor state into the collector or web service.
