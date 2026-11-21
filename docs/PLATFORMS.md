# Alternative platforms — experimental

For V2 installations, use the maintained
[Umbrel package](https://gitlab.com/arkpool/arkpool-gateway-umbrel) or
[StartOS package](https://gitlab.com/arkpool/arkpool-gateway-startos) and its exact
revision, configuration and qualification record. Historical V1 platform tests
below do not qualify the newer V2 packages.

The existing Linux Docker installation remains the default. Nothing in this
feature automatically migrates, restarts or reconfigures an existing gateway.

| Platform | Implementation | What is not yet established |
| --- | --- | --- |
| Linux Docker Engine / Compose v2 | Existing deployment and upgrade helpers | See the mining/recovery release gates in TESTING.md |
| Rootful Linux Podman 5.4+ / systemd | Offline Quadlet generator; four separate containers | Native startup, SELinux, actual LAN peer IP, Tor failover and mining |
| Umbrel | Operator-specific candidate passed native install, restart, transport and an approved real-miner trial | Native update/restore, dual-architecture image and distributable first-run setup |
| StartOS 0.4.0.2+ | Public native package is maintained separately; real-miner share, update and same-server backup/restore passed | Cross-server restore and non-x86_64 builds; 0.3 remains unsupported |
| Rootless Podman, Docker Desktop, other appliances | Not supported by these adapters | Source-preserving networking and the complete isolation contract |

An exported file, green unit test or healthy UI is not proof of platform support,
job delivery, accepted shares or payment. Do not list an app in a store before
its native acceptance checks pass. Do not publish operator-specific exports.

## Dashboards and widgets

### Shared design

Use one shared page, script and sanitized status schema across Docker, Umbrel
and StartOS. Platform-specific code should provide installation, authentication
and snapshot mounts, not a separate dashboard design or different metric meanings.
The current Umbrel candidate and public native StartOS package share that renderer;
standalone Docker dashboard authentication/integration is still in development.
This design target does not imply every platform package is store-listed.

Opt-in faster-path selection is implemented in the shared gateway, with matching
Docker/Umbrel/Podman configuration and shared dashboard timing/preference display.
Its default is unchanged round-robin; see the README before enabling probes.
The native StartOS package pins its own gateway source and publishes its own
release evidence; shared code is not proof that every installed package is updated.

Proposed additions, **not implemented yet**, are a compact accepted/rejected share
timeline, last accepted response per session, share-response timing, Tor route
connection/retry counts, and gateway uptime/restart markers. Existing transport
telemetry contains most live values, but they are not all exposed in the dashboard
snapshot schema. A historical chart also needs bounded storage, defined time
buckets and explicit gaps/resets; current process totals are not historical data.
Keep one-screen readability and retain text equivalents for charts. Do not add
hashrate, temperature, earnings or payout balances without a separate trustworthy
data source and an explicitly reviewed privacy boundary.

### Current capabilities

These are the interfaces currently implemented in the experimental candidates,
not a promise of store availability or completed platform support:

| Capability | Umbrel candidate | Native StartOS package |
| --- | --- | --- |
| Browser setup instructions | Read-only page behind Umbrel login; displays miner host and ports | Dashboard setup information plus native connection interfaces; no pool/client-policy setup or TLS-pairing action |
| Service readiness | Service health checks; the UI health endpoint checks only the UI itself | Native health checks for Tor A, Tor B, gateway, ingress and dashboard |
| Live mining observations | Shared read-only dashboard behind Umbrel login | Same dashboard behind OS HTTPS proxy and generated admin password |
| Native home-screen widget | Not implemented | Not implemented |
| Wallet controls or payout claims | None | None |

The shared dashboard code and Umbrel adapter are in this repository. The native
StartOS package and its checksum-verified release assets are maintained at
[arkpool-gateway-startos](https://gitlab.com/arkpool/arkpool-gateway-startos).
A green service indicator or reachable page does not prove fresh work, an accepted
share or a payment. See [telemetry semantics](../README.md#private-mining-telemetry).

### Read-only dashboard boundaries

- Shows connected sessions, accepted/rejected/submitted responses, unanswered
  requests, difficulty-weighted accepted work, per-session job age, Tor A/B
  readiness/cooldowns and listener/TLS admission. Accepted work is the sum of
  validated pool difficulty captured at submission time for correlated accepted
  responses; missing data stays unavailable. It does not estimate hashrate,
  earnings or wallet balance.
- With `TOR_ROUTE_POLICY=latency`, shows per-route median test timings and the
  preferred path for new connections. These use bounded Tor-only subscription
  probes, not shares; missing/stale/failed tests never display a speed winner
  without the transport's required evidence. No UI controls change the policy.
- Gateway and ingress write separate sanitized snapshots every five seconds.
  The UI reads only these two read-only mounts, never engine/mining sockets,
  Tor cookies/state, TLS keys or wallets. The gateway stays networkless.
- Browser polling is same-origin, one request at a time, every ten seconds with
  a three-second timeout. Snapshots older than 30 seconds are hidden; failed
  requests clear previous readings. A stopped/background tab expires old status.
- Session numbers are temporary. Client IPs are omitted unless the authenticated
  dashboard's explicit RFC1918-only opt-in is enabled. Usernames, payout addresses,
  pool destinations and raw protocol messages are always omitted. Counters are
  process-scoped and reset on restart. Share gaps alone are not treated as failures.
- Keep platform authentication on every page, script, API and health route.
  `DASHBOARD_AUTH=platform` does not provide authentication itself. Never publish
  the UI's raw port or use its health endpoint as a mining-readiness signal.
- There are no miner settings, restart, payout, claim or redeem controls. UI and
  snapshot failures cannot initiate mining recovery actions. Native widgets
  remain separate, unimplemented work.

## Inputs and safe exports

Use the same mode-0600 literal settings file described in the README. Existing
private addresses, pool destination, exact-IP policy and TLS settings are retained.
No wallet address/key belongs in this file: the miner supplies its own username.
The exporter never reads wallet files, starts an engine, pulls an image or changes
permissions on existing files. It creates a **new**, mode-0700 directory outside
Git; generated files are mode 0600. Existing destinations and symlinks are refused.

Supply the exact reviewed image: a full local `sha256:` image ID for Podman,
or a fully qualified `registry/repository:version@sha256:digest`. Umbrel requires
the latter, publicly pullable and containing both amd64 and arm64 variants.
Image syntax is checked, not registry availability, image contents or provenance.
Build the image from this branch to include `appliance_ui.py`; older images do not.
Use the resulting immutable ID/digest, never a fabricated digest or mutable tag.

`acceptance.json` initially marks runtime, LAN, Tor, mining and payment checks
`not_run`. Preserve that distinction when recording actual results privately.

## Podman

Use a separate approved **rootful Linux** host with Podman 5.4+ and systemd.
Do not alias Docker commands, change the Docker socket, put the services in a
Podman pod, or point the Docker upgrade helper at Podman. Pods share networking;
the gateway must keep `Network=none` and its private Unix-socket mounts.

Build/preload the reviewed image on that host, record its immutable ID, and run:

```sh
python3 -B platform_export.py podman --settings /private/path/gateway.env \
  --image "$REVIEWED_IMAGE_ID" --output ../arkpool-podman-candidate
```

Set `REVIEWED_IMAGE_ID` from actual image inspection first. Review `INSTALL.txt`.
Check that the `arkpool-*` names, ports and volumes do not belong to an existing
installation before installing anything. Validate the files using your packaged
Quadlet generator in dry-run mode. After explicit installation approval, install
only `.container`, `.network` and `.volume` files, mode 0600, under
`/etc/containers/systemd`; reload systemd and start `arkpool-ingress.service`.
Its dependencies start the other services. Unit installation/start is a separate
operator action, not part of export. The selected image must already be loaded:
`Pull=never` prevents an unexpected download or mutable-image replacement.

The Tor supervisor retains its existing recovery behavior. Systemd restarts
exited processes, but health checks do not kill working mining sessions. Resource
limits, read-only roots, non-root service users and capability dropping remain.
Socket volumes use shared SELinux labeling; Tor-state/TLS volumes use private
labels. Validate on an enforcing SELinux host; never disable SELinux to pass.
Rootless networking may rewrite peer addresses depending on its backend; it is
not certified by this exporter and the units require a root system manager.

Native administration uses `systemctl` and `podman`, not `gateway.sh`. For example,
read telemetry with `sudo podman exec arkpool-gateway python3 /app/gateway.py telemetry`.
Optional public pairing can be read through trusted Podman administration using
`tls_identity.py export`; keep the output private and never export the identity
volume. New certificates/volumes are **not** a settings-preserving migration from
Docker. Moving existing state and upgrade rollback remain separate reviewed work.

Reference: [Podman Quadlet documentation](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html).

## Umbrel

### Generic community-store candidate

The maintained alpha package is distributed through the
[separate Umbrel repository](https://gitlab.com/arkpool/arkpool-gateway-umbrel).
Use that project's README, package changelog and verification record for installs.
The store is independent of the official Umbrel store.

**Legacy V1 reference only:** `scripts/build_umbrel_store.py` and the
operator-specific exporter below still generate V1 runtime configuration. They
do not reproduce the maintained V2 package. Do not use their output to install,
regenerate or overwrite a V2 gateway. Generating a tree does not qualify or
publish it. The following describes those older exporters only.

`scripts/build_umbrel_store.py` generates a fresh-install community store using
only reviewed public defaults and an explicitly supplied immutable registry image.
It never imports a deployment `.env` or an operator-specific export:

```sh
python3 -B scripts/build_umbrel_store.py --image "$REVIEWED_MULTIARCH_IMAGE" \
  --submission "$PACKAGE_REVIEW_MERGE_REQUEST_URL" \
  --output ../arkpool-community-candidate
```

The package requires umbrelOS 2.0 and its host Python 3/iproute2 tools. Its exports
detect the single default RFC1918 LAN interface without sending network traffic;
ambiguous, VPN, container and public interfaces fail closed. Reserve the appliance
address. The normal browser workflow shows the detected miner endpoint, and the
operator enters their own Ark address only in their miner. Stratum port 23333 is
plaintext on the private LAN. This initial community candidate does not expose
TLS pairing through the UI. The existing operator-specific TLS exporter remains
separate and is not an automatic migration path into this fresh-install package.
The browser uses port 23335; these community-package ports avoid the existing
official apps that use ports 3333, 3334 and 3335.

Native app settings expose `MINER_IPS` to both ingress and gateway: the default
`subnet` permits only the detected LAN subnet; `lan` explicitly permits routed
RFC1918 clients. Keep host/router restrictions and never port-forward the port.
The networkless gateway, distinct Tor state directories, authenticated read-only
dashboard, non-root users and dropped capabilities are unchanged.

Output is a candidate, not a verified published store. Verify the supplied image
is anonymously pullable with both native architecture tests passed; lint the
store tree and test native installation, settings, restart, updates and mining
before distribution. The store repository needs its generated files at the
default branch root. Keep private evidence outside the published repository.

### Operator-specific export

Generate an operator-specific candidate package for an isolated Umbrel test:

```sh
python3 -B platform_export.py umbrel --settings /private/path/gateway.env \
  --image "$REVIEWED_MULTIARCH_IMAGE" --ui-port 3335 \
  --output ../arkpool-umbrel-candidate
```

The image must be built, reviewed and publicly published separately. This command
does not publish an image, create a community store or submit an official app.
The output contains an `arkpool-gateway/` app directory. JSON syntax in its `.yml`
files is valid YAML. Review port availability on the test appliance; the example
browser port is not reserved across Umbrel's store. There are no wallet inputs.

- Umbrel's `app_proxy` protects a separate read-only dashboard/setup page. Only ingress
  publishes Stratum, bound to the chosen private LAN IP. Do not publish the UI
  directly or turn off Umbrel login to work around proxy issues.
- The UI receives only separate read-only gateway/ingress snapshot mounts, plus
  miner host/port settings. No Tor/pool settings, Tor state, TLS keys, engine socket
  or gateway transport socket are mounted. It cannot control mining.
- Each Tor keeps its own app-data directory. Named Docker volumes are replaced
  by Umbrel-owned bind mounts, with all runtime processes using UID/GID 1000.
  Optional TLS identity is persisted separately. Only temporary socket/heartbeat/status
  directories are excluded from appliance backups; Tor/TLS identity is retained.
  Tor receives a 30-second stop grace so its bounded shutdown can flush state.
- Client-IP display is explicitly disabled on both the snapshot producer and UI.
  Enabling it is a separate privacy decision and is not part of generated exports.
- Only the gateway receives the ten-minute bootstrap health grace. Ingress and
  the UI use a short grace so their own failures surface promptly after startup.
- Keep `gateway.network_mode: none` after Umbrel rewrites the Compose package.
  Treat the appliance's shared network as untrusted. Verify the actual miner IP
  through the raw TCP listener; do not trust HTTP headers or a NATed private IP.
- A stock Compose validator rejects the image-less `app_proxy` metadata because
  Umbrel supplies its semantics. Validate the runtime services independently,
  then validate the **complete** package on Umbrel. Removing the proxy from a
  diagnostic fixture is not a replacement for appliance testing.

Do not overwrite an installed app using the exporter or use `gateway.sh upgrade`
on this layout. Before store distribution, implement/rehearse native updates and
backup restoration with retained settings, Tor state and TLS CA, then collect
LAN/mining evidence. Operator-specific LAN or pool configuration must never be
committed to a shared store; a distributable first-run configuration flow remains
required. The current candidate assumes configuration was privately supplied at
export time, rather than claiming universal one-click setup.

Reference: [Umbrel app packages](https://github.com/getumbrel/umbrel-apps).

## Start9 / StartOS

StartOS 0.4 users should use the separately maintained
[ArkPool Gateway native package](https://gitlab.com/arkpool/arkpool-gateway-startos).
Its repository contains the package-specific architecture, security policy,
instructions, upgrade notes, dated changelog and checksum-verified release assets.
The current package requires StartOS 0.4.0.2 or newer and is x86_64-only. StartOS
0.3 is unsupported.

This repository intentionally does not generate or install the native package.
Its read-only compatibility reporter points automation to the authoritative
package without claiming that a report installed or tested anything:

```sh
python3 -B platform_startos.py --version-family 0.4 --json
```

Exit 1 is intentional because this command is still an exporter gate: no `.s9pk`
is emitted from this tree. For version family 0.4, its JSON reports
`status: external_package`, the authoritative repository and minimum OS version.
Do not turn that result into a generated package, silently sideload an unverified
artifact, or treat it as live mining evidence.

The native package runs separate Tor A, Tor B, gateway, ingress and dashboard
subcontainers with additional non-root Bubblewrap isolation. The gateway daemon
has a private network namespace, read-only root and SOCKS mounts, zero capabilities,
and no Tor control cookie or TLS key. Plain and end-to-end TLS listeners preserve
the off-box client's source IP. Native validation covers both Tor paths' recovery,
fail-closed behavior, real-miner job/share handling, in-place update and destructive
same-server backup/restore with retained identities. See the package repository
for the precise release evidence and remaining cross-server and architecture gaps.

The native dashboard becomes available only after its password action runs. Its
generated admin password stays in an SDK-only volume, outside application
subcontainers; the OS HTTPS proxy enforces Basic authentication on every route.
Password rotation updates the proxy binding without restarting mining. Runtime
sockets and dashboard snapshots are excluded from backup, while Tor state, TLS
identity and the credential store are retained.

Do not combine Tor clients and the bridge into one networked process, mount a host
engine socket, grant network-administration capabilities, trust miner-supplied
proxy headers, or replace private SOCKS sockets with TCP. Verify a release checksum,
retain the miner's existing settings for rollback, use the package-reported ports,
and keep every listener private. StartOS wallet setup is independent and never
authorizes wallet access for this transport package.

References: [StartOS subcontainers](https://docs.start9.com/packaging/0.4.0.x/main.html),
[network/interface semantics](https://docs.start9.com/packaging/0.4.0.x/interfaces.html),
[older packaging model](https://docs.start9.com/0.3.5.x/developer-docs/packaging).

## Maintainer acceptance checklist

1. Record platform version, source commit, exact image digest and architecture.
2. Keep tests separate from the working miner; use synthetic identity fixtures.
3. Verify namespace isolation, mount scope, non-root users and no engine socket.
4. Verify real LAN reachability, preserved client IP and refusal of public clients.
5. Verify independent Tor bootstrap, jobs, accepted shares, and recovery with a
   separate authorized test worker. Both Tor clients down must fail closed.
6. Rehearse restart/update/backup-restore with original configuration and identities.
7. Reconcile pool accounting/payment read-only; never claim or redeem anything.
8. Document untested cases. Do not convert parser/fixture results into support badges.

Run `python3 -B scripts/check.py` for offline tests. With a real Podman package:

```sh
python3 -B scripts/check_platform_generators.py \
  --quadlet-generator /usr/libexec/podman/quadlet
```

This invokes only generator dry-run mode in disposable fixture directories. It
does not start systemd, create engine networks, or require a Docker/Podman socket.
