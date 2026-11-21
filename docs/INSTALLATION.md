# Installation guide

This guide is for operators installing ArkPool Gateway on a Linux Docker
host. Setup must be repeatable without putting private configuration in source
control or interrupting a miner that is already working.

## Selecting the source track

For a latest-development request, begin with
[LATEST_DEVELOPMENT.md](LATEST_DEVELOPMENT.md). Fetch the current default branch
and record its exact revision before proceeding. Do not silently substitute an
older tagged release or reuse a cached image. Continue with the checkpoints below;
source selection does not bypass deployment or mining authorization.

## Recommended deployment path

Use **Linux Docker Engine with Docker Compose v2** for a normal installation.
This is the primary documented and tested workflow. Unless the operator has
explicitly selected another platform, follow the Docker prerequisites and the
ordered Docker checkpoints in this guide. Do not redirect an ordinary Docker
request into an appliance experiment.

Only when the operator specifically selects Podman, Umbrel or StartOS, read
[PLATFORMS.md](PLATFORMS.md) before executing Docker-specific commands here.
Podman and Umbrel exports remain experimental. StartOS 0.4 uses the separately
maintained [native package](https://gitlab.com/arkpool/arkpool-gateway-startos),
not the exporter in this repository. Do not alias engines, bypass a compatibility
gate, publish operator-specific exports, or use the Docker upgrade helper on an
appliance layout. Offline export is not installation authority or mining evidence.

The experimental appliance dashboard is read-only. Open it through the platform's
authenticated app route; never publish its internal HTTP port. Its `/api/status`
is a sanitized appliance-only snapshot endpoint, not a new `gateway.sh` command
or a default Docker API. Do not mount engine/mining sockets or wallet files into
the UI. Missing/stale readings require diagnosis, not an automatic miner restart,
payout operation or identity change. Preserve process-counter reset semantics;
accepted responses do not prove a payment. Native widgets remain unavailable;
StartOS package installation, upgrade and rollback follow that package's own
checksum-verified release instructions. See the platform guide for verified
capabilities.

Optional `TOR_ROUTE_POLICY=latency` selects a preferred path for new connections
using bounded real onion-subscription probes. Read the README's faster-path
section before enabling it. Never rotate Tor identities, move healthy sessions,
rank by random share arrival, or treat probe success as an accepted share.
Configuration checks/exports do not run probes. Existing installs retain
round-robin unless explicitly changed in an approved restart/update; preserve
image pins, Tor state and payout identity. Dashboard timing and preference are
read-only observations, not controls or a reason to restart a miner.

Keep the default `TOR_ISOLATION=miner` unless the operator explicitly chooses
per-session or shared stream behavior after reviewing the README. Never copy an
IP address, payout address, or wallet data into SOCKS credentials. Changing this
policy on a running gateway requires a reviewed restart and miner reconnect.

## Installation checklist

1. Read `MAINTAINING.md`, `README.md`, `SECURITY.md` and this entire guide.
2. Identify the approved host, checkout path and source revision. Start with
   read-only inspection. Do not clone over an existing directory or run commands
   against an unrelated Docker project.
3. Discover the host's private IPv4 addresses. If several interfaces are valid,
   ask which network should serve miners; do not pick a VPN or management network
   silently. Keep the default public Tor endpoint and `MINER_IPS=subnet` for new
   installations. Confirm the host's actual private `LAN_CIDR`; do not guess it
   or require a list of miner IPs.
4. Ask only for missing decisions or authority. The user's own complete Ark
   receive address is the only personal payout input; handle it privately.
   You may prepare and check the gateway before obtaining that address.
   Never ask for wallet seeds, private keys, claims or redemptions.
5. Check the existing state before each write. Install prerequisites, start new
   services or change networking only within granted authority. A working miner
   stays untouched until its owner approves a backed-up, reversible cutover.
6. If tools, permissions or repository access are missing, explain the exact
   missing capability. Do not fabricate observations or ask for secrets in chat.

### Commands and results

| Command | Purpose and limits |
| --- | --- |
| `./gateway.sh version` | Source package version; also record the Git revision because unreleased commits may share a version |
| `./gateway.sh preflight --json` | Read-only local checks: exit 0 passed, 1 blocked, 2 review required; does not prove mining |
| `./gateway.sh status` | Human-readable Compose service status, not a JSON mining-health API |
| `./gateway.sh telemetry` | Read-only private JSON job/share/route counters; resets on process restart; not payout proof |
| `./gateway.sh tls-status` | Read-only private JSON certificate expiry/admission status; no key export or rotation |
| `./gateway.sh pairing` | Exports public TLS setup to a private local file; requires optional TLS already running; does not configure/restart the miner |
| `./gateway.sh upgrade-status --json` | Saved upgrade transaction only, not current mining health |

Do not invent `status --json`, `doctor` or auto-install commands. In shell tools
that stop on nonzero status, capture preflight's exit code and JSON so a review
result is not discarded or retried as an installation command.
Use `up` only for an approved new installation. For an existing deployment,
read [UPGRADING.md](UPGRADING.md); do not overwrite `.env`, relax an existing
exact-IP policy or discard managed image pins to make a command succeed.

### Resume and hand off safely

After an interruption, inspect the current containers, source revision and
upgrade status before continuing. Do not repeat startup, restart or cutover
commands just because the conversation resumed. A pending upgrade requires
the documented recovery procedure, not another blind upgrade.

Keep a private handoff outside Git containing the selected host/path, source
revision, image IDs, completed checkpoints, next action, backup location and
rollback state. Never include wallet secrets; redact addresses and private
network details from any public report. Reuse [acceptance.example.json](acceptance.example.json)
and preserve `not_run` for unperformed checks.

Tell the user whether only the gateway is ready or a real miner has resumed
jobs and received a new accepted share. Explain remaining validation without
equating container health, Tor bootstrap or a long share gap with mining success
or failure. Pool accounting and payment remain separate checks.

## Preflight

Run `./gateway.sh preflight --json` after private configuration is in place.
It is read-only and never contacts the pool or miner. Interpret its exit codes
and limits using [RELEASING.md](RELEASING.md); a passing local check is not a
mining or payout verdict. Versioned bundles must pass checksum verification
before extraction and setup.

Start at step 1; do not jump directly to miner configuration. Use these explicit
checkpoints to decide whether it is safe to continue:

| Checkpoint | Required evidence | If missing |
| --- | --- | --- |
| Scope | Target host, operator authority, and whether interruption is allowed | Continue read-only checks; do not redirect a miner |
| Network | Operator-selected network/interface, source-preserving route, and free listener port | Keep old mining intact; request the precise missing decision or rule |
| Identity | Complete mainnet Ark receive address from the user's own wallet | Stop before authorization; never invent or normalize an identity |
| Ready | Build, tests, listener, and both Tor subscriptions succeed | Diagnose the isolated stack; do not move the miner |
| Cutover | Private original settings, working rollback, and explicit approval | Leave the existing miner unchanged |
| Mining | Fresh jobs and a new pool-accepted share on the trial session | Report jobs/hashrate separately from accepted-share evidence |
| Release | Recovery/share and payout gates in `TESTING.md` completed | Retain the alpha label; do not announce a supported release |

If a tool or credential lacks authority, say exactly what failed. Do not silently
substitute a different wallet, topology, host, or firewall policy. Notify the
operator when a live cutover succeeds, rather than waiting for the final report.

## 1. Establish the deployment boundary

Read `MAINTAINING.md`, `README.md`, and `SECURITY.md` first.

Confirm the target host and directory, whether this is a new installation or an
upgrade, and whether any miner already depends on it. For evaluation, use a
separate host or isolated deployment with a non-conflicting LAN port. Do not
stop existing containers to make room for a test.

Run read-only prerequisites:

```sh
docker version
docker compose version
ip -4 address show
ss -lnt
docker compose ls
```

Verify Linux Docker Engine, Compose v2, the host's actual reserved IPv4 address,
and that the intended listener port is free. Confirm Docker permissions and
adequate available memory/disk; the image is approximately 129 MB and the four
containers have configured memory ceilings totaling 640 MiB. These ceilings
are not a guarantee that a host with only that much RAM will suffice.

Avoid Docker Desktop, rootless networking, or NAT that hides miner source IPs
until that specific topology has been validated. Do not modify a host firewall
or router beyond the operator's authorized scope.

Confirm the chosen network, DHCP lease/reservation, host interface names, and
miner-to-host reachability before writing firewall rules. Do not assume an
interface is named `eth0` or `ens18`. Read-only router access does not imply
permission to add rules. If the chosen location cannot meet the connectivity
requirements, report the boundary and offer alternatives for the operator to
choose; do not select a different network automatically. A dedicated VM, an
existing Docker host, or a small server may be appropriate. Do not add network
interfaces to trusted services or weaken isolation to make a test pass.
A temporary DHCP address must be stabilized before unattended
operation; label a non-HA test VM as a trial, not a finished production service.

## 2. Obtain the required inputs

| Input | Authoritative source | Where it belongs |
| --- | --- | --- |
| `LAN_IP` | Reserved IPv4 address actually assigned to this Docker host | Private `.env` |
| `LAN_CIDR` | Actual private subnet containing `LAN_IP`, such as `192.168.1.0/24` | Private `.env` |
| `MINER_IPS` | Prefilled `subnet`; exact private IP list or wider explicit `lan` optional | Private `.env` |
| `POOL_ONION` | Approved public default already in `.env.example`; preserve existing settings on upgrades | Private `.env` |
| `LAN_PORT` | Free local port; default `3333` | Private `.env` |
| `POOL_PORT` | Pool operator; default `3333` | Private `.env` |
| Ark receive address | User's own wallet or existing verified payout configuration | Miner's Stratum username |

For a new default ArkPool installation, do not ask for an invitation, enrollment
record, or a pool onion address. The endpoint is prefilled. Ask for the user's
complete mainnet Ark receive address as the only personal payout input. Establish
the gateway host's local IP and verify source preservation separately. Keep
`MINER_IPS=subnet`; determine and confirm the actual private CIDR containing the
gateway without silently assuming `/24`. Do not ask users to list every miner
unless they want a tighter restriction. The explicit wider `lan` mode permits all
RFC1918 source addresses, including routed private networks/VPNs; neither mode is
authentication. Never allow public exposure or
source NAT to disguise outside clients as private. Do not overwrite existing
pool settings or access policies on upgrades.

Do not invent an onion address or use an example payout identity. Do not infer a
full address from an abbreviation, prior chat fragment, or similar-looking value.
No wallet key, seed phrase, API token, or wallet export is required by this package.
If address compatibility or identity custody is uncertain, finish independent setup checks
and leave miner configuration pending.

### Help an operator obtain an Ark address

Use [the README wallet walkthrough](../README.md#get-your-ark-payout-address)
and the [current ArkPool wallet guide](https://arkpool.org/#wallet). Explain:

- For phone options, link to Second's
  [mobile wallets built with Bark](https://second.tech/docs/built-with-bark#mobile-wallets).
  Directory inclusion is not proof of ArkPool compatibility; verify the
  current address format and server requirements before recommending a wallet.
- Bark Wallet on Umbrel is a graphical option; Bark CLI is a command-line
  option. Link to Second's official installation and mainnet instructions in
  the README rather than inventing wallet commands or recommending an
  unverified wallet.
- The wallet must use Second's mainnet Ark server, not Signet. Current pool
  support is for Bark-format mainnet addresses with a public-key policy and
  server mailbox on its payout server. Check the
  [pool compatibility FAQ](https://arkpool.org/#questions); the `ark1` prefix
  alone proves neither compatibility nor custody.
- The operator creates and backs up the wallet outside the gateway. Explain
  that Bark recovery requires both the recovery phrase and wallet database
  backups, and that wallet refresh guidance must be followed. Never request,
  inspect, export or store those secrets as part of gateway setup.
- Obtain only the full Ark receive address, privately. If given a combined
  payment URI or QR code, ask the operator to copy the Ark address itself.
  Do not silently extract, normalize, abbreviate or reconstruct an identity.
- The address goes in the miner's username with password `x`, not in gateway
  `.env`. No manual ArkPool registration or funding transaction is a gateway
  setup step. Never send a test payment or claim/redeem funds to validate it.

Gateway setup authorization does not authorize wallet creation, wallet
maintenance, or payout-identity changes. Preserve any existing verified
identity. When compatibility is uncertain, report the uncertainty and leave
cutover pending; do not fall back to another address or wallet. Record only
redacted identity-confirmation evidence in public reports, never the address.

## 3. Create private configuration

Use the reviewed checkout or verified source archive. Check its commit or checksum
and keep real configuration out of the build context and commits.
Inspect the archive's directory layout and enter the actual project directory
before creating `.env`. Do not assume extraction places `gateway.py` at the
destination root.

For a new deployment only:

```sh
test ! -e .env && test ! -L .env &&
  (umask 077; cp .env.example .env)
```

The checks are chained so a failed check skips the copy; existing files and
symlinks are retained. The restrictive umask creates the new file with mode 600
and the invoking deployment user as owner. Preflight refuses configuration owned
by another account; do not work around that check by making the file public.
Run this step from one setup process at a time.

Fill `.env` using the confirmed inputs. Never overwrite an existing `.env`
without reviewing the intended change. Keep assignments literal: no command
substitution, shell code, credentials, or wallet keys. Do not source the file as
a shell script or echo its contents into chat or logs.

Validate Compose without displaying expanded settings:

```sh
docker compose config --quiet
./gateway.sh preflight --json
```

Do not paste output from `docker compose config`, container environment dumps,
or unfiltered `docker inspect` into a public report.

## 4. Build and start this deployment

```sh
./gateway.sh up
./gateway.sh status
```

The helper builds the shared image, validates configuration, starts the four
services, waits for health, and checks that ingress has a published port. Allow
several minutes for initial Tor bootstrap. Do not weaken readiness checks to
force a success result.

Expected layout:

| Service | Role | Network access |
| --- | --- | --- |
| `ingress` | LAN listener and source allowlist | Normal Docker bridge; configured LAN port only |
| `gateway` | Stratum validation and Tor route selection | `network_mode: none`; Unix sockets only |
| `tor-a` | First Tor client and supervisor | External Tor connections; no published port |
| `tor-b` | Second Tor client and supervisor | External Tor connections; no published port |

All services must remain non-root, read-only, and without Linux capabilities or
a mounted Docker socket. Ingress is trusted and has normal bridge connectivity;
its code forwards only to the private gateway socket. Do not describe its network
access as equivalent to the networkless gateway.

After `./gateway.sh up` succeeds, these commands provide sanitized local checks
from the project directory. Full tests are in the source/test image, not the
production runtime image:

```sh
docker build --target test -t arkpool-gateway:test .
docker run --rm --network none --read-only --tmpfs /tmp \
  --cap-drop ALL --security-opt no-new-privileges:true \
  arkpool-gateway:test
docker compose exec -T gateway python3 /app/gateway.py healthcheck
docker compose exec -T ingress python3 /app/ingress.py healthcheck
docker image inspect arkpool-gateway:local --format '{{.Id}}'
docker compose ps
```

Use command exit status, not just an output keyword, to judge success. The first
command uses synthetic local traffic; the health checks do not contact the pool
or prove mining. `docker compose ps` shows this installation's listener address;
redact that address in public reports. Do not use container environment dumps
or expanded Compose configuration as evidence attachments.

If an earlier alpha retained an internal LAN network, follow the scoped migration
in `docs/TESTING.md`. That migration disconnects attached miners, so it requires
an authorized maintenance window. Never run Docker-wide cleanup.

## 5. Verify in layers

1. **Build:** the image builds successfully.
2. **Synthetic tests:** run the Docker test command in `docs/TESTING.md`.
3. **Readiness:** ingress and gateway are healthy; both Tor supervisors run.
4. **LAN path:** a private client reaches the published port and non-RFC1918
   sources are refused. In optional exact-IP mode, also verify an unlisted
   private client is refused. Confirm actual source addresses survive the path.
5. **Tor transport:** confirm a real pool subscription response through each path.
6. **Mining:** use an authorized separate worker, or an explicitly approved
   live-miner cutover with the safeguards below. Verify job delivery and a
   pool-accepted share using the confirmed Ark receive address.
7. **Recovery:** failure-test Tor paths only in that separate deployment. Verify
   subscriptions, then real accepted shares after reconnecting.
8. **Payout:** reconcile read-only pool/wallet evidence with the operator. Never
   claim or redeem funds to make a test pass.

Steps 1–5 do not prove steps 6–8. A live miner that must remain uninterrupted
stays on its current gateway and identity throughout evaluation.

For an approved live-miner cutover:

- Save the original miner settings privately and keep the old gateway intact.
  Confirm a usable rollback before writing anything.
- Read the complete Ark identity from the authoritative existing upstream
  configuration or the user's own wallet; compare it privately, never in
  chat, logs, commits, or sample files. A local worker alias is not the payout
  address when the old gateway rewrites authorization.
- Keep firmware, power/fan tuning, payout identity, and direct-fallback policy
  unchanged. Apply only the necessary endpoint and credential-field changes.
- Validate the new listener and both Tor subscription paths first. After
  reconnecting, compare the running miner's identity with the verified source,
  confirm actual source-IP preservation, fresh jobs, and resumed hashing.
- Notify the operator immediately once switched so they can monitor the pool
  backend. An old gateway's ledger will not count traffic that bypasses it;
  never add test totals to that ledger or imply automatic history migration.
- If using an approved timed rollback, record its deadline and cancel it only
  after the intended recovery checks pass. Do not leave a surprise rollback armed.
- Distinguish the miner reporting a pool-accepted share from independent
  operator-side reconciliation and from a completed payment. No claims or
  redemptions belong in this procedure.

The local Tor watchdog checks bootstrap readiness, not ongoing share delivery.
The gateway job watchdog separately detects missing jobs following authorization
or work and bounds session recovery. Neither proves share delivery or payment.
Use private telemetry and preserve a working miner when testing failures.

### Supervised transport-only updates

The unreleased [upgrade helper](UPGRADING.md) automates local backup, candidate
testing, image pinning and service-health rollback for supported deployments.
Read its compatibility limits; do not bypass a blocked configuration or treat
its JSON service result as proof of mining. Operator confirmation is mandatory.

When a reviewed change affects only gateway/ingress code, preserve healthy Tor
clients and their persistent state. Do not restart all four services by default.

1. Build and test a separately tagged candidate image. Record its exact image ID
   and source commit; retain the current image and deployment files privately.
2. Run the isolated synthetic suite on the target host. Check actual pool
   subscription responses through each Tor route with the candidate parser,
   without authorization, share submission, or disrupting existing sessions.
3. Inspect existing Compose overrides before adding anything. Prepare a scoped
   image override and rollback that restores only gateway and ingress. Keep the
   same listener, configured access policy, private configuration, and Tor volumes.
4. With cutover approval, recreate only gateway and ingress using
   `docker compose up -d --no-deps --no-build gateway ingress` with the reviewed
   configuration/override selected. This closes the current mining connection;
   allow for firmware-specific reconnect delays. Do not change firmware or tuning.
5. Verify the running image IDs, gateway network isolation, health, unchanged Tor
   container IDs/start times, fresh jobs, hashing, and a new accepted share.
   Miner counters can reset on reconnect even if device uptime does not: record
   the new session separately rather than subtracting incompatible counters.
6. Keep rollback available. If a timed rollback was armed, record and cancel it
   only after the required recovery checks pass. Continue observing connection
   stability beyond the idle-timeout window; do not infer continuity from hashrate
   alone. Record gateway connection/restart counters as well.
7. Record which source directory and image override are active. Do not rebuild
   from stale source or silently remove a pinned override during later updates.

This procedure is not permission to failure-test Tor paths on a working miner.
Forced-recovery share verification still requires a separate approved worker.

## 6. Report an evidence-based result

Copy [the JSON evidence template](acceptance.example.json) to an operator-approved
private working location **outside the repository**. Replace `not_run` only when
an actual observation supports `pass`, `fail`, or `blocked`; use `not_applicable`
only with a reason. `null` means unmeasured, not zero. Store UTC observation times,
the source revision and image ID, and separate before/after session counters.
Do not include wallet addresses, onion names, private IPs, passwords, or raw logs
in the record intended for publication. Keep detailed private evidence separate.

Use a short report such as:

```text
Revision: <verified commit>
Deployment: <new test deployment / authorized production deployment>
Build: PASS / FAIL / NOT RUN
Synthetic tests: <actual count and result>
LAN allowlist: PASS / FAIL / NOT RUN
Real Tor subscription: PASS / FAIL / NOT RUN
Failover: PASS / FAIL / NOT RUN
Accepted share through this gateway: VERIFIED / NOT VERIFIED
Eligible payout: VERIFIED READ-ONLY / NOT VERIFIED
Existing miner endpoint: UNCHANGED / <authorized cutover>
Payout identity: VERIFIED UNCHANGED / NOT VERIFIED
Safety rollback: NOT ARMED / ARMED WITH DEADLINE / CANCELED / COMPLETED
Remaining work: <specific outstanding checks>
```

Do not include a full Ark address, real onion hostname, `.env`, authentication
material, or wallet data in the report. Keep local configuration and Tor volumes
separate from source archives. The owner selected the [MIT License](../LICENSE)
for project code and documentation. Preserve its notice and dependency licenses;
do not present this alpha as a supported release before its validation gates pass.
