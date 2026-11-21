# Settings-preserving transport upgrades

This alpha helper updates **gateway and ingress images only**. It does not
update Tor, migrate network topology, change a miner, operate a wallet, or prove
accepted shares. Use a maintenance window: recreating transport services briefly
disconnects miners. Do not deploy an unreviewed image just because it passes its
own tests.

## What is retained

- `.env` bytes, permissions and modification time are unchanged.
- Existing `compose.yaml` and one standard `compose.override.yaml` or
  `compose.override.yml` are retained, including custom settings and limits.
- The exact LAN listener, allowlists, pool configuration, environment, mounts,
  resource limits and effective container settings must match after cutover.
- Both Tor containers and their state volumes are left running.
- The helper never reads or changes miner payout settings. The gateway's
  byte-preserving protocol behavior is covered separately by transport tests.
- Exact old image IDs, private configuration backups and resolved models remain
  available for rollback. Do not prune images or delete upgrade state.

## Tor and OS security updates

`upgrade` remains transport-only. It **does not patch the running Tor clients**.
Use `./gateway.sh security-check` from current reviewed source after an update;
it checks all four required services and running optional services against the
host checkout's package floors without changing the containers. Then run
`./gateway.sh security-audit` to compare one disposable copy of each deployed
image with current package indexes. The audit mounts no configuration, socket,
identity or state, but it does contact the configured Debian/Tor repositories.
The current checker is supplied on standard input; an old image's bundled
minimums cannot mask a newer requirement. Missing required services, inventory
failures, or unsupported optional runtimes fail closed. Package currency is
still not a complete CVE or application-security audit.

For existing installations, prepare a separate reviewed image, verify its
package versions and run the isolated tests first. The October 2026 image moves
to Debian 13 to obtain the patched Tor and PCRE2 packages from Debian security.
Version `0.1.1-alpha.1` obtains Tor 0.4.9.14 or newer from Tor Project's signed,
package-scoped Debian 13 repository; the PCRE2 security floor remains unchanged.
The host OS/repositories need not change. Do not replace `.env` or discard custom settings.

Updating Tor requires a separately approved maintenance operation, not a blind
rerun of `up` or removal of managed pins. Record current image IDs and effective
Compose files, privately back up state with an appropriate consistent backup,
and retain rollback images. Recreate only one Tor service at a time with the
reviewed immutable image and the **same existing state/socket volumes**. Verify
bootstrap and a real onion subscription on that route before proceeding to the
other. An active miner session on the replaced route can disconnect and must
reconnect; redundancy is not seamless session migration or zero downtime.
Do not stop both clients, delete volumes, or weaken routing to force recovery.
Verify fresh mining jobs and accepted shares separately after maintenance.

The automated transport rollback does not cover Tor image/state changes. Stop
and investigate if the candidate cannot read preserved state; do not assume
an older Tor image can safely consume state rewritten by a newer version.

The initial helper targets the four-service Linux Docker/Compose deployment.
It explicitly uses the local Docker Unix socket. Alternative Compose filenames,
extra services, ambiguous override files, symlinked configuration, nonliteral or
extra `.env` keys, configuration drift, or missing/unhealthy services are blocked
for operator review. It does not silently repair or discard unsupported settings.
Deployments started with a different project name or external `COMPOSE_FILE`
list need a separately reviewed migration; do not rename them to bypass checks.

Compose 2.26.1 includes dependencies in its configuration hash, but `up --no-deps`
can prune that graph before labeling a recreated container. This can cause a
false `deployment_config_drift` on a later upgrade. The helper recognizes this
specific recorded version for gateway/ingress only: it checks the unchanged
stock dependency graph, reconstructs the exact subset recorded in the container's
dependency label, and requires Compose's recalculated hash to match. The private
resolved model is sent on stdin without a second interpolation pass or disk copy.
The full original model remains intact for upgrade and rollback. All other
settings remain hashed; custom dependency changes, missing/malformed evidence,
other unverified versions and mismatches still require review. Do not remove
dependencies, rewrite labels or bypass drift checks to make an upgrade proceed.

## Prepare a trusted candidate

Keep the existing installation and private configuration in place. Obtain the
reviewed helper files from a verified source revision; do not extract a whole
archive over an existing deployment or replace its settings to install tooling.
The helper's host files are `gateway.sh`, `upgrade.py`, `preflight.py`, and
`gateway.py` and its `route_quality.py` dependency (configuration validation).
Review/back up
existing source files first. Host Python 3.10+ and local Docker access are needed.

Build the candidate from reviewed source in a **separate** directory/tag:

```sh
docker build --build-arg SOURCE_VERSION="$(sed -n '1p' VERSION)" \
  --build-arg SOURCE_REVISION="$(python3 -B deployment_version.py --build-revision)" \
  -t arkpool-gateway:candidate .
docker image inspect arkpool-gateway:candidate --format '{{.Id}}'
```

Use the complete returned `sha256:...` image ID below, not a mutable tag. The
helper does not pull or build an image during cutover. Retain the old images.
Check the candidate's source identity and trust separately; a local ID proves
which image is used, not that its code is trustworthy.

Run these build commands from the separate reviewed source checkout. Builds
from a dirty checkout report an unknown revision. After updating, compare the
running services using `./gateway.sh version --json --expected-revision SHA`.
Tor may intentionally retain an older revision after a transport-only update.

This release also gives every miner session its own Tor SOCKS authentication
token. Existing installations receive that isolation when gateway/ingress are
upgraded to the new image; retained Tor state and miner settings do not need to
be replaced. The two Tor clients still share the host and internet connection.

## Upgrade with explicit approval

From the existing deployment directory, using the deployment owner account:

```sh
./gateway.sh upgrade --image sha256:FULL_IMAGE_ID --confirm-interruption --json
```

Without `--confirm-interruption`, the helper refuses before filesystem or Docker
actions. With confirmation it takes an exclusive lock, validates the running
deployment against Compose's configuration hashes, and saves mode-0600 backups
under the private mode-0700 `.arkpool-upgrade/` directory. Keep this directory
outside every handoff, commit and distribution archive.

It runs the candidate's production self-check in a resource-limited, read-only,
networkless disposable container with **no production mounts or environment**.
Full tests are built and run from the separate Dockerfile `test` target in CI;
the production image intentionally contains no test suite.
It rechecks settings and running containers before changing the two image pins.
Only gateway/ingress are recreated, with no build/pull, dependency restart or
volume deletion. Failed startup, health or settings checks trigger an attempt
to restore the old images. Recovery failure is reported explicitly, not as
success.

After success, verify real source-IP preservation, fresh jobs, hashing and a new
accepted share. `services_healthy_verify_mining` deliberately does not certify
mining or payment. There is no automatic miner restart or payout action.

## Status and rollback

```sh
./gateway.sh upgrade-status --json
./gateway.sh rollback --confirm-interruption --json
```

Status reads the saved transaction only; use `./gateway.sh status` for current
container state. Manual rollback also interrupts transport and preserves
settings. If an operator edits configuration after the backup, rollback refuses
to overwrite it and requires manual review. A failed later candidate test does
not erase the last successful upgrade's rollback target.

Exit `0` means the requested service operation completed (or was already done),
`1` means blocked/failed and may require manual recovery, and `2` means the
upgrade failed but automatic rollback restored healthy previous services.
JSON always includes `mining_verified: false` and `payout_verified: false`;
`runtime_change_attempted` distinguishes cutover/recovery from only local tests
or backup creation. Output excludes settings, addresses and raw command errors.

## Important operational limits

- Always use `gateway.sh` afterward: it includes the persistent image-pin file.
  Bare `docker compose` does **not** include that extra file and can select old
  images. `gateway.sh up` refuses while managed pins exist; use `upgrade` instead.
- Keep the original deployment source and candidate source provenance recorded.
  The helper changes images, not the host's source checkout or version file.
- Automatic rollback runs in the foreground process. It is **not a system
  watchdog** and cannot guarantee recovery after power loss, SIGKILL, daemon
  failure or a second interruption. Persistent pending/rolling-back records block
  another upgrade; inspect them and run an approved rollback after recovery.
- Do not run raw Compose commands or edit configuration concurrently. The lock
  coordinates this helper, not arbitrary external administrators.
- Docker tests verify service behavior with synthetic fixtures, not a complete
  firmware compatibility matrix, actual Tor failover shares or payouts.

## Adding optional TLS

TLS is off by default. An image-only upgrade on an existing plaintext deployment
keeps that behavior. The new image still runs without a TLS volume or extra port.

Enabling TLS on an existing deployment requires the new `compose.tls.yaml`,
`TLS_ENABLED=1` in `.env`, and a matching reviewed image. This publishes another
port and mounts a new private identity volume on ingress. It is a topology change,
outside the settings-preserving image-only upgrade operation. The helper must
continue to refuse configuration drift; do not discard an active image pin or
bypass that check. Back up the existing source/settings/pin and prepare a separate
TLS-enabled deployment with different ports, or schedule a backed-up migration.

Only recreate or redirect a working deployment during an approved migration.
Check source-address enforcement and certificate verification on the actual LAN
before moving the miner. Existing plaintext miners can keep using the original
gateway while the isolated TLS deployment is tested. Keep both Tor state and the
new TLS identity volume. Disabling TLS removes the listener via the topology
update but must not delete its identity; re-enabling should retain the paired CA.

## Changing Tor route policy

An image-only update with no `TOR_ROUTE_POLICY` setting keeps round-robin
selection and does not start probes. The new source's Compose profile passes
the setting only to the gateway; adding it to old source/configuration is an
explicit settings change, not an image-only upgrade. Do not bypass drift checks
or discard a managed image pin. Back up the actual configuration and images,
rehearse on an isolated deployment, then schedule a reviewed gateway-only
configuration update with rollback. Changing policy requires a gateway restart
and briefly disconnects its miners; Tor/ingress and their identities need not
be recreated. Keep the listener, source policy, pool destination and payout
identity unchanged. Reverting to `round-robin` stops future probes after the
approved restart. Measurements are transient and need no state migration.

Appliance adapters use their native update procedure, not this Docker helper.
The shared gateway accepts the same environment setting on all platforms;
native StartOS distribution/qualification remains separate work.
