# Latest-development setup

Use this path when the operator requests the latest ArkPool Gateway development
version. Use a specifically requested release or revision instead when provided.

## 1. Resolve the current source

Create a fresh checkout outside any existing deployment:

```sh
git clone --branch main https://gitlab.com/arkpool/arkpool-gateway.git arkpool-gateway-dev
cd arkpool-gateway-dev
git fetch origin main
git switch --detach origin/main
git rev-parse HEAD
```

Record the full revision. If the destination already exists, inspect it first;
use a separate clean worktree or directory. Preserve local changes and private
configuration. Do not reset, clean or overwrite a working installation.

Read `MAINTAINING.md`, `README.md`, `SECURITY.md` and `docs/INSTALLATION.md` from that
same revision. A recent checkout is not proof that a running image is current.

## 2. Select the deployment path

| Target | Development source | Installation path |
| --- | --- | --- |
| Linux Docker | This repository's `main` | Follow the installation checkpoints; build the resolved revision |
| Umbrel | `arkpool/arkpool-gateway-umbrel`, branch `main` | Use its current manifest and immutable image index through Umbrel |
| StartOS | `arkpool/arkpool-gateway-startos`, branch `main` | Build the current native candidate with its pinned Gateway revision and SDK |
| Shhark integration | `PiHiker/shhark`, branch `shhark-main` | Follow its development, verified-backup and wallet-operation gates |

The platform repository's pin is authoritative for its package. Do not substitute
an arbitrary Gateway image, change its topology, or import an older release just
because it has a published tag. If a required candidate artifact is unavailable,
build and verify it through that platform's documented process; report a blocker
rather than silently installing an older version.

## 3. Build and verify

- Follow the source checkout's supported Docker or native packaging workflow.
- For a Gateway Docker build, supply `SOURCE_REVISION` as the full resolved
  commit and `SOURCE_VERSION` from `VERSION`; retain the resulting immutable ID.
- Use fresh package metadata and the current `runtime_packages.py` security
  floors. Do not accept an older image's bundled checks as current evidence.
- For an existing Docker deployment, follow `docs/UPGRADING.md`. Transport-only
  upgrades do not replace Tor; Tor maintenance has separate rolling checkpoints.
- Verify the actual running services with `gateway.sh version --json`,
  `gateway.sh security-check`, and the documented route/mining checks.
- On appliances, verify native package versions, actual Tor versions, both
  routes and dashboard access. A running container is not accepted-share proof.

## 4. Preserve existing installations

Latest development selects source; it does not bypass backups, pending wallet
operations, platform compatibility, access policy or operator authorization.
Preserve payout identity, Tor state, TLS identity, settings and miner failover.
Use a separate build/qualification environment before an authorized live update.
Do not create wallets, move funds, wipe data or restart hosts to obtain a newer
version. Report source revision, immutable image/package identity, actual Tor
version, completed checks and remaining limitations separately.
