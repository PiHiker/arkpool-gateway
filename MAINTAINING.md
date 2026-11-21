# ArkPool maintenance instructions

Read `README.md`, `SECURITY.md`, and `docs/INSTALLATION.md` before deployment work.
Read `docs/TESTING.md` before interpreting test results or changing transport code.

For normal installations, use Linux Docker Engine and Docker Compose v2 as the
default deployment path. Use Podman or appliance packaging only when the operator
explicitly selects it, then follow `docs/PLATFORMS.md` and its current limits.

For installation, follow the ordered checkpoints in `docs/INSTALLATION.md`.
See its command/result contract and safe-resumption checklist. Do not invent
runtime JSON status commands or repeat a cutover after a conversation restart.
Use `docs/acceptance.example.json` as a sanitized evidence template; never mark
an unperformed check as passed. Keep deployment-specific records outside Git.

## Latest development

When the operator asks for **latest**, **latest dev**, or **current development**,
use the current default branch, not an old release link, cached checkout or
previously downloaded image. Resolve that branch to an exact full commit before
building and record the revision in the result. Development source is not a
stable release and must not be presented as one.

For this repository the default branch is `main`. Follow
[latest-development setup](docs/LATEST_DEVELOPMENT.md), then the normal
[installation checkpoints](docs/INSTALLATION.md). A request for a named release or exact
commit takes precedence over this development-track selection.

## Required invariants

- Preserve existing mining by default. Build and failure-test in a separate
  deployment. Redirect an existing miner only with explicit operator approval
  for a live trial or migration, a private settings backup, and a rollback plan.
  Announce the actual cutover once new job delivery is verified. A live-trial
  approval does not authorize destructive Tor failure tests on that miner.
- Do not generate, replace, normalize, shorten, or infer a payout identity.
  The Ark receive address belongs to the operator and must pass unchanged.
  If an address is missing, explain the README wallet walkthrough and official
  Bark mainnet guides. The operator creates and backs up their own wallet;
  gateway setup does not authorize wallet creation or access to its backups.
  An `ark1` prefix alone does not prove pool compatibility or wallet custody.
- Never claim, redeem, send, or withdraw funds as a setup or verification step.
- Never commit or print `.env`, credentials, wallet data, Tor state, or keys.
  Keep private onion hosts and installation-specific IPs out of example files.
  The owner-approved public ArkPool endpoint in `.env.example` is the only
  publication exception; do not replace it from chat fragments or print private
  deployment configuration. The same reviewed public endpoint may appear in the
  generated `arkpool-gateway/docker-compose.yml` community package; the public
  source checker permits only that exact endpoint. No invitation is required.
- Keep the gateway on `network_mode: none`. Its upstream paths are Unix sockets
  to the two Tor clients. Do not add a TCP, DNS, or direct-internet fallback.
- Enforce the configured client policy at both ingress and gateway. New installs
  default to RFC1918-only LAN access (`MINER_IPS=lan`); exact-IP restrictions remain
  supported. Preserve existing policies on upgrades. Never allow public clients,
  trust miner-supplied source headers, or broaden access to work around NAT.
- Preserve Tor volumes and guard state. Do not use `docker compose down -v`,
  volume pruning, or Docker-wide cleanup during installation or upgrades.
- Never report a healthy container, subscription response, or synthetic test as
  proof of an accepted share or payout.

## Development workflow

1. Inspect the worktree and preserve unrelated changes. Use a focused branch.
2. Make the smallest change that fixes the observed behavior.
3. Run `python3 tests.py` for transport changes, then the isolated Docker suite
   in `docs/TESTING.md` when the image, Compose topology, or runtime changes.
   For release/preflight changes, read `docs/RELEASING.md` and run
   `python3 -B scripts/check.py`. Never claim a workflow passed merely because
   its file was committed; verify the actual runner result separately.
4. Test actual LAN access after networking changes; container-only tests missed
   the original internal-network port-publishing bug.
5. Keep user instructions in the README. Put detailed test evidence and pending
   release checks in `docs/TESTING.md`.
6. Inspect explicit staged paths for secrets before committing or pushing.
7. Report completed checks separately from outstanding mining/payout validation.

Do not change the MIT project license, publish externally, change router/firewall
policy, or configure a live miner without the operator's applicable authority.
Honor existing authorization; do not ask repeatedly for the same permission.
