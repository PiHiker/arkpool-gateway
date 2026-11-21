# Changelog

## Gateway security hardening — 2026-11-18

- Bound partial translated-miner requests independently of reverse-direction
  pool traffic, and release V1 connection slots that never authorize.
- Bound dashboard/status request handling and total miner-telemetry fetch time so
  slow clients or miners cannot indefinitely occupy the available workers.
- Cool a Tor route after an early upstream close and require real upstream bytes
  before considering the route recovered.
- Limit each source to two V1 sessions and add optional private source-to-Ark-
  account fingerprint pins for exact-IP installations.
- Clarify that HTTP miner API credentials can carry full management authority,
  even though the collector issues only bounded reads.
- These shared runtime changes require separate local Gateway, Umbrel, and
  StartOS qualification before publication or live package upgrades.

Reported through responsible disclosure. Public reporter attribution is omitted
pending explicit consent to publish a name or handle.

## Native V2 upstream silence recovery — 2026-11-17

- Close a native V2 session after ten minutes without upstream bytes, even when
  outgoing miner traffic continues. Only that session reconnects; other miners
  and both Tor clients remain running.
- Preserve end-to-end encryption and V2-only Tor routing. Transport activity is
  not proof of jobs, accepted shares or payment.

## Translator share-response recovery — 2026-11-17

- Reconnect a translated V2 session when forwarded shares receive no pool response for two minutes. Additional submissions or job traffic cannot conceal the stall.
- Keep idle miners connected when no replies are outstanding. Recovery preserves V2-only Tor routing, never replays shares, and leaves native V2 sessions and Tor clients running.

## Translated miner Tor paths — 2026-11-17

- Show the observed Tor A/B client on monitored V1 miner rows when current,
  verified translator sessions match that miner's configured binding.
- Leave the path unknown when matching sessions disagree; preserve existing
  freshness, account, source-address and gateway checks. No transport changes.

## Tor path labels — 2026-11-16

- Describe A/B counts by transport without assuming each transport has a separate
  pair of Tor clients. This also covers a single host sharing its Tor clients.

## Local gateway telemetry — 2026-11-16

- Let colocated native V2 relays supply bounded, freshness-validated route
  snapshots through a read-only volume. Avoid a separate route API listener
  and token when the collector shares the gateway host.
- Reject ambiguous local-plus-remote route configuration; unavailable snapshots
  remain unknown rather than reporting zero active sessions.

## Dashboard connection status — 2026-11-16

- Flag measured job ages over 180 seconds as waiting for work, even when a
  miner still reports a connection. Unknown job ages remain unavailable.
- Preserve the expanded gateway-connection details across telemetry refreshes.

## Dashboard layout — 2026-11-16

- Add a fleet overview with reported hashrate, connected miners, verified upstream
  protocol and observed active Tor paths. Keep unknown readings explicit.
- Refresh the layout with a larger chart, shaded measured totals, responsive
  miner rows and expandable gateway diagnostics. Preserve 24-hour history,
  15-minute samples and gaps; add no external chart dependencies.
- Add copy controls to displayed connection settings, with a selection fallback
  when browser clipboard access is unavailable.


## Dashboard: V1 migration help

- Make V1 badges open an accessible explanation of V2 benefits, compatible-miner
  setup and V1-to-V2 translation, with a shortcut to connection settings.
- Explain each protocol hop without changing mining settings or promising extra
  hashrate, blocks or payments.


## Dashboard: individual hashrates and inactive-miner expiry

- Add per-miner chart lines and current-rate legends beside the total, retaining
  15-minute samples, a 24-hour window and gaps for unavailable readings.
- Hide miners after 24 hours without valid telemetry; restore their table row
  and chart series on contact, preserving the remaining miners' identities.
- Use configured LAN addresses in the table and chart when the existing private
  dashboard address-display option is enabled; keep addresses redacted by default.
- Preserve existing total history and use a bounded persistent contact ledger;
  add no mining controls, listeners or third-party chart dependencies.

Release history and changes on the default development branch.

## Next release

Updated 2026-11-16. These changes are available on `main`; published container
images are identified by their exact source revision. This section does not
represent a new versioned Gateway release.

### Chart visibility

- Shade missing and partial history intervals with a subtle pattern and explicit
  labels. Keep gaps in measured lines; do not interpolate or invent hashrate.
- Give overlapping miner samples distinct markers and outlined edges.
- Let users select a miner in the chart legend to view its history on its own
  scale, then return to the combined view. Preserve selection and keyboard focus
  across live refreshes without changing sampling, retention or mining settings.

### CI publication

- Require an explicitly launched GitLab web pipeline on protected `main`, with
  `ARKPOOL_PUBLISH_IMAGES=1`, for both architecture builds and image publication.
  Ordinary pushes keep verification but no longer rebuild the Rust translator
  or publish images. Document the separate publication step and compute budget.

### Source packaging

- Include the latest-development and V2 migration guides in the explicit source
  release allowlist. Check the actual tracked tree so omitted documents block
  verification before a release attempt.

### Miner hashrate dashboard

- Verify translated miners' upstream V2 badges against an exact private binding
  and fresh authenticated gateway-job evidence; keep their local V1 badge and
  never imply miner-side Noise authentication.

- Keep physical miners in the main table; move transport rows into collapsed
  connection details and render partial observed hashrate as a distinct amber series.
- Add a lightweight total-hashrate chart using actual physical-miner observations,
  15-minute samples and a strict 24-hour / 96-sample retention limit.
- Persist bounded private history across collector restarts; show missing or
  partial readings as gaps instead of zeros or invented history.
- Add a fixed read-only summary/pools adapter and count each physical miner once;
  distinguish gateway connection rows from miner telemetry.
- Accept bounded, timestamped observations from an existing trusted monitor
  without expanding access to an isolated miner management network; show source age.
- Keep the existing authenticated dashboard API, inline SVG and isolated collector;
  no chart dependency, external script, new public endpoint or mining-control API.

### Native Stratum V2

- Add an explicit native V2 relay that preserves end-to-end Noise authentication
  and binary messages across the existing networkless, dual-Tor architecture.
- Race ready Tor routes within a bounded connection budget, close unused
  sockets, and record sanitized disconnect diagnostics.
- Bound connections globally and per source; isolate miners with opaque SOCKS
  credentials rather than exposing their addresses to Tor authentication fields.
- Require separate V2 receiver settings with no automatic V1 or clearnet
  fallback. Document migration and rollback policy, two-miner accepted-share
  evidence, outstanding reconnect diagnosis and separate V1 translator qualification.

### V1-to-V2 translator

- Label dashboard connections Miner 1, Miner 2 and onward without device-specific names.

- Disable SRI's unused monitoring/ASIC telemetry default feature in translator
  builds. The separate read-only gateway dashboard remains available.
- Clarify that V1 miners work through translator-enabled gateway builds without
  new miner firmware; distinguish functionality from package qualification.
- Mark the older Umbrel exporters as V1-only and direct V2 installations to the
  maintained appliance repository.
- Reduce CI disk use by removing compiler artifacts before saving image layers;
  require 8 GiB free before starting translator publication builds.
- Add a shared appliance runtime with separate native V2 and V1 compatibility
  listeners, strict private configuration and V2-only upstream connections.
- Keep native sessions running during translator recovery; enforce combined
  admission limits and preserve unknown encrypted share/job observations.
- Make the optional V1 translation identity explicit in setup; native-only
  installations no longer imply that V1 compatibility is enabled.
- Make dual-runtime health checks read-only and refuse unknown CLI arguments
  before opening or replacing sockets.
- Align translated-session capacity with the eight-session gateway budget and
  keep native-only per-route counters unavailable instead of showing zeros.
- Retain a non-mining readiness connection in appliance mode so an idle
  translator does not close its V2 channel; report translation readiness
  separately from Tor bootstrap. Existing standalone settings are unchanged.
- Add an optional isolated SRI runtime and pinned-source image build, preserving
  exact Ark identities and refusing mismatched V1 authorization/submission names.
- Open an authenticated V2 channel before admitting miners, retain Tor-only
  egress, and provide no V1 upstream fallback.
- Separate pool-confirmed V2 acknowledgments from local V1 success responses;
  add a read-only observer and redact upstream identity/job logging.
- Record accepted-share evidence from an authorized V1-miner trial with unchanged
  custom firmware. Appliance packaging has its own qualification gates.

### Protocol dashboard

- Highlight the preferred Native Stratum V2 setup card with a gentle green
  pulse; respect reduced-motion preferences with a steady green border.
- Give miner uptime its own column and condense Tor usage into a two-row
  summary, with listener and TLS information under Connection details.

- Show actual Tor A/B paths from native relay snapshots, with gateway-scoped
  path totals and unavailable states when metadata expires.
- Keep connection state separate from job freshness and provide generic,
  V2-first miner setup instructions.
- Support translated V1-to-V2 session badges and aggregate pool-confirmed
  counts without inventing per-session share allocations.

- Use neutral session labels by default; installation names are an explicit opt-in.
- Present native V2 and legacy V1 sessions together in one full-width table,
  with counter sources labeled per row and no inner horizontal scrollbar.
  Stack rows for narrow screens and move Tor/listener details below sessions.

- Show separate **Miner → gateway** and **Gateway → ArkPool** protocol badges,
  alongside a distinct V2 preference indicator and authentication state.
- Add opt-in native-miner observations for hashrate, accepted/rejected shares,
  job age and uptime, separate from legacy gateway process counters.
- Show a concise V1-only warning when current monitored connections use V1.
  Hide stale counters and never label a configured V2 primary as active V2
  while a miner uses V1 fallback.
- Keep read-only monitoring credentials in a separate collector; the web service
  receives only bounded, allowlisted snapshots. No mining control API is added.

### Security

- Patch the pinned translator lockfile to Tokio 1.53.3 and anyhow 1.0.103
  for RUSTSEC-2026-0386 and RUSTSEC-2026-0190. Gate the actual translator
  dependency graph to reject old versions or reintroduced monitoring stacks.
- Require Tor **0.4.9.17** or newer in build and runtime package checks.
- Enforce patched OpenSSL CLI/shared libraries and PCRE2 package minimums.
- Refresh Debian security packages during image builds and reject incomplete
  repository refreshes or pending runtime updates.
- Check running optional services alongside the required gateway services.
  Supply current package checks to older images so outdated bundled checks
  cannot hide a missing security update.
- Add disposable-image package audits without mounting credentials or state.
- Tighten private configuration ownership and public-source credential checks.

### Umbrel integration

- Publish the separate [Umbrel community package](https://gitlab.com/arkpool/arkpool-gateway-umbrel)
  with persistent Tor state, native client-policy settings and authenticated
  dashboard access.
- Initialize private socket-directory permissions during native startup.
- Use community ports 23333 and 23335 to avoid official app-port conflicts.
- Improve dashboard spacing for 1280×720 displays.
- Build and publish verified AMD64/ARM64 images and a combined immutable index
  from the default branch.

### Reliability and observability

- Clear retained Tor dormant mode at startup and verify authenticated network
  liveness alongside bootstrap completion.
- Bound Tor shutdown within the container stop window while preserving state.
- Distinguish fresh jobs, stale jobs, subscriptions and unverified pool paths
  in dashboard status.
- Publish bounded payout-identity fingerprints only after verified pool
  authorization; never display or retain the complete payout address.
- Add an optional authenticated, read-only status listener for Shhark.
- Report image versions and revisions without inventing missing metadata.
- Reuse route-specific SOCKS identities for subscription probes to reduce
  circuit churn while keeping probes separate from miner traffic.

### Installation and maintenance

- Add explicit latest-development setup with exact source revisions,
  platform image pins and running-version verification.

- Validate the listener's IPv4 subnet and warn about Docker/VPN overlap.
- Include the optional Shhark listener in port-conflict checks.
- Preserve the documented client-IP privacy setting during maintenance.
- Avoid false rollback caused by Docker representing unset DNS as `null`.
- Remove unused mount utilities from runtime images.
- Direct StartOS installations to the separately maintained native package.

### Validation

- Verified AMD64 Umbrel installation/update, app-data recovery, authenticated
  dashboard access and a bounded Bitaxe trial with accepted shares.
- ARM64 images are built and verified; ARM appliance installation, forced-route
  recovery and independent payment verification remain outstanding.
- See [testing details](docs/TESTING.md) and the platform repositories for
  package-specific qualification.

## 0.1.2-alpha.1 — 2026-10-11

This is an **alpha source version**, not a stable binary release. It adds the
privacy, listener-scope, runtime-image, diagnostics and guidance changes below
to the `0.1.1-alpha.1` security-update base.

### Private listener scope

- Default new installations to an explicit RFC1918 subnet instead of all private
  IPv4 space. Keep existing `lan` and exact-IP policies compatible, and enforce
  the same policy independently in ingress and the networkless gateway.

### Tor stream isolation

- Enable Tor `IsolateSOCKSAuth` and use process-local pseudorandom credentials
  per miner by default. Keep probes on one-use credentials and provide explicit
  per-session or shared modes without logging or persisting isolation tokens.
- Show the configured stream-isolation policy on the authenticated appliance
  dashboard without exposing miner addresses, SOCKS credentials or circuits.

### Runtime image and build verification

- Move full Python tests into a separate Dockerfile test target, remove the
  blanket distribution upgrade, and keep only a production invariant self-check
  in the runtime image. Add a GitLab job that builds and executes both targets
  under read-only, networkless restrictions.

### Gateway resilience and diagnostics

- Count a Tor route retry only when the gateway actually attempts another
  eligible route, avoiding false fallback-churn metrics in single-route states.
- Report gateway health as unavailable while every heartbeat-ready Tor route is
  in connection cooldown, instead of presenting an unusable path as healthy.
- Expose a sanitized admission summary that distinguishes usable routes, route
  cooldown, and loss of Tor readiness without revealing destinations or clients.
- Add process-scoped per-route active-session, job, submission and share-outcome
  counters to private telemetry and the authenticated appliance dashboard.
- On orderly shutdown, stop admission first and wait up to five seconds for
  already-forwarded share replies; never retry or replay a mining submission.

### Validation status

- Pass the complete 210-test host suite, shell validation and public-source
  screen.
- Pass all 103 transport/TLS tests in an isolated hardened container running as
  a non-root user with no network, a read-only root filesystem, dropped
  capabilities and `no-new-privileges`.
- Keep local deployment, real-miner recovery, pool accounting and payout
  evidence as separate operational checks; the source and container tests do
  not establish those outcomes.

### Installation and setup guidance

- Make Linux Docker Engine with Docker Compose v2 the recommended installation
  path in the README, setup example and installation guide. Keep Podman and
  appliance packaging clearly optional and subject to their documented
  experimental or blocked status.

## 0.1.1-alpha.1 — 2026-10-08

Cumulative source changes since `0.1.0-alpha.1`, including the previously
unversioned updates below. This is an **alpha source version**, not a newly
qualified stable download. Existing archives and running installations are not
changed by a source push. See [upgrade guidance](docs/UPGRADING.md) and
[verification and remaining release gates](docs/TESTING.md).

### Security and privacy

- Require **Tor 0.4.9.14 or newer** and Debian PCRE2 `10.46-1~deb13u3` or newer.
  Use a digest-pinned Debian 13 runtime; reject images below reviewed minimums.
- Obtain Tor from Tor Project's signed Debian 13 repository. Verify the archive
  key fingerprint, scope trust with `Signed-By`, and restrict that repository
  to Tor packages. Other runtime packages continue to come from Debian.
- Check all four services with the read-only `security-check` command.
  Tor clients still need separate, one-at-a-time maintenance preserving state.
- Reject deeply nested or ambiguous JSON before forwarding, including duplicate
  and case-aliased keys that could bypass redirect filtering. Preserve valid
  wire bytes and operator-supplied payout identities.
- Add optional LAN TLS, per-installation certificates, pairing export and
  in-place certificate renewal. Preserve the networkless gateway and Tor-only
  upstream paths; plaintext remains the default local listener.
- Prefill the public ArkPool Tor endpoint for new installs and default to
  private RFC1918 clients. Preserve existing exact-IP policies and settings.

### Mining reliability and observability

- Share idle activity across forwarding directions so incoming jobs keep quiet
  miners connected. Retain incomplete-frame, blocked-write and size limits.
- Apply bounded cooldowns to failed Tor routes without disrupting healthy
  sessions. Limit stale-job recovery to three closures per hour and require an
  alternate route; infrequent shares alone do not trigger recovery.
- Track private, process-scoped job/share counters and acknowledgement timing.
  Account for unanswered or ambiguous submissions without replaying work.
- Add **opt-in** initial-connection route preference using bounded subscription
  tests, recent success rates and median response times. Round-robin remains the
  default; preference never moves an established mining session.

### Dashboard and experimental platforms

- Add a compact, read-only shared appliance dashboard for job freshness, Tor
  paths, listener/TLS status, sessions and observed share responses, including
  pending/unclear outcomes and route-test timings.
- Keep snapshots bounded, sanitized and one-way, with counter-reset and stale
  warnings. No miner identities, wallet access, earnings estimates or controls.
- Improve responsive layout, keyboard access, status labels and ArkPool.org links.
- Add no-overwrite offline exports and **experimental** rootful Podman Quadlet
  and Umbrel packaging with immutable-image requirements and preserved isolation,
  listener policies and Tor/TLS state. Umbrel uses authenticated browser routing.
- Add opt-in authenticated Unix Tor control for isolated appliance development.
  Native StartOS packaging remains blocked pending release qualification.
  These changes do not establish supported appliance/store releases or widgets;
  the default Docker deployment does not automatically enable the dashboard.

### Upgrades, testing and documentation

- Add confirmed, settings-preserving transport upgrade/rollback commands with
  private backups, immutable image selection, isolated checks and recovery records.
  These commands do not automatically upgrade the two Tor clients.
- Fix false Compose 2.26.1 configuration-drift errors after `--no-deps`
  recreations while retaining checks on configuration, isolation and image pins.
- Add GitLab verification, required regression coverage for transport, packages,
  upgrades, platforms and dashboard behavior, and operator-friendly setup/maintenance
  guidance. Always check CI for the exact commit rather than a previous revision.
- Enforce an explicit public-source packaging allowlist. License project code
  and documentation under MIT while retaining upstream acknowledgments.
- Keep accepted-share evidence separate from payment verification. Forced-recovery
  mining and independent payout reconciliation remain release gates.

## 0.1.0-alpha.1

- Initial versioned alpha source bundle with an explicit file allowlist,
  deterministic archives, commit/file manifests and SHA-256 checksums.
- Read-only local preflight with human-readable and JSON results, explicit
  review/block exit codes, and no pool, miner or wallet operations.
- Automated transport/release-tool tests and a Forgejo workflow for an
  operator-provided isolated runner.
- Deployment-neutral, operator-friendly installation, cutover and evidence guides.

This historical release changed release tooling, not transport. Its separate
per-direction idle timeout, lack of share telemetry/watchdogs and original
license state describe that archive only; later changes are listed above.
Existing alpha.1 archives have not been rewritten.
