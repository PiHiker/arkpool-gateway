# Developer testing

## Platform packaging status note

The dated StartOS candidate records below describe what was true during those
tests. The native StartOS 0.4 package was subsequently published in the separate
[arkpool-gateway-startos repository](https://gitlab.com/arkpool/arkpool-gateway-startos),
where its current release evidence, checksums, security policy and remaining
limitations are maintained. This repository's exporter still emits no `.s9pk`;
its non-zero compatibility-report exit must not be mistaken for package failure
or installation evidence.

## Current verification

### November 18 local security candidate qualification

Gateway revision `e14cd997a77c77a8cedb7e07745f2f25fae0f51b` passed
233 isolated runtime tests. Additional networkless checks passed 105 transport
and preflight cases, 16 TLS cases, and 34 package and platform cases. Tests ran
with read-only source, no network, bounded resources and disposable storage.

The same revision then ran for 60 minutes on the local Gateway appliance. All
57 monitoring samples completed without an observation error. Pool-confirmed
translated accepts increased from 24 to 302, jobs increased from 11 to 155,
the maximum pending count was four and the final pending count was zero. Both
native V2 miners and the translated V1 miner continued hashing. Candidate
services did not restart, Tor client start times remained unchanged, and free
appliance storage remained 5.79 GiB. No host, appliance or miner was rebooted.

Test-only Umbrel runtime and translator images built from the same revision
passed 233 runtime tests and 13 package tests, and their local Compose candidate
resolved successfully with platform injection represented by a local stub. A
corrected test-only StartOS image, whose embedded source revision and filesystem
ownership match the candidate, passed 233 runtime tests and 11 focused package
tests. These tests qualify local candidates only: no live Umbrel or StartOS app
was changed, no signed StartOS package was produced, no public registry image or
GitLab commit was published, and no payment result was established. Each package
must still pin a published immutable candidate and complete its own native
install, upgrade and miner trial before release.

### November 17 native upstream silence recovery

The isolated, networkless Docker suite passed 225 tests. New regressions verify
that outgoing traffic cannot hide a silent pool, incoming bytes refresh the
deadline without miner submissions, and timed-out sessions close both sockets
and release admission capacity. The ten-minute production deadline is shortened
only in synthetic tests. These checks do not establish live failover or payment.

### November 17 translator response watchdog

The isolated Docker suite passed 222 tests, including nine share-progress and
watchdog regressions. A synthetic stalled child verifies that the runtime closes
translated admission and terminates the child for supervised recovery. Other
cases cover continuing outgoing traffic, fresh jobs, malformed/zero-count
responses, batched and partial acknowledgments, rejection responses, quiet
miners, and watchdog cancellation. Tests use no real pool, miner or credentials.
These checks do not establish live recovery or payment; verify fresh pool
acknowledgments after deploying the reviewed image.

### November 16 dashboard layout and status checks

The dashboard, miner-status and history suites passed 53 checks. Browser checks
covered widths 320, 390, 768, 1100 and 1440 pixels without horizontal page
overflow, per-miner chart selection, V1 help, connection-setting copy feedback,
and expanded connection details surviving refresh. Synthetic stale-work and
stale-telemetry responses verified attention labels and removal of old totals.
No JavaScript page exceptions occurred. These UI checks do not establish mining
recovery, pool accounting or payment.

### November 16 combined V2 runtime checks

The shared appliance runtime passed 305 offline checks across 13 suites,
including bounded configuration, source admission, native/translated snapshots,
and supervisor recovery. Isolated Docker checks ran without networking, with
read-only filesystems, dropped capabilities and bounded memory/PIDs. A real
pinned SRI binary parsed the generated appliance TOML in a networkless container;
that parser check does not establish receiver authentication or an accepted share.

Recovery checks cover V1 disconnection while native sessions remain connected,
child/grandchild cleanup, oversized log draining, and upstream readiness loss.
Browser checks display distinct V2/V2 and V1/V2 badges and leave encrypted or
unallocatable per-session counters unavailable. Package installation and mining
qualification remain separate entries in the StartOS and Umbrel repositories.

A separate networkless receiver canary exposed idle-channel teardown after the
readiness probe disconnected. Retaining that non-mining connection kept a single
authenticated V2 channel healthy across two 60-second variable-difficulty ticks.
No miner was attached and no share was submitted during this check; it does not
replace appliance mining qualification. Standalone translator behavior remains
unchanged unless its explicit keepalive option is enabled.

### November 13 community-package qualification

The new generator uses only public defaults and a reviewed registry digest.
Host checks cover interface ambiguity, public/VPN interface rejection, subnet
policy, package reproducibility, registry architecture/revision/digest binding,
and removal of authorization headers on cross-host registry redirects.

Both native amd64 and arm64 image jobs executed the isolated transport/TLS/UI
suite successfully. The combined image was anonymously inspected and pulled by
the amd64 Umbrel lab. CI execution on ARM does not establish an ARM appliance
installation test.

A separate qualification app on umbrelOS 2.0.1 completed a clean native install
after correcting Tor socket directory permissions. HTTP and HTTPS browser checks
passed authentication, denial of four anonymous routes, current sanitized status,
and absence of JavaScript errors. HTTPS testing accepted the lab's local server
certificate; it is not a public-PKI certificate validation claim. Native app
settings applied the selected policy to both ingress and gateway. The native
update lifecycle preserved those settings and a data marker. This was a package
metadata version update, not migration from the old operator-specific exporter.

The final runtime revision `d4697372d0367d3bb942b0d8860032f4a456a41c`
passed [GitLab pipeline 3064286313](https://gitlab.com/arkpool/arkpool-gateway/-/pipelines/3064286313),
including both native architecture jobs and multiarchitecture publication. The
community package pins the anonymously inspected OCI index digest
`sha256:3c9545969d5f5d459d288d1a6e7534072bd9b1d255e02d7a71845256ce965681`.
A subsequent native update installed this image on all five application services,
preserved both selected client policies and the data marker, and passed HTTP/HTTPS
browser checks. The dashboard now fits the tested 1280-by-720 desktop viewport.
All 255 host tests passed; the regenerated package passed its 20 platform tests.
The final image also passed the GitLab-realm-compatible linter described below.

A stopped application-data backup was extracted and checked against all 23
saved regular files. Restored file ownership and modes also required preservation;
after restoring that metadata the app resumed. This verifies an app-data recovery
exercise, not Umbrel's whole-OS backup service or cross-device recovery.

The stock upstream linter passed static package checks but rejected GitLab's
separate `https://gitlab.com/jwt/auth` token realm during image verification.
A local compatibility patch permitting only that exact HTTPS realm for
`registry.gitlab.com` passed image and full official-store port-conflict checks,
with five intentional `no-new-privileges` warnings and no errors. This is not an
unmodified upstream image-linter pass or official store approval.

A bounded Bitaxe 403 trial through the final community package's private-LAN
plaintext listener verified fresh jobs, the operator-supplied Ark account
fingerprint, and three correlated pool-accepted shares with no rejected shares.
Observed one-minute hashrate was approximately 656–694 GH/s. The authenticated
browser simultaneously showed the real session and accepted work without exposing
private fields. The isolated app used a distinct app ID and non-conflicting lab
ports; the distributed package uses ports 23333 and 23335.

The trial restored the original Umbrel TLS primary and DATUM secondary, verified
unchanged pool settings and tuning, and removed its temporary miner slot and
exact firewall allowance.

The overnight TLS operator export remains a separate deployment. Pool-side
boost/accounting checks, payment verification, forced-route recovery and ARM
appliance installation remain outstanding; no wallet operation was performed.
These results support an alpha community package, not a supported-release or
payment claim. Community-store URL registration is a separate distribution check.

### November 12 Umbrel release qualification

An amd64 Umbrel lab was upgraded through the native OS updater to umbrelOS
2.0.1. Gateway source `b90ad4311776db0cdd6e7b1d83b3e1e9adced18a`
passed 250 host checks and 143 isolated container checks. A fresh runtime image
was installed in the existing lab app and started through Umbrel. This was an
image replacement, not a native app-store update or fresh-install qualification.
Tor state and TLS identity file hashes were preserved across the OS update.

Authenticated browser checks verified current gateway/ingress snapshots,
redaction, no JavaScript errors, denial of four anonymous routes and denial of
the raw UI port. At a 1280 by 720 viewport the page measured 749 pixels high;
the one-screen layout check therefore failed. A trusted-CA TLS connection and
real pool subscription succeeded. Both Tor routes reported successful probes.

The first authorized Bitaxe 403 trial did not establish an Umbrel mining session.
The miner used its original gateway as fallback while the lab gateway recorded
no miner connection. The routed miner network lacked the required lab-listener
firewall exception. The bounded trial restored the original pool selections,
removed its temporary profile, verified unchanged pool entries and tuning,
and confirmed fresh jobs on the original TLS gateway. No firewall rule was
changed during this attempt. This is a blocked mining test, not an accepted-share
or payout result.

After explicit approval of a single-miner TLS firewall exception, a second
trial established fresh jobs and verified the gateway account fingerprint against
the operator-provided trial address. Gateway telemetry correlated one accepted
share and zero rejected shares while the miner reported approximately 647 GH/s.
The bounded trial then restored the original pool entries, selections and tuning,
removed the temporary miner profile and confirmed fresh work on the original
TLS gateway. The narrowly scoped firewall allowance was retained at the operator's
request for continued testing. Pool accounting, the promotional boost and payout
remain unverified; none is implied by the accepted share.

Before a distributable Umbrel release, complete:

- Independent pool accounting and boost verification where claimed, plus
  accepted-share qualification of the final distributable package.
- Generic first-run configuration without publishing an operator-specific export.
- Public digest-pinned images for amd64 and arm64, with declared execution coverage.
- Store lint, native fresh installation and app update, HTTP/HTTPS browser access,
  restart persistence and backup/restore checks.
- Resolution of the dashboard overflow and reviewed, sanitized release evidence.

Until these gates pass, retain the experimental/alpha label. A GitLab branch or
source prerelease does not establish official Umbrel store acceptance.

### November 10 optional-service security checks

The complete offline suite passed **250 tests**, including regressions for
optional-service package failures, required services missing from discovery,
inventory failures, and delivery of the current host checker to both live
checks and disposable-image audits. The audit still deduplicates shared images
and mounts no deployment configuration, identity, socket or state.

These checks do not update containers or prove live mining, payout delivery, or
a complete vulnerability scan. Runtime package checks require current reviewed
host tooling; an old checkout cannot know future security minimums.


### Hash-only Ark account handoff candidate

On October 14, 2026, all **232 host checks** passed, including 98 transport,
15 TLS, 27 release/preflight, 39 upgrade, 12 package-security, 16 platform and
25 dashboard tests, plus shell syntax and the public-source policy screen.
Regression coverage validates Bech32m Ark addresses, derives the expected
SHA-256 fingerprint only after a correlated successful authorization, refuses
malformed, failed and ambiguous authorizations, and never retains the address.

The hardened test image passed all **138 transport/TLS/dashboard tests** as
non-root with networking disabled, a read-only root filesystem, dropped
capabilities and `no-new-privileges`. Image:
`sha256:9a9883616ccfad000a7e3609426178a15a556cc65708bc8fd479d1fbf618a6bb`.
The build reused the cached reviewed package layer and is not a fresh package
update audit. These synthetic checks do not establish live deployment, share
delivery, pool accounting or payment.

### Gateway resilience improvements candidate

Five focused changes improve failure visibility and maintenance behavior:

1. Fallback counters advance only when another Tor route is actually attempted.
2. Health becomes unavailable when all heartbeat-ready routes are cooling down.
3. Private telemetry distinguishes ready, cooldown and Tor-unready admission.
4. Sanitized per-route session, job and share-outcome counters support diagnosis.
5. Orderly shutdown allows up to five seconds for in-flight share replies, with
   bounded cancellation and no submission replay.

On October 9, 2026, all **210 host tests** passed: 88 transport, 15 TLS, 24
release/preflight/export, 39 upgrade, eight package-security, 16 platform and 20
dashboard tests. Shell syntax, diff checks and the public-source policy screen
also passed.

A separately tagged candidate image passed all **103 transport/TLS tests** as
non-root with networking disabled, a read-only root filesystem, dropped
capabilities and no-new-privileges. Image:
`sha256:c8148b3f14260f8ce0a7289c26b1cfcf1c4d9f54199d2c7ffd88e32fb635cb70`.
The build reused the cached reviewed package layer, so this was not a fresh
package-update verification.

No live gateway, miner, Tor state, payout identity or wallet was changed. These
synthetic checks do not prove production rollout, real share delivery after
failure recovery, pool-side accounting or payment.

### October 8 Tor 0.4.9.14 security maintenance

The `0.1.1-alpha.1` source passed **202 local offline tests** (82 transport,
15 TLS, 24 release, 39 upgrade, eight package/repository, 16 platform and
18 dashboard). The initial restricted-sandbox run could not create synthetic
Unix sockets; the complete rerun with socket permission passed without skips.
The public-source screen and diff checks passed. The local Quadlet generator
was unavailable; its hosted-CI result must be checked separately.

A fresh amd64 image build authenticated Tor Project's signed APT metadata using
the fingerprint-verified scoped key. It installed Tor
`0.4.9.14-1~d13.trixie+1` and PCRE2 `10.46-1~deb13u3`. That image passed **115
isolated transport/TLS/dashboard tests** with networking disabled, a read-only
root, dropped capabilities and no-new-privileges. Build-only key tools are not
copied into the runtime. Arm64 image execution was not tested in this review.

These results do not by themselves establish a live rollout, accepted share,
payment receipt or complete vulnerability audit. Existing deployments require
the separately approved, backed-up rolling procedure in `UPGRADING.md`.

### October 7 upgrade-helper dependency hashes

The host-helper fix passed **199 offline tests**, including **39 upgrade tests**.
The compatibility path is limited to recorded Compose 2.26.1 gateway/ingress
containers and the stock dependency graph. Regression coverage checks exact
recorded subsets, malformed/missing labels, unknown versions, project mismatches,
literal dollar preservation, unchanged returned models, and refusal of actual
settings changes. Public-source and shell/diff checks passed.

A separate four-service, network-disabled synthetic deployment on Compose
2.26.1 passed **13 real-Compose checks**: the full dependency graph; no-dependency
recreations selecting both transport services, gateway only, ingress only, or a
partial dependency subset; rejection of seven actual configuration edits; and
validation after restoring the original settings. The first rehearsal exposed
Compose's dollar-sign escaping in rendered JSON and failed safely. The corrected
rehearsal preserved literal values while continuing to reject environment, memory,
network mode, read-only, mount, command and dependency edits. Only disposable
fixture containers were removed; no production services or volumes were touched.
These local Docker checks are separate from hosted CI and are not mining tests.

The committed host helper was then installed with a private byte-exact backup.
Its configuration validation passed on the original live deployment. No container
was recreated: all four IDs, images, start times and restart counts, complete
runtime settings and deployment configuration files remained unchanged. This
closes the hash follow-up from the share-accounting rollout below. No candidate
image was deployed or full transport upgrade forced merely to test the helper.

### October 7 share-accounting candidate

The candidate passed **184 offline tests** (82 transport, 15 TLS, 24 release,
24 upgrade, five package, 16 platform and 18 dashboard) and **115 tests** in a
network-disabled, read-only, capability-dropped candidate image. The package
layer was cached; this is not a new vulnerability audit. The public-source
screen, shell syntax, JavaScript syntax and diff checks passed.

New regression cases cover finalizing pending shares once after disconnect,
shutdown and invalid-frame cleanup; duplicate-ID ambiguity through multiple
responses; share-only overflow accounting; expiration and unknown responses;
and balancing submitted shares against settled outcomes plus pending work.
The transport fixture verifies unchanged payload bytes and no share replay.
Dashboard checks cover optional pending gauges, strict bounds, redaction and
round-trip validation. These checks do not establish real mining or payouts.

Synthetic browser verification passed three desktop sizes, two mobile widths,
eight scrollable sessions, keyboard setup, pending/unclear outcomes, legacy
pending-unavailable state, and stale/reset/failed-poll recovery without errors.
The same candidate then passed **115 isolated tests on the deployment host**
and subscription-only probes through both real Tor clients, without worker
authorization, submitted shares or interruption of the existing miner.

Following explicit approval, only the original gateway container was updated.
The automated helper first refused a Compose configuration-hash mismatch before
attempting a runtime change. Full effective runtime/configuration comparisons
against the previous approved rollout found no settings changes apart from the
expected prior image pins. A separately reviewed gateway-only procedure retained
private backups, exact old images and a guarded independent rollback timer;
the helper's validation was not weakened. The Compose hash discrepancy was
subsequently resolved by the separately tested host-helper fix above; it was
not a mining failure or a reason to disable drift checks.

Ingress and both Tor containers retained their identities, start times and restart
counts. The gateway retained all effective settings, network isolation and mounts;
five deployed runtime files matched the tested source hashes. The unchanged miner
reconnected over TLS with fresh jobs. Initial verification observed **two new
accepted pool responses and zero rejected responses** through the new process;
the timed rollback was then disarmed, with backup images/configuration retained.
Payout identity, miner settings, firmware and tuning were compared privately and
left unchanged. The production route policy remains round-robin; this image-only
update does not enable optional latency preference or install a dashboard.

The same live session subsequently remained connected beyond the ten-minute
transport-idle window with fresh jobs, **five accepted responses and zero
rejections**, zero gateway failures/reconnects/restarts, and unchanged settings.
Every sampled share total reconciled to settled outcomes plus pending shares.
An additional deterministic offline stress check exercised 200,000 mixed
request/response events with collisions, invalid IDs, expiration and repeated
finalization: pending state stayed bounded and all submissions were accounted
for. This supplementary check was local, not a hosted-CI test case.

These are correlated live responses, not independent pool-ledger or payment
verification, long-term reliability evidence or forced mining-recovery tests.
No wallet action occurred. Umbrel/StartOS were not redeployed in this rollout;
their new dashboard fields are source-tested, not native-rollout evidence.

### October 6 initial-connection Tor preference

The opt-in routing and shared-dashboard changes passed **176 offline tests**:
76 transport/probe/selection, 15 TLS, 24 release, 24 upgrade, five package,
16 platform and 16 dashboard checks. The candidate image passed **107
transport/TLS/dashboard tests** with networking disabled, a read-only root,
dropped capabilities and no-new-privileges. The Debian package layer was cached;
these results are not a fresh vulnerability audit.

Coverage includes strict policy opt-in, warmup and sample expiry, median/outlier
handling, minimum speed and reliability margins, bounded history, bootstrap and
cooldown precedence, old round-robin behavior, malformed/oversized/redirect
responses, frame limits, deadline/cancellation cleanup, bounded sequential probe
scheduling, and a real fake-SOCKS exchange with no worker authorization or
mining-counter changes. An existing synthetic mining connection retained exact
bytes while a later connection chose the measured faster path; failed preferred
dials used the alternate path. Dashboard tests cover private-field removal,
old-snapshot compatibility, invalid timings/selection and stale data.

The first real-server probe test found that a valid subscription may have an
empty extranonce prefix. The validator was corrected and regression coverage
added; the rejected candidate was not installed on the lab gateway or production.
A subsequent rehearsal failed without sufficient phase diagnostics; a repeat
with explicit diagnostic phases passed. Do not treat these initial failures as passes.

The corrected image then ran a disposable, non-root, networkless rehearsal using
only the isolated lab's existing read-only Tor SOCKS mounts. Both routes returned
three successful real subscription samples. The measured faster route was
preferred and delivered another subscription. Artificial dial failures confined
to that disposable bridge exercised alternate-route subscription, both-unavailable
failure and restored subscription traffic. Real Tor clients were not stopped.
The existing lab transport IDs, PIDs, start times and restart counts were unchanged.
No worker was authorized, share submitted, miner redirected or wallet accessed.
These are probe/transport checks, not accepted-share or forced-Tor mining recovery
evidence for this new candidate.

Synthetic browser checks passed timing/preference display, failed-test state,
stale-value removal, restart/poll recovery, keyboard access and the compact
layout at three desktop and two mobile widths, including eight sessions.

After the rehearsal, the unoccupied Umbrel lab gateway and web service were
updated to the same pinned candidate, enabling latency policy only in that lab.
Installed/generated Compose files were backed up; old images and state retained.
Tor A, Tor B and ingress kept their IDs/PIDs/start times/restart counts. Gateway
network isolation, resource/security settings, mounts and platform authentication
were retained. The actual daemon collected three successful samples on each path.
Authenticated browser checks verified displayed timings/preference, redaction,
current snapshots, no JavaScript errors and the 1280×720 layout; all four anonymous
UI routes and the raw web port remained inaccessible. A subsequent off-box TLS
subscription passed certificate validation and actual source-IP preservation.
At that instant the measured gap was below the speed margin, so selection correctly
remained alternating. The production miner stayed on its original gateway.
StartOS and the production Docker gateway were not updated by this lab rollout.

### October 6 read-only appliance dashboard

The visual-polish follow-up passed the same **155 offline tests** and **88
hardened-image tests**, with checks for the shorter connection guidance and
ArkPool.org links. Synthetic browser checks still cover three desktop sizes,
two mobile widths, keyboard access, eight sessions, counter resets, stale data
and failed-poll recovery. The UI remains read-only. The lab rollout recreated
only the web service and retained authentication and read-only mounts. A first
attempt safely rolled back because equivalent mount lists arrived in a different
order; comparing complete mount records sorted by destination resolved it. Both
Tor clients, ingress and gateway kept their IDs, PIDs and restart counts.

A later explicitly approved, bounded Umbrel demonstration used the real miner's
unchanged payout identity and tuning. Preflight verified both Tor subscriptions
and actual off-box client IP preservation. The trial delivered fresh jobs over
verified TLS and observed **three accepted pool responses, zero rejected**.
The authenticated browser showed the real session and share counters; anonymous
requests remained refused. An independent rollback timer was armed before the
switch. The monitor restored the original gateway, verified fresh original jobs,
removed only the temporary pool slot, and verified unchanged identity and tuning.
This is accepted-response evidence, not pool-ledger/payout reconciliation, a
Tor failure-injection test on the real miner, or complete platform qualification.

The compact-layout follow-up passed **155 offline tests** and **88 hardened-image
tests**, including a new setup-disclosure/accessibility structure check. Local
browser checks verified the collapsed desktop dashboard fits 1280×720, 1366×768
and 1024×768, including eight sessions in a keyboard-scrollable table. Setup opens
and closes using the keyboard without JavaScript controls; mobile widths of 390
and 320 pixels have no page-wide horizontal overflow. Existing stale-data, reset,
failed-poll and recovery checks still pass. At smaller/zoomed viewports or with
setup expanded, natural page scrolling remains available rather than clipping data.
The isolated Umbrel lab was updated by recreating **only its web container**;
gateway, ingress and both Tor clients retained their container IDs, process IDs,
start times and restart counts. Configuration backups and the earlier image were
retained. A strict list-order comparison initially triggered a web-only rollback;
comparing the environment's key/value mapping instead allowed the update while
still verifying every value. Authentication and snapshot mounts were unchanged.

The shared dashboard candidate passed **154 offline tests**: 59 transport/control,
15 TLS, 23 release, 24 upgrade, five package, 15 platform and 13 dashboard checks.
The candidate Docker image passed **87 transport/TLS/dashboard tests** with no
network, UID/GID 1000, a read-only root, dropped capabilities and no-new-privileges.
Its Debian layer was cached; this is not a fresh comprehensive vulnerability scan.

New checks cover strict field allowlists, secret-field removal, malformed and
oversized files, symlink/FIFO refusal, atomic private writes, independent gateway
and ingress status, missing/stale/future timestamps, process-counter reset,
disabled-by-default publishers, failed/slow writes without blocking the event
loop, and a read-only HTTP API with no cache, cross-origin access or arbitrary
file reads. Synthetic desktop/mobile browser tests passed healthy/stale job
rendering, Tor warnings, process-reset notices, stale/failed-poll hiding and
recovery without JavaScript errors. Those browser checks were local, not hosted CI.

On the isolated UmbrelOS 2.0.0 lab, a snapshotted manual candidate update followed
by native app restart retained existing configuration, Tor-state directories and
TLS CA/keys. This was **not** a community-store update or backup restoration.
All five services retained non-root users, read-only roots, dropped capabilities
and no-new-privileges. The gateway remained networkless. The UI had only two
read-only snapshot mounts and no published raw port. Native browser login,
current gateway/ingress readings, redaction and no JavaScript errors passed;
anonymous requests to the page, script, status API and health route were denied.
Off-box TLS subscription probes passed before and while the lab dashboard was
stopped, retaining the actual client IP and the same running gateway process.
The dashboard was then restored. No worker was authorized or share submitted.

The private native StartOS candidate advanced to revision 3 on StartOS 0.4.0.2.
Its SDK build, 27 package contract checks and eight graceful-launcher tests passed.
The dashboard ran separately, reading only snapshot volumes. Its generated
password was stored only in the SDK credential volume, never mounted into an app
subcontainer. OS HTTPS with the pinned appliance CA passed certificate verification.
Anonymous and wrong-password requests were refused on all four UI routes, raw
HTTP access was refused, and authenticated browser rendering had no JavaScript
errors. Rotating the password revoked the previous one without restarting the
gateway process. A native app restart retained the dashboard password, all 20
recorded guards for each Tor client, and the TLS identity; source-preserving TLS
subscriptions recovered and the actual gateway remained isolated.

The initial dashboard-only checks above did not authorize a worker or produce
an accepted share; the later approved Umbrel demonstration is recorded separately
at the start of this section. No dashboard testing accessed a wallet. The
earlier Umbrel trial below used an earlier image. The shared dashboard and Umbrel
adapter are public source; the
native StartOS wrapper remains private and no `.s9pk` is distributed. Native
widgets, general first-run setup, backup restoration, multi-architecture image
publication, and the remaining platform mining/recovery gates are still open.

### Experimental appliance and Podman adapters

On October 5, 2026, the platform candidate passed **130 offline tests**:
48 transport, 15 TLS, 23 release, 24 upgrade, five package and 15 platform
checks. The platform tests cover private exports, immutable image references,
namespace/mount restrictions, UI behavior, persistent appliance state and
explicit refusal of unsupported StartOS packaging.

The actual Debian Podman **5.4.2** Quadlet generator accepted both plaintext and
TLS profiles. Generated systemd commands were checked for all four services,
non-root users, dropped capabilities, read-only roots, disabled HTTP proxy
inheritance and the gateway's networkless configuration. This is generator
validation, not a native Podman runtime or SELinux test.

The Umbrel runtime services passed Docker Compose configuration validation after
excluding the platform-owned, image-less `app_proxy` metadata from the diagnostic
fixture. A separately built candidate image passed **63 transport/TLS tests** as UID/GID 1000, with no
network, a read-only root, dropped capabilities and no-new-privileges. Its Debian
package layer was cached; this was not a fresh package audit. These tests do not
validate appliance bind-mount ownership, installation or backup restoration.

Follow-up isolated testing on UmbrelOS passed native installation, authenticated
setup UI, actual client-IP preservation, runtime isolation, and native app restart
with retained configuration, Tor state and TLS identity. Subscription probes passed
Tor A failure/recovery, Tor B failure/recovery, and both paths stopped fail-closed
followed by recovery. These failures were tested with no real miner attached.
A separately approved real-miner TLS trial then delivered fresh jobs and one new
pool-correlated accepted share with zero rejects, followed by three minutes of
stable mining and verified restoration to the original gateway. This used a private
amd64 lab-image fixture, not a published store image; no payment was claimed.

Native Podman startup, SELinux validation, Umbrel native update/backup-restore,
multi-architecture image publication and general first-run distribution remain
unverified. At this stage, StartOS export was blocked pending a design that
preserves per-container network isolation. The later October 6 native transport
results below advance that work without qualifying a distributable `.s9pk` or
supported native package. The existing payout identity
and firmware/tuning were preserved; no wallet operations were performed.
The original five-commit platform pipeline passed. A subsequent opt-in Unix Tor
control change passed **134 offline tests** and **67 hardened transport/TLS tests**.
Later native results are recorded below; hosted CI for these follow-up changes
has not been verified.

### October 6 appliance follow-up tests

The expanded suite passed **141 offline tests**: 59 transport/control/watchdog,
15 TLS, 23 release, 24 upgrade, five package and 15 platform checks. Seven added
regression tests cover control-cookie validation, authenticated bootstrap,
control timeouts, disabling TCP control in Unix mode, invalid-mode refusal,
bootstrap/readiness watchdog deadlines and forced termination of a stuck child.
Shell syntax, diff whitespace and the allowlisted public-source screen passed.

A fresh candidate image build, using the cached Debian package layer, passed
all **74 transport/TLS tests** with networking disabled, UID/GID 1000,
read-only root, dropped capabilities and no-new-privileges. Its reviewed Tor
and PCRE2 version floors passed; this is not a fresh comprehensive CVE audit.

The private StartOS isolation-only package passed **63 existing transport/TLS
tests inside its native Bubblewrap sandbox**, then passed the same suite after
each of two native app restarts. A synthetic volume marker survived both
restarts and was removed after verification. Each restart was confirmed in
native daemon logs. Runtime checks verified UID/GID 1000, no capabilities,
no-new-privileges, a read-only root, private PID/network namespaces, and refusal
of direct IP connectivity. The native fixture uses the earlier image; it does
not include the newly added Tor-control tests and exposes no mining listener.

These were native isolation and synthetic-protocol results, not proof of a full
StartOS mining installation. Ingress/source-IP preservation, complete Tor/gateway
integration, accepted shares and lifecycle checks were not part of that initial
prototype. The later native transport results below cover some of those gaps;
remaining release checks are stated separately. The production miner was not
redirected or restarted for these tests.

A separate, resource-limited Docker fixture ran two real Tor clients sharing
one network namespace with `TOR_CONTROL_UNIX=1`, and a networkless gateway.
Both clients bootstrapped, used independent cookie-authenticated Unix control
sockets, and exposed no TCP control listener or host port. The gateway had
read-only SOCKS mounts, no Tor control cookie and no direct IP route.

Real unauthenticated pool-subscription probes passed through each route,
through the surviving route with either client stopped, and after recovery.
Stopping both paths failed closed. Synthetic unlisted/private and public source
envelopes were refused; these internal probes do not validate real LAN source-IP
preservation. No worker was authorized and no shares were submitted.

Freezing one lab Tor child exercised the actual readiness watchdog, without
shortening its timers: its supervisor exited after approximately 195 seconds,
including forced child shutdown. The other path still returned a subscription.
The test explicitly restarted the stopped client; automatic platform restart
was not tested by this fixture. Subscription traffic through that restored client
passed. Temporary fixture containers were removed, with their private state kept
outside Git. This shared-network Docker rehearsal is separate
from the native StartOS isolation tests, not a full native StartOS deployment.

### October 6 native StartOS transport candidate

The private isolation-only prototype was expanded into four native services:
independent Tor A and Tor B, a networkless gateway, and a private-LAN ingress.
The package builds with SDK 3.0.0, whose minimum runtime is StartOS 0.4.0.2.
The older lab OS accepted sideloading but its host-address API lacked metadata
required by that SDK. After a lab snapshot and the official stable patch update,
all four native daemon health checks passed. No production OS was restarted.

Tests of the actual long-running gateway process verified UID1000, zero
capabilities, no-new-privileges, separate PID/network namespaces, only loopback,
no default IP route, read-only root/SOCKS mounts, and no Tor control cookie or
TLS private key. These are distinct from tests of a separate sandbox helper.
The new image passed all **74 transport/TLS tests** both in a hardened Docker
fixture and inside a separate native StartOS sandbox. **27 offline package
contract checks** covered strict private IPv4 selection, rejection of missing,
ambiguous or disabled addresses, and required sandbox arguments.

Off-box plaintext and TLS probes returned real pool-subscription responses,
using Tor A and Tor B respectively. The native ingress's established TCP peers
matched the probing client's actual address and ephemeral port. TLS succeeded
with the privately exported public CA and failed without trusting it. A synthetic
public-source envelope was refused by the gateway; this is not a real external
public-client test or a router exposure audit.

With no miner attached, each socket-identified Tor child was paused in turn.
Subscriptions used the surviving route, then used the recovered route after
resuming the child. Pausing both made connections fail closed; resuming them
restored subscriptions. These are native transport failure/recovery results,
not accepted-share, automatic supervisor-restart or payment verification.

The first fresh-state guard-retention restart check failed, although TLS identity
survived and a repeat check passed. The candidate was therefore refined to request
authenticated Tor shutdown over each private control socket and wait for exit
before native sandbox teardown. Eight additional tests cover control validation,
absence of fallback, graceful completion, bounded termination and exit propagation.
This lifecycle launcher is private package code, not a change to Docker transport.

A native candidate update from revision 1 to revision 2 retained all 20 recorded
guard identities on each Tor client, byte-identical TLS certificates/keys, actual
gateway isolation and source-preserving TLS subscriptions. A subsequent revision-2
app restart passed the same checks; native logs confirmed both graceful shutdown
acknowledgments. This is one private update path with fixed candidate settings,
not full first-run/migration/backup qualification. A fresh-install persistence
repeat is still required before distribution.

The public exporter remains blocked. This private x86_64 candidate has fixed
LAN/pool test settings and no user-facing configuration or pairing action.
Real-miner acceptance, broader update/backup-restore, unattended recovery and
multi-architecture distribution still need qualification. The production miner
remained on its original gateway with unchanged identity and tuning throughout;
no worker was authorized, no share submitted, and no wallet operation performed
by the native probes.

### Gateway observability and recovery candidate

The four changes add private protocol telemetry, bounded Tor-route cooldowns,
job-age recovery, and live TLS leaf maintenance. The offline suite passed 115
tests: 48 transport/telemetry/recovery, 15 TLS, 23 release, 24 upgrade, and five
package checks. Shell syntax and the public-source screen also passed.

Synthetic coverage includes response correlation without identities, duplicate
IDs, bounded pending requests, stale-job detection without share-gap triggers,
recovery budgets, actual session closure/reconnection through the alternate fake
Tor route, and TLS renewal while an existing encrypted stream remains usable.
TLS failure refuses new handshakes and recovers without replacing the CA.
These checks do not establish production deployment, real failure-recovery
shares, or payouts. The existing mining stack is not changed by these tests.

The candidate image also passed all **63 transport/TLS tests** with networking
disabled, a read-only root, dropped capabilities and no-new-privileges. A separate
network-disabled smoke test exercised actual gateway/ingress startup, private
status-socket permissions, synthetic share-response correlation, and both status
commands. The feature pipeline [passed](https://gitlab.com/arkpool/arkpool-gateway/-/pipelines/2911191970).
These remain isolated checks, not a production rollout or new release qualification.

### October 4 runtime security update

Before this feature merge, the security-only backport on `main` passed **85
offline tests** (38 transport, 19 release, 23 upgrade, and five package checks),
shell validation and the public-source screen. Optional TLS was not part of
that earlier backport; the historical result is separate from the candidate above.

The TLS branch passed **102 offline tests** (38 transport, 12 TLS, 23 release,
24 upgrade, and 5 package-security checks), shell validation and the public-source
screen. A fresh, uncached Debian 13 image build installed Tor
`0.4.9.13-0+deb13u1` and PCRE2 `10.46-1~deb13u3`; the build-time minimum-version
check passed. Its **50 transport/TLS tests** passed with no network, a read-only
root, non-root execution, dropped capabilities and no-new-privileges.

Tests cover refusal of outdated/missing packages and checking every service even
when one fails. These are package-floor and synthetic transport checks, not a
complete vulnerability scan or a live Tor/miner/payout trial. Existing deployment
images and miner settings were not changed by this verification.

### Optional TLS and pairing setup

On October 2, 2026, all **97 offline tests** passed: 38 existing transport, 12
TLS identity/transport, 23 release/preflight/export, and 24 upgrade tests.
The source-policy and shell checks passed. All **50 transport/TLS tests** also
passed in a freshly built, non-root container with networking disabled, a
read-only root, dropped capabilities and no-new-privileges. The final image is
`sha256:6831a04f91d9c1fe906b9ef025f9e20c3f478068b9cb93c5a87962aa54d05c4b`.

A separate real Docker Compose fixture used loopback-only published ports,
synthetic settings, and networkless fake Tor services. It verified:

- Default plaintext setup without a TLS listener or identity mount.
- Optional TLS plus plaintext, custom port export, and byte-exact messages.
- Valid CA trust, refusal of untrusted CA, and verified TLS reconnects.
- A synthetic client choosing plaintext fallback only when permitted.
- Ingress restart retaining the paired CA.
- TLS disable/re-enable removing/restoring its port while preserving the CA.
- Unchanged fake Tor container IDs and gateway `network_mode: none`.

Unit coverage additionally checks wrong-host certificates, source rejection
before handshake, shared handshake/session capacity, timeout recovery, malformed
encrypted frames, private file permissions, key corruption/symlinks, CA-preserving
leaf renewal, optional-port preflight, private exports and source-archive exclusion.
The isolated fixture containers/networks were stopped afterward; volumes were
retained. No live deployment was recreated, redirected, or reconfigured.

The exported public setup file was also imported into the candidate miner portal
in desktop/mobile browser fixtures for both encrypted-only and explicit plaintext
fallback modes. These checks used synthetic pool credentials. They verified
unchanged usernames/passwords and unrelated pools, explicit save only, and no
automatic restart. Physical miner TLS handshakes/failover, real LAN firewall
reachability, and accepted shares through the candidate remain untested. The
running RC2 miner stayed on its existing deployment throughout.

### Unreleased JSON nesting limit

On October 2, 2026, all **80 offline tests** passed: 38 transport, 19
release/preflight and 23 upgrade tests, plus shell syntax and the source-policy
screen. New coverage rejects overly nested objects and arrays before JSON
decoding, accepts the exact 32-container boundary, ignores delimiters inside
strings, preserves valid wire bytes, blocks deep frames in both directions,
and verifies that a new session works after rejection.

A fresh Docker build completed with package updates and passed all **38
transport tests** with networking disabled, a read-only root, non-root execution,
dropped capabilities and no-new-privileges. Candidate image:
`sha256:03b5d56066bd19c2aed683614ff4847eeec804e637a9ef088078c50081060495`.

The running 601a/BM1370 miner reported the September 29 RC2 firmware
and ESP-IDF `v6.0.2`. A three-minute passive check reassembled live Stratum
traffic in memory and applied the candidate validator to four complete
`mining.notify` frames. All passed; maximum observed JSON depth was three.
The initial partial-session line was skipped. Only aggregate results were
retained; no raw traffic or deployment identifiers are published.

This confirms compatibility with the observed job messages from the current
miner session. No share submissions or authorization exchange were observed
in that window, so it does not establish full-session or accepted-share
validation of the candidate. The miner's uptime continued increasing and its
accepted/rejected counters remained unchanged. No live image, miner settings,
firmware, or Tor state was changed; no malformed frames were sent to the miner.

### Unreleased public endpoint and private-LAN defaults

The new-install template includes the owner-approved public Tor endpoint and
`MINER_IPS=lan`. Both ingress and gateway enforce RFC1918-only source access;
existing exact-IP configurations remain restrictive. This does not authenticate
clients or prevent source NAT from disguising an outside client as private.
See [SECURITY.md](../SECURITY.md) for the firewall and source-preservation boundary.

All **74 offline tests** passed: 33 transport, 18 release/preflight and 23 upgrade,
plus shell syntax and the source-policy screen. New tests cover private/public
source boundaries, ingress peer checks, gateway envelope checks, unchanged
exact-IP behavior, the checksum-valid default endpoint and tightly scoped
publication exceptions. Other onion endpoints and private-key patterns remain
flagged by the source screen.

A separately tagged candidate image built using the cached Debian package layer
and passed all 33 transport tests with networking disabled, a read-only root,
non-root execution, dropped capabilities and no-new-privileges. This is synthetic
validation, not a fresh package-update check or live LAN/mining trial of LAN mode.
No live deployment, pool registration policy or wallet setting was changed.

### Unreleased settings-preserving upgrade helper

On October 2, 2026, the expanded offline suite passed **66 tests**: 28 transport,
15 release/preflight and 23 upgrade tests, plus shell syntax checks. The upgrade
tests cover unchanged user files, custom settings, Tor invariants, private backup
permissions, candidate failure before cutover, failed startup, automatic/manual
rollback, interruption recovery, configuration drift, concurrent-run refusal,
immutable image selection, and secret-free JSON output. Release tests verify
that private upgrade-state files remain outside the source archive.

A separate real Docker/Compose fixture also passed:

- Candidate image upgrade with custom ingress memory limits retained.
- Manual restoration of the exact previous image IDs.
- Automatic restoration after a candidate passed its synthetic tests but failed
  to start correctly.
- Unchanged configuration files and Tor-fixture container identities/settings.

The fixture used synthetic settings, loopback-only publishing and networkless
heartbeat processes in place of Tor. It did not contact a miner, pool or wallet,
and it did not touch the existing live deployment. Its containers/networks were
stopped afterward; test volumes were retained, with no global pruning.

GitLab YAML parsed locally and the current-source policy screen passed. No
destination GitLab CI Lint or runner result is claimed yet. The upgrade helper
is not installed on the live miner's deployment and does not extend the earlier
live transport trial into proof of automated mining recovery.

### Unreleased review fixes

The review-fix branch adds regression coverage for redirect parser ambiguity
in both directions (duplicate/case-aliased keys, escaped keys and null-truncated
methods), byte-exact valid-message forwarding, quiet-miner sessions across both
forwarding layers, session-idle closure, independent partial-frame and blocked-
write deadlines, and cancellation cleanup. Packaging tests also require failure
when a newly tracked source or private file falls outside the explicit allowlist.

On October 2, 2026, all **43 host checks** passed (28 transport and 15
release/preflight tests), as did the shell syntax check. A separately tagged
Docker image built on the alternate test host and passed all **28 transport
tests** as non-root with networking disabled, a read-only root filesystem,
dropped capabilities, and no-new-privileges. That build reused the cached Debian
package layer; it was not a fresh package-update verification. The first host's
build failed package-signature checks and that host reported a full filesystem;
signature enforcement was not weakened and no cleanup was performed.

Test image: `sha256:6570bed91bb0bf625ec3457d7833bcd05db830bcec33b4b9da8ff4f3b6ba7b97`.

These synthetic checks are separate from the live trial below; they are not
mining or payout evidence on their own.

### Approved review-fix live trial

On October 2, 2026, revision `76b5c68` and the test image above were staged on
the existing trial host. All 43 host tests and shell syntax checks passed there;
all 28 transport tests also passed inside the hardened candidate image.
Subscription-only probes received real successful
pool responses through both Tor routes, validated by the candidate parser.

Following operator approval, only gateway and ingress were recreated with the
reviewed image at approximately 16:40 UTC. The exact image was pinned in a private
Compose override; original deployment files and the old image were retained.
A ten-minute rollback was armed before the change. Both Tor containers retained
their IDs, start times, and state. Miner settings, payout identity, firmware,
tuning, listener, allowlists, and gateway network isolation remained unchanged.

The miner automatically reconnected and resumed fresh jobs and hashing. Its work
and share counters reset during reconnect without a device-uptime reset. At
16:42:58 UTC, the new session reported **1 accepted share, 0 rejected**, and a
one-minute hashrate of approximately 1.06 TH/s. This was a new response through
the reviewed transport, not a carried-over accepted-share counter. Both updated
containers were healthy, with zero restarts and no reported transport failures.
The timed rollback was then canceled; recovery files and the old image remain.
Running gateway/ingress file hashes matched the reviewed source. The real
miner's source IP still reached ingress unchanged; both updated containers
retained non-root users, read-only filesystems, dropped capabilities and
no-new-privileges. The gateway continued to use Docker networking `none`.

At 16:53:13 UTC, the recovered connection had remained established beyond the
ten-minute timeout window. The miner reported 25 work items, **1 accepted share,
0 rejected**, approximately 1.08 TH/s (one-minute average), and 61.6°C. Aggregate
gateway counters remained `active=1 opened=2 closed=1 refused=0 failed=0` after
initial reconnect recovery, and both updated containers had zero restarts.
Identity, firmware, tuning, and Tor-container invariants still matched. The
rollback marker was disarmed. This is a short supervised soak, not a claim of
long-term reliability or forced-recovery validation.

This establishes initial live compatibility for the tested miner/pool pair,
not compatibility with every firmware or pool. It does not independently
reconcile backend accounting, validate forced Tor recovery with a mining worker,
or prove payment. No wallet operation occurred.

### Isolated transport rehearsal

On October 2, 2026 (UTC), the four-service package passed:

- A Docker image build and all **21 synthetic tests inside that image**.
- The documented `./gateway.sh up` workflow on Linux Docker Engine 26.1.5,
  Compose 2.26.1, with a fresh set of Compose networks.
- Successful startup of the LAN listener, networkless gateway, and two Tor clients.
- A real Stratum subscription from an allowlisted LAN host through the published
  listener, private gateway socket, Tor, and the configured pool onion.
- Refusal of a second, unlisted LAN host. The hosts' source addresses reached
  the allowlist unchanged.
- Real LAN subscription success with Tor A stopped, using Tor B.
- Real LAN subscription success with Tor B stopped, using Tor A.
- Failure to establish an upstream connection with both Tor clients stopped.
- Restored LAN subscription traffic after Tor clients restarted.
- Gateway `network_mode: none`, no published gateway port, and an empty routing
  table. Only the separate LAN listener publishes the configured Stratum port.

The rehearsal used a temporary host port and a narrow, expiring host firewall
allowance for two test clients. The package does not install or change firewall
rules. The running production miner was not redirected; its session remained
unchanged, and its accepted-share counter increased during this work.

These initial probes did **not** authorize a worker, hash, submit work, or access
a wallet. The subsequent live-miner trial below supplies separate mining evidence.

The tested image ID was:

```text
sha256:943c16f4a9be7d1a08aaf9cf95ba13ebc59aab2dd03ebf81fee0a00ea90b7a10
```

Image size was approximately 129 MB. Rebuilds fetch available Debian package
updates, so future builds may have different IDs and package versions.

### Clean-host installation and approved live-miner trial

Later on October 2, revision `d658601a74f478feb70b475ebc9bcb514e6706d2`
was installed on a newly provisioned Debian 13 VM with Docker Engine 26.1.5
and Compose 2.26.1, using fresh Docker networks and Tor volumes. Installation
details specific to the operator's network are retained only in private records;
the package does not prescribe where users place their host.

The documented `./gateway.sh up` workflow built and started the package. All
**21 tests passed inside the new image**, and both Tor paths independently
returned real pool subscription responses before the miner was redirected.

With explicit operator approval, the existing physical Stratum V1 miner was
briefly restarted onto this gateway. Its original configuration was saved
privately, the old gateway stayed available, and its firmware and tuning were
unchanged. The miner's complete Ark username was compared privately against
the previous gateway's authoritative upstream identity and matched exactly.

Observed results:

- The physical miner's actual source IP reached ingress unchanged.
- Gateway Docker networking remained `none`, with no published gateway port.
- Fresh jobs arrived and hashing resumed at approximately 1.07 TH/s.
- At 14:05:39 UTC, the miner reported **1 accepted share and 0 rejected** in
  the new session, after 141 seconds of uptime. These were not inherited totals
  from the previous gateway or a synthetic share submission.
- Both Tor clients remained available; no live-miner failure injection was
  performed. The temporary safety rollback was canceled after job delivery
  and resumed hashing were confirmed.

This is real mining evidence as reported by the miner from the pool response,
not independent backend accounting reconciliation or proof of payment. The
operator was notified to monitor their backend. No wallet operations occurred.

The clean-host image ID was:

```text
sha256:0240b1d43107db0a65afb98618bd4e9fb03409414f55ee87973dd5cf688869b8
```

### Release lessons from the trial

- Verify deployment authority and connectivity before a cutover. Offer suitable
  placement options, but leave the host and network choice to the operator.
- Use the actual archive subdirectory and discovered interface names, not
  assumptions carried over from another host.
- A gateway that rewrites a worker alias can hide the real upstream identity.
  Migration to this pass-through package requires the exact verified Ark
  username on the miner, without changing payout ownership.
- Address reservations and monitoring are deployment requirements. The trial
  used a supervised DHCP lease; old gateway ledger counters do not follow the
  redirected miner. HA, stable addressing, and telemetry integration were not
  demonstrated by this trial.
- A long share gap alone does not establish a miner fault. Check fresh jobs,
  hashing, pool difficulty, and actual accepted responses separately.

## Why the LAN listener is separate

The earlier three-container prototype attached the gateway only to an internal
Docker network. On the tested Docker version, a configured published port was
absent from the container's actual port bindings. Container-only tests passed,
but a real LAN client could not connect.

The current design publishes a small ingress service on a normal bridge and
connects it to a networkless gateway through a Unix socket. This follows Docker's
separation of an externally reachable frontend from isolated backend services.
See [Docker networking](https://docs.docker.com/engine/network/) and
[port publishing](https://docs.docker.com/engine/network/port-publishing/).

The ingress sends the actual TCP source address in a four-byte local envelope.
Both services enforce the configured client policy. Only ingress and gateway mount that
socket; the gateway does not accept a miner-provided source header.

## Run the synthetic suite

```sh
docker build --target test -t arkpool-gateway:test .
docker run --rm --network none --read-only --tmpfs /tmp \
  --cap-drop ALL --security-opt no-new-privileges:true \
  arkpool-gateway:test
```

The build requires network access. The tests use only synthetic JSON, local
TCP/Unix sockets, and a fake SOCKS server. They exercise the complete ingress
and gateway path, including identity preservation, client refusal, malformed
frames, connection limits, redirects, missing sockets, partial source envelopes,
round-robin selection, and Tor connection failure.

## Rehearse recovery

Use a separate test deployment and worker. Stopping Tor closes sessions on that
path, so do not perform these failure tests on a production miner that must stay
connected.

1. Confirm jobs and accepted shares on the separate test worker.
2. Stop `tor-a`; confirm reconnection and accepted shares through `tor-b`.
3. Restore `tor-a` and wait for readiness, then repeat with `tor-b` stopped.
4. Stop both; confirm connections fail closed.
5. Restore both; confirm jobs and accepted shares recover.
6. Reconcile any eligible payout with the operator using read-only evidence.

Transport-only subscription tests have completed these route checks, but the
mining-worker portion is still pending.

## Remaining release validation

- [x] Repeat installation on a newly provisioned Linux Docker host.
- [x] Verify the physical miner's source address through its actual network path.
- [x] Verify real job delivery and a pool-accepted share reported by the miner through this package.
- [ ] Verify share delivery after recovery using a separate mining worker.
- [ ] Independently reconcile the trial's accepted share with the pool operator's backend.
- [ ] Reconcile an eligible payout with the pool operator without claiming or redeeming it.

The clean-host trial completes the first three checks but does not close the
remaining release gates. A successful subscription is not an accepted share;
an accepted share is not proof of payment. The project is MIT-licensed but
remains alpha until the outstanding validation is completed.

## Upgrading an earlier alpha

Docker may retain the old internal LAN network across a Compose update. Stop
only that ArkPool deployment and recreate its networks, preserving volumes:

```sh
docker compose down
./gateway.sh up
```

Do not add `-v`: Tor state should be retained. The startup helper now checks
the actual published listener port and reports an error instead of declaring
success if the mapping is missing. Schedule this migration around downtime;
it disconnects miners attached to that deployment.

## Watchdog behavior and limits

Each Tor supervisor checks its authenticated local control port approximately
every five seconds. It exits and lets Docker restart its container after ten
minutes without initial bootstrap or three minutes of lost readiness after
bootstrap. It also exits when the Tor process exits. Gateway readiness ignores
Tor heartbeats older than 30 seconds.

The opt-in `TOR_CONTROL_UNIX=1` transport is covered by offline tests for its
fixed private socket, bounded connection timeout, descriptor cleanup, unchanged
default behavior, and refusal to fall back to TCP. Native appliance runtime and
Tor bootstrap tests are separate requirements; these unit tests do not qualify
StartOS support.

Pool connection attempts time out after 30 seconds per path. Established
connections close after ten minutes without valid messages in either direction
or a write blocks for 30 seconds. Quiet miner submissions do not trigger idle
closure while pool messages arrive. Ingress shares a byte-activity deadline;
the gateway independently requires valid complete frames. From its first byte,
a frame has ten minutes to finish even if the other direction stays active.
The miner is responsible for reconnecting.

Bootstrap status can remain complete during network or pool trouble. These
checks do not prove a fresh onion circuit, new job, or accepted share. The job
watchdog separately distinguishes stale work from share gaps (see README).
Docker's unhealthy status alone does not
restart a still-running gateway process.

Ingress health confirms its process responds and the private gateway socket
exists. Gateway health separately requires a responsive local health socket and
at least one recent Tor heartbeat.
