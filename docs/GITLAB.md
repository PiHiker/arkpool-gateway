# GitLab handoff

The public gateway source and runtime images live in
[`arkpool/arkpool-gateway`](https://gitlab.com/arkpool/arkpool-gateway).
Platform packaging has separate projects:
[Umbrel](https://gitlab.com/arkpool/arkpool-gateway-umbrel) and
[StartOS](https://gitlab.com/arkpool/arkpool-gateway-startos).

A committed CI file is not a successful pipeline. Record the actual pipeline URL
and result; see [testing evidence](TESTING.md). The software remains alpha, with
supported-release and independent payment checks still outstanding. The import
procedure below applies to future private source imports, not to changing the
visibility or rewriting the history of these existing public projects.

## Import safely

1. Confirm the destination project, namespace, visibility and authorized access.
   Start private unless the owner explicitly approves public visibility.
2. Review the current source with `python3 -B scripts/check_public_source.py`
   and inspect the complete file list/diff manually. This is a limited pattern
   screen, not a secret-scanning guarantee.
3. Do **not mirror the private development repository or push all old refs**.
   Earlier history may contain deployment-specific information. Export only the
   reviewed source tree into a fresh directory, inspect it, then initialize a new
   Git history there for GitLab. Keep private Forgejo history separate.
4. Never transfer `.env`, `.arkpool-upgrade`, Tor volumes, logs, credentials,
   wallet data, operational notes, CI secrets, private issues, or old release
   attachments. Use explicit source allowlisting, not a directory-wide copy.
5. The owner selected the [MIT License](../LICENSE) for project code and
   documentation. Retain its copyright and permission notice. Dependency
   licenses remain applicable; review any additional third-party code separately.
6. Preserve the alpha wording and the unresolved checks in [TESTING.md](TESTING.md).
   The old alpha.1 bundle does not include the hardening or upgrade helper.

## CI requirements

`.gitlab-ci.yml` runs the offline tests and current-source screen on branches,
merge requests and tags. It avoids duplicate branch/MR jobs using GitLab's
[workflow rules](https://docs.gitlab.com/ci/yaml/workflow/).

Use an isolated **Linux Docker-executor runner**, not a shell runner on an
infrastructure, mining or wallet host. The job refuses execution without Docker's
container marker. It needs package-repository access to install Python and Git;
the tests themselves use synthetic data and local TCP/Unix sockets, not a miner,
pool or wallet. No privileged Docker service, host Docker socket, production
variables, deployment credentials or package-publishing token is required.

Validate the file with the destination GitLab CI Lint, then run a real pipeline.
Runner availability, server-version compatibility and pipeline success remain
unverified until that happens. The pipeline never deploys to appliances or uploads
the working directory as an artifact.

Image publication requires a separate, explicitly requested pipeline. In GitLab,
select **Build → Pipelines → New pipeline**, choose the protected default branch
`main`, and set `ARKPOOL_PUBLISH_IMAGES=1` for that run. Leave the variable unset
for verification only. Ordinary pushes, merge requests, tags, schedules and API
triggers do not run publication jobs, even if the variable is set. Keep `main`
protected; publication is refused for an unprotected ref.

The publication pipeline builds and executes isolated image tests on native
amd64 and arm64 runners, including the Rust translator. Budget compute and disk
for both architectures before starting it. Normal pipelines still run source and
container verification; they do not build the translator or publish images.
Only after verification succeeds does the opted-in pipeline publish
commit-addressed base and translator runtime images to this project's registry,
then combine their returned digests into separate OCI indexes.
Authentication uses GitLab's ephemeral registry credentials. No deployment keys,
appliance settings, private exports or wallet information enter those jobs.
Archive the final `image-digest.txt` and `image-translator-digest.txt`, and verify
anonymous pullability and both architectures before
pinning the index in a store package. Published images are not a GitLab release,
store approval, installation test or mining proof.

## Before a supported release

- Complete separate-worker share recovery tests and independent backend/payout
  reconciliation without claiming or redeeming funds.
- Review licensing, source and metadata; obtain publication approval.
- Verify a clean-host installation and the documented settings-preserving
  upgrade/rollback workflow on supported Docker/Compose versions.
- Create a new immutable version/tag and source artifacts using
  [RELEASING.md](RELEASING.md); never replace the existing alpha.1 tag.
- Keep synthetic, service-health, miner-reported-share, independent accounting,
  and payout evidence distinct.
