# Release tooling

This workflow produces **alpha source artifacts**, not an approved supported
release. Review the unresolved checks in [TESTING.md](TESTING.md). The owner
selected the [MIT License](../LICENSE); include it in every source artifact.
External publication still requires the owner's applicable authorization.

## Operator preflight

Python 3.10+ is required on the host for the setup checker. From the project
directory, after privately filling `.env`:

```sh
./gateway.sh version
./gateway.sh preflight
./gateway.sh preflight --json
```

The checker reads configuration, local IPv4/listener state, memory/disk headroom,
and local Docker/Compose versions. It only queries the local Unix Docker socket;
remote Docker contexts, Docker Desktop, and rootless sockets are not supported
by this checker. It never starts containers, pulls images, changes permissions,
reserves ports, contacts a pool/miner, or operates a wallet. It does not certify
the Compose topology or query the existing gateway's health.

| Exit code | Meaning | Next step |
| --- | --- | --- |
| `0` | Local checks passed; manual network/mining checks remain | Continue only within approved scope |
| `1` | Required prerequisite missing or invalid | Report the failed check; do not deploy |
| `2` | Review required, such as occupied port or limited headroom | Inspect ownership/capacity; never stop an existing service automatically |

JSON schema version 1 includes `result`, `checks`, `mutations_performed: false`,
and `ready_for_mining: false`. The latter stays false because local checks cannot
prove identity, actual reachability, Tor subscriptions, or accepted shares.
Output suppresses actual addresses, onion hosts, config contents and subprocess
errors. A missing/invalid `.env` is not repaired. The checker requires a private
regular file owned by the invoking deployment account and literal assignments
rather than shell expansion, quotes, or additional secret keys.

## Automated checks

```sh
python3 -B scripts/check.py
```

This runs the transport suite, preflight safety tests, deterministic packaging
tests, TLS identity/handshake tests, and shell syntax checks. It requires Python 3.10+, Git, OpenSSL and local TCP/Unix
socket permissions, but not Docker or internet access. A restrictive sandbox
may deny socket creation: report that as an environment failure and use an
authorized test environment; never skip tests and call the result a pass.
Temporary fixture repositories use synthetic data and are removed afterward.

Container builds apply all updates visible in their freshly downloaded package
indexes and fail if an update remains pending. Before publishing an already
built image, run `./gateway.sh security-audit` from a representative deployment;
it audits disposable image copies and does not mount production data. Record the
repository-check time because package currency is time-dependent.

The Forgejo workflow uses the **`arkpool-ci`** runner label. An operator must
provide an isolated Linux runner with Python, Git, and the Node runtime needed
by the pinned checkout action. No live deployment credentials or Docker socket
are required. Automatic jobs run only for pushes to the configured release refs
(`main` and version tags); an operator may also dispatch an explicitly reviewed
ref. Whether those refs are protected is a Forgejo repository setting and must
be verified separately. It does not run
for pull requests, publish releases, or deploy software automatically; untrusted
changes are validated by GitLab's isolated merge-request pipeline instead.
A committed workflow is not evidence of an executed CI run; check the Actions
result before claiming CI passed. Runner provisioning is a separate operation.

GitLab has a separate verification workflow and private-first import guide in
[GITLAB.md](GITLAB.md). Never mirror unreviewed private Git history. Run
`python3 -B scripts/check_public_source.py` and manually review the allowlisted
tree; a pattern screen is not proof that all secrets or private metadata are absent.
Upgrade backups under `.arkpool-upgrade/` are private operational data, never
release inputs. The source builder continues to use an explicit allowlist.

## Build versioned source artifacts

1. Update `VERSION` and `CHANGELOG.md` on a focused branch. Review the exact
   explicit list in `scripts/build_release.py` whenever adding a release file.
2. Run `python3 -B scripts/check.py`, inspect the diff for private information,
   and commit only the intended files. Keep the worktree clean.
3. Verify the selected commit and create its matching immutable alpha tag.
   For example, for version `0.1.0-alpha.1`:

   ```sh
   git tag -a v0.1.0-alpha.1 -m 'ArkPool Gateway 0.1.0-alpha.1'
   python3 -B scripts/build_release.py --output-dir ../arkpool-release-0.1.0-alpha.1
   ```

   The output directory must be new and outside the repository. Existing
   destinations are never overwritten. The builder rejects dirty worktrees,
   mismatched/missing tags, missing files and symlinks in its file allowlist.
   Tracked files must exactly match the explicit allowlist: new tracked files
   block packaging until reviewed. Nothing is silently omitted or automatically
   added. Ignored local configuration remains excluded. If intentional tracked
   exclusions become necessary, add an explicit reviewed policy and tests first.
4. Rebuild the same commit to a second new directory and compare checksums.
   These **source** archives are reproducible. Container builds intentionally
   fetch security updates, so resulting image digests are not reproducible.
5. Inspect the archive and upload only the source archive, manifest and
   `SHA256SUMS` to an operator-approved **prerelease**. Never upload the whole
   checkout, Git history, `.env`, Tor volumes, logs, credentials or wallet files.
   Do not repoint an existing release tag; make a new version for changes.

Artifacts use the names `arkpool-gateway-<version>.tar.gz`,
`arkpool-gateway-<version>.manifest.json`, and `SHA256SUMS`. The archive includes
one versioned project directory and `SOURCE.json` with the full source commit
and hashes of all packaged source files. Packaging uses committed Git blobs,
not the working tree or ignored local files. Allowlisting does not detect a
secret deliberately placed in an allowed source file: review is still required.

## Verify a download before extraction

Obtain the three files from the same trusted release, then run in their directory:

```sh
sha256sum --check SHA256SUMS
```

Verify **both** files pass, inspect the archive's file list, and extract into a
new directory without overwriting an existing installation. Enter the versioned
project subdirectory before setup. Compare `SOURCE.json` with the intended
release commit. Checksums detect corruption, not authenticity if an attacker
replaces both the download and checksum; this initial workflow does not claim
signed-release verification. Use a trusted authenticated distribution channel.

Before moving any private repository to a public forge, separately audit its
entire history and metadata. These sanitized source artifacts do not include
history; they do not certify that old commits are suitable for publication.
