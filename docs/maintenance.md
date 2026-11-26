# Maintain a catalog package

Use the core in `.syrox-core` for catalog locks and qualification. The additional
scaffolds also require a core that lists them in `srx catalog new --help`; until
the cross-repo core bump lands, test those scaffolds with `SRX` set to the
candidate binary, without regenerating the catalog locks with it.

## Add

1. Confirm upstream ownership, version and license. Download the exact artifact,
   verify its detached signature or a signed checksum manifest, and record the
   reviewed signer fingerprint, download URL, SHA-256 and byte limit. HTTPS and
   the digest are necessary, but do not replace publisher authentication.
2. Preview the selector, release data and typed build contract:

   ```sh
   srx catalog new demo --scaffold cmake --version 1.2.3 \
     --url https://example.org/demo-1.2.3.tar.gz --sha256 REVIEWED_SHA256 \
     --maximum-bytes 2097152 --dry-run
   ```

   Remove `--dry-run` only after inspecting the output. Source starters support
   `.tar.gz` and Linux x86-64 GNU host bootstrap. `--source-directory` can
   override the archive root. CMake defaults to Unix Makefiles, Meson uses Ninja
   without wrap downloads, and plain Make assumes `CC`, `PREFIX`, `DESTDIR`
   and an `install` target. Review actual compiler/tool dependencies, flags,
   install paths and package tests; these defaults are not managed-toolchain or
   musl support. `prebuilt` accepts a raw static Linux x86-64 ELF, uses
   `--binary-name` for its command under `usr/bin`, and checks the ELF during
   realization before it can run. Dynamic binaries and other ABI/CPU variants
   need their own reviewed recipe and qualification.
3. Define the public settings and commands, explicitly wire any platform factory,
   and add inventory and native checks before treating the recipe as releasable.
   For a raw binary, retain both the executable pin and its reviewed license
   materials; `security/package-licenses.json` can specify a separate
   `license_archive` with `url`, `sha256` and archive `root`.
4. Refresh intentionally and run the portable suite:

   ```sh
   srx catalog generate .
   srx project lock .
   srx catalog lock .
   cargo xtask check
   ```

## Update

Stable channels in `catalog.toml` use pinned upstream hosts, signing keys and
version-specific detached signatures. This automated path is only for those
onboarded channels with a supported numeric version scheme. Keep the existing
default and prior pins. Review key rotations separately: verify the new
fingerprint out of band and retain a way to verify historical releases. Never
learn or replace a trusted key from an update candidate.

Run `bash .github/scripts/prepare-updates.sh /absolute/new/output` for local
observation (requires the pinned `srx`, GnuPG and `jq`). Append an exact
`PACKAGE VERSION` to observe just that candidate, e.g. `nginx 1.30.8`. It stages
changes in disposable clones of `HEAD`; commit local inventory changes first
if the run needs to see them. No checkout file, branch or PR is changed.
`index.json` lists prepared patches; `failures.json` lists rejected candidates.
The run logs authenticated URLs, digests, size limits and signers for prepared
candidates. An exact request fails if it cannot be authenticated.

Manual Actions dispatch is observation only. Scheduled Actions report no new
versions, observation mode, missing controls, existing PRs, or preparation
failures. After [#6](https://github.com/ryro-hq/srx-pkgs/issues/6) is proved,
[enable proposal mode](security/releases.md#enable-scheduled-proposals) to open
PRs. The updater does not change license policy, approve PRs, merge or publish.
A maintainer must review license policy for each new version.

## Qualify

Run the checks for every registered variant/system on the pinned Debian and
Ubuntu guests; see [testing](testing.md). Capture upstream verification, native
command/service behavior and offline import. Run the package evidence command
with the canonical qualification directory and an exact selector:

```sh
cargo xtask evidence generate .release hello 2.12.1 default linux-x86_64-musl /absolute/new/evidence
cargo xtask evidence check .release hello 2.12.1 default linux-x86_64-musl /absolute/new/evidence
```

This reimports the catalog qualification bundles offline into a fresh Store,
checks the selected artifact against the current locks, and runs the same SPDX,
license and vulnerability policies as release preflight. It downloads the
pinned scanner and uses its current validated database. It records both pins
and the exact qualification report. `check` compares independently regenerated
evidence and refuses changed database or artifact identities; regenerate on a
database change. A failed scan can leave an `INCOMPLETE` directory with
diagnostics; it is not passing evidence and must not be published. These
commands are not a substitute for both VM runs or signed release attestation.

Review the exact versions in `security/runtime-dependencies.json`. The site of
the build or its target ABI does not identify linked components. The runtime
roles must match the loader/library outputs in the imported and checked bundle;
license and source policy identifies each output's reviewed component. Static
components are explicitly declared from the reviewed recipe and checked against
the qualification host inventory; they are not inferred from an ELF header.
For a prebuilt binary, review upstream static/vendored dependencies rather than
assuming a missing loader means there are no dependencies. A new or modified
recipe needs dependency review before producing release evidence. Use
`cargo xtask security dependency-scopes` to print the recipe fingerprints for
review. The evidence retains the output digests and SPDX link relationships.

## Retire

Identify consumers, describe the migration and date, and choose a replacement
default where relevant. Remove or disable the active update channel in a
reviewed PR, and remove consumer-facing recommendations before changing
selectors. Do not delete historical pins/identities to retire an entry:
`srx catalog preserve` is still required. For compromised releases follow
[recovery](security/releases.md) and notify users of the affected identities.

## Renew a security assessment

`cargo xtask security exceptions` validates expiring advisory/license exceptions
against `deny.toml`. `cargo xtask security vex-status` reports scoped VEX expiry;
`--require-current` fails on expiry. The UTC warning window is 30 days;
the expiry date itself is no longer valid.

1. Recheck the exact finding, versions, sources, patches, recipe scope and
   qualification, and document new review evidence. For a changed glibc scope,
   `cargo xtask security vex-scope` prints the new digest; do not copy it into
   policy without re-assessing the changed context.
2. For an unchanged scope, preview a renewal (future date within 90 days):

   ```sh
   cargo xtask security renew vex glibc@2.44 YYYY-MM-DD https://example.org/review
   ```

   Use `advisory ADVISORY_ID` or `license 'NAME@=VERSION'` instead for exceptions.
   The command prints the current scope and candidate JSON, never edits policy.
   Review a diff and submit it for human approval. Drop a finding or exception
   when it no longer needs suppression; do not extend it on a timer.

## PR review checklist

- [ ] Exact sources, signer, byte limits, patches and locks are verified and
  previous version identities/default behavior are preserved or migrated.
- [ ] The typed selector and settings match the intended variant/ABI; commands,
  tools, transitive runtimes and installed outputs are explicitly reviewed.
- [ ] Both required VM runs passed for the candidate; qualification, licenses,
  SPDX and scanner output match the exact artifact and target.
- [ ] Assessments are applicable, unexpired and reviewed; no failed match is
  hidden by widening an exception. A tool-generated update is not an approval.
- [ ] The PR has human approval and all required checks, and publication will
  use the protected-branch commit, verified assets and offline import.
- [ ] Document installation, migration or retirement impact as appropriate.

## Measure authoring effort

Record the same representative package before and after on fresh checkouts.
Keep upstream pins, requirements, target/variant matrix, machine and cache
conditions comparable. Start before writing the recipe and stop when the PR
is ready for human review with qualification and complete evidence. Record:

| Run | Core/catalog revisions | Active author time | CI wait | Total elapsed | Links |
| --- | --- | ---: | ---: | ---: | --- |
| Before | baseline | — | — | — | — |
| After | candidate | — | — | — | — |

Keep plan-only timings separate. They exclude licensing, source-signature
review and native checks, and do not close the end-to-end metric.

**Local snapshot (2026-11-26):** five fresh checkouts per route, warm debug CLI,
the same synthetic CMake recipe/source pin and identical generated SRX files.
Scripted manual file creation + format with the old pin (`025f32a`) took a
median **0.385 s** through project lock/check/plan. The candidate scaffold took
**0.440 s** through the same checks, including its staged validation. This
measures machine time, not human effort or time to a qualified PR. The full
comparison remains pending.
