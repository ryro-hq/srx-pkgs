# Maintenance rollout evidence — 2026-11-26

These checks were performed without updating the protected branch, secrets,
repository settings or releases. They are not release approval.

| Control | Local evidence | Remaining rollout |
| --- | --- | --- |
| Extended authoring | Four dry runs and generated recipes passed typed project/plan checks. A wrong prebuilt target was rejected. | Publish/pin the compatible core and run native build/qualification fixtures. The repository still uses its exact baseline core; the format repin in [#9](https://github.com/ryro-hq/srx-pkgs/pull/9) and bootstrap recipes in [#8](https://github.com/ryro-hq/srx-pkgs/pull/8) were deliberately not adopted here. |
| Scheduled updates | Read-only observation authenticated nginx 1.30.8 using the pinned nginx authority and validated its staged diff and exact locks. Hello 2.12.3 presented a different signer and was rejected, without discarding the verified nginx candidate. | Review the Hello signer separately. After #6, exercise scheduled mode and the two App installations with a real protected PR. |
| Assessments | Scoped-hash tests distinguish unrelated lock changes from recipe changes. Current `vex-status` warns; the required check rejects the expired glibc assessment. Renewal produced a candidate diff without changing the policy date. | A maintainer must re-evaluate the VEX and approve any new expiry before a GNU release can use it. |
| Per-package evidence | Re-imported bundles from [run 39555337165](https://github.com/ryro-hq/srx-pkgs/actions/runs/39555337165) offline using the pinned core; the resulting manifest was byte-identical. Per-package evidence for Hello 2.12.1 musl generated licenses/SPDX and retained a real Grype report from the 2026-11-26 database. One high finding correctly blocked it, and `check` refused the incomplete output. | Review the finding and qualify with the current accepted runtime. Positive check/evidence comparisons are covered with fixtures; no passing live result is claimed from this scan. |
| Immutable publication | The historical job log showed HTTP 403 on the first immutable-settings request. The regression exercises missing credentials, 403, 404, malformed/disabled responses and enabled settings. | Configure the read-only Administration credential and publish/verify a new immutable release, including byte and offline-import checks of the actual published payload. |
| Measurement | The [maintenance guide](../maintenance.md#measure-authoring-effort) records controlled before/after local plan timings. | Measure human author time and CI wait on a representative qualified package. |

## Dependency inventory and candidate repin

The SBOM now gives each qualified combination its own application node. It
checks the reviewed provider roles against the bundle imported under its exact
manifest pin, and retains the corresponding output digests. Static host
components require an explicit recipe review and guest inventory; a target
label alone does not add a component or activate VEX.

Replaying the six archived qualification bundles produced independent SPDX
graphs: the three GNU applications linked dynamically to glibc, and the three
musl applications linked statically to the reviewed guest component. The
aggregate preflight stopped on the expired glibc assessment as expected.

An isolated checkout pinned SRX PR #62 at `9a7bab5`, regenerated both locks and
verified that all previous version identities remained pinned. The portable
suite exercised the four extended scaffolds with the candidate. The catalog
branch does not pin the still-unmerged PR commit.

Native Hello 2.12.1/musl qualification with the new pin was attempted but did
not produce fresh evidence: host `setpriv` 2.41.3 rejected the required Landlock
access list, and this account could not open `/dev/kvm` read/write for the
pinned guest. No isolation control was disabled. Run the native matrix in the
catalog CI after the core revision is integrated; portable checks and
inspection of historical bundles are not a substitute.

## Fresh Store for native CI

[PR #11's first CI run](https://github.com/ryro-hq/srx-pkgs/actions/runs/45895441255)
started the pinned guests but all twelve qualification rows reported
`view file mode or size changed`. A
[main run on October 25](https://github.com/ryro-hq/srx-pkgs/actions/runs/40179643439/job/121128675818)
reported the same error after a Store cache hit. The same Debian Hello/musl
combination [passed with no cached Store](https://github.com/ryro-hq/srx-pkgs/actions/runs/43711536720/job/132809407490).

Qualification now uses an empty private Store per job; it does not restore or
save materialized views. The environment artifact, materialization checks,
native matrix and offline import requirements are unchanged. The
[hosted rerun](https://github.com/ryro-hq/srx-pkgs/actions/runs/45897538347)
passed all twelve native rows and both host manifests. `verify` revalidated the
bundles offline, then stopped on the expired single-patch glibc assessment.

## Release scan blockers

A separate, unsuppressed Grype scan of the SPDX generated from that run (database
built `2026-11-26T06:22:34Z`) found CVE-2026-84243 (High) in the old glibc runtime.
It also found independent blocking matches:

- nginx 1.30.5 and 1.30.6: multiple Critical findings, including
  [CVE-2026-123007](https://nginx.org/en/security_advisories.html). Updating the
  default alone does not remediate either qualified historical version.
- Debian's `musl-dev` `1.2.5-3.1~deb13u1`:
  [CVE-2026-107891](https://security-tracker.debian.org/tracker/CVE-2026-107891)
  (High). Debian lists a fix in its newer `1.2.6-2` source package, not in the
  pinned stable guest's version.

These findings are not covered by the new glibc assessment. The candidate
[nginx backports](nginx.md) retain both old selectors, and the
[canonical musl update](musl.md) admits the fixed Debian package. Standalone
builds and scanner compatibility checks do not qualify the new bundles.
Run the full native matrix and release gate before publishing.
