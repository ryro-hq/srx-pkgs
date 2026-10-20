# Rollout evidence

Snapshot: 2026-10-20. This records observed runs, separately from final enforcement.

- Organization MFA is enabled; both members remain, with no outside collaborators.
- Immutable releases and Dependabot security updates are enabled in both repositories.
- CNCF DCO2 is installed (App 974774); signed contributions pass its `DCO` check.
- Independent write reviewers: zero. No independent-review or certification claim.
- The catalog updater is prepared and disabled by explicit maintainer choice; no App credentials or PAT are configured. Runtime ryro-bot is outside this migration.

Implementation PRs: [core #9](https://github.com/ryro-hq/srx/pull/9) and
[catalog #4](https://github.com/ryro-hq/srx-pkgs/pull/4).

Core PR #9 merged through its required rebase queue at
`025f32a5c3eec7fc7854f2b950afce625075477f`, retaining the author's signoff and
linear history. Both the [PR run](https://github.com/ryro-hq/srx/actions/runs/39487235286)
and [merge-group run](https://github.com/ryro-hq/srx/actions/runs/39489405928)
passed every required gate: GNU/musl candidates, SPDX/source/license preflight,
Grype, four sanitizer fuzz campaigns, portable tests, both Clippy configurations,
dependency/workflow policy, native VM tests and GNU/musl acceptance VM lanes.
CodeQL was removed by explicit maintainer decision; its gate, triage and exception
records are not part of the final implementation.

The [catalog run before the final core pin](https://github.com/ryro-hq/srx-pkgs/actions/runs/39485797014)
passed both environment builds, all twelve qualification cases and both manifests,
after repeating the Debian Hello GNU case following a temporary DNS failure.
Release preflight found a redundant glibc license symlink and then blocked on
glibc vulnerability matches. The [glibc assessment](glibc.md) records the upstream
security backport, regression and exact expiring OpenVEX scope. The final core pin,
patched GNU runtime and renewed lock must pass their own complete qualification;
the earlier cases do not qualify a changed head.
Final catalog aggregate and trusted publication are still pending. The portable
catalog suite passes locally against the merged core. No local KVM is available,
and no K3s cluster was started.

The [core main run](https://github.com/ryro-hq/srx/actions/runs/39491356644) passed
every gate; its rules now require `verify` and CNCF DCO2 `DCO`. Catalog main rules
still require transitional `success` and `DCO`. Both use rebase-only linear
integration and one-PR ALLGREEN queues (360 minutes, no bypass). DCO2 also passed
the core merge-group check. Replace catalog required `success` with `verify`
after its default-branch workflow succeeds. Release attestation/offline
verification must be checked on actual publication before any release-assurance
claim. The initial GitHub settings snapshot predates this rules transition;
this document records the subsequent rollout.
