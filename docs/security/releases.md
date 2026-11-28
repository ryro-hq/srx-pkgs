# Releases and recovery

Core releases use a verified SemVer tag pointing to a commit on main. Catalog
releases use `catalog-<full-commit-sha>` after both pinned userspaces qualify every
matrix entry. Documentation-only changes do not publish catalog releases. Older
published snapshots and source pins are retained without rewriting history.

Build jobs have read permissions. The final trusted publication job downloads the
qualified artifacts, verifies SHA256, attaches license files and SPDX SBOMs,
requires a successful Grype report, and requests GitHub OIDC provenance and SBOM
attestations using the pinned `actions/attest` action. Releases are published as
immutable assets. A workflow file alone is not evidence that a release was qualified.

Before using a downloaded artifact, verify its checksum and expected repository
and workflow identity, for example:

```sh
gh attestation verify FILE --repo ryro-hq/srx-pkgs \
  --signer-workflow ryro-hq/srx-pkgs/.github/workflows/catalog.yml
```

The publisher exports `attestations.jsonl` and a
`trusted_root.jsonl` snapshot and verifies both provenance and SPDX predicates
using those files before publication. To verify a retained artifact offline:

```sh
gh attestation verify FILE --repo REPOSITORY \
  --bundle attestations.jsonl --custom-trusted-root trusted_root.jsonl \
  --signer-workflow REPOSITORY/.github/workflows/WORKFLOW.yml \
  --source-digest EXPECTED_COMMIT --deny-self-hosted-runners
```

Use `--predicate-type https://spdx.dev/Document` to check the SPDX binding as well.
Obtain and retain trust roots through a trusted channel before disconnecting;
shipping roots alongside an untrusted artifact does not itself establish trust.
The artifact digest, issuer and expected signer workflow must all match.

## Publication preflight

The [failed #6 job](https://github.com/ryro-hq/srx-pkgs/actions/runs/39555337165/job/119087618722)
received HTTP 403 before creating a release: the default workflow token cannot
read the `/immutable-releases` repository administration setting. Do not
remove or replace its live check with a claim based on a historical release.
An administrator must configure immutable releases and a protected
`catalog-publication` environment restricted to `main`. In that environment,
configure `CATALOG_IMMUTABILITY_READ_TOKEN`, a repository-scoped credential
with **Administration: read**, not write. Only the live GET steps receive it.
The default job token remains scoped to the existing release and attestation
permissions. No update App credential is used in publication.

The publisher confirms immutability before creating and again before undrafting.
It compares every uploaded draft asset digest with local bytes and checks the
complete payload inventory and both attestations. Missing or mismatching assets
leave a draft, not a public release. Inspect any remaining draft before a
retry; do not overwrite or remove a published release. After publication, check
the immutable release and its exact commit, retain the run, and verify offline
import with the pinned core. A local test does not establish successful live
publication.

## Enable scheduled proposals

Leave `CATALOG_UPDATER_ENABLED` off until the repaired publisher has produced
a verified immutable release and observation has been exercised with a real
signed candidate. Set `CATALOG_UPDATER_FORK` to `owner/repo` for a dedicated
public fork under a separate owner. Register **two** GitHub Apps:

| Installation | Repository permissions | Variable | Secret |
| --- | --- | --- | --- |
| Base catalog only | Pull requests: write (no contents write) | `CATALOG_UPDATER_APP_ID` | `CATALOG_UPDATER_APP_PRIVATE_KEY` |
| Proposal fork only | Contents: write | `CATALOG_UPDATER_FORK_APP_ID` | `CATALOG_UPDATER_FORK_APP_PRIVATE_KEY` |

Keep the keys in `catalog-updater`, restricted to `main`. Do not grant either
App Administration, Actions, or rule bypass. The fork token cannot publish
to the base repository, and the base token cannot write commits or releases.
Confirm that main requires human approval, dismisses stale approvals and
requires both the catalog (`verify` or transitional `success`) and DCO checks.
Enable proposals only after these checks. Verify a real fork PR starts the
required checks (a human may need to authorize the first fork workflow) and
cannot merge without human approval. Roll back by disabling the variable and
revoking both keys or installations.

If a release or account is compromised: revoke the relevant App installation/key
and active tokens, restrict publishing, preserve Actions runs/audit logs and hashes,
assess source and Store exposure, publish a GitHub Security Advisory identifying
exact affected/fixed identities, then rebuild and attest a replacement through the
normal queue. Do not silently replace an immutable release or remove retained lock
history. Tell operators explicitly how to identify and remove affected cached or
installed bytes. Never claim that an updater or bot can recall those bytes.

`@fullzer4` currently administers repository access and security reports. Access
escalation needs a documented maintainer decision, MFA readiness and least privilege.
Review access quarterly and after role changes. A second independent write reviewer
and periodic recovery exercises remain explicit human follow-ups.
