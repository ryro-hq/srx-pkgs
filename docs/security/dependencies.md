# Dependency and source policy

Cargo.lock pins the full Rust graph, including development and maintenance tools.
`cargo xtask security audit` runs cargo-deny for advisories, licenses and sources;
`cargo xtask security exceptions` rejects expired or untracked exceptions.
Daily audits run separately from weekly VM qualification. Dependabot groups Cargo
and Actions updates weekly with limited concurrent PRs; each update uses normal gates.

Actions use full commit SHAs. Container inputs use digest references. Maintenance
binaries are pinned by version and SHA256 in `security/tools.json`, downloaded via
HTTPS and verified before execution. `cargo xtask security tools --output /absolute/path`
installs them into a new destination; `--tool workflows` selects pinned actionlint and ShellCheck.
Run `cargo xtask security workflows` with actionlint and ShellCheck available.

CodeQL scans Rust and Actions. It does not analyze the srx language; compiler checks,
configuration tests, fuzzing and sandbox/VM tests cover those inputs. A Rust SARIF
gate rejects high/critical findings, malformed reports, missing invocations and
failed analysis even when invoked for a merge group. Inline SARIF suppressions do
not relax that gate. A future exception requires a separately reviewed policy.

Rust tooling's permissive license allowlist does not determine the licenses of
GNU programs or distributed package outputs. Catalog releases need package license
files, exact upstream and patch pins, an SPDX SBOM and a Grype vulnerability report.
A package with uncertain license or vulnerability applicability cannot be published.

The catalog updater is prepared and disabled by maintainer choice. Activation later
requires an App installed only in this repository with Contents and Pull requests
write permissions, `CATALOG_UPDATER_APP_ID`, the private-key secret
`CATALOG_UPDATER_APP_PRIVATE_KEY`, and `CATALOG_UPDATER_ENABLED=true`. Do not use a PAT
or share the runtime ryro-bot credentials. Preparation runs without write credentials;
the writer applies only allowed patch paths and never executes prepared code.
Every new upstream version also needs a maintainer-reviewed exact source/license
entry in `security/package-licenses.json`; automation cannot approve that review.

Secrets belong in environment-scoped GitHub App credentials or OIDC, never source
files. Untrusted builds receive no publication credentials, persisted checkout
credentials, writable shared Store or release signing identity. Rotate App private
keys after access changes or suspicion of leakage, revoke the installation/token,
review audit logs and rerun affected releases with fresh credentials.
