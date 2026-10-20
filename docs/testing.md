# Testing the catalog

With the pinned `srx` on PATH (or `SRX=/absolute/path`), run `cargo xtask check` in
a fresh checkout. Rust is pinned by `rust-toolchain.toml`; no root privileges or
Python interpreter are needed for these maintenance checks. Locks are read-only.

| Command | Scope |
| --- | --- |
| `cargo xtask check` | Formatting, generated data, project/catalog locks and all portable suites |
| `cargo xtask fmt` | Explicit Rust and maintained srx formatting |
| `cargo xtask test --suite projections` | Exact package/platform selection, unsupported targets, nominal configured builders, shared libc and seed refinements |
| `cargo xtask test --suite authoring` | Dry run, escaping, collisions, concurrent authors and generated-project planning |
| `cargo xtask test --suite examples` | Four K3s examples, TOML host input and comment-preserving YAML patches |
| `cargo xtask test --suite all` | All suites and Rust qualification/security unit tests |
| `cargo xtask security audit` | cargo-deny, including maintenance dependencies |
| `cargo xtask security workflows` | SHA pinning policy, actionlint and its ShellCheck integration |

Tests create and lock only isolated temporary fixture projects. They never acquire
packages or activate services. Source replacement, syntax/type errors and mismatched
nominal settings must fail before realization. VM execution is a separate required
CI lane for relevant changes and weekly qualification.

`.github/qualification-hosts.json` pins both userspaces. `cargo xtask qualification
matrix MATRIX.json` expands each identity across hosts without allowing metadata
overrides. `record HOST DIRECTORY` binds image/runtime/firmware hashes; `verify
HOST DIRECTORY` binds every successful report and confirmed cleanup to the manifest.
Artifacts/caches are separated by host, core pin, environment and package identity.

Only root prose documents and `docs/*.md` are eligible for the conservative doc-only
classification. Unknown paths, recipes, contracts, locks, dependency/tool/workflow
changes run full qualification. `verify` also requires CodeQL and the strict SARIF
gate, Cargo policy, workflow checks and retained-identity checks. The `success`
context is transitional until required GitHub rules use `verify`.
