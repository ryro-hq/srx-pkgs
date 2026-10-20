# srx-pkgs

The package catalog for [srx](https://github.com/ryro-hq/srx). It owns package
recipes, typed configuration contracts, source pins and package qualification.
The core owns the language, authenticated std, build operations and host contracts.

Select a platform once and request an exact version:

```srx
inputs { pkgs = "path:../srx-pkgs"; }
let packages = pkgs.forPlatform { system = "linux-x86_64"; libc = "musl"; };
services.nginx = {
    package = packages.nginx { version = "1.30.6"; };
    settings = { listen = 8080; };
};
```

`forPlatform` normalizes architecture and libc and rejects contradictory package
selections. ARM platform descriptions can be inspected but packages currently
qualify Linux x86_64 GNU/musl only. Managed builds additionally require explicit,
authenticated compiler, Python, runtime, sysroot and tool providers. Checking and
planning never acquire sources, admit a seed or start services.

## Develop

Install the Rust toolchain from `rust-toolchain.toml` and the exact core revision
in `.syrox-core`. Put that `srx` on PATH or set `SRX=/absolute/path/to/srx`.

```sh
cargo xtask check
cargo xtask fmt
cargo xtask test --suite all
```

`check` preserves repository sources and locks. Tests create isolated projects and
explicitly lock those fixtures. To admit reviewed source changes in this catalog:

```sh
srx catalog generate .
srx project lock .
srx catalog lock .
cargo xtask check
```

See [authoring](docs/recipes.md), [testing](docs/testing.md),
[contributing](CONTRIBUTING.md), and [security policy](SECURITY.md).

## Repository structure

| Path | Responsibility |
| --- | --- |
| `recipes/packages/` | Package selectors, source data, construction, contracts and integrations |
| `recipes/lib/` | Shared platform and managed-toolchain selection |
| `recipes/builders/` | Typed recipe, process, configured-package and autotools construction |
| `assets/` | Authenticated upstream patch bytes used by recipes |
| `scaffolds/` | `.srx.in` authoring templates, outside the module loader |
| `qualification/` | Typed package command/configuration/HTTP checks and fixtures |
| `security/` | Pinned tools, source/license policy and scoped vulnerability assessments |
| `tests/fixtures/` | Projection and negative cases, outside the module loader |
| `tools/xtask/` | Rust maintenance entry point |
| `examples/k3s/` | Explicitly prepared configuration examples |
| `.github/qualification-hosts.json` | Pinned CI userspaces and canonical publication host |
| `catalog.toml`, `Catalog.lock`, `Syrox.lock` | Version inventory and authenticated identities |

There is no catalog `hosts/` mirror: use `srx host contract` and explicit
`srx host inspect --systemd-system` or `--systemd-user-bus /absolute/socket`.
There is no root `toolchains/` profile directory. The catalog selects platforms;
CI selects its images; build receipts authenticate the compiler and actual inputs.

## Create a package

```sh
srx catalog new hello_demo --path . --scaffold autotools \
  --version 1.0.0 --url https://example.org/hello_demo-1.0.0.tar.gz \
  --sha256 REVIEWED_64_LOWERCASE_HEX_DIGITS --maximum-bytes 2097152 \
  --dry-run
```

Remove `--dry-run` after reviewing the generated sources. Generation validates the
whole staged project before editing it, rejects name collisions, serializes
concurrent authors and preserves editor changes. A generated package is experimental
until its commands, licenses, source provenance and native qualification are reviewed.

## K3s

K3s is fixed at `1.37.1+k3s1`, using the official amd64 binary and retained upstream
checksum manifest. Initial-server, joining-server, agent and existing-YAML examples
cover TOML host data and YAML edits that preserve comments and unknown fields.

```sh
cargo xtask examples k3s --output /tmp/srx-k3s-examples
cargo xtask test --suite examples
```

The destination must not exist. Preparation makes package/shared/example projects
siblings so authenticated input locators stay explicit. Realizing the package can
verify `k3s --version`; these examples do not activate a privileged cluster,
provision hosts or include RKE2.

## Qualification and publication

The mandatory application matrix contains Hello 2.12.1 and nginx 1.30.5/1.30.6 for
GNU and musl. Both pinned Debian and Ubuntu userspaces run on the pinned Linux
6.12.109 microVM kernel; this does not qualify distribution kernels or all Linux
hosts. Debian produces canonical bundles and Ubuntu contributes independent reports.

Catalog releases are immutable `catalog-<commit>` snapshots of qualified source and
artifact identities. They do not version the core and do not imply that every
experimental package is qualified. Documentation-only changes skip VM publication.
Each release must retain source/signature evidence, host-bound reports, license
information, SBOMs, vulnerability results and byte-bound attestations. See
[controls and rollout evidence](docs/security/controls.md).
