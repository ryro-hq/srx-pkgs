<p align="center"><img src="assets/syrox-pkgs.png" width="300" alt="Syrox Packages" /></p>

# Syrox Packages

Pinned package recipes and configuration contracts for [Syrox](https://github.com/ryro-hq/syrox).
The version inventory starts with Hello 2.12.1 and nginx 1.30.5/1.30.6 on Linux
x86_64 GNU and musl. Packages and services configure the existing Linux host.
Place this checkout beside the consuming project:

```srx
inputs { pkgs = "path:../syrox-pkgs"; }

let packages = pkgs.forPlatform { system = "linux-x86_64"; };

services.nginx = {
    enable = true;
    package = packages.nginx { version = "1.30.6"; };
    settings = {
        listen = 8080;
        proxyPass = "http://127.0.0.1:3000";
    };
};
```

Omitted `libc` selects GNU. Use `pkgs.forPlatform { system = "linux-x86_64";
libc = "musl"; }` for musl. Conditions can inspect `packages.platform.system`
and `packages.platform.libc`; `packages.buildPlatform` remains Linux x86_64 GNU.
Calls through the set inherit its platform and reject contradictory overrides.
Selection also rejects inconsistent platform fields in a manually constructed
`PackageSet`; use `forPlatform` to derive the normalized and legacy fields together.
Direct package calls default to Linux x86_64 GNU. The compatible
`forSystem("linux-x86_64-musl")` interface, its full-tag `resultSystem`/`toolsSystem`
fields and full target spellings remain valid.
`PlatformSelection` requires `system` and defaults `libc` to GNU; `Platform`
contains both normalized fields. `linux-aarch64` can be used in conditions but has
no registered package implementations. `linux` and `linux-arm` require an
explicit architecture. Locks, receipts and evidence retain full target tags.

Public `std` names are implicit; `std::Recipe` remains valid. Module `let`
bindings share immutable reusable values, allow forward references, diagnose
cycles and export explicitly with `pub let`. Known conditions in configurations
select one contract before acquisition. The package reference keeps its version,
variant, system and
nominal `.srx` contract through configuration checking. The minimal nginx builds
support HTTP proxying; TLS, rewrite and gzip options are outside that contract.
`extraConfig` accepts text and is checked with the selected `nginx -t` in an
isolated runtime before generation freeze. Exact versions and string constants
are supported. Adding a version preserves the default and all prior source pins.

## Check and maintain

The recipe tree has three clear areas:

- `recipes/packages/<name>/`: package API, exact releases, build and configuration contracts.
- `recipes/lib/`: platform selection, compiler setup and runtime helpers.
- `recipes/templates/`: typed `.srx` templates for source recipes, processes and autotools.

The [folder and authoring guide](docs/recipes.md) includes the full layout, the
managed seed contract and a command to create a package from maintained skeletons:

```sh
python3 tools/package.py new --help
```

`main.srx` defines the public API through explicit exports and lazy bindings.
Existing selectors and recipe references keep their names independently of file
locations, including `pkgs::hello` and the six `pkgs::versioned_*` references.
Tests exercise the complete legacy reference inventory. Templates produce typed build descriptions; arguments and paths stay
separate values. Package authors supply source, options, dependencies and commands
without repeating the shared build machinery. Large embedded programs use readable
multiline strings; the formatter wraps long calls and lists automatically.
Static `Package` and `ServicePackage` traits retain nominal settings contracts.

`catalog.toml` records each release's origin once and explicitly lists its
variants, systems and contracts. `catalog generate` writes release data only;
selection and construction stay in the package modules. `catalog check`
instantiates every listed combination and checks its metadata and source pins.
`Catalog.lock` binds recipe, contract, toolchain, standard-library bytes and the
core revision pinned in `.syrox-core`;
`Syrox.lock` pins the complete
module and standard-library inventory. Signing-key changes require an explicit
lock operation. Existing upstream content cannot be replaced.

Glibc 2.44 now has an exact public selector too:

```srx
let packages = pkgs.forPlatform { system = "linux-x86_64"; };
let libc = packages.glibc { version = "2.44"; };
```

Glibc returns a `RecipeRef<Recipe>` with development and runtime outputs. Qualified
GNU applications share one versioned runtime reference. Git 2.55.0 and zlib 1.3.2
also have exact selectors with explicit managed providers; their managed builds
remain experimental. Their source tables are hand-maintained until those
combinations have native qualification and can enter `catalog.toml`.

Run the maintenance commands from this catalog checkout, using `srx` built from
the commit in `.syrox-core`. The example assumes a matching clean core checkout
at `../syrox`; adjust that sibling path for your local layout. Exporting its
interface specification makes the systemd test verify correspondence with the
engine as well as the XML comparison behavior.

```sh
test "$(git -C ../syrox rev-parse HEAD)" = "$(cat .syrox-core)"
(cd ../syrox && cargo run --locked -p syrox-engine --example systemd_contract) > /tmp/systemd-contract.json
python3 tests/test-package-templates.py "$(command -v srx)"
python3 tests/test-configured-template.py "$(command -v srx)"
python3 hosts/systemd/sync.py /tmp/systemd-contract.json --check
python3 tests/test-systemd-contract.py /tmp/systemd-contract.json
python3 tests/check-packages.py "$(command -v srx)"
python3 tests/check-platforms.py "$(command -v srx)"
python3 tests/check-toolchains.py "$(command -v srx)"
python3 tests/test-qualification-hosts.py
srx catalog check .
srx catalog generate . --check
srx catalog lock .
srx catalog lock . --check
srx catalog matrix .
srx catalog verify-sources .
srx catalog updates .
srx catalog add . nginx 1.30.7
```

The final command is an example for a signed release present upstream. It verifies
the fixed signing key, adds release data, locks and a change record, and preserves
shared recipes. A new configuration shape requires a separate contract and an
explicit compatibility entry for each supported combination.
Recipe and toolchain changes retain prior identities in the lock history.
GNU and musl builds use GNU Linux tools with explicit result systems. Actual
compiler inventories and worker bytes are authenticated in each build receipt.

## Qualify and distribute

A configured build host supplies systemd user services, Bubblewrap, setpriv
Landlock support, gcc, musl-gcc and an explicit `/usr` toolchain.
The [versioned systemd host contract](hosts/systemd/README.md) belongs in `hosts/`,
separate from package recipes and compiler toolchains. The distribution supplies
the manager. `syrox-systemd-v1` describes the engine's supervision and managed
interfaces, with upstream baselines 250 and 254 respectively; the optional
read-only probe checks actual D-Bus signatures so distro backports remain usable.
Application GNU/musl selection does not select or replace the host manager.
This is not a claim of support for every Linux distribution. Run the native
qualifier for every identity emitted by the matrix:

```sh
srx catalog qualify . --identity SHA256 --config build.toml \
    --store ./store --output ./qualification
srx catalog release-manifest . --evidence ./qualification --output manifest.json
```

The qualifier performs real builds and native execution, nginx HTTP and shutdown,
valid and invalid `extraConfig` through actual service preparation, native
configuration checks, and import and execution in a
fresh offline Store. The release manifest requires every combination and rechecks
all transported artifact pins. Availability requires successful qualification.
GitHub Actions qualify every package combination in both pinned Debian and Ubuntu
24.04 userspaces, using the same Linux 6.12.109 VM kernel. This covers those two
userspaces, not their distribution kernels or arbitrary Linux installations.
Environment archives, caches, VM reports and release manifests remain separate by
host; a report from another image cannot satisfy the required host's check.
Debian supplies the canonical distributed bundles. Ubuntu's independent native
builds and offline checks have a separate manifest and qualification report.
Publication requires both environments to pass, followed by integration on
`main`, with release immutability enabled. The daily update
workflow requires `SYROX_UPDATES_TOKEN` (contents, pull requests and actions write)
because the organization blocks PR creation by `GITHUB_TOKEN`. Bot PRs receive
checks against their exact head SHA; promotion of a default is a separate change.
The bootstrap fixture and managed factories retain their existing sources and
compatible entry points. The [managed seed contract](docs/recipes.md#managed-seed-contract)
documents the required explicit providers; no admitted managed seed is published.

Licensed under [Apache-2.0](LICENSE).

## K3s

K3s `1.37.1+k3s1` uses the official checksum-pinned Linux amd64 binary and a
nominal YAML settings contract. It is available directly as `pkgs.k3s` or from
a GNU x86_64 package set:

```srx
inputs { pkgs = "path:../srx-pkgs"; }
let packages = pkgs.forPlatform { system = "linux-x86_64"; };
services.k3s = {
    package = packages.k3s { version = "1.37.1+k3s1"; };
    settings = {
        nodeName = "notebook-test";
        nodeIp = "192.168.1.50";
        clusterInit = Some(true);
        tokenFile = Some("/etc/rancher/k3s/token");
        disable = Some(["traefik", "servicelb", "metrics-server"]);
    };
};
```

Use the notebook's own address for `nodeIp`. Supply the protected token file
separately. Preparation renders `k3s.yaml` and explicit version/server/agent
commands; it does not start processes or activate a privileged cluster.

`examples/k3s` contains an initial server reading host data from locked TOML,
a joining server, an agent, and an existing YAML document patched while retaining
comments and unknown settings. Materialize the examples as sibling projects and
check their format, types, locks and plans without starting a cluster:

```sh
python3 examples/k3s/prepare.py /tmp/srx-k3s-examples
python3 examples/k3s/check.py --srx /path/to/srx
```

K3s is a preparation example. The catalog's six application qualification rows
continue to cover Hello and nginx; K3s cluster activation and provisioning are
separate operations.
