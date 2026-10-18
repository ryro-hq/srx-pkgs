# Package authoring

The recipe tree separates packages, shared library code and reusable templates.
The public names stay in `main.srx`; moving implementation files does not require
consumers to change `pkgs.forPlatform`, `packages.nginx` or other selectors.

```text
main.srx                         Explicit public exports and stable lazy recipe references
catalog.toml                     Qualified releases and compatibility matrix
recipes/
  packages/
    glibc/
      package.srx                Exact selection and shared runtime reference
      releases.srx               Official URL, SHA256 and bounded source size
      build.srx                  Bootstrap build specialization
      managed.srx                Explicit managed seed specialization
      steps.srx                  Shared locale and dev/runtime partition program
    hello/
      package.srx                Public version/platform selection
      releases.srx               Generated qualified release data
      build.srx                  GNU/musl specializations of shared templates
      variants.srx               Package trait implementations
      managed.srx                Experimental managed construction
      legacy.srx                 Existing bootstrap factory
      contracts/default.srx      Nominal settings and rendering
    nginx/                       Same structure, plus service integration and build steps
    git/                         Explicit managed Git and service adapter
    zlib/                        Explicit managed library
    bootstrap/                   Existing bootstrap fixture
  lib/
    set.srx                      Public platform-bound package set
    platform.srx                 Normalization and compatibility checks
    toolchain.srx                Explicit managed seed layout
    gnu.srx                      Host GNU compiler setup
    managed.srx                  Shared managed compiler flags and environments
    runtime.srx                  Runtime helper validation
  templates/
    recipe.srx                   SourceRecipe, dependencies and GNU command construction
    process.srx                  Typed process, environment and argument helpers
    autotools.srx                Configurable configure / make / install sequence
  support.srx                    Source and Compatibility data shared with generated releases
tools/
  package.py                     Create a package from reviewed source metadata
  templates/autotools/*.srx.in    Maintained authoring skeletons
hosts/systemd/                    Versioned host integration contract and read-only probe
tests/                           Public API, template authoring and compatibility checks
toolchains/                      Build/result platform records
keys/                            Pinned upstream signing authorities
```

Only `.srx` modules live under `recipes/`. Authoring documentation stays in `docs/`
and skeleton files stay under `tools/templates/`, outside the module loader.
Small packages use only the modules they need. A new version adds source data;
it does not copy a whole build into another version directory. `variants.srx`
contains platform implementations, avoiding the old `package.srx` / `packages.srx`
filename ambiguity. Forwarding-only source modules have been removed.

Public recipe references are explicit `pub let` bindings in `main.srx`, rather
than names inferred from internal file paths. The legacy references `pkgs::hello`,
`pkgs::glibc`, `pkgs::bootstrap` and the six `pkgs::versioned_*` selections remain
available. A package move changes its binding's implementation path, not its
public name. `tests/check-packages.py` checks all nine references.

## Use the typed templates

A build specialization supplies its differences to a checked `.srx` template:

```srx
pub fn gnu(source: support::Source) -> Recipe {
    templates::recipe::from_source({
        id = "hello";
        source = source;
        build = lib::gnu::autotools({
            source_directory = "hello-${source.version}";
            timeout_seconds = 180;
        });
        build_inputs = templates::recipe::selected_inputs([
            recipe_output(glibc::runtime, "dev"),
            recipe_output(glibc::runtime, "out")
        ]);
        commands = [templates::recipe::gnu_command("hello", "usr/bin/hello", glibc::runtime, [])];
    })
}
```

`SourceRecipe` builds the common package/acquisition/build structure. The autotools
`Options` record controls the directory, timeout, profile, shell/make paths,
configure arguments, environment, pre-configuration steps and make/install
arguments. Hello's managed adapter lives in `hello/managed.srx`, where it supplies
the seed paths, `build-aux/install-sh` and its configure options. Package-specific
programs, such as glibc's out-of-tree build and nginx's configure/install steps,
remain in their package directories and reuse the smaller process helpers.

Template arguments remain typed `BuildPath`, `BuildText` and `BuildEnv` values.
There is no shell interpolation of paths by the template layer. Shell programs
are explicit process arguments. Native `${...}` interpolation is evaluated by
Syrox's checker and evaluator, including existing configuration renderers.
The Python authoring tool only creates files; it does not participate in evaluation.

## Create a package

Use a verified exact source pin. This example reuses the existing Hello source
under a separate experimental recipe name:

```sh
python3 tools/package.py new hello_demo \
  --version 2.12.1 \
  --url https://ftp.gnu.org/gnu/hello/hello-2.12.1.tar.gz \
  --sha256 8d99142afd92576f30b0cd7cb42a8dc6809998bc5d607d88761f512e26c7db20 \
  --maximum-bytes 2097152 \
  --source-name hello
srx project lock .
srx project check .
```

Use `--srx /path/to/srx` when it is not installed, or `--dry-run` to inspect the
rendered files as JSON without writing to the catalog. The tool formats the
generated modules and checks the complete catalog in a temporary sibling directory
before applying changes. This catches conflicting public names and package names
that shadow shared modules. It refuses an existing package. Concurrent invocations
are serialized while the tool rereads, validates and applies their changes;
if committing `main.srx` fails, it rolls back the new package. Edits made by another
editor during validation are preserved and cause the operation to stop for retry.

`@{...}` authoring placeholders leave Syrox's `${source.version}` interpolation
intact. No download or build occurs. `--source-name` preserves the upstream directory
prefix while keeping its version interpolated; `--source-directory` provides an
explicit fixed-directory override for unusual archives.

The result provides `pkgs.hello_demo_version { version = "2.12.1"; }` and the
compatible default recipe reference `pkgs::hello_demo`, both exported explicitly
from `main.srx`. Review the actual configure
options, installed paths and command declarations. The initial skeleton is for
GNU x86_64 autotools `.tar.gz` sources; it rejects unsupported targets. Add a
package-set method in `recipes/lib/set.srx` when a platform-bound selector is
needed. Keep a new package experimental until its source provenance, settings
contract and native build/runtime/offline import checks can be registered in
`catalog.toml`. The tool neither supplies evidence nor edits that qualification matrix.

## Package inventory

| Package | Exact versions | Results | Status |
| --- | --- | --- | --- |
| Hello | 2.12.1 | x86_64 GNU/musl | Catalog qualification matrix |
| nginx | 1.30.5, 1.30.6 | x86_64 GNU/musl | Catalog qualification matrix |
| glibc | 2.44 | x86_64 GNU | Bootstrap dependency; managed path experimental |
| zlib | 1.3.2 | x86_64 GNU | Explicit managed providers, experimental |
| Git minimal | 2.55.0 | x86_64 GNU | Explicit managed providers, experimental |

Versions are exact. Unknown versions and incompatible platforms fail before
acquisition. Glibc, Git and zlib selectors return `RecipeRef<Recipe>`; Hello and
nginx return `PackageRef<Settings>` with nominal configuration contracts.
`packages.glibc { version = "2.44"; }` inherits its package set's platform. A
single shared lazy `glibc::runtime` supplies both GNU application recipes.
Musl recipes do not consume it. Compatible legacy entry points remain available.
`PackageSet` retains its public platform and legacy tag fields for compatibility.
Package calls validate that the fields agree and that the build platform remains
Linux x86_64 GNU. Construct sets with `forPlatform` or `forSystem`; record literals
alone do not enforce these cross-field invariants.

## Managed seed contract

The caller supplies `Toolchain` with five selected outputs and the layout contract
`gcc16-linux-x86_64-gnu-v1`. The `contract` field defaults to that value, preserving
existing five-output records; another contract is rejected by the refined
`ToolchainContract` type. This identifies the expected layout and ABI. The actual
provider bytes still require authentication and runtime audits.
Stable input slots
are compiler (0), Python (1), runtime (2), sysroot (3) and tools (4). Consumers add
libc development (5) and runtime (6), then zlib development (7), zlib runtime (8)
and Git's checked static shell/pager tools (9) when needed. References and pure
planning do not admit the seed or establish managed execution.

The current layout expects GNU GCC 16 for Linux x86_64, its complete helper and
runtime closure, matching libc/kernel headers and startup objects in the sysroot,
Python's standard library, sh, make, awk, bison, m4 and binutils. Compiler specs,
bison data, Python imports, shebangs and loader paths must resolve from admitted
inputs. `recipes/lib/toolchain.srx` defines the paths. Git additionally requires
checked static `bin/sh` and `bin/cat`. There is no implicit managed seed.

Managed execution also requires the core's explicit `[build.managed]`
configuration: worker, worker digest, scope, socket parent and user bus for user
scope. Real builds and runtime closure audits remain necessary before promoting
these factories. Systemd belongs to [host integration](../hosts/systemd/README.md).

## Qualification environments

`.github/qualification-hosts.json` pins Debian and Ubuntu 24.04 base images and
selects Debian as the canonical release host. CI expands each catalog combination
across both userspaces. Both VMs boot the same authenticated Linux 6.12.109 kernel;
this is userspace coverage, not qualification of distribution kernels or every
Linux host. The guest image builds the required setpriv against the pinned Rust
image's Landlock UAPI header because Ubuntu's older headers omit `IOCTL_DEV`.
This adjusts the test utility's build headers, not the running kernel.

The image builder is limited to two CPUs and 4 GiB, and qualification VMs use one
CPU and 2 GiB. Each environment has its own archive digest, Store cache and
artifact names. Each host's release manifest must cover the complete package
matrix. `.github/scripts/qualification.py` also checks that every VM report used
that host's exact image archive, runtime and firmware, completed successfully and
destroyed its VM.

Release assets retain canonical Debian bundles and `manifest.json`, plus separate
`manifest-<host>.json`, `qualification-<host>.json` and VM reports for both hosts.
Ubuntu's bundles remain in the corresponding workflow qualification artifacts;
the release's canonical bundles are the ones built and validated in Debian.
The two hosts' artifacts and receipts are not interchangeable, even when their
catalog combination identity is the same.
