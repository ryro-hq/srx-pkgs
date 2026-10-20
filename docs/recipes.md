# Authoring packages

Packages live in `recipes/packages/<name>/`. Keep source pins in `releases.srx`,
selection in `package.srx`, construction in `build.srx`, configuration types in
`contracts/`, and service integration beside the package. Module trees contain
only `.srx` sources. Assets, test fixtures, documentation and authoring templates
stay outside them.

`recipes/builders/` contains reusable typed construction. `scaffolds/autotools/`
contains textual `.srx.in` scaffolds used by `srx catalog new`. They are distinct:
a builder is checked/evaluated srx; a scaffold creates new source files.

Use `srx catalog new NAME --path . --scaffold autotools --version EXACT --url HTTPS
--sha256 REVIEWED_DIGEST --maximum-bytes LIMIT --dry-run` to preview. Review upstream
archive layout and use `--source-name PREFIX` or `--source-directory DIRECTORY` when
needed. The source directory must be one archive directory component. HTTPS URLs
cannot contain credentials or fragments. Tarball and digest validation happen
before writes, downloads or builds. Literal dollars are escaped while typed
`${source.version}` interpolation remains intact.

The generator locks the project directory while taking and checking a source
snapshot. It formats and checks a sibling staging project, rejects existing
packages and public/module name collisions, then compares the snapshot again.
Concurrent authors start from the last committed exports. Package installation is
rolled back if the main-file replacement fails. Locks are never updated implicitly.

## Typed construction

```srx
builders::recipe::from_source({
    id = "example";
    source = source;
    build = lib::gnu::autotools({
        source_directory = "example-${source.version}";
        timeout_seconds = 180;
    });
    build_inputs = builders::recipe::selected_inputs([
        recipe_output(glibc::runtime, "dev"), recipe_output(glibc::runtime, "out")
    ]);
})
```

Configured packages use `builders::configured::reference<Settings>`. Their renderer
must accept the same nominal `Settings`; mismatched renderers fail checking. A
service integration is explicit and retains the exact package identity. Configuration
preparation may run the selected package's validator; checking and planning remain pure.

`BuildStep::ValidateStaticElf(path)` checks a bounded executable regular file and
rejects implicit loaders/dependencies. `BuildStep::ReplaceShebang(path, expected,
interpreter)` edits only a writable build path with the exact expected header,
preserves permissions and refuses symlinks. Neither operation executes its input.
GNU glibc still requires Python as an upstream build dependency; maintenance and
these build transformations use Rust.

## Platforms and managed providers

Use `pkgs.forPlatform { system = "linux-x86_64"; libc = "gnu"; }`, then `.hello`,
`.nginx`, `.k3s`, `.glibc`, `.managed_glibc`, `.git` or `.zlib` with an exact version.
A `PackageSet` exposes `platform` and `buildPlatform`; explicitly constructed sets
are checked before selection. Contradictory ABI overrides fail instead of silently
selecting another platform.

Managed factories require a `Toolchain` with the refined
`gcc16-linux-x86_64-gnu-v1` contract. Its input slots are compiler (0), Python (1),
runtime (2), sysroot (3) and tools (4). libc, zlib and Git's static shell/pager are
additional explicit inputs. The contract checks layout compatibility, while receipts
and admitted manifests authenticate actual bytes. No implicit host fallback exists.
Managed glibc also requires `usr/bin/patch` in the tools output to apply its
authenticated upstream security backport before configuration.

## Qualification

Register an exact upstream release once in `catalog.toml`, with explicit version,
variant and ABI combinations. `qualification/<package>/checks.toml` is deserialized
into the core's strict qualification types. It selects the command/version arguments
and optional positive/negative configuration, HTTP and service-consumer fixtures.
All referenced bytes enter `Catalog.lock`. A new service needs data in the catalog,
not package-name conditionals in the core.

Run `srx catalog generate .`, `srx project lock .` and `srx catalog lock .`
explicitly after review. Then `cargo xtask check` verifies generated data, typed
contracts, pins, migration retention and all portable regression cases. CI runs
actual source signature verification, native builds, configuration validation,
HTTP execution and offline import in both userspaces before publication.

## Breaking migration

`forSystem`, `resultSystem`, `toolsSystem`, fixed `versioned_*` references, the
compiled bootstrap fixture and legacy unversioned factories were retired. Use
`forPlatform` and an exact version. `hello_version`, `glibc_version`, `git_version`
and `zlib_version` selectors became `hello`, `glibc`, `git` and `zlib` respectively.
Managed glibc now takes `(selection, seed)`; Git and zlib also retain explicit
providers. Existing published releases and their pinned core commits remain
available. Current locks retain historical identities while new source layout,
std and contract revisions produce new identities.

The systemd wire contract is owned by the core. Export it with `srx host contract`;
read-only host inspection checks actual interfaces on existing units, not distro
version strings. Permission, FDSTORE and lifecycle qualification need explicit
operation-specific tests. CI userspaces belong in `.github/qualification-hosts.json`,
not in runtime toolchain profiles.
