<p align="center"><img src="assets/syrox-pkgs.png" width="300" alt="Syrox Packages" /></p>

# Syrox Packages

Pinned package recipes and configuration contracts for [Syrox](https://github.com/ryro-hq/syrox).
The version inventory starts with Hello 2.12.1 and nginx 1.30.5/1.30.6 on Linux
x86_64 GNU and musl. Packages and services configure the existing Linux host.

```srx
inputs { pkgs = "path:../syrox-pkgs"; }

services.nginx = {
    enable = true;
    package = pkgs.nginx { version = "1.30.5"; };
    settings = {
        listen = 8080;
        proxyPass = "http://127.0.0.1:3000";
    };
};
```

Use `pkgs.forSystem("linux-x86_64-musl").nginx` for musl. A project can select
both systems. The package reference keeps the version, variant, system and
nominal `.srx` contract through configuration checking. The minimal nginx builds
support HTTP proxying; TLS, rewrite and gzip options are outside that contract.
`extraConfig` accepts text and is checked with the selected `nginx -t` in an
isolated runtime before generation freeze. Exact versions and string constants
are supported. Adding a version preserves the default and all prior source pins.

## Check and maintain

`catalog.toml` fixes official origins, stable channels, signing-key fingerprints,
recipes, contracts, toolchain specifications and every version/variant/system
combination. `Catalog.lock` binds their bytes; `Syrox.lock` pins the complete
module and standard-library inventory. Signing-key changes require an explicit
lock operation. Existing upstream content cannot be replaced.

```sh
srx catalog check .
srx catalog lock .
srx catalog lock . --check
srx catalog matrix .
srx catalog verify-sources .
srx catalog updates .
srx catalog add . nginx 1.30.7
```

The final command is an example for a signed release present upstream. It copies
version-specific recipes, verifies the fixed signing key and generates locks.
Recipe and toolchain changes retain prior identities in the lock history.
GNU and musl builds use GNU Linux tools with explicit result systems. Actual
compiler inventories and worker bytes are authenticated in each build receipt.

## Qualify and distribute

A configured build host supplies systemd user services, Bubblewrap, setpriv
Landlock support, gcc, musl-gcc and an explicit `/usr` toolchain. Run the native
qualifier for every identity emitted by the matrix:

```sh
srx catalog qualify . --identity SHA256 --config build.toml \
    --store ./store --output ./qualification
srx catalog release-manifest . --evidence ./qualification --output manifest.json
```

The qualifier performs real builds and native execution, nginx HTTP and shutdown,
valid and invalid native configuration checks, and import and execution in a
fresh offline Store. The release manifest requires every combination and rechecks
all transported artifact pins. Availability requires successful qualification.
GitHub Actions qualify every matrix row in the pinned Linux VM and publish only
after integration on `main`, with release immutability enabled. The daily update
workflow requires `SYROX_UPDATES_TOKEN` (contents, pull requests and actions write)
because the organization blocks PR creation by `GITHUB_TOKEN`. Bot PRs receive
checks against their exact head SHA; promotion of a default is a separate change.
Legacy bootstrap and managed factories remain experimental and require explicit
providers; their existing sources and tests are preserved.

Licensed under [Apache-2.0](LICENSE).
