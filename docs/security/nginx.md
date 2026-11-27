# nginx 1.30 security backports

The exact 1.30.5 and 1.30.6 selectors and their signed source archives are
retained. New builds apply the relevant upstream `src/` and `auto/` changes
through 1.30.8 before configuration. The backports leave the version-only
`src/core/nginx.h` change out so that the original selectors and runtime
version checks remain valid. New 1.30.8 builds use its signed release directly.

The fragments in `assets/nginx/` were generated from the upstream
`release-1.30.5..release-1.30.6` and `release-1.30.6..release-1.30.8` tag ranges,
with `git diff --no-renames --full-index -- src auto ':(exclude)src/core/nginx.h'`.
They are split at file boundaries to fit bounded build literals. Verify both
backports against the signed 1.30.8 tarball: after zero-fuzz application, every
file under `src/` and `auto/` matches it except the retained `nginx.h`.
The guest and managed builds use the same fragments. The managed seed must
provide `usr/bin/patch` in its tools output.

The pinned core evaluates the catalog selector without an asset environment.
`cargo xtask security nginx-patch-module --write` generates the recipe module
from the authenticated fragments. Both portable checks and release preflight
reject mismatches between the module and those files.

The [upstream advisory list](https://nginx.org/en/security_advisories.html)
identifies the fixed release for each Critical finding from the original scan.
The candidate VEX statements apply only to the two new patched PURLs, exact
source archives, and authenticated GNU and musl recipes. They do not match
previous unpatched builds. New or unrelated findings, including findings in
linked libraries, remain visible and subject to the normal severity gate.
The candidates still require independent review and new native qualification.
