# Canonical musl toolchain

The previous Debian 13 guest linked the affected `musl-dev`
`1.2.5-3.1~deb13u1`. The
[Debian security tracker](https://security-tracker.debian.org/tracker/CVE-2026-107891)
records the fix in `1.2.6-2`, available in Forky but not Trixie. The canonical
Debian image is digest-pinned and installs the exact `musl`, `musl-dev`, and
`musl-tools` versions from its signed APT repository. Ubuntu 24.04 remains
the independent qualification guest; its bundles are not published.

[Debian Forky is Debian 14](https://www.debian.org/releases/forky/), but its
image omits `VERSION_ID` while still in testing. Syft then emits
`distro=debian` without a version, which makes Grype match unrelated legacy
suites. Release preflight checks the actual `ID` and `VERSION_CODENAME`,
bound by the guest metadata to the qualified image, before using Grype's
Debian 14 advisory namespace for the exact installed musl package. The
original Syft SPDX and `os-release` are retained. Unknown distros, ambiguous
identities and unexpected package versions fail instead of guessing.

No VEX or exclusion is used for musl. The Debian 14 advisory feed still
matches versions below the fixed `1.2.6-2` threshold.
