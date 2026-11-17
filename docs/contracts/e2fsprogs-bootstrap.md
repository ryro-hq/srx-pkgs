# e2fsprogs bootstrap tools

The experimental `e2fsprogs_bootstrap` factory selects source version `1.47.4`
for Linux x86_64 GNU. It produces static `mke2fs`, `dumpe2fs` and `e2fsck`
executables, with the upstream NOTICE and uuid/et library notices and sources.
It uses the explicit `HostBootstrap`
profile and requires the builder administrator to select `/usr`. Its host
toolchain inventory is part of build identity. This is a bootstrap input for
builder development, not a toolchain-independent system component.

```srx
inputs { pkgs = "path:../syrox-pkgs"; }
pub let filesystem_tools = pkgs.e2fsprogs_bootstrap { version = "1.47.4"; };
```

The catalog also exports `bootstrap_e2fsprogs_1_47_4_gnu`. Other versions,
architectures and libc selections fail during checking. The recipe uses the
existing Large envelope, with a 900-second deadline and source ceiling of
8 MiB. It explicitly selects the xz source format, which admits the upstream
`RELEASE-NOTES` link to a verified regular file in a descendant directory.
It builds bundled uuid/blkid and disables gettext, libarchive, fuse,
shared libraries and optional libmagic/dlopen features. The explicit upstream
static targets are linked with `LDFLAGS_STATIC=-static`. Output admission and
runtime ELF verification remain responsible for checking actual produced bytes.

The source URL and SHA-256 in `releases.srx` were checked against
[kernel.org's published checksums](https://www.kernel.org/pub/linux/kernel/people/tytso/e2fsprogs/v1.47.4/sha256sums.asc):

```text
fd5bf388cbdbe006a3d3b318d983b2948382440acc85a87f1e7d108653e8db0b
```

On 2026-10-21 the detached upstream `e2fsprogs-1.47.4.tar.sign` was verified
against the **uncompressed tar**, following the
[kernel.org procedure](https://www.kernel.org/signature.html). The maintainer
primary fingerprint is `3AB057B7E78D945C8C5591FBD36F769BC11804F0`;
the signing subkey is `2B69B954DBFE0879288137C9F2F95956950D81A3`.
The direct kernel.org WKD copy initially had expired subkey certifications.
Updating the same primary key from the official Debian keyring provided current
self-signatures; the final verification reported `GOODSIG` and `VALIDSIG`
without `EXPKEYSIG`. The minimized public key is retained in
[`keys/e2fsprogs.asc`](../../keys/e2fsprogs.asc), SHA-256
`3fa550eda5199a73495301f2fdae2f85ce749d376d5bd5311bf5d43b82bc5cc7`.
This admission review does not automatically trust subsequent upstream versions.

This recipe is not in the qualified release matrix. One
[native source build and runtime check](../evidence/e2fsprogs-1.47.4-host-bootstrap-2026-10-21.md)
succeeded, including creation and e2fsck verification of a disposable 64 MiB
regular image. Mounted scratch enforcement, managed toolchain construction,
reproducibility and qualified publication remain pending. These tool checks do
not qualify the complete ext4 stack or privileged provisioning. No authority
over disks follows from selecting these tools.
