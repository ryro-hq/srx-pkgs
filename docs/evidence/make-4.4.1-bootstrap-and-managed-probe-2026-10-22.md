# GNU make bootstrap and managed consumption, 2026-10-22

One Linux x86_64 GNU native build of the experimental
[make recipe](../contracts/make-bootstrap.md), a Managed consumer and its runtime
bundle completed successfully. Core and catalog contain uncommitted changes.
This is development evidence, with an open signature-expiry qualification issue;
it does not qualify a catalog release or complete managed bootstrap.

## Source and native build

The exact historical GNU archive was imported offline against its declared
SHA-256. SRX admitted 416 tar records, 395 regular files and 8,780,526 expanded
bytes. Signature verification reported `VALIDSIG` **and `EXPKEYSIG`**, as detailed
in the contract. Verification used the current date, without suppressing expiry
or changing the verification clock. This experiment remains outside the
`catalog.toml` qualified matrix.

```text
source     dd16fb1d67bfab79a72f5e8390735c49e3e8e70b4945a15ab1f81ddb78658fb3
worker     320d7a837cfc3d5ec82eed17219032849e50c03b2e482f8531d30092cfa1c4cb
toolchain  9732f4f6ebd8db5569fb809bded6e439eeb99ad423b0f1d74a1b946f08084d80
action     02562f7c55357b1fee6cab7e34dca5e9c13b6c9a0c37ed01f4a185ec4fa18733
artifact   44d7d4aab29a9fc3585301cfe409ca28d1d203b7fdb53b0623b33214c2c58a64
receipt    d8b0f544a5d2c6a3a172249ccb5b8e14b887899114eb298dff70f949d7b1d235
lock       8ed29b69512328e30ff96045a52779afe3394819178657084cb2ea217706bd14
```

The explicit `/usr` seed supplied the compiler and supporting build tools.
The unchanged Standard envelope enforced 768 MiB memory, 64 tasks, CPU 100%,
256 descriptors, 384 MiB scratch tmpfs and 64 MiB output, with a 600-second
deadline. Two files were collected: static `usr/bin/make` and upstream COPYING.
The recipe tested the new make's builtin file function and compared its result
with exact expected bytes before collection. The make binary's SHA-256 is
`abd02bc6b1352a45f8e9f9aac79525cd81405e2c537d4df5ff3728eabf4fe9ef`.
Bundle export independently admitted its static ELF closure without loader or
library providers.

## Managed consumer

`source_built_make_binutils_probe` selected the make output, the previously built
[binutils output](binutils-2.47-bootstrap-and-managed-probe-2026-10-22.md) and the
pinned catalog Makefile. Make ran with builtin rules and variables disabled,
an empty PATH and no `/usr` toolchain mount. Its builtin file function generated
assembly, then direct invocations of the selected assembler and linker built
the probe. SRX executed it before collecting two files.

```text
source    bf78ee297a410832bc342260a07f6d1fdacdcb485f656c748764cf8cd8ade1fc
worker    1e448137838a57bd592464aab72bf7389533539d923e1300d35d568ebe5045ae
action    523c9e590c4ee1ede12beb78237ae75fc09962211f00059f3c6b51d97b150222
artifact  43546922d16828057a9297377201f45dc25ff2050dc93a472722f15da0003e10
receipt   44fd1d889ab3c84ce13b31d35d34e030022f2040c0530a819b0c2bfd97ec57f4
```

The receipt records `toolchain none` and nine retained producer inputs:
make/binutils sources, actions, artifacts and receipts, plus their shared seed
inventory. Both native and Managed receipts record
`payload-settlement subreaper-echild` and
`settlement systemd-unit-inactive-or-collected`.

The static development worker was built using the local Rust toolchain and
explicitly pinned. This does not establish a source-built Rust compiler.
This Makefile's commands use make's direct-execution path; general Makefiles
still require an explicitly supplied shell and auxiliary tools.

## Runtime bundles and remaining work

The exported probe ran offline in the SRX runtime and exited zero with no stdout.

| Command | Result manifest SHA-256 | Bundle SHA-256 |
|---|---|---|
| make | `8cb98ff8e11d20a4e0654f96031cfc9a67121314df01962d78e5a44e86daaa05` | `6fb8978c2e932b4cabe3086cc2c3be73f7216041f56da1328e72bc57dbc6b582` |
| probe | `3b6cf8a07fff9c13c791e18f8a0c3d99b8f0a5fa4c17f7f44568675a04014965` | `88b47a1c57838bd512f32b0acf2633b9e0d43c38cf75746de30708037fd99534` |

The local Store is `../syrox/.syrox/system-bootstrap-store`; logs and bundles
are under `../syrox/.syrox/work-logs/`. These are development paths, not release
endpoints. Build and result roots retain their distinct content identities.

Still required: resolution of temporal source admission; a source-built compiler,
libc/sysroot, shell, auxiliary tools and Rust chain; system resource enforcement;
independent rebuilds and publication gates; kernel/userspace and firmware boot
qualification. No block device or host boot setting was modified.
