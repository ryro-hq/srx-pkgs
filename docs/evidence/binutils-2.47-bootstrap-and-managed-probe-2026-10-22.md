# Binutils bootstrap and managed consumption, 2026-10-22

One native Linux x86_64 GNU build of the experimental
[binutils recipe](../contracts/binutils-bootstrap.md) and one managed consumer
completed successfully. The core/catalog had uncommitted changes. This is
bootstrap/consumption evidence, not a qualified catalog release, an independent
compiler/sysroot bootstrap or a bootable operating system.

The upstream xz archive passed SHA-256 and maintainer-signature verification as
recorded in the contract, then entered the Store through `project import-source`.
The build stayed offline and explicitly admitted the `/usr` seed. The SRX tar
walker admitted 30,016 records, 30,001 regular files and 310,125,784 expanded bytes,
including bounded GNU long-name metadata. No host tar utility performed extraction.

```text
source     154ab23b60070e8f27013c22977f1129425d67d1e8acd6e13010e617811e4cff
worker     320d7a837cfc3d5ec82eed17219032849e50c03b2e482f8531d30092cfa1c4cb
toolchain  9732f4f6ebd8db5569fb809bded6e439eeb99ad423b0f1d74a1b946f08084d80
action     1d08eca2014133b774c949acb46bcf96f20bde91647d0d96e943150e1c183962
artifact   66e56f60e4d18b5c22e472f78f2a154b1f5bfc2fe119b17825f48895fbedece9
receipt    40ae640c405471a4a3130e870bad82423285ab13f4a1589820fd2fba5ce55102
lock       480f913b3fa45f9ee16cb179e17cf23f0b5d6993a4f7ec33bed3b495b5639e31
```

The existing Large envelope enforced 1,536 MiB memory, 256 tasks, CPU 100%,
4,096 descriptors, 1 GiB work tmpfs and 128 MiB output. Timeout was 1,800 seconds.
The output has 108 files, including nine static tools, linker scripts, an empty
declared target sysroot and license notices. The recipe required successful
assembly/archive/index/link/header/symbol/disassembly/debug/strip/run steps before
output collection. All nine executables independently passed host `readelf`
inspection with no `PT_INTERP` or `DT_NEEDED`. Assembler and linker hashes:

```text
as  d10d36b9673447dad9d0918b857e168c5a4d2ec4054f3af42b45e1e1c27103cb
ld  d21e20dbf91a17f7d2ccefc9eafedcec050db302f3441b384184a5653dc720da
```

## Managed consumer

`source_built_binutils_probe` selected that precise output as its only tools
input and the pinned catalog assembly source. It ran the assembler, linker and
produced executable in a Managed namespace with an empty PATH and no `/usr`
toolchain mount. Its source and result identities:

```text
source    72484eadade977eb301a4d7e893dca5f4861507c46b6e418c77edd33d2ddcab7
worker    1e448137838a57bd592464aab72bf7389533539d923e1300d35d568ebe5045ae
action    1d83c27db85d4182e7bfc7eea6d8b3668b43c0a5e44b4da86603c2d41c441cb7
artifact  4452d0f4cfa5c731cbe8c3868caa609779ee8e2cae91f0edf5f408acfd47551e
receipt   fe1674e68c3031c4452084d59d94c61e4f9e489375dbc6decb10e39bdbf29a3f
```

The Managed receipt records `toolchain none`, two output files and five retained
producer references: the binutils source, action, receipt, output and seed
inventory. Both receipts record `payload-settlement subreaper-echild` and
`settlement systemd-unit-inactive-or-collected`.

The worker was explicitly built as a static GNU ELF with the local Rust
development toolchain, copied into a private builder directory and pinned by
SHA-256. It had no ELF interpreter or dynamic dependency. That is an admitted
development worker; this evidence does not establish a source-built Rust compiler
or reproducible worker bootstrap.

## Runtime bundles

Export independently validated the ELF closures without loader/library providers.
The probe bundle then ran offline in the SRX runtime, exited zero and printed
`SRX source-built binutils`.

| Command | Result manifest SHA-256 | Bundle SHA-256 |
|---|---|---|
| as | `4343476a3825c895d64410389e57a04caf6ebd21bdd1b5e56202fdd006060442` | `476e8dc237543dd4a0ccc6599cf90ffdbe8c6d65d58ffceb15695df2cb4e7eb8` |
| ld | `0beebc573d8ca6530b3b9501a239c36bfbfe0437cb5207759ed65eed4e0e9270` | `30daf845c3fe6793389796dfb6fda1aebf3aa83cfffa166e9870e5ff8a16f5f4` |
| probe | `6385731c3a643fc6f16d67c7c688fc4114356c063cd6870622b3a9e03d2ee936` | `ac60d822cc4a9eaf6f6c116c748ea792fc35ecabdcde5fa1f8f6bfe4f89ce0f5` |

The local Store is `../syrox/.syrox/system-bootstrap-store`, with
`build_<receipt>` and `result_<manifest>` roots. Logs and bundles are under
`../syrox/.syrox/work-logs/`. These local paths are not publication endpoints.
The old dynamic output and receipts retain their own identities; they were not
relabelled as static outputs.

Still required: a source-built compiler, libc/sysroot, auxiliary tools and Rust
chain; complete system resource enforcement; rebuild/reproducibility evidence;
full licenses/SBOM/vulnerability/publication gates; kernel/userspace and firmware
boot qualification. No block device or host boot setting was modified.
