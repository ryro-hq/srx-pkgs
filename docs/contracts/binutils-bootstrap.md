# Source-built binutils bootstrap

`binutils_bootstrap` selects the exact GNU binutils `2.47` source for Linux
x86_64 GNU and builds an `x86_64-srx-linux-gnu` target. The convenience export is
`bootstrap_binutils_2_47_gnu`. Its `HostBootstrap` profile requires the
administrator's explicit `/usr` seed, whose authenticated inventory participates
in the action. It is an experimental bootstrap component, not a complete managed
toolchain or qualified catalog release.

```srx
inputs { pkgs = "path:../syrox-pkgs"; }
pub let tools = pkgs.binutils_bootstrap { version = "2.47"; };
```

The source is the unchanged upstream xz archive, with a 32 MiB compressed ceiling
and the existing Large profile's independent expanded, file, scratch and process
limits. GNU long-name metadata in the upstream tar must pass the core's bounded
path validation; no host tar executable performs extraction.

The build explicitly selects gcc/g++, make and shell from the admitted seed.
It disables shared libraries, plugins, gettext, debuginfod, system zlib, zstd, libctf,
gprof/gprofng and GDB. Libtool receives `AM_LDFLAGS=-all-static` in addition to
the configure compiler's `LDFLAGS=-static`; libtool's `-static` alone does not
exclude a dynamic libc. Runtime ELF admission must verify the produced bytes
before claiming that no loader/library providers are needed.
The output has nine prefixed commands: `as`, `ld`, `ar`, `nm`, `ranlib`,
`objcopy`, `objdump`, `readelf` and `strip`, plus linker scripts and upstream
COPYING notices and the bundled zlib license. The authenticated source archive's
bundled zlib is built and linked statically. Info/manpage generation is skipped
explicitly through upstream make variables; no documentation is exported.
The configured sysroot is an empty, declared output directory;
it supplies no target headers or libraries.

Before collecting outputs, the recipe uses the newly produced tools to assemble
a Linux x86_64 `_start`, create and index a deterministic archive, link it without
libc, inspect symbols/headers/disassembly, extract debug information, strip and
execute it. Any unsuccessful step prevents publication. This smoke test does not
replace the upstream testsuite, compiler qualification or a boot test.

`managed_binutils_probe(tools)` consumes one explicit tools output and the
catalog's pinned `assets/binutils-probe-x86_64.s`. Its `Managed` profile invokes
only the selected assembler/linker and the produced executable, with an empty
PATH and no host toolchain mount. The convenience export
`source_built_binutils_probe` selects this catalog's bootstrap output. The probe
prints `SRX source-built binutils` and exits successfully only when its write
succeeds. Its action and receipt must establish the actual input closure; the
declaration alone is not execution evidence.

## Source admission

The [upstream 2.47 announcement](https://sourceware.org/pipermail/binutils/2026-July/150520.html)
publishes the selected archive's SHA-256:

```text
154ab23b60070e8f27013c22977f1129425d67d1e8acd6e13010e617811e4cff
```

On 2026-10-21 the detached
[`binutils-2.47.tar.xz.sig`](https://sourceware.org/pub/binutils/releases/binutils-2.47.tar.xz.sig)
was verified against the compressed archive using the official
[GNU keyring](https://ftp.gnu.org/gnu/gnu-keyring.gpg). GnuPG reported `GOODSIG`
and `VALIDSIG` for Nick Clifton's primary fingerprint
`3A24BC1E8FB409FA9F14371813FCEF89DD9E3C4F`. The detached signature's SHA-256 is
`9fa42a8770ff1fdb3059a6d5c7b7030899acee58b343364bc42b6facfa35ce65`.
The minimized public key is retained in [`keys/binutils.asc`](../../keys/binutils.asc),
SHA-256 `6e74acf35f0590dc20cb0eed40be78bceb672bc8e3714ebd7e149e7401cc7d2a`.
This source-admission review does not automatically authorize later versions.

The archive was imported through `srx project import-source` against its locked
request. The URL and content pin were preserved. One
[native build and managed-consumption probe](../evidence/binutils-2.47-bootstrap-and-managed-probe-2026-10-22.md)
completed successfully, including static ELF closure validation and offline
runtime execution. This does not qualify an independent compiler/sysroot chain
or a complete system bootstrap.
