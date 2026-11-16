# GNU make bootstrap

The experimental `make_bootstrap` selects exact GNU make `4.4.1` for Linux
x86_64 GNU. `bootstrap_make_4_4_1_gnu` is its convenience export. It requires
the explicitly admitted `/usr` host seed and keeps the existing Standard
resource envelope, 4 MiB source bound and 600-second deadline. It builds a static
`usr/bin/make`, with upstream COPYING, without gettext, Guile, dynamic `load`
or posix_spawn. Before output collection the newly built make must generate
a file through its builtin file function, compared with the exact expected
bytes by the seed's explicitly selected cmp.

`managed_make_binutils_probe(make, binutils)` selects two explicit outputs and
the pinned `assets/make-binutils-probe.mk`. Its Managed profile invokes the
source-built make to generate assembly, run the selected source-built assembler
and linker, then executes the result. Builtin compiler rules/variables are
disabled. The fixture has only direct command invocations; general makefiles
still need an explicitly supplied shell and other tools. Its declaration does
not prove successful execution. The convenience export is
`source_built_make_binutils_probe`. A native bootstrap, Managed consumer and
runtime bundle have now passed; their exact identities and limits are recorded
in the [development evidence](../evidence/make-4.4.1-bootstrap-and-managed-probe-2026-10-22.md).

## Historical source admission and open qualification issue

The unchanged [GNU archive](https://ftp.gnu.org/gnu/make/make-4.4.1.tar.gz)
has SHA-256
`dd16fb1d67bfab79a72f5e8390735c49e3e8e70b4945a15ab1f81ddb78658fb3`.
Its detached signature SHA-256 is
`b0085e6c3f9a7461e739786a8d28dec9aeb090335bb8818e42b497fdeb73b929`.
The [upstream announcement](https://lists.gnu.org/archive/html/info-gnu/2023-02/msg00011.html)
dates this exact release to 2023-02-26.

On 2026-10-22 GnuPG cryptographically verified that signature and reported
`VALIDSIG` for signing subkey `B2508A90102F8AE3B12A0090DEACCAAEDB78137A`,
primary `6D4EEB02AD834703510B117680CB727A20C79BB2` (Paul D. Smith).
The GNU keyring's subkey certification expired on **2026-10-20 21:36:15 UTC**,
so current verification also reports **EXPKEYSIG**. Retrieving the same primary
key from the Ubuntu public keyserver preserved that expiry; no renewed
certification was found. The minimized public key is retained in
[`keys/make.asc`](../../keys/make.asc), SHA-256
`d2e9570fa913c8c03168580e5fba3ad33b9b3649aa424f1d1537b2f1b525e7c2`.

This experiment pins a historical source whose signature predates that expiry.
It does not claim a currently valid signing subkey, suppress expiry diagnostics,
backdate verification or authorize new releases signed by the expired subkey.
Resolution of this temporal source-admission policy remains an **open release
qualification issue**. The recipe is outside `catalog.toml`'s qualified matrix;
native development execution alone cannot qualify its publication or the full
managed bootstrap. Compiler/sysroot, shell/auxiliary tools, reproducibility and
complete system qualification remain separate work.
