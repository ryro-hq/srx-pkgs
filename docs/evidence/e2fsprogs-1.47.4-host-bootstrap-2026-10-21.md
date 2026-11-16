# Native e2fsprogs bootstrap evidence, 2026-10-21

This records one successful native Linux x86_64 **host bootstrap** build from
the experimental [recipe](../contracts/e2fsprogs-bootstrap.md). It is not a
qualified catalog release, a managed compiler bootstrap, a system image or a
boot/storage-stack qualification. The core and catalog had uncommitted changes.
The executable worker and admitted host inventory are bound by the action below.

The official 1.47.4 xz archive was downloaded, checked against its pinned SHA-256
and verified with the maintainer signature over the uncompressed tar. It was
then imported using `srx project import-source`, without changing the upstream
URL or pin. Inspection admitted 2,796 tar entries, 2,333 regular files and
37,390,701 expanded file bytes, including the contained RELEASE-NOTES link.
The subsequent build used `--offline` and the explicitly configured `/usr` seed.
No network resolver fallback or ambient undeclared toolchain was used.

```text
source     fd5bf388cbdbe006a3d3b318d983b2948382440acc85a87f1e7d108653e8db0b
worker     d56532a16249efd3c160b2565868f00d5313d3e2aece3367a206b8cfe7905c71
toolchain  9732f4f6ebd8db5569fb809bded6e439eeb99ad423b0f1d74a1b946f08084d80
action     29884d21380056c158ab2ae9a574ca1b1595c7544507a3d2c5b898d585cf0b9b
artifact   c32afad9bc20a3fc56d1bc9af7f6e0167ad6d3cffb35dcea23431175794c3a6f
receipt    bef87c82ca4130c8b34ad67587194ba92e47bc51aaa7d530df30f7eecdff8eac
lock       9cef4d901f55ae90cd9db594ae73de199cdce10fc75be6de40bb239eb0197e77
root       build_bef87c82ca4130c8b34ad67587194ba92e47bc51aaa7d530df30f7eecdff8eac
```

The receipt is `syrox-build-result-v4` with 71 output files. It records
`payload-settlement subreaper-echild` and
`settlement systemd-unit-inactive-or-collected`. The existing Large envelope
enforced 1,536 MiB memory, 256 tasks, CPU 100%, 4,096 descriptors, 1 GiB work
tmpfs and a 128 MiB output limit. The recipe's timeout was 900 seconds.

The build compiled bundled uuid/blkid and the three static targets. Before
collecting outputs it used the newly built mke2fs to create a 64 MiB regular
ext4 image in private `/work` (4 KiB blocks, 1,024 requested inodes, no reserved
block percentage, synchronous inode-table/journal initialization), then required
`e2fsck -f -n` to succeed. `MKE2FS_CONFIG=/dev/null` excluded host mkfs policy.
The temporary filesystem was not mounted and is not an exported rootfs.
No host block device or boot setting was modified.

The verified runtime admitted and exported each executable with no loader or
library providers. Independent `readelf` inspection also found no ELF
interpreter/dynamic dependency section. Executable hashes:

```text
mke2fs    59935ec5c57f7f3b2e5ef1119d7480275264a9f5adecb862b7bd2ae813fd83ec
dumpe2fs  8290839adc84fc54a4317262443b7a40beb934ef270820ca57ee32e8a666380f
e2fsck    da1f6de6ac3a2efd7fc6d2581199ce7109a22dee7843ce923e4111a92666a95a
```

Each runtime `-V` invocation exited zero and reported 1.47.4. e2fsck initially
reported a missing `/dev/null`; the direct runtime was corrected to bind only
the validated Linux null device. Repeating e2fsck with the same admitted
artifact and corrected runtime succeeded without that diagnostic. The source
tools and their existing receipt were not rewritten by this runtime correction.

Separate runtime bundles were exported locally:

| Command | Result manifest SHA-256 | Bundle SHA-256 |
|---|---|---|
| mke2fs | `01e9d0dba5cfee8c6e039360295a938438f20ae68939f84e6d8a80c43212947e` | `7c4a0736156505762bbcc457c320267f40721c4a2bf8b97c8d1a9535b6fcfa42` |
| dumpe2fs | `18cdd35b898d39a5ef3f5758ff91431e6e26f2b9242b9af28995c0bddf5720bb` | `cdcfd608bc929626bcfd992d1cc127eb92b237f42e0c886f4999700c1f17a310` |
| e2fsck | `922d66c93414c1b480f2568fb8a10759729b0586fa0571aab02e717cd0fcdd91` | `b84966cf0b15972e15be4d950b191df546b47c445ab7313a2f908439f94b1d8e` |

The local Store is `../syrox/.syrox/system-bootstrap-store`. Bundles were
exported to `/tmp/srx-e2fsprogs-{mke2fs,dumpe2fs,e2fsck}-20261021.bundle`;
those temporary files were subsequently cleared by an environment reset. The
result roots and Store objects remain available for export. These paths are
local observations, not published distribution endpoints. The Store root retains
the action, source, inventory, output and receipt. A future core/worker or recipe
change must produce its own action and evidence rather than relabel this result.

Still required: rebuild with the managed source-built toolchain; qualify byte
and inode exhaustion on a mounted private scratch filesystem, helper recovery,
concurrency and cancellation; establish deterministic outputs and complete
publication provenance. This build does not establish any of those properties.
