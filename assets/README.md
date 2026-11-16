# Host bootstrap for the first dynamic Hello proof

`bootstrap-glibc-host-x86_64.tar.gz` is a byte-pinned, project-local source
(`project:assets/bootstrap-glibc-host-x86_64.tar.gz`), not an independently
portable glibc build or a download from the runtime host. The recipe pins its
compressed SHA-256 (`09bede497713ef311ca7e35a24942b67faaf2beaa879c74d39b4e48defdb4941`).

This initial bundle comes from GNU libc 2.44 on the Linux x86_64 bootstrap
host. The exact input SHA-256 values are:

| Input | SHA-256 |
|---|---|
| `/usr/lib64/ld-linux-x86-64.so.2` | `d011113b7054c641c8ca064f58bcc23804fd2654a3dff2444dad06ddeda61bfb` |
| `/usr/lib64/libc.so.6` | `e221b10fee9ee4776d8f0f1701253bc06817f7a4dbe6c5292487277d0bf8ffff` |

The bundled libc has its standalone executable `PT_INTERP` program-header
type changed to `PT_NULL`. This leaves the library's loadable bytes intact and
prevents an embedded host loader path from becoming part of the Syrox runtime
closure. The resulting bundled libc SHA-256 is
`aa82cd54a22b3455be4e4c0a465f54a13a9b8e1a0be0106d27cc1f5c40e8fc3e`.
The archive also contains this host's `C.utf8` locale data under `locale/`;
the source digest pins every byte of it. All entries are regular files.

The generated source archive contains a bounded `configure` for the existing
Autotools host builder. It installs loader, libc and locale data together in
one output. The application build action identifies this provider receipt;
the build sandbox receives only the two pinned ELF inputs at their logical
paths. Runtime mounts the entire verified output, including locale data, and
sets `LOCPATH` to that logical output. It never mounts the host `/usr`.

The glibc binaries are under the GNU LGPL-2.1-or-later; upstream sources are
available from <https://ftp.gnu.org/gnu/glibc/>. This catalog bootstrap is a
host-specific integration fixture; replacing it with a sourced, reproducible
toolchain and runtime is the next portability cut.
