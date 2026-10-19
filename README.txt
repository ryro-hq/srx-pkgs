Syrox package catalogue

The top-level declaration `pub publish(catalog, recipe): std::Recipe;` publishes
lazy typed recipe references independently from deployment outputs. Enumeration
and named access share the same references without executing recipe factories.
Parameterized factories and service integrations use ordinary pub fn/pub use.

This catalogue targets native Linux x86_64. Recipes declare build outputs and
zero or more named commands. Building an output does not choose an executable.
The glibc recipe owns its packaging program and produces dev and out; GNU Hello
uses dev and out during its build and declares the hello command in out.

With a configured Linux build host and pinned sources available:

    srx project lock .
    srx build .#hello --config /path/to/config.toml --store /path/to/producer
    srx run .#hello --command hello --config /path/to/config.toml \
        --store /path/to/producer -- --greeting 'Olá'

The build configuration supplies [build] host-toolchain = '/usr' and authorizes
the exact source URLs declared in recipes/hello_source.srx and recipes/glibc_source.srx when
network acquisition is required. The core documentation describes the systemd,
namespace, worker and isolation requirements for the build host. Offline build
and run use -o and require their build inputs already retained locally.

Recipe and environment selection

A command declares name, output and relative executable path; its loader selects
an OutputRef plus a relative path, and its libraries select OutputRefs. Multiple
commands may share one output or use different outputs. Outputs without commands
are data and have no placeholder executable. Command names must be unique within
a recipe. The standard library's Build and BuildOptions do not have an entry
field.

For example, an environment may select these references from this catalogue:

    pkgs = [
        std::select_command(project::hello, "out", "hello"),
        std::select_output(project::glibc, "dev")
    ];

The helper select_package(recipe) selects out without exposing commands.
CLI execution selects a published member and named command explicitly:
srx run .#hello --command hello. Selecting an unknown command or an output that
does not contain it fails during planning.

Portable consumption

After a build, keep the reported root and receipt for Hello and glibc. Substitute
those values below; GLIBC_ROOT is normally build_<GLIBC_RECEIPT>. The destination
bundle file must not exist.

    srx bundle export --store /path/to/producer \
        --root HELLO_ROOT --receipt HELLO_RECEIPT \
        --artifact-output out --entry usr/bin/hello --name hello \
        --loader-root GLIBC_ROOT --loader-receipt GLIBC_RECEIPT \
        --loader-output out --loader-entry usr/lib/ld-linux-x86-64.so.2 \
        --library GLIBC_ROOT@GLIBC_RECEIPT@out --output /path/to/hello.bundle

Export reports "manifest <sha256>". Supply the independently approved manifest
digest when importing; import does not obtain its authorization from the bundle.

    srx bundle import --store /path/to/receiver --root hello_import \
        --manifest-sha256 MANIFEST_SHA256 --file /path/to/hello.bundle
    srx bundle inspect --store /path/to/receiver --root hello_import \
        --manifest-sha256 MANIFEST_SHA256
    srx bundle run --store /path/to/receiver --root hello_import \
        --manifest-sha256 MANIFEST_SHA256 --command hello -- --greeting 'Olá'

Bundle execution needs no project, source archive, compiler inventory, build
configuration or network acquisition on the receiver. The current canonical
manifest version is syrox-result-v2, carried by syrox-runtime-bundle-v1 transport.
Output metadata describes artifacts; command metadata separately carries
application_path and loader_path. Imported provenance remains distinct from
built provenance. The CLI currently exports one chosen command per invocation;
the manifest and engine support data outputs and multiple commands.

Candidate verification

Run this gate with explicitly selected core sources and binaries:

    python3 scripts/test-candidate.py --core /path/to/syrox \
        --candidate-bin /path/to/srx

It records the candidate SHA256, pins temporary copies of srx and its adjacent
syrox-worker, locks an isolated catalogue copy, plans Hello, and tests glibc
partitioning. It does not depend on a sibling checkout. Build and retained-output
host tests remain opt-in:

    python3 scripts/test-candidate.py --core /path/to/syrox \
        --candidate-bin /path/to/srx -- -- --ignored

Host fixtures use SYROX_GLIBC_ARCHIVE, optional SYROX_HELLO_ARCHIVE, and for retained
result inspection SYROX_REALIZED_GLIBC_STORE and SYROX_REALIZED_GLIBC_RECEIPT.
The Hello host test also exports/imports between Stores, checks that source,
toolchain and build records were not transferred, and runs the imported command.
Skipped host tests are pending validation, not successful execution proofs.

Managed Git and nginx integration

The catalogue exports git_service(tool, configuration) and
nginx_service(tool, configuration). Each takes an author-selected RecipeRef;
the recipe must declare the command git or nginx respectively. Neither helper
searches PATH or supplies a host binary. Their service IDs are git and nginx,
so instantiate each helper at most once in a consumer.

Git writes the supplied public text as its private gitconfig. Its exposed git
command receives GIT_CONFIG_GLOBAL pointing to that declared file. nginx writes
its private nginx.conf, invokes the managed nginx command with -c pointing to
that file and the literal arguments -g 'daemon off;', and declares the server
process. File arguments are typed configuration references, resolved only within
the service. Configuration is public plan content and must not contain secrets.
The nginx configuration must use destinations accessible to the session; the
helper does not create privileged ports or host log/cache directories.

A consumer with an imported catalogue and managed recipe references can use:

    services = [
        catalog::git_service(project::git_tool, "[core]\n    filemode = false\n"),
        catalog::nginx_service(project::nginx_tool,
            "events {}\nhttp { server { listen 8080; location / { root /tmp/www; } } }\n")
    ];

Experimental source factories live in recipes/git.srx, recipes/nginx.srx and
recipes/zlib.srx: managed_git(toolchain, libc, zlib, runtime_tools), managed_nginx(toolchain, libc)
and managed_zlib(toolchain, libc). The zlib factory supplies dev/out library
outputs with no command. They require
author-selected managed RecipeRefs; no recipe() export advertises an unavailable
seed. Toolchain holds compiler/python/runtime/sysroot/tools OutputRefs. Git also
requires a separate runtime_tools output with validated static bin/sh and bin/cat;
these must not be copied from the dynamic seed. Git is a minimal builtin/configuration binary without HTTPS or scripted
helpers. nginx supplies core HTTP/static serving without TLS, rewrite/return,
PCRE or gzip. The example above requires separately provisioned /tmp/www content.

The catalogue exports managed_glibc(toolchain), requiring the complete bootstrap
sysroot described in MANAGED.txt and producing dev/out for downstream factories.
It shares the existing glibc source pin and preserves the default HostBootstrap
recipe. Its projection test connects it to managed_hello without executing tools.

The catalogue also exports managed_hello(toolchain, libc), using the same pinned
Hello source as its default HostBootstrap recipe. Its declared inputs are the Toolchain outputs
compiler/python/runtime/sysroot/tools plus libc/dev and libc/out; its runtime command retains only libc/out.
The shared managed_build helper supplies explicit compiler, headers, crt, shell,
PATH and loader flags. These declarations have projection tests, not build proof.

The managed compiler/shell/make seed is still missing. The source factories
declare BuildProfile::Managed and require explicit Managed execution configuration.
The seed must be an admitted ImportedResult with five outputs; the legacy single-out
seed extractor has been removed. Relocation and real build/transfer gates remain pending.
The existing Hello/glibc/bootstrap recipes use HostBootstrap. Only pure projection has passed; builds,
source archive/signature verification and service execution remain pending.
MANAGED.txt records output layouts, checksum provenance, feature limits,
usage and the real-host acceptance gates. These pins are experimental and have
not been approved or promoted.

K3s configuration preparation
=============================

packages.k3s selects the official Linux amd64 binary 1.37.1+k3s1. Its SHA-256
92b94582eb7b34a8cf532e6006842b9ed215a6783cf56a3dd6271fd35243b2c0 matches
https://github.com/k3s-io/k3s/releases/download/v1.37.1%2Bk3s1/sha256sum-amd64.txt.
The recipe uses the bounded Large resource profile for this 82 MB raw source.

The nominal Settings contract renders YAML through std::yaml. services.k3s
prepares k3s.yaml and explicit server/agent commands. It registers no processes.
Tokens stay in administrator-provided protected files; plans contain their paths.
Privileged activation, provisioning and RKE2 are outside this package.

The examples separate shared cluster settings, per-host TOML data and service
settings. initial-server initializes a server, joining-server joins a server,
agent prepares an agent, and existing-yaml edits a larger YAML document while
preserving comments and unknown options. These describe configurations; they
never start a cluster during check, plan or version verification.

Local project inputs must be siblings. Materialize that supported layout:

  python3 examples/k3s/prepare.py /tmp/k3s-workspace
  srx project lock /tmp/k3s-workspace/packages
  srx project lock /tmp/k3s-workspace/shared
  srx project check /tmp/k3s-workspace/initial-server
  srx project lock /tmp/k3s-workspace/initial-server
  srx project plan /tmp/k3s-workspace/initial-server --output os

Check every example without executing K3s:

  python3 examples/k3s/check.py --srx /absolute/path/to/srx

On a configured Linux build host, realize the pinned package and check its version:

  srx project lock /tmp/k3s-workspace/existing-yaml
  srx shell /tmp/k3s-workspace/existing-yaml#dev --command k3s --non-interactive \
    --config examples/k3s/build.toml --store /absolute/private-parent/store -- --version

Use --offline when the authenticated source is already retained in that Store.
