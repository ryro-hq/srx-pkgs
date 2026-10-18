# Host systemd integration

`syrox-systemd-v1` describes the D-Bus interfaces used by the current engine.
The distribution supplies and updates the running manager, D-Bus, PAM and udev.
This directory is a host compatibility contract, not a systemd package recipe.
An application choosing musl still talks to the same host manager.

| Profile | Upstream baseline | Relevant interfaces |
| --- | --- | --- |
| `supervision` | systemd 250 | Transient services, job subscription and `ExitType=cgroup` |
| `managed` | systemd 254 | Supervision plus unit references and FD store metadata |

The baselines follow the engine's `systemd` module and upstream's
[250 service documentation](https://github.com/systemd/systemd/blob/v250/man/systemd.service.xml)
and [254 D-Bus interface](https://github.com/systemd/systemd/blob/v254/man/org.freedesktop.systemd1.xml).
The contract pins method, signal and property signatures. It accepts distro backports
by checking interfaces rather than rejecting a manager's version string.

`contract.toml` is generated from the core's request signatures and the actual
transient, Shell and persistent-service property observers. The D-Bus client uses
that same specification to validate requests and property replies. CI compares
the complete generated export with this file; the XML comparison tests alone
do not establish correspondence with the engine.

From the core checkout, export the current specification and then synchronize
the catalog checkout:

```sh
cargo run --locked -p syrox-engine --example systemd_contract > /tmp/systemd-contract.json
```

```sh
python3 hosts/systemd/sync.py /tmp/systemd-contract.json
python3 hosts/systemd/sync.py /tmp/systemd-contract.json --check
python3 tests/test-systemd-contract.py /tmp/systemd-contract.json
```

```sh
python3 hosts/systemd/check.py --profile managed --scope user
python3 hosts/systemd/check.py --profile supervision --scope system
python3 hosts/systemd/check.py --scope user --unit an-already-loaded.service
```

The check requires Python 3.11+ and `busctl`. It queries an explicitly selected
local socket and an already loaded service (default `dbus.service`). It never
starts, loads, stops or changes units. `--bus-socket /absolute/path` selects an
explicit local bus. An absent manager, unloaded service, missing interface or
changed signature produces JSON and a nonzero exit status. The report includes
the running manager's version, independent of the installed `systemctl` version.

`interfaces-observed` is a preflight observation, not native qualification.
Cgroup delegation, permissions, resource enforcement, namespaces, Landlock,
Bubblewrap, a matching worker and actual service execution are still checked by
the engine and the native VM suites. No distro-wide support matrix follows from
this probe. Linux hosts without systemd require a separate service backend;
ARM64 package builds are not registered in this delivery.

Review interface changes alongside the core's `crates/syrox-engine/src/systemd`.
Compatible additions may extend this contract; incompatible changes require a
new contract ID. Every catalog combination hashes `contract.toml` into its lock
identity, so changing the requirements requires new qualification evidence while
retaining previous identities.
