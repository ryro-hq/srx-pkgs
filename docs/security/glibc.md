# glibc 2.44 security assessment

The GNU runtime keeps its exact upstream source archive and applies upstream
commit `b090cf226ff65b913e41536f1f573f500855615c` for CVE-2026-19499. The original
patch is retained in `assets/glibc/`, authenticated as a project asset and included
in catalog recipe inputs. Both bootstrap and managed builds apply it with zero
fuzz and run upstream `tst-strfmon-bug34510` before installation. Managed seeds must
provide `usr/bin/patch` in their tools output.

The first complete catalog matrix exposed these four blocking scanner matches:

| CVE | Assessment | Upstream evidence |
| --- | --- | --- |
| CVE-2019-1010022 | Upstream treats the stack-canary report as a non-security bug. Stack canaries provide mitigation; independent memory-corruption bugs still require fixes. | [Upstream report](https://sourceware.org/bugzilla/show_bug.cgi?id=22850#c3), [CVE record](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1010022) |
| CVE-2019-1010023 | Upstream treats running attacker-supplied ELF files through ldd as outside its security guarantees. | [Upstream report](https://sourceware.org/bugzilla/show_bug.cgi?id=22851), [Debian upstream-status record](https://security-tracker.debian.org/tracker/CVE-2019-1010023) |
| CVE-2026-0861 | Fixed upstream in 2.43; the fix is included in the pinned 2.44 source. | [GLIBC-SA-2026-0001](https://sourceware.org/pipermail/libc-announce/2026/000049.html) |
| CVE-2026-19499 | Fixed by the retained upstream patch; new GNU qualification must execute its regression. | [Upstream patch](https://sourceware.org/git/?p=glibc.git;a=patch;h=b090cf226ff65b913e41536f1f573f500855615c), [upstream announcement](https://www.openwall.com/lists/oss-security/2026/09/14/31) |

`security/vex/glibc-2.44.openvex.json` records these exact assessments. Its package
URL includes the SHA256 identity of the patch set, so its fixed statement does
not address unpatched glibc 2.44. `security/vex/policy.json` binds the document,
source, patch bytes and complete catalog lock, with expiry on 2026-11-20. Changes
to any bound input require a renewed assessment. No independent human review is
claimed.

Daily audits and dependency-policy jobs validate these bindings and expiry.
Release preflight also verifies the retained source and patch files, supplies the
validated OpenVEX to Grype and rejects every suppressed match outside the exact
package/CVE/status inventory. The complete report retains `ignoredMatches` for
inspection. Other high, critical or unknown-severity findings continue to block.
The release retains the VEX document and policy alongside sources, licenses,
SPDX and checksums.

A scanner compatibility probe on the old bundles retained the strfmon high alert
after applying only the other three assessments. Those old bundles cannot pass
the new catalog identity check. Patched bundles require their own full VM matrix;
the probe is not qualification evidence.
