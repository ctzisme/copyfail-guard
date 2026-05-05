# copyfail-guard

[![PyPI](https://img.shields.io/pypi/v/copyfail-guard)](https://pypi.org/project/copyfail-guard/)
[![Python](https://img.shields.io/pypi/pyversions/copyfail-guard)](https://pypi.org/project/copyfail-guard/)
[![License](https://img.shields.io/pypi/l/copyfail-guard)](LICENSE)
[![pylint](https://img.shields.io/badge/pylint-10.00%2F10-brightgreen)](https://pylint.readthedocs.io/)

A zero-dependency Python CLI that checks whether a Linux host appears exposed to
[CVE-2026-31431](https://copy.fail) ("Copy Fail") **without running an exploit**.
It can also apply a conservative temporary mitigation when the affected component
is loadable as a kernel module.
Supports Debian/Ubuntu, RHEL/Rocky/AlmaLinux, Fedora, and SUSE.

```sh
pip install copyfail-guard
copyfail-guard
```

## Background

CVE-2026-31431 is a logic bug in the `algif_aead` (AF_ALG AEAD socket) kernel
interface that lets an unprivileged local user perform a controlled 4-byte write
into the page cache of any readable file, leading to root privilege escalation.
CVSS 7.8, present since kernel 4.14, patched in stable releases starting April 2026.
A public exploit exists and the vulnerability is listed in CISA KEV.

## Why not just run an exploit?

Some vulnerability checks amount to "run the exploit and see whether it works".
That is not a great thing to do on production hosts.
copyfail-guard takes a non-exploit approach. It does not try to trigger the bug,
modify setuid binaries, or prove exploitability. Instead, it inspects host state
(kernel version, module load status, modprobe configuration) and reports whether
the machine appears exposed.

## What this tool does

| Subcommand | Action |
|---|---|
| `detect` | Combines five signals (kernel version, `/proc/modules`, `modules.builtin`, `modules.dep`, modprobe config) into one of six verdicts |
| `fix` | Atomically writes an `install algif_aead /bin/false` modprobe rule and tries to unload `algif_aead` |
| `reset` | Removes the modprobe rule installed by `fix` (run after upgrading to a patched kernel) |

`fix` is intentionally minimal — it does **not** call your package manager.
Permanent remediation requires upgrading the kernel through your distribution's
normal update mechanism.

## Install

```sh
pip install copyfail-guard
```

Or run directly from a checkout without installing:

```sh
PYTHONPATH=src python3 -m copyfail_guard detect
```

## Usage

```
copyfail-guard [--json] [--dry-run] [--quiet] [detect | fix | reset]
```

### detect (default)

```
$ copyfail-guard
[copyfail-guard] CVE-2026-31431 (Copy Fail) — VULNERABLE
  Distribution: Ubuntu 24.04.1 LTS  (debian family)
  Kernel:       6.8.0-50-generic  (branch 6.12, fixed at 6.12.85)
  Module:       algif_aead — loaded as .ko
  Mitigation:   none

Recommended actions:
  1. Apply mitigation now:
       sudo copyfail-guard fix
  2. Update the kernel for a permanent fix:
       Update the kernel on this system to 6.12.85 or later (whatever your
       distribution ships once it has integrated the CVE-2026-31431 fix), then reboot.
```

### fix

Always preview with `--dry-run` before applying:

```
$ sudo copyfail-guard --dry-run fix
[copyfail-guard] fix (dry-run) — OK
  [ ok ] Pre-flight checks (Linux, host, root)
  [skip] Would write modprobe blacklist  [/etc/modprobe.d/cve-2026-31431-copyfail-guard.conf]
  [skip] Would attempt to unload algif_aead (not currently loaded)  [algif_aead]
  [skip] Would append audit record  [/var/log/copyfail-guard.log]

$ sudo copyfail-guard fix
[copyfail-guard] fix — OK
  [ ok ] Pre-flight checks (Linux, host, root)
  [ ok ] Wrote modprobe blacklist  [/etc/modprobe.d/cve-2026-31431-copyfail-guard.conf]
  [ ok ] Unloaded algif_aead  [algif_aead]
  [ ok ] Appended audit record  [/var/log/copyfail-guard.log]

Next step for a permanent fix:
  Update the kernel to a CVE-2026-31431-patched version using your
  distribution's normal update mechanism, then reboot.
```

If the module is currently in use, the unload step may fail. In that case the
persistent modprobe rule can still be installed successfully, and copyfail-guard
will report the unload failure as a warning-style action record rather than
pretending the module was removed.

### JSON output

`--json` emits a structured document on stdout, suitable for jq, Ansible, or SOAR pipelines:

```sh
$ copyfail-guard --json | jq .verdict
"vulnerable"

$ copyfail-guard --json | jq '{verdict, kernel: .kernel.patched_threshold}'
{
  "verdict": "vulnerable",
  "kernel": "6.12.85"
}
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Safe — verdict is `patched`, `mitigated`, or `not_applicable`; or the persistent fix step succeeded |
| `1` | Vulnerable — verdict is `vulnerable` or `unmitigable_builtin` |
| `2` | Error — state could not be determined, precondition refused, or the persistent fix step failed |

## Verdicts

| Verdict | Description |
|---|---|
| `patched` | Running kernel is at or beyond the fixed version |
| `mitigated` | Kernel is vulnerable but `algif_aead` is blocked by modprobe config |
| `not_applicable` | Kernel is vulnerable but `algif_aead` is not present on this system |
| `vulnerable` | Kernel is vulnerable, module is loadable, no mitigation in place |
| `unmitigable_builtin` | `algif_aead` is compiled into the kernel image — modprobe mitigation has no effect; kernel upgrade required |
| `unknown` | Kernel version could not be parsed or is outside the assessed range |

## Removing the mitigation

After upgrading to a patched kernel, use the `reset` subcommand to remove the
modprobe rule installed by `fix`:

```
$ sudo copyfail-guard --dry-run reset
[copyfail-guard] reset (dry-run) — OK
  [skip] Would remove /etc/modprobe.d/cve-2026-31431-copyfail-guard.conf

$ sudo copyfail-guard reset
[copyfail-guard] reset — OK
  [ ok ] Removed /etc/modprobe.d/cve-2026-31431-copyfail-guard.conf

Reboot to allow algif_aead to load again if needed.
```

`reset` is idempotent — if the file is already absent it exits 0 with a
"nothing to do" message. Then reboot.

## Notes

**Containers.** `fix` refuses to run inside a container because `/proc/modules`
reflects the host kernel but the container has no authority to load or unload
modules. Run copyfail-guard on the host directly.

**Built-in `algif_aead`.** Some kernels compile `algif_aead` directly into the
image (`CONFIG_CRYPTO_USER_API_AEAD=y`). modprobe mitigation has no effect in
this configuration; the only remediation is a kernel upgrade. `detect` reports
`unmitigable_builtin` in this case. Running `fix` will still install the modprobe
rule (which prevents any co-existing loadable copy from loading) but the built-in
instance is unaffected — kernel upgrade and reboot are the only real remedy.

**`blacklist` vs `install … /bin/false`.** Both directives block ordinary
auto-loading, but `install algif_aead /bin/false` is stronger because it also
blocks ordinary explicit `modprobe algif_aead` invocations. A sufficiently
privileged administrator can still bypass modprobe policy, for example by using
low-level module loading tools or special modprobe flags. copyfail-guard always
installs the stronger form. If your system already has a plain `blacklist`
directive, the tool reports `mitigated` but emits a note recommending the upgrade.

**SELinux/AppArmor.** Writes to `/etc/modprobe.d/` on RHEL normally inherit
`system_u:object_r:modules_conf_t:s0` from the parent directory, so no manual
relabel should usually be needed for the file copyfail-guard writes.

**initramfs.** `algif_aead` is not normally included in the boot image on major
distributions, so copyfail-guard does not run `update-initramfs -u` or
`dracut -f` after installing the modprobe rule. If your distribution or local
build includes `algif_aead` in initramfs, follow your distribution's
kernel/module guidance.

## License

Apache 2.0 — see [LICENSE](LICENSE).
