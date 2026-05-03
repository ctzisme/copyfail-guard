# copyfail-guard

[![PyPI](https://img.shields.io/pypi/v/copyfail-guard)](https://pypi.org/project/copyfail-guard/)
[![Python](https://img.shields.io/pypi/pyversions/copyfail-guard)](https://pypi.org/project/copyfail-guard/)
[![License](https://img.shields.io/pypi/l/copyfail-guard)](LICENSE)
[![pylint](https://img.shields.io/badge/pylint-10.00%2F10-brightgreen)](https://pylint.readthedocs.io/)

A zero-dependency Python CLI that detects and temporarily mitigates
[CVE-2026-31431](https://nvd.nist.gov/vuln/detail/CVE-2026-31431) ("Copy Fail")
on Linux. Works on Debian/Ubuntu, RHEL/Rocky/AlmaLinux, Fedora, and SUSE.

## Background

CVE-2026-31431 is a logic bug in the `algif_aead` (AF_ALG AEAD socket) kernel
interface that lets an unprivileged local user perform a controlled 4-byte write
into the page cache of any readable file, leading to root privilege escalation.
CVSS 7.8, present since kernel 4.14, patched in stable releases starting April 2026.
A public PoC exists and the vulnerability is listed in CISA KEV.

## What this tool does

| Subcommand | Action |
|---|---|
| `detect` | Combines four signals (kernel version, `/proc/modules`, `modules.builtin`, modprobe config) into one of six verdicts |
| `fix` | Atomically writes an `install algif_aead /bin/false` blacklist and runs `modprobe -r algif_aead` |

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
copyfail-guard [--json] [--dry-run] [--quiet] [detect | fix]
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
       Update the kernel on this system to 6.12.85 or later, then reboot.
```

### fix

Always preview with `--dry-run` before applying:

```
$ sudo copyfail-guard --dry-run fix
[copyfail-guard] fix — DRY RUN (no changes made)
  [dry] Would write modprobe blacklist  [/etc/modprobe.d/cve-2026-31431-copyfail-guard.conf]
  [dry] Would attempt to unload algif_aead (not currently loaded)
  [dry] Would append audit record  [/var/log/copyfail-guard.log]

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
| `0` | Safe — verdict is `patched`, `mitigated`, or `not_applicable`; or fix succeeded |
| `1` | Vulnerable — verdict is `vulnerable` or `unmitigable_builtin` |
| `2` | Error — state could not be determined, precondition refused, or fix failed |

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

After upgrading to a patched kernel:

```sh
sudo rm /etc/modprobe.d/cve-2026-31431-copyfail-guard.conf
sudo reboot
```

## Notes

**Containers.** `fix` refuses to run inside a container because `/proc/modules`
reflects the host kernel but the container has no authority to load or unload
modules. Run copyfail-guard on the host directly.

**Built-in `algif_aead`.** Some kernels compile `algif_aead` directly into the
image (`CONFIG_CRYPTO_USER_API_AEAD=y`). modprobe mitigation has no effect in
this configuration; the only remediation is a kernel upgrade. The tool reports
`unmitigable_builtin` and skips the fix step.

**`blacklist` vs `install … /bin/false`.** Both directives block auto-loading,
but `install algif_aead /bin/false` cannot be overridden by an explicit
`modprobe algif_aead` invocation. copyfail-guard always installs the stronger
form. If your system already has a plain `blacklist` directive, the tool reports
`mitigated` but emits a note recommending the upgrade.

**SELinux/AppArmor.** Writes to `/etc/modprobe.d/` on RHEL inherit
`system_u:object_r:modules_conf_t:s0` from the parent directory — no manual
relabel is needed.

**initramfs.** `algif_aead` is not included in the boot image on any major
distribution, so running `update-initramfs -u` or `dracut -f` is not required
after installing the blacklist.

## Development

```sh
git clone https://github.com/ctzisme/copyfail-guard
cd copyfail-guard
PYTHONPATH=src python3 -m unittest discover tests   # stdlib only, no pytest needed
```

The test suite uses fixture filesystems under `tests/fixtures/` and runs fully
on macOS without a real Linux environment. Each fixture provides a synthetic
`/etc/os-release`, `/proc/modules`, and
`/lib/modules/<rel>/{modules.dep,modules.builtin}` tree.

## License

Apache 2.0 — see [LICENSE](LICENSE).
