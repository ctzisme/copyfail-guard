# copyfail-guard

A zero-dependency Python CLI that detects [CVE-2026-31431](https://nvd.nist.gov/vuln/detail/CVE-2026-31431)
("Copy Fail") on Linux systems and applies the modprobe-level mitigation. It supports
Debian/Ubuntu, RHEL/Rocky/AlmaLinux, Fedora, and SUSE.

## What is CVE-2026-31431?

A logic bug in the kernel `algif_aead` (AF_ALG AEAD socket) interface lets an
unprivileged local user perform a controlled 4-byte write into the page cache of
any readable file, leading to root privilege escalation. CVSS 7.8. The flaw has
been present since kernel 4.14 and was patched in stable releases starting in
April 2026.

## What this tool does

- **detect** — combine four signals (kernel version, `/proc/modules`,
  `modules.builtin`, modprobe blacklist) into one of six verdicts: `patched`,
  `mitigated`, `vulnerable`, `unmitigable_builtin`, `not_applicable`, `unknown`.
- **fix** — write `/etc/modprobe.d/cve-2026-31431-copyfail-guard.conf` with
  `install algif_aead /bin/false`, then run `modprobe -r algif_aead`. It does
  **not** call your package manager — instead it prints the recommended kernel
  upgrade command for your distribution so you can review and run it yourself.

## Install

```sh
pip install copyfail-guard
```

Or run from a checkout without installing:

```sh
PYTHONPATH=src python3 -m copyfail_guard detect
```

## Usage

```
copyfail-guard [--json] [--dry-run] [--quiet] [--root PATH] [detect|fix]
```

### detect (default)

```sh
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
       distribution ships once it has integrated the CVE-2026-31431 fix), then
       reboot.
```

### fix

```sh
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

The fix is intentionally minimal: it writes a modprobe blacklist and unloads
the module. It does **not** call your package manager. Updating the kernel
itself is up to you — use `apt`/`dnf`/`zypper` (or your configuration
management tool) however your environment normally handles security updates.

Always preview with `--dry-run` first.

### JSON output

`--json` emits a structured document on stdout, suitable for jq/Ansible/SOAR pipelines:

```sh
$ copyfail-guard --json detect | jq .verdict
"vulnerable"
```

## Exit codes

| Code | Meaning |
| ---- | ------- |
| 0    | safe — verdict is `patched`, `mitigated`, or `not_applicable`; or fix succeeded |
| 1    | vulnerable — verdict is `vulnerable` or `unmitigable_builtin` |
| 2    | error — could not determine state, refused due to preconditions, fix failed |

## Mitigation reversal

To remove the mitigation after upgrading to a patched kernel:

```sh
sudo rm /etc/modprobe.d/cve-2026-31431-copyfail-guard.conf
sudo systemctl reboot
```

## Notes

- **Container hosts.** copyfail-guard refuses to apply `fix` from inside a
  container because `/proc/modules` reflects the host but the container has no
  authority to load or unload modules. Run it on the host instead.
- **Built-in `algif_aead`.** Some custom kernels compile `algif_aead` directly
  into the image (`CONFIG_CRYPTO_USER_API_AEAD=y`). modprobe-level mitigation
  has no effect there; the only fix is upgrading the kernel. The detector
  reports `unmitigable_builtin` in this case.
- **`blacklist algif_aead` vs `install algif_aead /bin/false`.** Both block
  auto-loading via `request_module`, but the latter cannot be overridden with
  an explicit `modprobe` invocation. copyfail-guard installs the stronger form.
- **SELinux/AppArmor.** Writes to `/etc/modprobe.d/` inherit
  `system_u:object_r:modules_conf_t:s0` from the parent directory on RHEL; no
  relabel is needed.
- **initramfs/dracut.** `algif_aead` is not included in the boot image on
  any major distribution, so `update-initramfs -u` / `dracut -f` is not
  required after installing the blacklist.

## Development

```sh
PYTHONPATH=src python3 -m unittest discover tests
```

The test suite uses fixture filesystems under `tests/fixtures/` so it runs on
macOS without needing real Linux. Each fixture contains a synthetic
`/etc/os-release`, `/proc/modules`, `/sys/module/`, and
`/lib/modules/<rel>/{modules.dep,modules.builtin}` tree.

## License

Apache 2.0 — see [LICENSE](LICENSE).
