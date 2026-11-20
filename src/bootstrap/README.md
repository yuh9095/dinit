# Linux Bootstrap

Linux Bootstrap is a generated Dinit service package. The build-host C++
program emits native Dinit service descriptions; the target-side C++ helper
performs the operations used by those services.

## Installed layout

* `/usr/lib/dinit`: target-side C++ helper.
* `/usr/lib/dinit.d`: generated early/bootstrap and filesystem service definitions.
* `/etc/dinit.d`: generic Linux services and targets, optional `boot.d` and required `boot-required.d` activation markers, and device/network/storage extension directories.
* `/run/dinit`: runtime environment and root-fsck recovery status.

The package does not replace the distribution's boot service. The generated
`/etc/dinit.d/boot-required.d/early-root-rw.target` marker must be consumed by
the distribution's boot service through `depends-ms.d`, so a root-filesystem
preparation failure is observed as a boot failure and can enter Dinit's native
boot-failure recovery handling. The optional
`/etc/dinit.d/boot.d/pre-local.target` marker remains a `waits-for.d`
extension and does not block boot when it fails. A typical boot service uses:

```ini
depends-ms.d: /etc/dinit.d/boot-required.d
waits-for.d: /etc/dinit.d/boot.d
```

Distributions using another boot arrangement must provide the equivalent hard
dependency on `early-root-rw.target`.

## Startup stages

The generated services form a dependency graph, not a strictly serialized
shell script:

1. `bootstrap-proc`, `bootstrap-environment`, `bootstrap-sys`,
   `bootstrap-dev`, `bootstrap-devpts` and `bootstrap-shm` prepare the
   required pseudo-filesystems and device filesystem.
2. `early-prepare.target` aggregates that preparation stage.
3. `early-modules` loads configured kernel modules when `modprobe` is available.
4. `early-devd` provides the distribution device-manager integration point.
5. `early-devices.target` marks the device preparation stage complete.
6. After `early-devices.target`, the root-filesystem path and the non-root
   filesystem-preparation path can proceed independently:
   * `early-root-fsck` performs the guarded root check described below;
     `early-root-rw.target` then applies the configured root remount policy.
   * `early-fs-pre.target` waits for enabled non-root storage preparation
     services; `early-fs-fsck` checks eligible local fstab filesystems before
     `early-fs-fstab.target` mounts them.
7. `early-fs-local.target` marks local filesystem preparation complete.
   `local-fs.target` exposes that completed stage.
8. Hostname, sysctl, loopback, hardware-clock, machine-id and swap helpers run
   at their declared dependency points. `pre-local.target` marks core local
   startup complete.
9. `network.target` waits for distribution-selected network services;
   `multi-user.target` combines local and network readiness.

The root check depends on `early-devices.target`, not
`early-fs-pre.target`. This lets the device-preparation stage finish before the
root check without making root fsck wait for optional integrations intended
for non-root local filesystems.

## Filesystem operations

The C++ helper applies machine-id, hostname, sysctl and loopback settings
directly, and invokes hwclock, modprobe, fsck, mount and swapon with argv; it
does not use a shell. Machine-id is preserved when already valid and is never
regenerated inside a container. Hardware-clock setup is skipped in containers
or when hwclock is absent. Sysctl settings are read from the standard sysctl.d
directories with filename precedence; invalid or unavailable settings are
logged without aborting boot. Module configuration is read from the standard
modules-load.d configuration directories in precedence order; duplicate
filenames are shadowed by the first directory, and duplicate module names are
loaded once. Individual module-load failures are logged but do not block boot.
Container module loading is skipped.

### Root filesystem

Root-device assembly (RAID, LVM, encryption, and any other required root-device
setup) must be completed before Dinit starts, normally in the initramfs. The
Dinit root-fsck helper does not attempt to assemble or discover the root device.

The helper skips root fsck in containers, when kernel command-line policy
disables it, when `/etc/fstab` has no root entry, a non-positive fsck pass
number, or the `noauto` option, and when the root is virtual, already
read-write, not explicitly mounted read-only, or cannot be matched safely to
its backing block device. It also
skips when the required `fsck` frontend or `fsck.TYPE` helper is unavailable.
It only invokes fsck when the fstab requests a check and the mounted root is
confirmed read-only and backed by the matching block device. When a root operation needs to consult fstab, multiple root entries are
treated as ambiguous and cause that operation to fail rather than selecting
one arbitrarily.

The helper accepts fsck status 0 (clean) and 1 (errors corrected). The fsck status bits for reboot-required (2) and uncorrected errors (4) are
reported distinctly and fail the root-fsck milestone. Only a normal fsck process
exit is interpreted as an fsck bitmask; an execution failure or signal
termination is reported separately and cannot be mistaken for an fsck status.
Failed attempts are recorded atomically in `/run/dinit/root-fsck.status` for a
distribution-provided recovery service. Unlike systemd, this initial Bootstrap
implementation does not yet translate those conditions into separate reboot
and emergency actions.

After the root-fsck milestone, `early-root-rw.target` remounts root read-write
only when fstab contains a root entry whose options do not specify `ro`.
A root explicitly configured `ro`, or a root without an fstab policy, is left
unchanged. Container roots are not remounted by this helper.

### Other local filesystems

For non-root local filesystems, the helper runs the system `fsck -A -R`
frontend, excluding filesystems marked `_netdev`, before the fstab mount stage.
Missing optional fsck or swapon tools are skipped. A failed fsck or mount
operation prevents its dependent stage from completing.

## Distribution extension directories

The generic package creates these extension points under `/etc/dinit.d`:

* `early-devices.d` is read through Dinit's `depends-ms.d` mechanism by
  `early-devd`. Enabled device-preparation services must start successfully
  before `early-devices.target` can complete.
* `early-fs-pre.d` is read through `depends-ms.d` by
  `early-fs-pre.target`. It is intended for non-root local-storage
  preparation, and those services must start successfully before the local
  filesystem checks and mounts proceed.
* `network.d` is read through `waits-for.d` by `network.target`. These
  services are waited for, but their failure does not prevent the network
  target from starting.

Dinit treats these as dependency drop-in directories, not strict configuration
validators: an unreadable directory is warned about and ignored, and a listed
service that cannot be found is warned about and ignored. A service that is
found and loaded but fails to start has the effect specified by the dependency
type: milestone dependencies prevent their target stage from completing,
whereas `waits-for` dependencies do not.

An extension service must not depend on the target that loads it from its
drop-in directory. For example, a service in `early-devices.d` must not depend
on `early-devices.target`; doing so creates a dependency cycle. The
`early-devices.d` stage runs after Dinit has started on the mounted root, so it
is not a mechanism for assembling devices required to mount the root
filesystem. No particular device, storage or network manager is selected by
the generic package.
Distributions opt in by adding the relevant service names to these directories.

## Compatibility

Linux 4.9 is the minimum target. New kernel interfaces are optional and
must be detected at runtime. The build-host generator and target-side helper
are compiled separately for cross-compilation.
