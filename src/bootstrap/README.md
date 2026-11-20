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
   required pseudo-filesystems and device filesystem. Each required step uses
   a milestone dependency on its prerequisite, so a failed mount cannot be
   bypassed by later bootstrap stages.
2. `early-prepare.target` aggregates that preparation stage using milestone
   dependencies.
3. `early-modules` runs after the required preparation stage. Missing
   `modprobe` and individual module-load failures remain non-fatal.
4. `early-devd` runs after the module-loading stage and provides the distribution
   device-manager integration point; enabled services in `early-devices.d` are
   required to start successfully.
5. `early-devices.target` marks device preparation complete only after
   `early-devd` succeeds.
6. After `early-devices.target`, the root-filesystem path and the non-root
   filesystem-preparation path can proceed independently. Device-stage failure
   blocks both paths:
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

The root check has a milestone dependency on `early-devices.target`, not
`early-fs-pre.target`. Device preparation must succeed before root fsck can
run, while optional integrations intended only for non-root local filesystems
do not delay the root check.

## Filesystem operations

The helper reads `/proc/self/mountinfo` through a dedicated parser. It
validates the complete snapshot, decodes escaped mount paths, and uses mount
IDs and parent IDs to distinguish stacked mounts and mounts hidden by an
overmounted ancestor. If the visible mount state cannot be determined, the
helper does not treat that state as an unmounted directory.

The existing runtime-provided `/dev` mount is accepted without requiring
devtmpfs. `/dev/pts`, however, must be devpts: a different filesystem type
is reported as a conflict, and a failed devpts mount is never silently skipped
in a container. After preparation, the helper performs a real PTY allocation
test through `/dev/ptmx`, including opening the allocated slave. This checks
functionality without requiring `/dev/ptmx` to be a symlink; traditional
character-device layouts are accepted when they work.

The mountinfo parser's unprivileged fixture tests can be run with
`make -C src check-bootstrap` after configuring with
`./configure --enable-bootstrap`.

The C++ helper applies machine-id, hostname, sysctl and loopback settings
directly, and invokes hwclock, modprobe, fsck, mount and swapon with argv; it
does not use a shell.

### Environment detection and operation policy

Bootstrap uses one environment distinction: container or non-container Linux.
The detector checks runtime-provided markers, common container marker files,
cgroup identifiers, and the current PID namespace. A nested PID namespace is
sufficient to classify a generic container when no runtime name is available.
If PID-namespace inspection is unavailable and no runtime marker is found,
Bootstrap conservatively uses the container policy. The runtime name is optional
diagnostic information only; Docker, Podman, LXC, DroidSpaces, or any other
specific runtime is not required.

Detection is best-effort rather than a universal container oracle. A container
that shares the host PID namespace and exposes no recognizable runtime or
cgroup marker may be indistinguishable from the host from inside the helper.
Such deployments should provide a standard container marker when available.

Virtual machines follow the non-container path because a VM guest has its own
Linux kernel and machine scope. Bootstrap does not identify hypervisor vendors
or maintain a separate VM environment class.

The environment result is stored as `container=yes` or `container=no`.
If the result cannot be read or is unavailable, machine-wide operations are
denied conservatively; this does not prevent required pseudo-filesystem and
device-filesystem preparation from checking and acting on their actual mount
state and permissions. The Dinit-parent PID 1 check remains an independent
startup requirement and is not used as the container classifier.

Container and non-container policy is applied to root/local fsck, fstab mounts,
root remounting, swap activation, module loading, hostname changes, sysctl,
machine-id creation, and hardware-clock access. Loopback and required
pseudo-filesystem/device setup use their actual operation results rather than
requiring a particular container runtime name.

### Root filesystem

Root-device assembly (RAID, LVM, encryption, and any other required root-device
setup) must be completed before Dinit starts, normally in the initramfs. The
Dinit root-fsck helper does not attempt to assemble or discover the root device.

The helper skips root fsck in containers and unknown environments, when
kernel command-line policy disables it, when `/etc/fstab` has no root entry,
a non-positive fsck pass number, or the `noauto` option, and when the root is
virtual, already
read-write, not explicitly mounted read-only, or cannot be matched safely to
its backing block device. It also
skips when the required `fsck` frontend or `fsck.TYPE` helper is unavailable.
It only invokes fsck when the fstab requests a check and the mounted root is
confirmed read-only and backed by the matching block device. When a root operation needs to consult fstab, multiple root entries are
treated as ambiguous and cause that operation to fail rather than selecting
one arbitrarily.

The helper accepts fsck status 0 (clean) and 1 (errors corrected). The fsck
status bits for reboot-required (2) and uncorrected errors (4) are reported
independently, including when combined with operational or usage error bits,
and fail the root-fsck milestone. Only a normal fsck process
exit is interpreted as an fsck bitmask; an execution failure or signal
termination is reported separately and cannot be mistaken for an fsck status.
Failed attempts are recorded atomically in `/run/dinit/root-fsck.status` for a
distribution-provided recovery service. Unlike systemd, this initial Bootstrap
implementation does not yet translate those conditions into separate reboot
and emergency actions.

After the root-fsck milestone, `early-root-rw.target` remounts root read-write
only when fstab contains a root entry whose options do not specify `ro`.
A root explicitly configured `ro`, or a root without an fstab policy, is left
unchanged. Container and unknown-environment roots are not remounted by this
helper.

### Other local filesystems

For non-root local filesystems, the helper runs the system `fsck -A -R`
frontend, excluding filesystems marked `_netdev`, before the fstab mount stage.
Container and unknown environments skip local fsck and fstab mounting.
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
  filesystem checks and mounts proceed. The filesystem check, mount, and
  local-fs aggregate stages use milestone dependencies so a failed preparation
  or check cannot be bypassed by a soft dependency.
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
