# Linux Bootstrap

Linux Bootstrap is a generated Dinit service package. The build-host C++
program emits native Dinit service descriptions; the target-side C++ helper
performs the operations used by those services.

## Installed layout

* /usr/lib/dinit: target-side C++ helper.
* /usr/lib/dinit.d: generated early/bootstrap and filesystem service definitions.
* /etc/dinit.d: generated generic Linux targets and the boot.d activation marker.
* /run/dinit: runtime environment (per-operation status logging is still pending).

The package does not replace the distribution's boot service. The generated
/etc/dinit.d/boot.d/pre-local.target marker is consumed only by a boot service
which declares waits-for.d: /etc/dinit.d/boot.d. Distributions using another
boot arrangement must add pre-local.target to their own boot dependency graph.

## Current startup sequence

1. bootstrap-proc validates or mounts procfs.
2. bootstrap-environment inspects PID namespace, container/VM indicators and mounts.
3. bootstrap-sys prepares sysfs according to the detected environment policy.
4. bootstrap-dev prepares /dev without covering a runtime-provided mount.
5. bootstrap-devpts prepares /dev/pts, preserving an existing devpts mount.
6. bootstrap-shm prepares /dev/shm as tmpfs when it is not already mounted.
7. early-prepare.target aggregates the pseudofilesystem and device-filesystem stage.
8. early-root-fsck checks a root block device when a matching fsck helper exists.
9. early-root-rw.target remounts the root filesystem read-write when required.
10. early-fs-pre.target provides a waits-for.d extension point for optional storage activation.
11. early-fs-fsck checks eligible local fstab filesystems before mounting.
12. early-fs-fstab.target mounts local fstab entries, excluding network and pseudo filesystems.
13. early-fs-local.target marks local filesystem preparation complete.
14. early-swap enables fstab swap; pre-local.target marks core local startup complete.

The dependency graph uses native Dinit relationships: hard dependencies for
required preparation, milestone dependencies for successful prerequisites,
and waits-for for optional integrations. It is not a serialized shell script.

## Filesystem operations

The C++ helper invokes fsck, mount and swapon directly with argv; it does not
use a shell. Missing optional fsck/swapon tools are skipped. Root fsck is
skipped inside a confirmed container, when root is not a block device, when
fstab disables root checking, or when no matching fsck helper is installed.
A read-only container root is left unchanged. Uncorrected fsck errors and a
reboot-required result stop the dependent stage.

RAID, LVM, encryption, Btrfs and ZFS are not automatically activated yet.
Distributions can add optional storage services through
/etc/dinit.d/early-fs-pre.d; this avoids starting disk-assembly tools before
a suitable device manager has completed device discovery. Device-manager
integration and the remaining generic Linux service set are subsequent stages.

## Compatibility

Linux 4.9 is the minimum target. New kernel interfaces are optional and
must be detected at runtime. The build-host generator and target-side helper
are compiled separately for cross-compilation.
