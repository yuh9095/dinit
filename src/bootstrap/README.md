# Linux Bootstrap

Linux Bootstrap is a generated Dinit service package. The build-host C++
program emits native Dinit service descriptions; the target-side C++ helper
performs the operations used by those services.

## Installed layout

* /usr/lib/dinit: target-side C++ helper.
* /usr/lib/dinit.d: generated early/bootstrap and filesystem service definitions.
* /etc/dinit.d: generic Linux services and targets, boot.d activation marker, and device/network/storage extension directories.
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
8. early-modules loads configured kernel modules when modprobe is available.
9. early-devd is the distribution device-manager extension point.
10. early-devices.target marks device discovery complete.
11. early-root-fsck safely skips the mounted root; real root checks belong in the initramfs.
12. early-root-rw.target remounts the root filesystem read-write when required.
13. early-machine-id creates a persistent ID when one is absent, outside containers.
14. early-net-lo brings up loopback before network services.
15. early-hostname applies /etc/hostname outside containers.
16. early-sysctl applies sysctl.d settings outside containers.
17. early-fs-pre.target waits for explicitly enabled non-root local-storage preparation services.
18. early-fs-fsck checks eligible local fstab filesystems before mounting.
19. early-fs-fstab.target mounts eligible local fstab entries, excluding network filesystems and sysfs.
20. early-fs-local.target marks local filesystem preparation complete.
21. local-fs.target exposes the completed local filesystem stage.
22. early-hwclock reads the hardware clock when the utility is available.
23. early-swap enables fstab swap; pre-local.target marks core local startup complete.
24. network.target waits for distribution-selected network services.
25. multi-user.target combines local and network readiness.

The dependency graph uses native Dinit relationships: hard dependencies for
required preparation and milestone dependencies for distribution-enabled
local-storage integrations. It is not a serialized shell script.

## Filesystem operations

The C++ helper applies machine-id, hostname, sysctl and loopback settings directly, and
invokes hwclock, modprobe, fsck, mount and swapon with argv; it does not use a
shell. Machine-id is preserved when already valid and is never regenerated inside a container.
Hardware-clock setup is skipped in containers or when hwclock is absent.
Sysctl settings are read from the standard sysctl.d directories with filename
precedence; invalid or unavailable settings are logged without aborting boot.
Module configuration is read from the standard modules-load.d configuration
directories in precedence order; duplicate filenames are shadowed by the first
directory, and duplicate module names are loaded once.
Individual module-load failures are logged but do not block boot. Container
module loading is skipped. Missing optional fsck/swapon tools are skipped. Root fsck is deliberately
left to the initramfs: Dinit starts after the kernel has mounted the root
filesystem, and running a repairing fsck against that mounted device is unsafe.
A read-only container root is left unchanged. Uncorrected fsck errors and a
reboot-required result stop the dependent stage.

Root-device assembly (RAID, LVM, encryption, Btrfs and ZFS for the root
filesystem) must be completed before Dinit starts, normally in the initramfs.
For non-root local filesystems, distributions can opt in to storage preparation
services through /etc/dinit.d/early-fs-pre.d. This directory uses Dinit
milestone dependencies: when a distribution enables a service there, the
filesystem stage waits for it to start successfully. No storage tool is enabled
by default. Device-manager integration is selected by placing the chosen Dinit service
name in /etc/dinit.d/early-devices.d. Network integration can be selected in
the same way through /etc/dinit.d/network.d. Both use waits-for dependencies,
so optional manager failure does not prevent the target from starting. No
particular device or network manager is selected by the generic package.

## Compatibility

Linux 4.9 is the minimum target. New kernel interfaces are optional and
must be detected at runtime. The build-host generator and target-side helper
are compiled separately for cross-compilation.
