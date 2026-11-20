// Linux Bootstrap runtime support for Dinit.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
// This program is part of the generated dinit.d service package.

#include <cerrno>
#include <dirent.h>
#include <signal.h>
#include <cstdio>
#include <cstdlib>
#include <stdlib.h>
#include <cstring>
#include <fcntl.h>
#include "mountinfo.h"
#include <mntent.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <set>
#include <string>

#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

#if defined(__i386__) || defined(__x86_64__)
#include <cpuid.h>
#endif

namespace {

enum class environment_kind { bare_metal, virtual_machine, container, unknown };

struct environment_info {
    bool pid1;
    bool nested_pid_namespace;
    bool pid_namespace_depth_known;
    environment_kind kind;
    std::string container_name;
    std::string virtualization;
    bool mountinfo_available;
    std::string root_fs_type;
    std::string procfs;
    std::string sysfs;
    std::string devfs;
    std::string cgroups;
};

bool path_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

std::string read_file(const char *path)
{
    std::ifstream input(path);
    if (!input) return std::string();
    std::ostringstream contents;
    contents << input.rdbuf();
    return contents.str();
}

bool contains(const std::string &value, const char *needle)
{
    return value.find(needle) != std::string::npos;
}

std::string trim(std::string value)
{
    const std::string::size_type first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return std::string();
    const std::string::size_type last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

bool is_unknown_marker(const std::string &value)
{
    return value.empty() || value == "unknown" || value == "none";
}

bool contains_cgroup_marker(const std::string &cgroup, const char *marker)
{
    std::string::size_type pos = 0;
    const std::string token(marker);
    while ((pos = cgroup.find(token, pos)) != std::string::npos) {
        const bool left = pos == 0 || cgroup[pos - 1] == '/' || cgroup[pos - 1] == ':';
        const std::string::size_type after = pos + token.size();
        const bool right = after == cgroup.size() || cgroup[after] == '/' ||
                cgroup[after] == ':' || cgroup[after] == '-' || cgroup[after] == '.';
        if (left && right) return true;
        pos = after;
    }
    return false;
}

std::string detect_container()
{
    // Explicit runtime indicators only. PID namespace nesting by itself does
    // not grant the relaxed container mount policy.
    const char *env = std::getenv("container");
    if (env != nullptr) {
        const std::string marker = trim(env);
        if (!is_unknown_marker(marker)) return marker;
    }
    if (path_exists("/.dockerenv")) return "docker";
    if (path_exists("/run/.containerenv")) return "podman";
    if (path_exists("/proc/vz") && !path_exists("/proc/bc")) return "openvz";

    if (path_exists("/run/host/container-manager")) {
        const std::string manager = trim(read_file("/run/host/container-manager"));
        if (!is_unknown_marker(manager)) return manager;
    }

    const std::string cgroup = read_file("/proc/1/cgroup");
    if (contains_cgroup_marker(cgroup, "docker")) return "docker";
    if (contains_cgroup_marker(cgroup, "kubepods")) return "kubernetes";
    if (contains_cgroup_marker(cgroup, "libpod")) return "podman";
    if (contains_cgroup_marker(cgroup, "lxc")) return "lxc";
    return std::string();
}

std::string detect_virtual_machine()
{
#if defined(__i386__) || defined(__x86_64__)
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx) && (ecx & 0x80000000U)) {
        __cpuid(0x40000000U, eax, ebx, ecx, edx);
        std::string signature;
        const unsigned int words[] = { ebx, ecx, edx };
        for (unsigned int word : words) {
            for (unsigned int shift = 0; shift < 32; shift += 8)
                signature.push_back(static_cast<char>((word >> shift) & 0xffU));
        }
        if (contains(signature, "KVMKVMKVM")) return "kvm";
        if (contains(signature, "XenVMMXenVMM")) return "xen";
        if (contains(signature, "VMwareVMware")) return "vmware";
        if (contains(signature, "Microsoft Hv")) return "microsoft";
        if (contains(signature, "TCGTCGTCGTCG")) return "qemu";
        return "hypervisor";
    }
#endif

#if defined(__arm__) || defined(__aarch64__) || defined(__powerpc__) || defined(__powerpc64__) || defined(__riscv)
    const std::string device_tree_hypervisor =
            read_file("/proc/device-tree/hypervisor/compatible");
    if (contains(device_tree_hypervisor, "linux,kvm")) return "kvm";
    if (contains(device_tree_hypervisor, "xen")) return "xen";
    if (contains(device_tree_hypervisor, "vmware")) return "vmware";
    if (!device_tree_hypervisor.empty()) return "hypervisor";
    const std::string device_tree_compatible = read_file("/proc/device-tree/compatible");
    if (contains(device_tree_compatible, "qemu")) return "qemu";
#endif

    // DMI and sysfs are useful fallbacks, but may not be mounted yet.
    const std::string product = read_file("/sys/class/dmi/id/product_name");
    const std::string vendor = read_file("/sys/class/dmi/id/sys_vendor");
    const std::string info = product + vendor;
    if (contains(info, "KVM") || contains(info, "QEMU")) return "kvm";
    if (contains(info, "VMware")) return "vmware";
    if (contains(info, "VirtualBox") || contains(info, "innotek")) return "oracle";
    if (contains(info, "Microsoft") || contains(info, "Virtual Machine")) return "microsoft";
    if (contains(info, "Xen")) return "xen";
    if (contains(info, "Parallels")) return "parallels";
    const std::string hypervisor = read_file("/sys/hypervisor/type");
    return hypervisor;
}

struct mount_info {
    bool available;
    std::string root_fs_type;
    std::string procfs;
    std::string sysfs;
    std::string devfs;
    bool cgroup_v1;
    bool cgroup_v2;
    bool proc_ambiguous;
    bool sys_ambiguous;
    bool cgroups_ambiguous;
    mount_info() : available(false), cgroup_v1(false), cgroup_v2(false),
            proc_ambiguous(false), sys_ambiguous(false),
            cgroups_ambiguous(false) {}
};

mount_info detect_mounts()
{
    mount_info info;
    dinit_bootstrap::mount_table table;
    if (!dinit_bootstrap::read_mountinfo("/proc/self/mountinfo", table))
        return info;
    info.available = true;
    const dinit_bootstrap::mount_result root = dinit_bootstrap::find_visible_mount(table, "/");
    const dinit_bootstrap::mount_result proc = dinit_bootstrap::find_visible_mount(table, "/proc");
    const dinit_bootstrap::mount_result sys = dinit_bootstrap::find_visible_mount(table, "/sys");
    const dinit_bootstrap::mount_result dev = dinit_bootstrap::find_visible_mount(table, "/dev");
    if (root.state == dinit_bootstrap::mount_state::mounted) info.root_fs_type = root.entry.filesystem;
    if (proc.state == dinit_bootstrap::mount_state::mounted) info.procfs = proc.entry.filesystem;
    if (sys.state == dinit_bootstrap::mount_state::mounted) info.sysfs = sys.entry.filesystem;
    if (dev.state == dinit_bootstrap::mount_state::mounted) info.devfs = dev.entry.filesystem;
    info.proc_ambiguous = proc.state == dinit_bootstrap::mount_state::ambiguous;
    info.sys_ambiguous = sys.state == dinit_bootstrap::mount_state::ambiguous;

    std::set<std::string> paths;
    for (std::vector<dinit_bootstrap::mount_entry>::const_iterator i = table.entries.begin();
            i != table.entries.end(); ++i) {
        if (i->mountpoint == "/sys/fs/cgroup"
                || i->mountpoint.compare(0, 15, "/sys/fs/cgroup/") == 0)
            paths.insert(i->mountpoint);
    }
    for (std::set<std::string>::const_iterator i = paths.begin(); i != paths.end(); ++i) {
        const dinit_bootstrap::mount_result result = dinit_bootstrap::find_visible_mount(table, *i);
        if (result.state == dinit_bootstrap::mount_state::ambiguous) {
            info.cgroups_ambiguous = true;
        }
        else if (result.state == dinit_bootstrap::mount_state::mounted) {
            if (result.entry.filesystem == "cgroup") info.cgroup_v1 = true;
            else if (result.entry.filesystem == "cgroup2") info.cgroup_v2 = true;
        }
    }
    return info;
}

environment_info detect_environment()
{
    environment_info info;
    info.pid1 = getppid() == 1;

    // NSpid lists one PID for each visible ancestor PID namespace.
    const std::string status = read_file("/proc/self/status");
    const std::string nspid = "NSpid:";
    const std::string::size_type nspid_pos = status.find(nspid);
    info.nested_pid_namespace = false;
    info.pid_namespace_depth_known = nspid_pos != std::string::npos;
    if (info.pid_namespace_depth_known) {
        std::istringstream values(status.substr(nspid_pos + nspid.size()));
        std::string value;
        unsigned int count = 0;
        while (values >> value && value.find(':') == std::string::npos) ++count;
        info.nested_pid_namespace = count > 1;
    }

    info.container_name = detect_container();
    info.virtualization = detect_virtual_machine();

    const mount_info mounts = detect_mounts();
    info.mountinfo_available = mounts.available;
    info.root_fs_type = mounts.root_fs_type;
    info.procfs = mounts.procfs;
    info.sysfs = mounts.sysfs;
    info.devfs = mounts.devfs;
    if (!mounts.available || mounts.cgroups_ambiguous) info.cgroups = "unknown";
    else if (mounts.cgroup_v1 && mounts.cgroup_v2) info.cgroups = "hybrid";
    else if (mounts.cgroup_v2) info.cgroups = "v2";
    else if (mounts.cgroup_v1) info.cgroups = "v1";
    else info.cgroups = "none";
    // Virtual machines always retain the strict host policy. A container
    // marker must never override positive virtualization evidence.
    if (!info.virtualization.empty()) {
        info.kind = environment_kind::virtual_machine;
    }
    else if (!info.container_name.empty()) {
        info.kind = environment_kind::container;
    }
    else if (!info.pid_namespace_depth_known) {
        info.kind = environment_kind::unknown;
    }
    else if (info.pid1) {
        info.kind = environment_kind::bare_metal;
    }
    else {
        info.kind = environment_kind::unknown;
    }
    return info;
}

const char *kind_name(environment_kind kind)
{
    switch (kind) {
        case environment_kind::bare_metal: return "bare-metal";
        case environment_kind::virtual_machine: return "virtual-machine";
        case environment_kind::container: return "container";
        default: return "unknown";
    }
}

int open_runtime_state_directory()
{
    const int root_fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root_fd < 0) return -1;

    if (mkdirat(root_fd, "run", 0755) != 0 && errno != EEXIST) {
        const int saved_errno = errno;
        close(root_fd);
        errno = saved_errno;
        return -1;
    }
    const int run_fd = openat(root_fd, "run",
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    const int run_error = errno;
    close(root_fd);
    if (run_fd < 0) {
        errno = run_error;
        return -1;
    }

    if (mkdirat(run_fd, "dinit", 0755) != 0 && errno != EEXIST) {
        const int saved_errno = errno;
        close(run_fd);
        errno = saved_errno;
        return -1;
    }
    const int state_fd = openat(run_fd, "dinit",
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    const int state_error = errno;
    close(run_fd);
    if (state_fd < 0) {
        errno = state_error;
        return -1;
    }
    return state_fd;
}

bool write_runtime_state_file(const char *name, const std::string &contents)
{
    const int directory_fd = open_runtime_state_directory();
    if (directory_fd < 0) {
        std::cerr << "dinit-bootstrap: cannot safely open /run/dinit: "
                  << std::strerror(errno) << '\n';
        return false;
    }

    std::ostringstream temporary_name;
    temporary_name << name << ".tmp." << getpid();
    const std::string temporary = temporary_name.str();
    const int fd = openat(directory_fd, temporary.c_str(),
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        const int saved_errno = errno;
        close(directory_fd);
        std::cerr << "dinit-bootstrap: cannot create temporary " << name
                  << ": " << std::strerror(saved_errno) << '\n';
        return false;
    }

    bool write_ok = true;
    std::string::size_type offset = 0;
    while (offset < contents.size()) {
        const ssize_t written = write(fd, contents.data() + offset,
                contents.size() - offset);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) {
            if (written == 0) errno = EIO;
            write_ok = false;
            break;
        }
        offset += static_cast<std::string::size_type>(written);
    }
    const int write_error = write_ok ? 0 : errno;
    if (close(fd) != 0 && write_ok) write_ok = false;
    if (!write_ok) {
        const int saved_errno = write_error != 0 ? write_error : errno;
        unlinkat(directory_fd, temporary.c_str(), 0);
        close(directory_fd);
        std::cerr << "dinit-bootstrap: failed writing " << name
                  << ": " << std::strerror(saved_errno) << '\n';
        return false;
    }

    if (renameat(directory_fd, temporary.c_str(),
                directory_fd, name) != 0) {
        const int saved_errno = errno;
        unlinkat(directory_fd, temporary.c_str(), 0);
        close(directory_fd);
        std::cerr << "dinit-bootstrap: cannot publish " << name
                  << ": " << std::strerror(saved_errno) << '\n';
        return false;
    }
    if (fsync(directory_fd) != 0) {
        const int saved_errno = errno;
        close(directory_fd);
        std::cerr << "dinit-bootstrap: cannot sync /run/dinit after publishing "
                  << name << ": " << std::strerror(saved_errno) << '\n';
        return false;
    }
    close(directory_fd);
    return true;
}

bool write_state(const environment_info &info)
{
    std::ostringstream contents;
    contents << "kind=" << kind_name(info.kind) << '\n'
             << "pid1=" << (info.pid1 ? "yes" : "no") << '\n'
             << "nested-pid-namespace=" << (info.pid_namespace_depth_known ? (info.nested_pid_namespace ? "yes" : "no") : "unknown") << '\n'
             << "container=" << (info.container_name.empty() ? "none" : info.container_name) << '\n'
             << "virtualization=" << (info.virtualization.empty() ? "none" : info.virtualization) << '\n'
             << "mountinfo=" << (info.mountinfo_available ? "available" : "unavailable") << '\n'
             << "root-fs=" << (info.root_fs_type.empty() ? "unknown" : info.root_fs_type) << '\n'
             << "procfs=" << (info.mountinfo_available ? (info.procfs == "proc" ? "yes" : "no") : "unknown") << '\n'
             << "sysfs=" << (info.mountinfo_available ? (info.sysfs == "sysfs" ? "yes" : "no") : "unknown") << '\n'
             << "devfs=" << (info.devfs.empty() ? (info.mountinfo_available ? "no" : "unknown") : info.devfs) << '\n'
             << "cgroups=" << info.cgroups << '\n';
    return write_runtime_state_file("environment", contents.str());
}


environment_kind load_environment_kind()
{
    const int directory_fd = open_runtime_state_directory();
    if (directory_fd < 0) return environment_kind::unknown;
    const int fd = openat(directory_fd, "environment",
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    close(directory_fd);
    if (fd < 0) return environment_kind::unknown;

    std::string contents;
    char buffer[512];
    while (true) {
        const ssize_t count = read(fd, buffer, sizeof(buffer));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) {
            close(fd);
            return environment_kind::unknown;
        }
        if (count == 0) break;
        contents.append(buffer, static_cast<std::string::size_type>(count));
    }
    close(fd);

    std::istringstream input(contents);
    std::string line;
    while (std::getline(input, line)) {
        if (line == "kind=bare-metal") return environment_kind::bare_metal;
        if (line == "kind=virtual-machine") return environment_kind::virtual_machine;
        if (line == "kind=container") return environment_kind::container;
    }
    return environment_kind::unknown;
}

int mount_failure(environment_kind kind, const char *filesystem,
        const char *reason, bool container_may_skip)
{
    if (kind == environment_kind::container && container_may_skip) {
        std::cerr << "dinit-bootstrap: skipping " << filesystem
                  << " setup in container: " << reason << '\n';
        return 0;
    }
    std::cerr << "dinit-bootstrap: required " << filesystem
              << " setup failed: " << reason << '\n';
    return 1;
}

bool ensure_mountpoint_directory(const char *path)
{
    const std::string target(path);
    if (target.empty() || target[0] != '/' || target == "/"
            || target[target.size() - 1] == '/' || target.find("//") != std::string::npos) {
        std::cerr << "dinit-bootstrap: invalid mountpoint path " << path << '\n';
        return false;
    }
    std::string::size_type component_start = 1;
    while (component_start < target.size()) {
        const std::string::size_type component_end = target.find('/', component_start);
        const std::string component = target.substr(component_start,
                component_end == std::string::npos ? std::string::npos
                                                    : component_end - component_start);
        if (component == "." || component == "..") {
            std::cerr << "dinit-bootstrap: invalid mountpoint path " << path << '\n';
            return false;
        }
        if (component_end == std::string::npos) break;
        component_start = component_end + 1;
    }

    const std::string::size_type last_slash = target.find_last_of('/');
    std::string parent = last_slash == 0 ? "/" : target.substr(0, last_slash);
    std::string current;
    std::string::size_type pos = 1;
    while (pos <= parent.size()) {
        const std::string::size_type end = parent.find('/', pos);
        const std::string component = parent.substr(pos,
                end == std::string::npos ? std::string::npos : end - pos);
        if (!component.empty()) {
            current += "/" + component;
            struct stat parent_stat;
            if (lstat(current.c_str(), &parent_stat) != 0
                    || !S_ISDIR(parent_stat.st_mode)) {
                std::cerr << "dinit-bootstrap: mountpoint parent " << current
                          << " is missing or is not a real directory\n";
                return false;
            }
        }
        if (end == std::string::npos) break;
        pos = end + 1;
    }

    struct stat st;
    if (lstat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) return true;
        std::cerr << "dinit-bootstrap: " << path
                  << " exists but is not a real directory\n";
        return false;
    }
    if (errno != ENOENT) {
        std::cerr << "dinit-bootstrap: cannot inspect " << path
                  << ": " << std::strerror(errno) << '\n';
        return false;
    }
    if (mkdir(path, 0755) == 0) return true;
    if (errno == EEXIST && lstat(path, &st) == 0 && S_ISDIR(st.st_mode)) return true;
    std::cerr << "dinit-bootstrap: cannot create directory " << path
              << ": " << std::strerror(errno) << '\n';
    return false;
}

int ensure_pseudo_filesystem(const char *name)
{
    if (getppid() != 1) {
        std::cerr << "dinit-bootstrap: refusing pseudo-filesystem setup: "
                     "helper is not a direct child of PID 1\n";
        return 1;
    }

    const bool is_proc = std::strcmp(name, "proc") == 0;
    const bool container_may_skip = !is_proc && std::strcmp(name, "sys") == 0;
    const char *mountpoint = is_proc ? "/proc" : "/sys";
    const char *filesystem = is_proc ? "proc" : "sysfs";
    const environment_kind kind = is_proc ? environment_kind::unknown : load_environment_kind();

    if (!ensure_mountpoint_directory(mountpoint)) return 1;

    const mount_info current = detect_mounts();
    const std::string mounted = is_proc ? current.procfs : current.sysfs;
    const bool mount_ambiguous = is_proc ? current.proc_ambiguous : current.sys_ambiguous;
    if (mount_ambiguous) {
        std::cerr << "dinit-bootstrap: cannot determine visible mount at "
                  << mountpoint << '\n';
        return 1;
    }
    if (!is_proc && !current.available) {
        std::cerr << "dinit-bootstrap: cannot inspect mount table before setting up "
                  << mountpoint << '\n';
        return 1;
    }
    if (current.available && !mounted.empty()) {
        if (mounted == filesystem) {
            std::cout << "dinit-bootstrap: " << mountpoint
                      << " already mounted as " << filesystem << '\n';
            return 0;
        }
        return mount_failure(kind, filesystem,
                "mountpoint is already occupied by a different filesystem", container_may_skip);
    }

    // Before procfs is mounted, mountinfo cannot be read. Try the mount
    // directly; do not mistake an existing directory for an existing mount.
    const unsigned long flags = MS_NOSUID | MS_NODEV | MS_NOEXEC;
    const unsigned int max_attempts =
            (!is_proc && kind != environment_kind::container) ? 2 : 1;
    for (unsigned int attempt = 1; attempt <= max_attempts; ++attempt) {
        if (mount(filesystem, mountpoint, filesystem, flags, nullptr) == 0) {
            std::cout << "dinit-bootstrap: mounted " << filesystem
                      << " on " << mountpoint << '\n';
            return 0;
        }

        const int mount_error = errno;
        const mount_info refreshed = detect_mounts();
        const bool refreshed_ambiguous =
                is_proc ? refreshed.proc_ambiguous : refreshed.sys_ambiguous;
        if (refreshed_ambiguous) {
            std::cerr << "dinit-bootstrap: cannot determine visible mount at "
                      << mountpoint << '\n';
            return 1;
        }
        const std::string refreshed_mount = is_proc ? refreshed.procfs : refreshed.sysfs;
        if (refreshed.available && refreshed_mount == filesystem) {
            std::cout << "dinit-bootstrap: " << mountpoint
                      << " became available as " << filesystem << '\n';
            return 0;
        }
        if (attempt == max_attempts) {
            const std::string reason = std::strerror(mount_error);
            return mount_failure(kind, filesystem, reason.c_str(), container_may_skip);
        }
        sleep(1);
    }
    return 1;
}


dinit_bootstrap::mount_result mounted_filesystem(const char *mountpoint)
{
    dinit_bootstrap::mount_table table;
    if (!dinit_bootstrap::read_mountinfo("/proc/self/mountinfo", table))
        return dinit_bootstrap::mount_result(dinit_bootstrap::mount_state::ambiguous);
    return dinit_bootstrap::find_visible_mount(table, mountpoint);
}

int ensure_device_filesystem(const char *mountpoint, const char *filesystem,
        unsigned long flags, const char *options, bool accept_existing_any,
        bool container_may_skip)
{
    if (getppid() != 1) {
        std::cerr << "dinit-bootstrap: refusing device filesystem setup: "
                     "helper is not a direct child of PID 1\n";
        return 1;
    }
    if (!ensure_mountpoint_directory(mountpoint)) return 1;

    dinit_bootstrap::mount_result current = mounted_filesystem(mountpoint);
    if (current.state == dinit_bootstrap::mount_state::ambiguous) {
        std::cerr << "dinit-bootstrap: cannot determine visible mount at "
                  << mountpoint << "; refusing to mount over an unknown state\n";
        return 1;
    }
    if (current.state == dinit_bootstrap::mount_state::mounted) {
        const std::string &type = current.entry.filesystem;
        if (type == filesystem || accept_existing_any) {
            std::cout << "dinit-bootstrap: " << mountpoint
                      << " already mounted as " << type << '\n';
            return 0;
        }
        std::cerr << "dinit-bootstrap: " << mountpoint << " is mounted as "
                  << type << ", expected " << filesystem << '\n';
        return 1;
    }

    const environment_kind kind = load_environment_kind();
    if (mount(filesystem, mountpoint, filesystem, flags, options) == 0) {
        std::cout << "dinit-bootstrap: mounted " << filesystem
                  << " on " << mountpoint << '\n';
        return 0;
    }
    const int mount_error = errno;
    current = mounted_filesystem(mountpoint);
    if (current.state == dinit_bootstrap::mount_state::mounted) {
        const std::string &type = current.entry.filesystem;
        if (type == filesystem || accept_existing_any) {
            std::cout << "dinit-bootstrap: " << mountpoint
                      << " became available as " << type << '\n';
            return 0;
        }
        std::cerr << "dinit-bootstrap: " << mountpoint
                  << " became occupied by " << type << '\n';
        return 1;
    }
    if (current.state == dinit_bootstrap::mount_state::ambiguous) {
        std::cerr << "dinit-bootstrap: mount failed and the resulting mount state at "
                  << mountpoint << " cannot be determined\n";
        return 1;
    }
    return mount_failure(kind, filesystem, std::strerror(mount_error),
            container_may_skip);
}

int ensure_dev()
{
    // A runtime-provided bind mount or devtmpfs is already authoritative.
    // Never cover an existing /dev mount from inside a container.
    return ensure_device_filesystem("/dev", "devtmpfs",
            MS_NOSUID, "mode=0755", true, true);
}

int ensure_devpts()
{
    if (ensure_device_filesystem("/dev/pts", "devpts",
            MS_NOSUID | MS_NOEXEC, "mode=0620,ptmxmode=0666", false, false) != 0)
        return 1;

    // Verify the complete /dev/ptmx -> devpts path instead of requiring a
    // particular symlink or device-node layout.
    int master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (master < 0) {
        std::cerr << "dinit-bootstrap: cannot open /dev/ptmx: "
                  << std::strerror(errno) << '\n';
        return 1;
    }
    if (grantpt(master) != 0) {
        const int error = errno;
        close(master);
        std::cerr << "dinit-bootstrap: grantpt failed: "
                  << std::strerror(error) << '\n';
        return 1;
    }
    if (unlockpt(master) != 0) {
        const int error = errno;
        close(master);
        std::cerr << "dinit-bootstrap: unlockpt failed: "
                  << std::strerror(error) << '\n';
        return 1;
    }
    char slave_path[4096];
    const int name_error = ptsname_r(master, slave_path, sizeof(slave_path));
    if (name_error != 0) {
        close(master);
        std::cerr << "dinit-bootstrap: ptsname_r failed: "
                  << std::strerror(name_error) << '\n';
        return 1;
    }
    const int slave = open(slave_path, O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (slave < 0) {
        const int error = errno;
        close(master);
        std::cerr << "dinit-bootstrap: cannot open allocated PTY slave "
                  << slave_path << ": " << std::strerror(error) << '\n';
        return 1;
    }
    close(slave);
    close(master);
    std::cout << "dinit-bootstrap: PTY allocation test passed\n";
    return 0;
}

int ensure_shm()
{
    return ensure_device_filesystem("/dev/shm", "tmpfs",
            MS_NOSUID | MS_NODEV, "mode=1777", false, true);
}

std::string find_executable(const std::string &name)
{
    if (name.find('/') != std::string::npos)
        return access(name.c_str(), X_OK) == 0 ? name : std::string();

    std::string path = "/usr/sbin:/usr/bin:/sbin:/bin";
    const char *environment_path = std::getenv("PATH");
    if (environment_path != nullptr && *environment_path != '\0')
        path += ":" + std::string(environment_path);

    std::istringstream paths(path);
    std::string directory;
    while (std::getline(paths, directory, ':')) {
        if (directory.empty()) directory = ".";
        const std::string candidate = directory + "/" + name;
        if (access(candidate.c_str(), X_OK) == 0) return candidate;
    }
    return std::string();
}

bool executable_in_path(const std::string &name)
{
    return !find_executable(name).empty();
}

volatile sig_atomic_t active_child_pid = -1;

void forward_signal_to_child(int signal_number)
{
    const pid_t child = static_cast<pid_t>(active_child_pid);
    if (child > 0) (void) kill(child, signal_number);
}

int execute_program(const std::vector<std::string> &arguments, bool optional,
        bool *normal_exit = nullptr, int *term_signal = nullptr)
{
    if (normal_exit != nullptr) *normal_exit = false;
    if (term_signal != nullptr) *term_signal = 0;
    if (arguments.empty()) return 2;
    const std::string executable = find_executable(arguments[0]);
    if (executable.empty()) {
        if (optional) {
            std::cout << "dinit-bootstrap: optional tool " << arguments[0]
                      << " is not installed; skipping\n";
            return 0;
        }
        std::cerr << "dinit-bootstrap: required tool " << arguments[0]
                  << " is not installed\n";
        return 1;
    }

    sigset_t forwarded_signals, old_mask;
    sigemptyset(&forwarded_signals);
    sigaddset(&forwarded_signals, SIGTERM);
    sigaddset(&forwarded_signals, SIGINT);
    sigaddset(&forwarded_signals, SIGHUP);
    if (sigprocmask(SIG_BLOCK, &forwarded_signals, &old_mask) != 0) {
        std::cerr << "dinit-bootstrap: cannot block signals before spawning tool: "
                  << std::strerror(errno) << '\n';
        return 1;
    }

    struct sigaction action, old_term, old_int, old_hup;
    std::memset(&action, 0, sizeof(action));
    action.sa_handler = forward_signal_to_child;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, &old_term) != 0) {
        const int saved_errno = errno;
        (void) sigprocmask(SIG_SETMASK, &old_mask, nullptr);
        std::cerr << "dinit-bootstrap: cannot install SIGTERM forwarding: "
                  << std::strerror(saved_errno) << '\n';
        return 1;
    }
    if (sigaction(SIGINT, &action, &old_int) != 0) {
        const int saved_errno = errno;
        (void) sigaction(SIGTERM, &old_term, nullptr);
        (void) sigprocmask(SIG_SETMASK, &old_mask, nullptr);
        std::cerr << "dinit-bootstrap: cannot install SIGINT forwarding: "
                  << std::strerror(saved_errno) << '\n';
        return 1;
    }
    if (sigaction(SIGHUP, &action, &old_hup) != 0) {
        const int saved_errno = errno;
        (void) sigaction(SIGTERM, &old_term, nullptr);
        (void) sigaction(SIGINT, &old_int, nullptr);
        (void) sigprocmask(SIG_SETMASK, &old_mask, nullptr);
        std::cerr << "dinit-bootstrap: cannot install SIGHUP forwarding: "
                  << std::strerror(saved_errno) << '\n';
        return 1;
    }

    int error_pipe[2];
    if (pipe(error_pipe) != 0) {
        (void) sigaction(SIGTERM, &old_term, nullptr);
        (void) sigaction(SIGINT, &old_int, nullptr);
        (void) sigaction(SIGHUP, &old_hup, nullptr);
        (void) sigprocmask(SIG_SETMASK, &old_mask, nullptr);
        std::cerr << "dinit-bootstrap: pipe: " << std::strerror(errno) << '\n';
        return 1;
    }
    if (fcntl(error_pipe[1], F_SETFD, FD_CLOEXEC) != 0) {
        const int saved_errno = errno;
        close(error_pipe[0]); close(error_pipe[1]);
        (void) sigaction(SIGTERM, &old_term, nullptr);
        (void) sigaction(SIGINT, &old_int, nullptr);
        (void) sigaction(SIGHUP, &old_hup, nullptr);
        (void) sigprocmask(SIG_SETMASK, &old_mask, nullptr);
        std::cerr << "dinit-bootstrap: fcntl: " << std::strerror(saved_errno) << '\n';
        return 1;
    }
    const pid_t expected_parent = getpid();
    const pid_t child = fork();
    if (child < 0) {
        const int saved_errno = errno;
        close(error_pipe[0]); close(error_pipe[1]);
        (void) sigaction(SIGTERM, &old_term, nullptr);
        (void) sigaction(SIGINT, &old_int, nullptr);
        (void) sigaction(SIGHUP, &old_hup, nullptr);
        (void) sigprocmask(SIG_SETMASK, &old_mask, nullptr);
        std::cerr << "dinit-bootstrap: fork: " << std::strerror(saved_errno) << '\n';
        return 1;
    }
    if (child == 0) {
        close(error_pipe[0]);
        (void) sigaction(SIGTERM, &old_term, nullptr);
        (void) sigaction(SIGINT, &old_int, nullptr);
        (void) sigaction(SIGHUP, &old_hup, nullptr);
        (void) prctl(PR_SET_PDEATHSIG, SIGTERM);
        if (getppid() != expected_parent) _exit(128 + SIGTERM);
        (void) sigprocmask(SIG_SETMASK, &old_mask, nullptr);
        std::vector<char *> argv;
        for (std::size_t i = 0; i < arguments.size(); ++i)
            argv.push_back(const_cast<char *>(arguments[i].c_str()));
        argv.push_back(nullptr);
        execv(executable.c_str(), &argv[0]);
        const int exec_error = errno;
        (void) write(error_pipe[1], &exec_error, sizeof(exec_error));
        _exit(127);
    }
    active_child_pid = child;
    (void) sigprocmask(SIG_SETMASK, &old_mask, nullptr);
    close(error_pipe[1]);
    int exec_error = 0;
    ssize_t received;
    do { received = read(error_pipe[0], &exec_error, sizeof(exec_error)); }
    while (received < 0 && errno == EINTR);
    close(error_pipe[0]);
    int status = 0;
    pid_t waited;
    do { waited = waitpid(child, &status, 0); }
    while (waited < 0 && errno == EINTR);
    sigset_t current_mask;
    (void) sigprocmask(SIG_BLOCK, &forwarded_signals, &current_mask);
    active_child_pid = -1;
    (void) sigaction(SIGTERM, &old_term, nullptr);
    (void) sigaction(SIGINT, &old_int, nullptr);
    (void) sigaction(SIGHUP, &old_hup, nullptr);
    (void) sigprocmask(SIG_SETMASK, &old_mask, nullptr);
    if (waited < 0) {
        std::cerr << "dinit-bootstrap: waitpid: " << std::strerror(errno) << '\n';
        return 1;
    }
    if (received < 0) {
        std::cerr << "dinit-bootstrap: cannot read exec status pipe: "
                  << std::strerror(errno) << '\n';
        return 1;
    }
    if (received > 0) {
        if (optional && exec_error == ENOENT) {
            std::cout << "dinit-bootstrap: optional tool " << arguments[0]
                      << " is not installed; skipping\n";
            return 0;
        }
        std::cerr << "dinit-bootstrap: cannot execute " << arguments[0]
                  << ": " << std::strerror(exec_error) << '\n';
        return 1;
    }
    if (WIFEXITED(status)) {
        if (normal_exit != nullptr) *normal_exit = true;
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        if (term_signal != nullptr) *term_signal = WTERMSIG(status);
        return 128 + WTERMSIG(status);
    }
    return 1;
}

bool clear_root_fsck_status()
{
    struct stat directory_stat;
    if (lstat("/run/dinit", &directory_stat) != 0) {
        if (errno == ENOENT) return true;
        std::cerr << "dinit-bootstrap: cannot inspect /run/dinit: "
                  << std::strerror(errno) << '\n';
        return false;
    }
    if (!S_ISDIR(directory_stat.st_mode)) {
        std::cerr << "dinit-bootstrap: /run/dinit is not a real directory\n";
        return false;
    }
    if (unlink("/run/dinit/root-fsck.status") != 0 && errno != ENOENT) {
        std::cerr << "dinit-bootstrap: cannot clear previous root fsck status: "
                  << std::strerror(errno) << '\n';
        return false;
    }
    return true;
}

bool write_root_fsck_status(const std::string &contents)
{
    return write_runtime_state_file("root-fsck.status", contents);
}

struct fsck_options {
    bool skip;
    bool force;
    std::string repair;
    fsck_options() : skip(false), force(false), repair("-a") {}
};

fsck_options read_fsck_options()
{
    fsck_options options;
    std::istringstream cmdline(read_file("/proc/cmdline"));
    std::string item;
    while (cmdline >> item) {
        if (item == "fastboot") { options.skip = true; options.force = false; }
        else if (item == "forcefsck") { options.skip = false; options.force = true; }
        else if (item.compare(0, 10, "fsck.mode=") == 0) {
            const std::string mode = item.substr(10);
            if (mode == "auto") { options.skip = false; options.force = false; }
            else if (mode == "force") { options.skip = false; options.force = true; }
            else if (mode == "skip") { options.skip = true; options.force = false; }
        }
        else if (item == "fsckfix") options.repair = "-y";
        else if (item.compare(0, 12, "fsck.repair=") == 0) {
            const std::string repair = item.substr(12);
            if (repair == "yes" || repair == "true") options.repair = "-y";
            else if (repair == "no" || repair == "false") options.repair = "-n";
            else if (repair == "preen") options.repair = "-a";
        }
    }
    return options;
}

struct root_fstab_info {
    bool present;
    bool found_root;
    bool ambiguous_root;
    bool readonly;
    bool fsck_requested;
};

bool read_root_fstab_info(root_fstab_info &info)
{
    info.present = false;
    info.found_root = false;
    info.ambiguous_root = false;
    info.readonly = true;
    info.fsck_requested = false;

    errno = 0;
    FILE *fstab = setmntent("/etc/fstab", "r");
    if (fstab == nullptr) {
        if (errno == ENOENT) return true;
        if (errno == 0) errno = EIO;
        return false;
    }
    info.present = true;

    struct mntent *entry;
    while ((entry = getmntent(fstab)) != nullptr) {
        if (std::strcmp(entry->mnt_dir, "/") != 0) continue;
        if (info.found_root) {
            info.ambiguous_root = true;
            continue;
        }
        info.found_root = true;
        info.fsck_requested = entry->mnt_passno > 0;
        info.readonly = false;
        bool noauto = false;
        std::istringstream options(entry->mnt_opts);
        std::string option;
        while (std::getline(options, option, ',')) {
            if (option == "ro") info.readonly = true;
            else if (option == "rw") info.readonly = false;
            else if (option == "noauto") noauto = true;
        }
        // systemd-fstab-generator does not schedule an automatic fsck for
        // entries explicitly excluded from automatic activation.
        if (noauto) info.fsck_requested = false;
    }

    const bool read_error = ferror(fstab) != 0;
    const int saved_errno = errno;
    endmntent(fstab);
    if (read_error) {
        errno = saved_errno != 0 ? saved_errno : EIO;
        return false;
    }
    return true;
}

int run_root_fsck()
{
    if (load_environment_kind() == environment_kind::container) {
        std::cout << "dinit-bootstrap: root fsck is skipped inside a container\n";
        return 0;
    }
    if (!clear_root_fsck_status()) return 1;

    const fsck_options options = read_fsck_options();
    if (options.skip) {
        std::cout << "dinit-bootstrap: root fsck disabled by kernel command line\n";
        return 0;
    }
    root_fstab_info fstab_info;
    if (!read_root_fstab_info(fstab_info)) {
        std::cerr << "dinit-bootstrap: cannot read /etc/fstab for root fsck: "
                  << std::strerror(errno) << '\n';
        return 1;
    }
    if (fstab_info.ambiguous_root) {
        std::cerr << "dinit-bootstrap: multiple root entries in /etc/fstab; refusing root fsck\n";
        return 1;
    }
    if (!fstab_info.present || !fstab_info.found_root || !fstab_info.fsck_requested) {
        std::cout << "dinit-bootstrap: root fsck is not requested by /etc/fstab\n";
        return 0;
    }

    struct stat root_stat;
    if (stat("/", &root_stat) != 0) {
        std::cerr << "dinit-bootstrap: cannot inspect root filesystem: "
                  << std::strerror(errno) << '\n';
        return 1;
    }

    // Like systemd, only consider a read-only, block-device-backed root.
    // Virtual roots (tmpfs, overlayfs, containers, etc.) are not fsck targets.
    if (major(root_stat.st_dev) == 0) {
        std::cout << "dinit-bootstrap: root filesystem is virtual; skipping fsck\n";
        return 0;
    }

    struct timespec times[2];
    times[0] = root_stat.st_atim;
    times[1] = root_stat.st_mtim;
    if (utimensat(AT_FDCWD, "/", times, 0) == 0) {
        std::cout << "dinit-bootstrap: root filesystem is already read-write; skipping fsck\n";
        return 0;
    }

    FILE *mounts = setmntent("/proc/self/mounts", "r");
    if (mounts == nullptr) {
        std::cerr << "dinit-bootstrap: cannot inspect root mount source\n";
        return 1;
    }
    std::string root_source;
    std::string root_type;
    bool root_is_readonly = false;
    struct mntent *mount_entry;
    while ((mount_entry = getmntent(mounts)) != nullptr) {
        if (std::strcmp(mount_entry->mnt_dir, "/") == 0) {
            root_source = mount_entry->mnt_fsname;
            root_type = mount_entry->mnt_type;
            root_is_readonly = hasmntopt(mount_entry, "ro") != nullptr;
            break;
        }
    }
    endmntent(mounts);

    if (root_source.empty() || root_type.empty()) {
        std::cerr << "dinit-bootstrap: root mount entry is unavailable; refusing fsck\n";
        return 1;
    }

    // A failed timestamp probe alone is not enough: require the mount table
    // to explicitly report a read-only root before invoking fsck.
    if (!root_is_readonly) {
        std::cout << "dinit-bootstrap: root mount is not marked read-only; skipping fsck\n";
        return 0;
    }

    struct stat device_stat;
    if (stat(root_source.c_str(), &device_stat) != 0 ||
            !S_ISBLK(device_stat.st_mode) || device_stat.st_rdev != root_stat.st_dev) {
        std::cout << "dinit-bootstrap: root source is not the matching block device; skipping fsck\n";
        return 0;
    }

    if (!executable_in_path("fsck") ||
            !executable_in_path("fsck." + root_type)) {
        std::cout << "dinit-bootstrap: no fsck helper for root filesystem type "
                  << root_type << "; skipping\n";
        return 0;
    }

    std::vector<std::string> args;
    args.push_back("fsck");
    args.push_back("-t");
    args.push_back(root_type);
    args.push_back(options.repair);
    if (options.force) args.push_back("-f");
    args.push_back(root_source);

    bool normal_exit = false;
    int term_signal = 0;
    const int result = execute_program(args, false, &normal_exit, &term_signal);
    if (!normal_exit) {
        if (term_signal != 0) {
            std::ostringstream state;
            state << "kind=signaled\nsignal=" << term_signal << '\n';
            (void) write_root_fsck_status(state.str());
            std::cerr << "dinit-bootstrap: root fsck was terminated by signal "
                      << term_signal << '\n';
        }
        else {
            (void) write_root_fsck_status("kind=execution-failed\n");
            std::cerr << "dinit-bootstrap: root fsck did not exit normally; "
                         "not interpreting the result as an fsck status\n";
        }
        return 1;
    }
    if (result == 0 || result == 1) return 0;
    std::ostringstream state;
    state << "kind=exited\n"
          << "status=" << result << '\n'
          << "reboot_required=" << ((result & 2) ? "yes" : "no") << '\n'
          << "uncorrected_errors=" << ((result & 4) ? "yes" : "no") << '\n';
    (void) write_root_fsck_status(state.str());

    // fsck status is a bitmask: report every set condition independently,
    // since operational errors can be combined with recovery-critical bits.
    std::cerr << "dinit-bootstrap: root fsck failed (status " << result << ")";
    if ((result & 2) != 0)
        std::cerr << "; a system reboot is required";
    if ((result & 4) != 0)
        std::cerr << "; filesystem errors remain uncorrected";
    if ((result & 1) != 0)
        std::cerr << "; errors were corrected";
    if ((result & ~7) != 0)
        std::cerr << "; operational, usage, cancellation, or shared-library error bits are set";
    std::cerr << '\n';
    return 1;
}

int run_local_fsck()
{
    if (load_environment_kind() == environment_kind::container) {
        std::cout << "dinit-bootstrap: local fsck is skipped inside a container\n";
        return 0;
    }
    const fsck_options options = read_fsck_options();
    if (options.skip) return 0;
    if (!executable_in_path("fsck")) {
        std::cout << "dinit-bootstrap: fsck is not installed; skipping local checks\n";
        return 0;
    }
    std::vector<std::string> args;
    args.push_back("fsck"); args.push_back("-A"); args.push_back("-R");
    // BusyBox fsck requires an explicit descriptor after -C, while util-linux
    // treats it as optional. Progress reporting is cosmetic, so omit -C for
    // consistent behavior across both implementations.
    args.push_back("-t"); args.push_back("noopts=_netdev");
    if (options.force) args.push_back("-f");
    args.push_back(options.repair);
    const int result = execute_program(args, false);
    if (result == 0 || result == 1) return 0;
    std::cerr << "dinit-bootstrap: local fsck failed (status " << result << ")\n";
    return 1;
}

int run_mount_local()
{
    if (load_environment_kind() == environment_kind::container) {
        std::cout << "dinit-bootstrap: fstab mounting is skipped inside a container\n";
        return 0;
    }
    std::vector<std::string> args;
    args.push_back("mount"); args.push_back("-a"); args.push_back("-t");
    args.push_back("nosysfs,nfs,nfs4,smbfs,cifs");
    args.push_back("-O"); args.push_back("no_netdev");
    return execute_program(args, false);
}

int run_root_rw()
{
    FILE *mounts = setmntent("/proc/self/mounts", "r");
    if (mounts == nullptr) {
        std::cerr << "dinit-bootstrap: cannot inspect root mount options\n";
        return 1;
    }
    bool root_found = false;
    bool root_is_rw = false;
    struct mntent *entry;
    while ((entry = getmntent(mounts)) != nullptr) {
        if (std::strcmp(entry->mnt_dir, "/") == 0) {
            root_found = true;
            root_is_rw = hasmntopt(entry, "rw") != nullptr;
            break;
        }
    }
    endmntent(mounts);
    if (!root_found) {
        std::cerr << "dinit-bootstrap: root mount entry is unavailable; refusing remount\n";
        return 1;
    }
    if (root_is_rw) {
        std::cout << "dinit-bootstrap: root filesystem is already read-write\n";
        return 0;
    }
    root_fstab_info fstab_info;
    if (!read_root_fstab_info(fstab_info)) {
        std::cerr << "dinit-bootstrap: cannot read /etc/fstab for root remount: "
                  << std::strerror(errno) << '\n';
        return 1;
    }
    if (fstab_info.ambiguous_root) {
        std::cerr << "dinit-bootstrap: multiple root entries in /etc/fstab; refusing root remount\n";
        return 1;
    }
    if (!fstab_info.present || !fstab_info.found_root || fstab_info.readonly) {
        std::cout << "dinit-bootstrap: root filesystem is configured read-only or has no fstab policy; leaving it unchanged\n";
        return 0;
    }
    if (load_environment_kind() == environment_kind::container) {
        std::cout << "dinit-bootstrap: read-only container root is left unchanged\n";
        return 0;
    }
    std::vector<std::string> args;
    args.push_back("mount"); args.push_back("-o");
    args.push_back("remount,rw"); args.push_back("/");
    return execute_program(args, false);
}

int run_swap_on()
{
    if (load_environment_kind() == environment_kind::container) {
        std::cout << "dinit-bootstrap: swap activation is skipped inside a container\n";
        return 0;
    }
    std::vector<std::string> args;
    args.push_back("swapon"); args.push_back("-a");
    return execute_program(args, true);
}

std::map<std::string, std::string> collect_config_files(const char *subdirectory)
{
    const char *prefixes[] = { "/etc", "/run", "/usr/local/lib", "/usr/lib", "/lib" };
    std::map<std::string, std::string> files;
    for (const char *prefix : prefixes) {
        const std::string directory = std::string(prefix) + "/" + subdirectory;
        DIR *handle = opendir(directory.c_str());
        if (handle == nullptr) continue;
        struct dirent *entry;
        while ((entry = readdir(handle)) != nullptr) {
            const std::string name(entry->d_name);
            if (name.size() <= 5 || name[0] == '.' ||
                    name.compare(name.size() - 5, 5, ".conf") != 0 ||
                    files.find(name) != files.end())
                continue;
            const std::string path = directory + "/" + name;
            // Record the name before checking the target so /dev/null symlinks
            // mask lower-priority vendor files just like standard drop-in dirs.
            files[name] = std::string();
            struct stat st;
            if (stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode))
                files[name] = path;
        }
        closedir(handle);
    }
    return files;
}

int run_modules_load()
{
    if (load_environment_kind() == environment_kind::container) {
        std::cout << "dinit-bootstrap: module loading is skipped inside a container\n";
        return 0;
    }
    if (find_executable("modprobe").empty()) {
        std::cout << "dinit-bootstrap: modprobe is not installed; skipping module loading\n";
        return 0;
    }

    const std::map<std::string, std::string> files = collect_config_files("modules-load.d");
    std::set<std::string> loaded;
    unsigned int failures = 0;
    for (std::map<std::string, std::string>::const_iterator file = files.begin();
            file != files.end(); ++file) {
        if (file->second.empty()) continue;
        std::istringstream contents(read_file(file->second.c_str()));
        std::string line;
        while (std::getline(contents, line)) {
            const std::string::size_type comment = line.find('#');
            if (comment != std::string::npos) line.erase(comment);
            std::istringstream fields(line);
            std::string module;
            if (!(fields >> module)) continue;
            if (module[0] == '-') {
                std::cerr << "dinit-bootstrap: ignoring invalid module name in "
                          << file->second << '\n';
                continue;
            }
            bool valid = true;
            for (std::string::size_type i = 0; i < module.size(); ++i) {
                const char ch = module[i];
                if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                        (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.')) {
                    valid = false;
                    break;
                }
            }
            if (!valid) {
                std::cerr << "dinit-bootstrap: ignoring invalid module name in "
                          << file->second << '\n';
                continue;
            }
            if (!loaded.insert(module).second) continue;
            std::vector<std::string> args;
            args.push_back("modprobe");
            args.push_back(module);
            const int result = execute_program(args, false);
            if (result != 0) {
                ++failures;
                std::cerr << "dinit-bootstrap: could not load module " << module
                          << " (status " << result << "); continuing\n";
            }
        }
    }
    std::cout << "dinit-bootstrap: module loading completed; "
              << failures << " module(s) failed\n";
    return 0;
}

int run_set_hostname()
{
    if (load_environment_kind() == environment_kind::container) {
        std::cout << "dinit-bootstrap: hostname is supplied by the container runtime; leaving it unchanged\n";
        return 0;
    }
    const std::string hostname = trim(read_file("/etc/hostname"));
    if (hostname.empty()) {
        std::cout << "dinit-bootstrap: /etc/hostname is empty or unavailable; skipping hostname setup\n";
        return 0;
    }
    if (hostname.size() > 64 || hostname.find_first_of(" \t\r\n") != std::string::npos) {
        std::cerr << "dinit-bootstrap: /etc/hostname contains an invalid hostname\n";
        return 1;
    }
    if (sethostname(hostname.c_str(), hostname.size()) != 0) {
        std::cerr << "dinit-bootstrap: sethostname failed: " << std::strerror(errno) << '\n';
        return 1;
    }
    std::cout << "dinit-bootstrap: hostname set to " << hostname << '\n';
    return 0;
}

int run_sysctl_load()
{
    if (load_environment_kind() == environment_kind::container) {
        std::cout << "dinit-bootstrap: sysctl loading is skipped inside a container\n";
        return 0;
    }
    const std::map<std::string, std::string> files = collect_config_files("sysctl.d");
    unsigned int failures = 0;
    for (std::map<std::string, std::string>::const_iterator file = files.begin();
            file != files.end(); ++file) {
        if (file->second.empty()) continue;
        std::istringstream contents(read_file(file->second.c_str()));
        std::string line;
        while (std::getline(contents, line)) {
            const std::string::size_type comment = line.find('#');
            if (comment != std::string::npos) line.erase(comment);
            const std::string::size_type separator = line.find('=');
            if (separator == std::string::npos) continue;
            std::string key = trim(line.substr(0, separator));
            const std::string value = trim(line.substr(separator + 1));
            if (key.empty() || value.empty()) continue;
            if (key[0] == '-') key.erase(0, 1); // systemd-sysctl compatible ignore-errors prefix
            bool valid = !key.empty() && key[0] != '.' && key[key.size() - 1] != '.';
            for (std::string::size_type i = 0; valid && i < key.size(); ++i) {
                const char ch = key[i];
                if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                        (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.'))
                    valid = false;
                if (ch == '.' && i + 1 < key.size() && key[i + 1] == '.') valid = false;
            }
            if (!valid) {
                std::cerr << "dinit-bootstrap: ignoring invalid sysctl key in "
                          << file->second << '\n';
                continue;
            }
            std::string path = "/proc/sys/";
            for (std::string::size_type i = 0; i < key.size(); ++i)
                path += key[i] == '.' ? '/' : key[i];
            std::ofstream output(path.c_str());
            if (!output || !(output << value << '\n')) {
                ++failures;
                std::cerr << "dinit-bootstrap: could not apply " << key
                          << " from " << file->second << '\n';
            }
        }
    }
    std::cout << "dinit-bootstrap: sysctl configuration processed; "
              << failures << " setting(s) failed\n";
    return 0;
}

int run_machine_id()
{
    if (load_environment_kind() == environment_kind::container) {
        std::cout << "dinit-bootstrap: machine-id is supplied by the container runtime; leaving it unchanged\n";
        return 0;
    }

    const char *machine_id_path = "/etc/machine-id";
    struct stat original_stat;
    bool replace_existing = false;
    int existing_fd = open(machine_id_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (existing_fd >= 0) {
        if (fstat(existing_fd, &original_stat) != 0) {
            const int error = errno;
            close(existing_fd);
            std::cerr << "dinit-bootstrap: cannot inspect /etc/machine-id: "
                      << std::strerror(error) << '\n';
            return 1;
        }
        if (!S_ISREG(original_stat.st_mode)) {
            close(existing_fd);
            std::cout << "dinit-bootstrap: /etc/machine-id is not a regular file; leaving it unchanged\n";
            return 0;
        }

        char existing_buffer[129];
        std::size_t existing_size = 0;
        bool read_failed = false;
        while (existing_size < sizeof(existing_buffer)) {
            const ssize_t count = read(existing_fd, existing_buffer + existing_size,
                    sizeof(existing_buffer) - existing_size);
            if (count < 0 && errno == EINTR) continue;
            if (count < 0) {
                read_failed = true;
                break;
            }
            if (count == 0) break;
            existing_size += static_cast<std::size_t>(count);
        }
        const int read_error = errno;
        close(existing_fd);
        if (read_failed) {
            std::cerr << "dinit-bootstrap: cannot read /etc/machine-id: "
                      << std::strerror(read_error) << '\n';
            return 1;
        }
        if (existing_size == sizeof(existing_buffer)) {
            std::cerr << "dinit-bootstrap: existing /etc/machine-id is invalid; leaving it unchanged\n";
            return 0;
        }

        const std::string existing = trim(
                std::string(existing_buffer, existing_size));
        bool valid = existing.size() == 32;
        bool nonzero = false;
        for (std::string::size_type i = 0; valid && i < existing.size(); ++i) {
            const char ch = existing[i];
            const bool hex = (ch >= '0' && ch <= '9') ||
                    (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
            if (!hex) valid = false;
            if (ch != '0') nonzero = true;
        }
        if (valid && nonzero) {
            std::cout << "dinit-bootstrap: existing machine-id is preserved\n";
            return 0;
        }
        if ((valid && !nonzero) ||
                (existing.empty() && original_stat.st_size == 0)) {
            replace_existing = true;
        }
        else {
            std::cerr << "dinit-bootstrap: existing /etc/machine-id is invalid; leaving it unchanged\n";
            return 0;
        }
    }
    else if (errno != ENOENT) {
        const int error = errno;
        if (error == ELOOP) {
            std::cout << "dinit-bootstrap: /etc/machine-id is a symbolic link; leaving it unchanged\n";
            return 0;
        }
        std::cerr << "dinit-bootstrap: cannot open /etc/machine-id: "
                  << std::strerror(error) << '\n';
        return 1;
    }

    // Linux 4.9 (the minimum supported kernel) has getrandom(2). Calling the
    // syscall directly avoids requiring a newer libc wrapper, and blocking
    // mode prevents generating an ID from an uninitialized early-boot pool.
    unsigned char random_bytes[16];
#ifndef SYS_getrandom
    std::cerr << "dinit-bootstrap: getrandom syscall number is unavailable on this architecture\n";
    return 1;
#else
    std::size_t received = 0;
    while (received < sizeof(random_bytes)) {
        const long count = syscall(SYS_getrandom, random_bytes + received,
                sizeof(random_bytes) - received, 0);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) {
            std::cerr << "dinit-bootstrap: getrandom failed: "
                      << std::strerror(errno) << '\n';
            return 1;
        }
        if (count == 0) {
            std::cerr << "dinit-bootstrap: getrandom returned no data\n";
            return 1;
        }
        received += static_cast<std::size_t>(count);
    }
#endif

    static const char digits[] = "0123456789abcdef";
    std::string machine_id;
    for (unsigned int i = 0; i < sizeof(random_bytes); ++i) {
        machine_id += digits[(random_bytes[i] >> 4) & 0x0f];
        machine_id += digits[random_bytes[i] & 0x0f];
    }
    machine_id += '\n';

    // Prepare and sync a complete replacement before making it visible.
    std::string temporary_path = "/etc/.machine-id.XXXXXX";
    int temporary_fd = mkstemp(&temporary_path[0]);
    if (temporary_fd < 0) {
        if (errno == EROFS) {
            std::cout << "dinit-bootstrap: /etc is read-only; skipping machine-id creation\n";
            return 0;
        }
        std::cerr << "dinit-bootstrap: cannot create temporary machine-id: "
                  << std::strerror(errno) << '\n';
        return 1;
    }
    bool temporary_exists = true;
    const auto cleanup_temporary = [&]() {
        if (temporary_fd >= 0) close(temporary_fd);
        if (temporary_exists) unlink(temporary_path.c_str());
    };

    if (fcntl(temporary_fd, F_SETFD, FD_CLOEXEC) != 0 ||
            fchmod(temporary_fd, 0444) != 0) {
        const int error = errno;
        cleanup_temporary();
        std::cerr << "dinit-bootstrap: cannot prepare temporary machine-id: "
                  << std::strerror(error) << '\n';
        return 1;
    }

    std::size_t written = 0;
    while (written < machine_id.size()) {
        const ssize_t count = write(temporary_fd, machine_id.data() + written,
                machine_id.size() - written);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            const int error = count < 0 ? errno : EIO;
            cleanup_temporary();
            std::cerr << "dinit-bootstrap: cannot write temporary machine-id: "
                      << std::strerror(error) << '\n';
            return 1;
        }
        written += static_cast<std::size_t>(count);
    }
    if (fsync(temporary_fd) != 0) {
        const int error = errno;
        cleanup_temporary();
        std::cerr << "dinit-bootstrap: cannot sync temporary machine-id: "
                  << std::strerror(error) << '\n';
        return 1;
    }
    if (close(temporary_fd) != 0) {
        const int error = errno;
        temporary_fd = -1;
        unlink(temporary_path.c_str());
        std::cerr << "dinit-bootstrap: cannot close temporary machine-id: "
                  << std::strerror(error) << '\n';
        return 1;
    }
    temporary_fd = -1;

    const int directory_fd = open("/etc", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory_fd < 0) {
        const int error = errno;
        unlink(temporary_path.c_str());
        std::cerr << "dinit-bootstrap: cannot open /etc for syncing: "
                  << std::strerror(error) << '\n';
        return 1;
    }

    if (replace_existing) {
        struct stat current_stat;
        if (lstat(machine_id_path, &current_stat) != 0 ||
                !S_ISREG(current_stat.st_mode) ||
                current_stat.st_dev != original_stat.st_dev ||
                current_stat.st_ino != original_stat.st_ino) {
            close(directory_fd);
            unlink(temporary_path.c_str());
            std::cout << "dinit-bootstrap: machine-id changed concurrently; leaving it unchanged\n";
            return 0;
        }
        if (std::rename(temporary_path.c_str(), machine_id_path) != 0) {
            const int error = errno;
            close(directory_fd);
            unlink(temporary_path.c_str());
            std::cerr << "dinit-bootstrap: cannot atomically replace machine-id: "
                      << std::strerror(error) << '\n';
            return 1;
        }
        temporary_exists = false;
    }
    else {
        // link() provides atomic create-if-absent semantics; unlike rename(),
        // it cannot overwrite a file created by an administrator concurrently.
        if (link(temporary_path.c_str(), machine_id_path) != 0) {
            const int error = errno;
            close(directory_fd);
            unlink(temporary_path.c_str());
            if (error == EEXIST) {
                std::cout << "dinit-bootstrap: machine-id was created concurrently; leaving it unchanged\n";
                return 0;
            }
            std::cerr << "dinit-bootstrap: cannot install machine-id: "
                      << std::strerror(error) << '\n';
            return 1;
        }
        if (unlink(temporary_path.c_str()) != 0) {
            // The final link already exists. Still sync the directory before
            // reporting the leftover temporary name.
            const int error = errno;
            if (fsync(directory_fd) != 0) {
                const int sync_error = errno;
                close(directory_fd);
                std::cerr << "dinit-bootstrap: machine-id was installed but /etc could not be synced: "
                          << std::strerror(sync_error) << '\n';
                return 1;
            }
            close(directory_fd);
            std::cerr << "dinit-bootstrap: machine-id was installed but temporary link cleanup failed: "
                      << std::strerror(error) << '\n';
            return 1;
        }
        temporary_exists = false;
    }

    if (fsync(directory_fd) != 0) {
        const int error = errno;
        close(directory_fd);
        std::cerr << "dinit-bootstrap: machine-id was installed but /etc could not be synced: "
                  << std::strerror(error) << '\n';
        return 1;
    }
    close(directory_fd);
    std::cout << "dinit-bootstrap: generated a new machine-id\n";
    return 0;
}

int run_loopback_up()
{
    const int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        if (load_environment_kind() == environment_kind::container) {
            std::cout << "dinit-bootstrap: cannot inspect loopback in container; skipping\n";
            return 0;
        }
        std::cerr << "dinit-bootstrap: cannot open network control socket: "
                  << std::strerror(errno) << '\n';
        return 1;
    }

    struct ifreq request;
    std::memset(&request, 0, sizeof(request));
    std::strncpy(request.ifr_name, "lo", IFNAMSIZ - 1);
    if (ioctl(socket_fd, SIOCGIFFLAGS, &request) != 0) {
        const int error = errno;
        close(socket_fd);
        if (load_environment_kind() == environment_kind::container) {
            std::cout << "dinit-bootstrap: loopback interface is unavailable in container; skipping\n";
            return 0;
        }
        std::cerr << "dinit-bootstrap: cannot inspect loopback interface: "
                  << std::strerror(error) << '\n';
        return 1;
    }
    if ((request.ifr_flags & IFF_UP) != 0) {
        close(socket_fd);
        std::cout << "dinit-bootstrap: loopback interface is already up\n";
        return 0;
    }
    request.ifr_flags = static_cast<short>(request.ifr_flags | IFF_UP);
    if (ioctl(socket_fd, SIOCSIFFLAGS, &request) != 0) {
        const int error = errno;
        close(socket_fd);
        if (load_environment_kind() == environment_kind::container &&
                (error == EPERM || error == EACCES)) {
            std::cout << "dinit-bootstrap: container lacks permission to bring loopback up; skipping\n";
            return 0;
        }
        std::cerr << "dinit-bootstrap: cannot bring loopback interface up: "
                  << std::strerror(error) << '\n';
        return 1;
    }
    close(socket_fd);
    std::cout << "dinit-bootstrap: loopback interface is up\n";
    return 0;
}

int run_hwclock()
{
    if (load_environment_kind() == environment_kind::container) {
        std::cout << "dinit-bootstrap: hardware clock setup is skipped inside a container\n";
        return 0;
    }
    if (find_executable("hwclock").empty()) {
        std::cout << "dinit-bootstrap: hwclock is not installed; skipping hardware clock setup\n";
        return 0;
    }
    std::vector<std::string> args;
    args.push_back("hwclock");
    args.push_back("-s");
    const int result = execute_program(args, true);
    if (result != 0) {
        std::cerr << "dinit-bootstrap: hardware clock could not set system time (status "
                  << result << "); continuing\n";
    }
    return 0;
}

int run_detect(bool stay)
{
    sigset_t signals;
    if (stay) {
        sigemptyset(&signals);
        sigaddset(&signals, SIGTERM);
        sigaddset(&signals, SIGINT);
        sigaddset(&signals, SIGHUP);
        if (sigprocmask(SIG_BLOCK, &signals, nullptr) != 0) {
            std::cerr << "dinit-bootstrap: sigprocmask: " << std::strerror(errno) << '\n';
            return 1;
        }
    }

    const environment_info info = detect_environment();
    std::cout << "dinit-bootstrap: environment: " << kind_name(info.kind) << '\n'
              << "dinit-bootstrap: Dinit parent is PID 1: " << (info.pid1 ? "yes" : "no") << '\n'
              << "dinit-bootstrap: nested PID namespace: "
              << (info.pid_namespace_depth_known ? (info.nested_pid_namespace ? "yes" : "no") : "unknown") << '\n'
              << "dinit-bootstrap: procfs: "
              << (info.mountinfo_available ? (info.procfs == "proc" ? "mounted" : "not mounted") : "unknown") << '\n'
              << "dinit-bootstrap: sysfs: "
              << (info.mountinfo_available ? (info.sysfs == "sysfs" ? "mounted" : "not mounted") : "unknown") << '\n'
              << "dinit-bootstrap: root filesystem: "
              << (info.root_fs_type.empty() ? "unknown" : info.root_fs_type) << '\n'
              << "dinit-bootstrap: cgroups: " << info.cgroups << '\n';
    if (!info.container_name.empty())
        std::cout << "dinit-bootstrap: container: " << info.container_name << '\n';
    if (!info.virtualization.empty())
        std::cout << "dinit-bootstrap: virtualization: " << info.virtualization
                  << " (using bare-metal policy)\n";

    if (!info.pid1) {
        std::cerr << "dinit-bootstrap: refusing system bootstrap: helper parent is not PID 1\n";
        return 1;
    }
    if (!write_state(info)) return 1;
    if (!stay) return 0;


    // Dinit's ready-notification pipe prevents dependent services from racing
    // the environment-state write above.
    const char ready_message[] = "READY\n";
    if (write(4, ready_message, sizeof(ready_message) - 1)
            != static_cast<ssize_t>(sizeof(ready_message) - 1)) {
        std::cerr << "dinit-bootstrap: failed to notify Dinit that detection is ready\n";
        return 1;
    }

    int signal_number = 0;
    const int wait_result = sigwait(&signals, &signal_number);
    if (wait_result != 0) {
        std::cerr << "dinit-bootstrap: sigwait: "
                  << std::strerror(wait_result) << '\n';
        return 1;
    }
    return 0;
}

} // anonymous namespace

int main(int argc, char **argv)
{
    if (argc >= 3 && std::strcmp(argv[1], "mount-pseudo") == 0) {
        if (std::strcmp(argv[2], "proc") == 0 || std::strcmp(argv[2], "sys") == 0)
            return ensure_pseudo_filesystem(argv[2]);
        std::cerr << "dinit-bootstrap: unknown pseudo filesystem: " << argv[2] << '\n';
        return 2;
    }
    if (argc >= 2 && std::strcmp(argv[1], "mount-dev") == 0) return ensure_dev();
    if (argc >= 2 && std::strcmp(argv[1], "mount-devpts") == 0) return ensure_devpts();
    if (argc >= 2 && std::strcmp(argv[1], "mount-shm") == 0) return ensure_shm();
    if (argc >= 2 && std::strcmp(argv[1], "fsck-root") == 0) return run_root_fsck();
    if (argc >= 2 && std::strcmp(argv[1], "fsck-local") == 0) return run_local_fsck();
    if (argc >= 2 && std::strcmp(argv[1], "mount-local") == 0) return run_mount_local();
    if (argc >= 2 && std::strcmp(argv[1], "root-rw") == 0) return run_root_rw();
    if (argc >= 2 && std::strcmp(argv[1], "swap-on") == 0) return run_swap_on();
    if (argc >= 2 && std::strcmp(argv[1], "modules-load") == 0) return run_modules_load();
    if (argc >= 2 && std::strcmp(argv[1], "set-hostname") == 0) return run_set_hostname();
    if (argc >= 2 && std::strcmp(argv[1], "sysctl-load") == 0) return run_sysctl_load();
    if (argc >= 2 && std::strcmp(argv[1], "loopback-up") == 0) return run_loopback_up();
    if (argc >= 2 && std::strcmp(argv[1], "hwclock") == 0) return run_hwclock();
    if (argc >= 2 && std::strcmp(argv[1], "machine-id") == 0) return run_machine_id();
    if (argc < 2 || std::strcmp(argv[1], "detect") != 0) {
        std::cerr << "Usage: dinit-bootstrap detect [--stay] | mount-pseudo proc|sys"
                     " | mount-dev | mount-devpts | mount-shm | modules-load | set-hostname | sysctl-load | loopback-up | hwclock | machine-id | fsck-root | fsck-local | mount-local | root-rw | swap-on\n";
        return 2;
    }
    return run_detect(argc > 2 && std::strcmp(argv[2], "--stay") == 0);
}
