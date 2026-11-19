// Linux Bootstrap runtime support for Dinit.
// This program is part of the generated dinit.d service package.

#include <cerrno>
#include <signal.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <mntent.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
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

    mount_info() : available(false), cgroup_v1(false), cgroup_v2(false) {}
};

mount_info detect_mounts()
{
    mount_info info;
    std::ifstream input("/proc/self/mountinfo");
    if (!input) return info;
    info.available = true;

    std::string line;
    while (std::getline(input, line)) {
        std::istringstream fields(line);
        std::string id, parent, device, root, mountpoint, options, field;
        if (!(fields >> id >> parent >> device >> root >> mountpoint >> options))
            continue;

        while (fields >> field && field != "-") {}
        std::string filesystem;
        std::string source;
        std::string super_options;
        if (field != "-" || !(fields >> filesystem >> source >> super_options))
            continue;

        if (mountpoint == "/") info.root_fs_type = filesystem;
        else if (mountpoint == "/proc") info.procfs = filesystem;
        else if (mountpoint == "/sys") info.sysfs = filesystem;
        else if (mountpoint == "/dev") info.devfs = filesystem;

        if (mountpoint == "/sys/fs/cgroup"
                || mountpoint.compare(0, 15, "/sys/fs/cgroup/") == 0) {
            if (filesystem == "cgroup") info.cgroup_v1 = true;
            else if (filesystem == "cgroup2") info.cgroup_v2 = true;
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
    if (!mounts.available) info.cgroups = "unknown";
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

bool write_state(const environment_info &info)
{
    if (mkdir("/run", 0755) != 0 && errno != EEXIST) {
        std::cerr << "dinit-bootstrap: cannot create /run: " << std::strerror(errno) << '\n';
        return false;
    }
    if (mkdir("/run/dinit", 0755) != 0 && errno != EEXIST) {
        std::cerr << "dinit-bootstrap: cannot create /run/dinit: "
                  << std::strerror(errno) << '\n';
        return false;
    }
    std::ofstream output("/run/dinit/environment");
    if (!output) {
        std::cerr << "dinit-bootstrap: cannot write /run/dinit/environment\n";
        return false;
    }
    output << "kind=" << kind_name(info.kind) << '\n'
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
    return output.good();
}

environment_kind load_environment_kind()
{
    std::ifstream input("/run/dinit/environment");
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

bool executable_in_path(const std::string &name)
{
    if (name.find('/') != std::string::npos) return access(name.c_str(), X_OK) == 0;
    const char *path = std::getenv("PATH");
    if (path == nullptr || *path == '\0') path = "/usr/sbin:/usr/bin:/sbin:/bin";
    std::istringstream paths(path);
    std::string directory;
    while (std::getline(paths, directory, ':')) {
        if (directory.empty()) directory = ".";
        if (access((directory + "/" + name).c_str(), X_OK) == 0) return true;
    }
    return false;
}

volatile sig_atomic_t active_child_pid = -1;

void forward_signal_to_child(int signal_number)
{
    const pid_t child = static_cast<pid_t>(active_child_pid);
    if (child > 0) (void) kill(child, signal_number);
}

int execute_program(const std::vector<std::string> &arguments, bool optional)
{
    if (arguments.empty()) return 2;

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
    if (sigaction(SIGTERM, &action, &old_term) != 0 ||
            sigaction(SIGINT, &action, &old_int) != 0 ||
            sigaction(SIGHUP, &action, &old_hup) != 0) {
        (void) sigprocmask(SIG_SETMASK, &old_mask, nullptr);
        std::cerr << "dinit-bootstrap: cannot install child signal forwarding: "
                  << std::strerror(errno) << '\n';
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
        execvp(argv[0], &argv[0]);
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
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 1;
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
        if (item == "fastboot" || item == "fsck.mode=skip") options.skip = true;
        else if (item == "forcefsck" || item == "fsck.mode=force") options.force = true;
        else if (item == "fsckfix" || item == "fsck.repair=yes") options.repair = "-y";
        else if (item == "fsck.repair=no") options.repair = "-n";
    }
    return options;
}

int run_root_fsck()
{
    if (load_environment_kind() == environment_kind::container) {
        std::cout << "dinit-bootstrap: root fsck is skipped inside a container\n";
        return 0;
    }
    const fsck_options options = read_fsck_options();
    if (options.skip) return 0;
    if (!executable_in_path("fsck")) {
        std::cout << "dinit-bootstrap: fsck is not installed; skipping root check\n";
        return 0;
    }
    FILE *fstab = setmntent("/etc/fstab", "r");
    if (fstab != nullptr) {
        struct mntent *entry;
        while ((entry = getmntent(fstab)) != nullptr) {
            if (std::strcmp(entry->mnt_dir, "/") == 0 && entry->mnt_passno == 0) {
                endmntent(fstab);
                std::cout << "dinit-bootstrap: root check disabled by fstab pass number\n";
                return 0;
            }
        }
        endmntent(fstab);
    }
    FILE *mounts = setmntent("/proc/self/mounts", "r");
    if (mounts == nullptr) {
        std::cerr << "dinit-bootstrap: cannot read /proc/self/mounts for root fsck\n";
        return 1;
    }
    std::string device, filesystem;
    struct mntent *entry;
    while ((entry = getmntent(mounts)) != nullptr) {
        if (std::strcmp(entry->mnt_dir, "/") == 0) {
            device = entry->mnt_fsname; filesystem = entry->mnt_type; break;
        }
    }
    endmntent(mounts);
    struct stat device_stat;
    if (device.empty() || stat(device.c_str(), &device_stat) != 0 ||
            !S_ISBLK(device_stat.st_mode)) {
        std::cout << "dinit-bootstrap: root is not a checkable block device; skipping root fsck\n";
        return 0;
    }
    if (filesystem.empty() || !executable_in_path("fsck." + filesystem)) {
        std::cout << "dinit-bootstrap: no fsck helper for root filesystem "
                  << filesystem << "; skipping\n";
        return 0;
    }
    std::vector<std::string> args;
    args.push_back("fsck"); args.push_back("-C");
    if (options.force) args.push_back("-f");
    args.push_back(options.repair); args.push_back("-t");
    args.push_back(filesystem); args.push_back(device);
    std::cout << "dinit-bootstrap: checking root filesystem " << device << '\n';
    const int result = execute_program(args, false);
    if (result == 0 || result == 1) return 0;
    std::cerr << "dinit-bootstrap: root fsck requires intervention or reboot (status "
              << result << ")\n";
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
    args.push_back("-C"); args.push_back("-t"); args.push_back("noopts=_netdev");
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
    args.push_back("nosysfs,nonfs,nonfs4,nosmbfs,nocifs");
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
    bool root_is_rw = false;
    struct mntent *entry;
    while ((entry = getmntent(mounts)) != nullptr) {
        if (std::strcmp(entry->mnt_dir, "/") == 0) {
            root_is_rw = hasmntopt(entry, "rw") != nullptr; break;
        }
    }
    endmntent(mounts);
    if (root_is_rw) {
        std::cout << "dinit-bootstrap: root filesystem is already read-write\n";
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
    if (argc >= 2 && std::strcmp(argv[1], "fsck-root") == 0) return run_root_fsck();
    if (argc >= 2 && std::strcmp(argv[1], "fsck-local") == 0) return run_local_fsck();
    if (argc >= 2 && std::strcmp(argv[1], "mount-local") == 0) return run_mount_local();
    if (argc >= 2 && std::strcmp(argv[1], "root-rw") == 0) return run_root_rw();
    if (argc >= 2 && std::strcmp(argv[1], "swap-on") == 0) return run_swap_on();
    if (argc < 2 || std::strcmp(argv[1], "detect") != 0) {
        std::cerr << "Usage: dinit-bootstrap detect [--stay] | mount-pseudo proc|sys"
                     " | fsck-root | fsck-local | mount-local | root-rw | swap-on\n";
        return 2;
    }
    return run_detect(argc > 2 && std::strcmp(argv[2], "--stay") == 0);
}
