// Linux Bootstrap runtime support for Dinit.
// This program is part of the generated dinit.d service package.

#include <cerrno>
#include <signal.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

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

std::string detect_container()
{
    const char *env = std::getenv("container");
    if (env != nullptr && *env != '\0') return env;
    if (path_exists("/.dockerenv")) return "docker";
    if (path_exists("/run/.containerenv")) return "podman";
    if (path_exists("/run/host/container-manager")) {
        std::string manager = read_file("/run/host/container-manager");
        return manager.empty() ? "unknown" : manager;
    }
    if (path_exists("/proc/vz") && !path_exists("/proc/bc")) return "openvz";

    const std::string cgroup = read_file("/proc/1/cgroup");
    if (contains(cgroup, "docker")) return "docker";
    if (contains(cgroup, "kubepods")) return "kubernetes";
    if (contains(cgroup, "libpod")) return "podman";
    if (contains(cgroup, "lxc")) return "lxc";

    const std::string status = read_file("/proc/self/status");
    const std::string tracer = "TracerPid:\t";
    const std::string::size_type pos = status.find(tracer);
    if (pos != std::string::npos && status.compare(pos + tracer.size(), 1, "0") != 0)
        return "proot";
    return std::string();
}

std::string detect_virtual_machine()
{
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
    info.pid1 = getpid() == 1;

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
    if (!info.container_name.empty()
            || (info.pid_namespace_depth_known && info.nested_pid_namespace)) {
        // A nested PID namespace gets container-safe policy even when its
        // runtime (Docker/LXC/etc.) cannot be identified.
        info.kind = environment_kind::container;
    }
    else if (!info.virtualization.empty()) {
        info.kind = environment_kind::virtual_machine;
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

int ensure_pseudo_filesystem(const char *name)
{
    // procfs is required for normal process/system operation. sysfs may be
    // unavailable in restricted containers and is therefore skippable there.
    const bool container_may_skip = std::strcmp(name, "sys") == 0;
    const environment_kind kind = load_environment_kind();
    const mount_info current = detect_mounts();
    const std::string mounted = std::strcmp(name, "proc") == 0
            ? current.procfs : current.sysfs;
    const char *mountpoint = std::strcmp(name, "proc") == 0 ? "/proc" : "/sys";

    if (current.available && !mounted.empty()) {
        if (mounted == name) {
            std::cout << "dinit-bootstrap: " << mountpoint
                      << " already mounted as " << name << '\n';
            return 0;
        }
        return mount_failure(kind, name,
                "mountpoint is already occupied by a different filesystem", container_may_skip);
    }
    // If mountinfo is unavailable (for example because procfs is not mounted
    // yet), attempt the mount rather than making inspection itself fatal.

    const unsigned long flags = MS_NOSUID | MS_NODEV | MS_NOEXEC;
    if (mount(name, mountpoint, name, flags, nullptr) == 0) {
        std::cout << "dinit-bootstrap: mounted " << name
                  << " on " << mountpoint << '\n';
        return 0;
    }

    const std::string reason = std::strerror(errno);
    return mount_failure(kind, name, reason.c_str(), container_may_skip);
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
            std::cerr << "dinit-bootstrap: sigprocmask: " << std::strerror(errno) << '\\n';
            return 1;
        }
    }

    const environment_info info = detect_environment();
    std::cout << "dinit-bootstrap: environment: " << kind_name(info.kind) << '\n'
              << "dinit-bootstrap: PID 1: " << (info.pid1 ? "yes" : "no") << '\n'
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
        std::cerr << "dinit-bootstrap: refusing system bootstrap: Dinit is not PID 1\n";
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
    if (argc < 2 || std::strcmp(argv[1], "detect") != 0) {
        std::cerr << "Usage: dinit-bootstrap detect [--stay] | mount-pseudo proc|sys\n";
        return 2;
    }
    return run_detect(argc > 2 && std::strcmp(argv[2], "--stay") == 0);
}
