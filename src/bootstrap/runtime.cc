// Linux Bootstrap runtime support for Dinit.
// This program is part of the generated dinit.d service package.

#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

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
    if (!info.container_name.empty()) info.kind = environment_kind::container;
    else if (!info.virtualization.empty()) info.kind = environment_kind::virtual_machine;
    else if (info.pid1 && info.pid_namespace_depth_known && !info.nested_pid_namespace)
        info.kind = environment_kind::bare_metal;
    else info.kind = environment_kind::unknown;
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
           << "virtualization=" << (info.virtualization.empty() ? "none" : info.virtualization) << '\n';
    return output.good();
}

int run_detect(bool stay)
{
    const environment_info info = detect_environment();
    std::cout << "dinit-bootstrap: environment: " << kind_name(info.kind) << '\n'
              << "dinit-bootstrap: PID 1: " << (info.pid1 ? "yes" : "no") << '\n'
              << "dinit-bootstrap: nested PID namespace: "
              << (info.pid_namespace_depth_known ? (info.nested_pid_namespace ? "yes" : "no") : "unknown") << '\n';
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

    sigset_t signals;
    sigemptyset(&signals);
    sigaddset(&signals, SIGTERM);
    sigaddset(&signals, SIGINT);
    sigaddset(&signals, SIGHUP);
    if (sigprocmask(SIG_BLOCK, &signals, nullptr) != 0) {
        std::cerr << "dinit-bootstrap: sigprocmask: " << std::strerror(errno) << '\n';
        return 1;
    }

    // Dinit's ready-notification pipe prevents dependent services from racing
    // the environment-state write above.
    const char ready_message[] = "READY\n";
    if (write(4, ready_message, sizeof(ready_message) - 1)
            != static_cast<ssize_t>(sizeof(ready_message) - 1)) {
        std::cerr << "dinit-bootstrap: failed to notify Dinit that detection is ready\n";
        return 1;
    }

    int signal_number = 0;
    while (sigwait(&signals, &signal_number) == EINTR) {}
    return 0;
}

} // anonymous namespace

int main(int argc, char **argv)
{
    if (argc < 2 || std::strcmp(argv[1], "detect") != 0) {
        std::cerr << "Usage: dinit-bootstrap detect [--stay]\n";
        return 2;
    }
    return run_detect(argc > 2 && std::strcmp(argv[2], "--stay") == 0);
}
