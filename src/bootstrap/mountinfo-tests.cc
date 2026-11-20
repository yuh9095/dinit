#include "mountinfo.h"

#include <cstdlib>
#include <iostream>
#include <string>

using namespace dinit_bootstrap;

namespace {
int failures = 0;
void check(bool condition, const char *name)
{
    if (!condition) {
        std::cerr << "FAIL: " << name << '\n';
        ++failures;
    }
}

const char *base =
    "1 1 0:1 / / rw - rootfs rootfs rw\n"
    "2 1 0:2 / /proc rw - proc proc rw\n"
    "3 1 0:3 / /sys rw shared:1 - sysfs sysfs rw\n"
    "4 1 0:4 / /dev rw - devtmpfs devtmpfs rw\n"
    "5 4 0:5 / /dev/pts rw - devpts devpts rw\n";

void test_parse()
{
    mount_table table;
    check(parse_mountinfo(base, table), "parse normal snapshot");
    check(table.valid && table.entries.size() == 5, "snapshot contents");
    mount_result root = find_visible_mount(table, "/");
    check(root.state == mount_state::mounted && root.has_entry
            && root.entry.filesystem == "rootfs", "visible root mount");
    mount_result pts = find_visible_mount(table, "/dev/pts");
    check(pts.state == mount_state::mounted && pts.has_entry
            && pts.entry.filesystem == "devpts", "visible devpts");
    check(find_visible_mount(table, "/dev/shm").state
            == mount_state::not_mounted, "missing mountpoint");

    mount_entry entry;
    check(parse_mountinfo_line(
            "8 4 0:8 /foo\\040bar /dev/space\\040dir rw x-new:yes - tmpfs tmpfs rw",
            entry), "escaped path and optional field");
    check(entry.root == "/foo bar" && entry.mountpoint == "/dev/space dir",
            "escape decoding");
    check(entry.optional_fields.size() == 1, "optional field preserved");
    check(parse_mountinfo_line(
            "13 4 0:13 / /dev/source rw - tmpfs /dev/disk\\040one rw", entry)
            && entry.source == "/dev/disk one", "mount source escape decoding");
    check(parse_mountinfo_line(
            "9 4 0:9 / /dev/tab\\011line rw - tmpfs tmpfs rw", entry)
            && entry.mountpoint == "/dev/tab\tline", "tab decoding");
    check(parse_mountinfo_line(
            "10 4 0:10 / /dev/slash\\134name rw - tmpfs tmpfs rw", entry)
            && entry.mountpoint == "/dev/slash\\name", "backslash decoding");
    check(parse_mountinfo_line(
            "12 4 0:12 / /dev/line\\012break rw - tmpfs tmpfs rw", entry)
            && entry.mountpoint == "/dev/line\nbreak", "newline decoding");
}

void test_invalid()
{
    mount_table table;
    check(!parse_mountinfo("1 1 0:1 / / rw rootfs rootfs rw\n", table),
            "missing separator");
    check(!parse_mountinfo("1 1 0:1 / / rw - rootfs rootfs\\n", table),
            "missing super options");
    check(!read_mountinfo("/no/such/dinit-mountinfo", table),
            "mountinfo read failure");
    check(!parse_mountinfo(
            "1 1 0:1 / / rw - rootfs rootfs rw\n"
            "1 1 0:2 / /proc rw - proc proc rw\n", table),
            "duplicate mount ID");
    check(!parse_mountinfo(
            "1 1 0:1 / / rw - rootfs rootfs rw\n"
            "2 2 0:2 / /proc rw - proc proc rw\n", table),
            "non-root self parent");
    mount_entry invalid_escape;
    check(!parse_mountinfo_line(
            "8 4 0:8 / /dev/bad\\001path rw - tmpfs tmpfs rw",
            invalid_escape), "unsupported mountinfo escape");
    check(!parse_mountinfo(
            "1 2 0:1 / / rw - rootfs rootfs rw\n"
            "2 1 0:2 / /proc rw - proc proc rw\n", table),
            "parent cycle");
    check(!parse_mountinfo(
            "1 1 0:1 / / rw - rootfs rootfs rw\n"
            "2 1 0:2 / /bad\\09x rw - proc proc rw\n", table),
            "invalid escape");
}

void test_stacked_and_hidden()
{
    const char *stacked =
        "1 1 0:1 / / rw - rootfs rootfs rw\n"
        "4 1 0:4 / /dev rw - tmpfs olddev rw\n"
        "5 4 0:5 / /dev/pts rw - devpts devpts rw\n"
        "6 4 0:6 / /dev rw - tmpfs newdev rw\n";
    mount_table table;
    check(parse_mountinfo(stacked, table), "parse stacked snapshot");
    mount_result dev = find_visible_mount(table, "/dev");
    check(dev.state == mount_state::mounted && dev.has_entry
            && dev.entry.mount_id == 6, "select topmost stacked mount");
    check(find_visible_mount(table, "/dev/pts").state
            == mount_state::not_mounted, "hide child of covered parent");

    const char *visible_child =
        "1 1 0:1 / / rw - rootfs rootfs rw\n"
        "4 1 0:4 / /dev rw - tmpfs olddev rw\n"
        "5 4 0:5 / /dev/pts rw - devpts devpts rw\n"
        "6 5 0:6 / /dev/pts rw - devpts newpts rw\n";
    check(parse_mountinfo(visible_child, table), "parse stacked child");
    mount_result pts = find_visible_mount(table, "/dev/pts");
    check(pts.state == mount_state::mounted && pts.has_entry
            && pts.entry.mount_id == 6, "select topmost child mount");
}

void test_external_parent()
{
    mount_table table;
    check(parse_mountinfo(
            "10 999 0:10 / / rw - ext4 root rw\n"
            "11 10 0:11 / /proc rw - proc proc rw\n", table),
            "allow parent outside process root");
    check(find_visible_mount(table, "/proc").state == mount_state::mounted,
            "visible child with root external parent");

    check(parse_mountinfo(
            "20 20 0:20 / / rw - ext4 root rw\n"
            "21 999 0:21 / /dev rw - tmpfs dev rw\n", table),
            "parse ordinary mount with missing parent");
    check(find_visible_mount(table, "/dev").state == mount_state::ambiguous,
            "missing ordinary parent is ambiguous");
    check(find_visible_mount(table, "/dev/pts").state == mount_state::ambiguous,
            "missing mountpoint with ambiguous ancestor is ambiguous");
}
}

int main()
{
    test_parse();
    test_invalid();
    test_stacked_and_hidden();
    test_external_parent();
    if (failures != 0) {
        std::cerr << failures << " mountinfo test(s) failed\n";
        return EXIT_FAILURE;
    }
    std::cout << "mountinfo tests passed\n";
    return EXIT_SUCCESS;
}
