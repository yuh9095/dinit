#ifndef DINIT_BOOTSTRAP_MOUNTINFO_H
#define DINIT_BOOTSTRAP_MOUNTINFO_H

#include <stdint.h>
#include <string>
#include <vector>

namespace dinit_bootstrap {

struct mount_entry {
    uint64_t mount_id;
    uint64_t parent_id;
    unsigned int major;
    unsigned int minor;
    std::string root;
    std::string mountpoint;
    std::string mount_options;
    std::vector<std::string> optional_fields;
    std::string filesystem;
    std::string source;
    std::string super_options;

    mount_entry() : mount_id(0), parent_id(0), major(0), minor(0) {}
};

struct mount_table {
    bool valid;
    std::string error;
    std::vector<mount_entry> entries;

    mount_table() : valid(false) {}
};

enum class mount_state {
    not_mounted,
    mounted,
    ambiguous
};

struct mount_result {
    mount_state state;
    mount_entry entry;
    bool has_entry;

    mount_result(mount_state s = mount_state::ambiguous,
            const mount_entry *e = nullptr) : state(s), has_entry(e != nullptr)
    {
        if (e != nullptr) entry = *e;
    }
};

bool parse_mountinfo_line(const std::string &line, mount_entry &entry);
bool parse_mountinfo(const std::string &contents, mount_table &table);
bool read_mountinfo(const std::string &path, mount_table &table);
mount_result find_visible_mount(const mount_table &table,
        const std::string &mountpoint);

} // namespace dinit_bootstrap

#endif
