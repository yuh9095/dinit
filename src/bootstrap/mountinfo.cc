#include "mountinfo.h"

#include <fstream>
#include <limits>
#include <set>
#include <sstream>

namespace dinit_bootstrap {
namespace {

bool parse_uint(const std::string &text, uint64_t &value,
        bool allow_zero = false)
{
    if (text.empty()) return false;
    uint64_t result = 0;
    for (std::string::size_type i = 0; i < text.size(); ++i) {
        const char c = text[i];
        if (c < '0' || c > '9') return false;
        const unsigned int digit = static_cast<unsigned int>(c - '0');
        if (result > (std::numeric_limits<uint64_t>::max() - digit) / 10)
            return false;
        result = result * 10 + digit;
    }
    if (result == 0 && !allow_zero) return false;
    value = result;
    return true;
}

bool parse_device(const std::string &text, unsigned int &major,
        unsigned int &minor)
{
    const std::string::size_type colon = text.find(':');
    if (colon == std::string::npos || colon == 0
            || colon + 1 == text.size()
            || text.find(':', colon + 1) != std::string::npos)
        return false;
    uint64_t maj, min;
    if (!parse_uint(text.substr(0, colon), maj, true)
            || !parse_uint(text.substr(colon + 1), min, true)
            || maj > std::numeric_limits<unsigned int>::max()
            || min > std::numeric_limits<unsigned int>::max())
        return false;
    major = static_cast<unsigned int>(maj);
    minor = static_cast<unsigned int>(min);
    return true;
}

bool decode_mount_field(const std::string &input, std::string &output)
{
    output.clear();
    for (std::string::size_type i = 0; i < input.size(); ++i) {
        if (input[i] != '\\') {
            output += input[i];
            continue;
        }
        if (i + 3 >= input.size()) return false;
        unsigned int value = 0;
        for (unsigned int j = 1; j <= 3; ++j) {
            const char c = input[i + j];
            if (c < '0' || c > '7') return false;
            value = value * 8 + static_cast<unsigned int>(c - '0');
        }
        // mountinfo escapes only space, tab, newline and backslash.
        if (value != 040 && value != 011 && value != 012 && value != 0134)
            return false;
        output += static_cast<char>(value);
        i += 3;
    }
    return true;
}

bool valid_absolute_path(const std::string &path)
{
    if (path.empty() || path[0] != '/') return false;
    if (path.size() > 1 && path[path.size() - 1] == '/') return false;
    if (path.find("//") != std::string::npos) return false;
    std::string::size_type start = 1;
    while (start < path.size()) {
        const std::string::size_type end = path.find('/', start);
        const std::string component = path.substr(start,
                end == std::string::npos ? std::string::npos : end - start);
        if (component == "." || component == "..") return false;
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return true;
}

bool tokenize(const std::string &line, std::vector<std::string> &tokens)
{
    std::istringstream input(line);
    std::string token;
    while (input >> token) tokens.push_back(token);
    return !input.bad();
}

bool path_is_prefix(const std::string &prefix, const std::string &path)
{
    if (prefix == "/") return path.size() > 1 && path[0] == '/';
    return path.size() > prefix.size()
            && path.compare(0, prefix.size(), prefix) == 0
            && path[prefix.size()] == '/';
}

const mount_entry *find_id(const mount_table &table, uint64_t id)
{
    for (std::vector<mount_entry>::const_iterator i = table.entries.begin();
            i != table.entries.end(); ++i) {
        if (i->mount_id == id) return &*i;
    }
    return nullptr;
}

const mount_entry *topmost_at(const mount_table &table,
        const std::string &path, bool &ambiguous)
{
    ambiguous = false;
    std::vector<const mount_entry *> matches;
    for (std::vector<mount_entry>::const_iterator i = table.entries.begin();
            i != table.entries.end(); ++i) {
        if (i->mountpoint == path) {
            matches.push_back(&*i);
        }
    }
    if (matches.empty()) return nullptr;

    const mount_entry *top = nullptr;
    for (std::vector<const mount_entry *>::const_iterator i = matches.begin();
            i != matches.end(); ++i) {
        bool is_parent = false;
        for (std::vector<const mount_entry *>::const_iterator j = matches.begin();
                j != matches.end(); ++j) {
            if ((*j)->mount_id != (*i)->mount_id
                    && (*j)->parent_id == (*i)->mount_id) {
                is_parent = true;
                break;
            }
        }
        if (!is_parent) {
            if (top != nullptr) {
                ambiguous = true;
                return nullptr;
            }
            top = *i;
        }
    }
    if (top == nullptr) ambiguous = true;
    return top;
}

enum class visibility_state { unknown, hidden, visible };

visibility_state visible_recursive(const mount_table &table,
        const mount_entry *entry, std::set<uint64_t> &visiting,
        unsigned int depth)
{
    if (entry == nullptr || depth > table.entries.size())
        return visibility_state::unknown;
    if (!visiting.insert(entry->mount_id).second)
        return visibility_state::unknown;

    if (entry->mountpoint == "/") {
        visiting.erase(entry->mount_id);
        return visibility_state::visible;
    }

    std::string nearest_path;
    for (std::vector<mount_entry>::const_iterator i = table.entries.begin();
            i != table.entries.end(); ++i) {
        if (i->mountpoint != entry->mountpoint
                && path_is_prefix(i->mountpoint, entry->mountpoint)
                && i->mountpoint.size() > nearest_path.size())
            nearest_path = i->mountpoint;
    }
    if (nearest_path.empty()) {
        visiting.erase(entry->mount_id);
        return visibility_state::unknown;
    }

    bool ancestor_ambiguous = false;
    const mount_entry *ancestor = topmost_at(table, nearest_path,
            ancestor_ambiguous);
    if (ancestor == nullptr || ancestor_ambiguous) {
        visiting.erase(entry->mount_id);
        return visibility_state::unknown;
    }

    uint64_t parent = entry->parent_id;
    std::set<uint64_t> chain;
    bool connected = false;
    bool hidden = false;
    while (chain.insert(parent).second) {
        if (parent == ancestor->mount_id) {
            connected = true;
            break;
        }
        const mount_entry *parent_entry = find_id(table, parent);
        if (parent_entry == nullptr) break;
        if (parent_entry->mountpoint == nearest_path) {
            hidden = true;
            break;
        }
        if (parent_entry->mountpoint != entry->mountpoint
                && !path_is_prefix(parent_entry->mountpoint, entry->mountpoint))
            break;
        if (parent_entry->parent_id == parent_entry->mount_id) {
            hidden = true;
            break;
        }
        parent = parent_entry->parent_id;
    }

    if (hidden) {
        visiting.erase(entry->mount_id);
        return visibility_state::hidden;
    }
    if (!connected) {
        visiting.erase(entry->mount_id);
        return visibility_state::unknown;
    }

    const visibility_state ancestor_visibility =
            visible_recursive(table, ancestor, visiting, depth + 1);
    visiting.erase(entry->mount_id);
    return ancestor_visibility;
}
} // anonymous namespace

bool parse_mountinfo_line(const std::string &line, mount_entry &entry)
{
    std::vector<std::string> fields;
    if (!tokenize(line, fields) || fields.size() < 10) return false;

    std::string::size_type separator = 6;
    while (separator < fields.size() && fields[separator] != "-")
        ++separator;
    if (separator == fields.size() || fields.size() - separator != 4)
        return false;

    mount_entry parsed;
    if (!parse_uint(fields[0], parsed.mount_id)
            || !parse_uint(fields[1], parsed.parent_id)
            || !parse_device(fields[2], parsed.major, parsed.minor)
            || !decode_mount_field(fields[3], parsed.root)
            || !decode_mount_field(fields[4], parsed.mountpoint)
            || !valid_absolute_path(parsed.root)
            || !valid_absolute_path(parsed.mountpoint))
        return false;

    parsed.mount_options = fields[5];
    for (std::string::size_type i = 6; i < separator; ++i)
        parsed.optional_fields.push_back(fields[i]);
    parsed.filesystem = fields[separator + 1];
    if (!decode_mount_field(fields[separator + 2], parsed.source))
        return false;
    parsed.super_options = fields[separator + 3];
    if (parsed.filesystem.empty()) return false;

    entry = parsed;
    return true;
}

bool parse_mountinfo(const std::string &contents, mount_table &table)
{
    mount_table parsed;
    std::istringstream input(contents);
    std::string line;
    std::set<uint64_t> ids;
    while (std::getline(input, line)) {
        if (line.empty()) {
            table = mount_table();
            table.error = "empty mountinfo record";
            return false;
        }
        mount_entry entry;
        if (!parse_mountinfo_line(line, entry)) {
            table = mount_table();
            table.error = "malformed mountinfo record";
            return false;
        }
        if (!ids.insert(entry.mount_id).second) {
            table = mount_table();
            table.error = "duplicate mount ID";
            return false;
        }
        if (entry.parent_id == entry.mount_id && entry.mountpoint != "/") {
            table = mount_table();
            table.error = "non-root mount refers to itself as parent";
            return false;
        }
        parsed.entries.push_back(entry);
    }
    if (input.bad() || parsed.entries.empty()) {
        table = mount_table();
        table.error = "mountinfo snapshot is unreadable or empty";
        return false;
    }

    // Reject parent cycles among records visible in this snapshot. A missing
    // parent is valid: it may lie outside the process root (chroot).
    for (std::vector<mount_entry>::const_iterator i = parsed.entries.begin();
            i != parsed.entries.end(); ++i) {
        std::set<uint64_t> chain;
        uint64_t id = i->mount_id;
        while (true) {
            if (!chain.insert(id).second) {
                table = mount_table();
                table.error = "cycle in mount parent IDs";
                return false;
            }
            const mount_entry *current = find_id(parsed, id);
            if (current == nullptr || current->parent_id == id) break;
            id = current->parent_id;
            if (find_id(parsed, id) == nullptr) break;
        }
    }

    parsed.valid = true;
    table = parsed;
    return true;
}

bool read_mountinfo(const std::string &path, mount_table &table)
{
    std::ifstream input(path.c_str());
    if (!input) {
        table = mount_table();
        table.error = "cannot open " + path;
        return false;
    }
    std::ostringstream contents;
    contents << input.rdbuf();
    if (input.bad()) {
        table = mount_table();
        table.error = "error reading " + path;
        return false;
    }
    return parse_mountinfo(contents.str(), table);
}

mount_result find_visible_mount(const mount_table &table,
        const std::string &mountpoint)
{
    if (!table.valid || !valid_absolute_path(mountpoint))
        return mount_result(mount_state::ambiguous);

    bool ambiguous = false;
    const mount_entry *entry = topmost_at(table, mountpoint, ambiguous);
    if (entry == nullptr) {
        if (ambiguous) return mount_result(mount_state::ambiguous);

        // Even when the exact path is not a mountpoint, its containing
        // mount must be resolvable before callers attempt a new mount.
        std::string ancestor_path;
        for (std::vector<mount_entry>::const_iterator i = table.entries.begin();
                i != table.entries.end(); ++i) {
            if (path_is_prefix(i->mountpoint, mountpoint)
                    && i->mountpoint.size() > ancestor_path.size())
                ancestor_path = i->mountpoint;
        }
        while (!ancestor_path.empty()) {
            const mount_result ancestor = find_visible_mount(table, ancestor_path);
            if (ancestor.state == mount_state::mounted)
                return mount_result(mount_state::not_mounted);
            if (ancestor.state == mount_state::ambiguous)
                return mount_result(mount_state::ambiguous);

            std::string next_path;
            for (std::vector<mount_entry>::const_iterator i = table.entries.begin();
                    i != table.entries.end(); ++i) {
                if (path_is_prefix(i->mountpoint, ancestor_path)
                        && i->mountpoint.size() > next_path.size())
                    next_path = i->mountpoint;
            }
            ancestor_path = next_path;
        }
        return mount_result(mount_state::ambiguous);
    }

    std::set<uint64_t> visiting;
    const visibility_state visibility =
            visible_recursive(table, entry, visiting, 0);
    if (visibility == visibility_state::hidden)
        return mount_result(mount_state::not_mounted);
    if (visibility == visibility_state::unknown)
        return mount_result(mount_state::ambiguous);
    return mount_result(mount_state::mounted, entry);
}
} // namespace dinit_bootstrap
