#pragma once
#include <string>
#include <vector>

// CLI Commands definition

namespace pwman {
    int cmd_init(const std::string& db_path);
    int cmd_add(const std::string& db_path);
    int cmd_get(const std::string& db_path, const std::string& name);
    int cmd_list(const std::string& db_path);
    int cmd_del(const std::string& db_path, const std::string& name);
    int cmd_gen(size_t length);

    void print_usage(const std::string& program);

    int cmd_totp(); // Enable TOTP support in the future

}