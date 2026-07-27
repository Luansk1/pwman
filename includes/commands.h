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
    // Export all entries to a file. format is "csv" (default) or "xml";
    // out_path empty selects a default name (pwman-export.csv / .xml).
    int cmd_export(const std::string& db_path,
                   const std::string& format = "csv",
                   const std::string& out_path = "");

    // Import entries from a CSV file (same columns as the CSV export). Existing
    // entries (matching name) are skipped.
    int cmd_import(const std::string& db_path, const std::string& in_path);

    // Manage the persistent default database path stored in the config file.
    //   config                -> show current configuration
    //   config db <path>      -> set the default vault path
    //   config clear          -> remove the stored default
    int cmd_config(const std::vector<std::string>& args);
    void print_usage(const std::string& program);

    int cmd_totp(const std::string& db_path, const std::string& entry_name);
    int cmd_totp_add(const std::string& db_path, const std::string& entry_name);
    int cmd_totp_del(const std::string& db_path, const std::string& entry_name);

}
