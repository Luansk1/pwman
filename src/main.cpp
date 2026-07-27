#include "crypto.h"
#include "commands.h"
#include "database.h"
#include "terminal.h"

#include "base32.h"
#include "hmac.h"
#include "totp.h"

#include <sodium.h>
#include <iostream>
#include <string>
#include <vector>
#include <chrono>

#ifndef PWMAN_VERSION
#define PWMAN_VERSION "unknown"
#endif

using namespace pwman;

int main(int argc, char* argv[]) {
    try {
        pwman::crypto_init();
    } catch (const std::exception& e) {
        pwman::print_error(std::string("Initialization failed: ") + e.what());
        return 1;
    }

    std::vector<std::string> args(argv, argv + argc);
    std::string program = args.empty() ? "pwman" : args[0];

    std::string db_path;
    bool db_explicit = false;  // was --db given on the command line?
    std::string command;
    std::vector<std::string> cmd_args;

    for (size_t i = 1; i < args.size(); ++i) {
        if (args[i] == "--db" && i + 1 < args.size()) {
            db_path = args[++i];
            db_explicit = true;
        } else if (args[i] == "--help" || args[i] == "-h") {
            pwman::print_usage(program);
            return 0;
        } else if (args[i] == "--version" || args[i] == "-v") {
            std::cout << "pwman " << PWMAN_VERSION << "\n";
            return 0;
        } else if (command.empty()) {
            command = args[i];
        } else {
            cmd_args.push_back(args[i]);
        }
    }

    if (command.empty()) {
        pwman::print_usage(program);
        return 1;
    }

    // Resolve the default database path (PWMAN_DB env / config file / built-in)
    // unless --db was given explicitly, which always wins.
    if (!db_explicit) {
        db_path = pwman::configured_db_path();
    }

    // `config` manages the stored default path and touches no database.
    if (command == "config") {
        return pwman::cmd_config(cmd_args);
    }

    // Enforce the custom vault extension for every command that touches the
    // database. 'gen' is purely offline and needs no database file.
    if (command != "gen" && !pwman::has_vault_extension(db_path)) {
        pwman::print_error("Database file must use the '" +
                           std::string(pwman::kVaultExtension) +
                           "' extension: " + db_path);
        return 1;
    }

    try {
        if (command == "init") {
            return pwman::cmd_init(db_path);
        } else if (command == "add") {
            return pwman::cmd_add(db_path);
        } else if (command == "get") {
            if (cmd_args.empty()) {
                pwman::print_error("Usage: " + program + " get <name>");
                return 1;
            }
            return pwman::cmd_get(db_path, cmd_args[0]);
        } else if (command == "list") {
            return pwman::cmd_list(db_path);
        } else if (command == "del") {
            if (cmd_args.empty()) {
                pwman::print_error("Usage: " + program + " del <name>");
                return 1;
            }
            return pwman::cmd_del(db_path, cmd_args[0]);
        } else if (command == "gen") {
            size_t length = 20;
            if (!cmd_args.empty()) {
                length = std::stoul(cmd_args[0]);
                if (length < 10 || length > 128) {
                    pwman::print_error("Password length must be between 10 and 128.");
                    return 1;
                }
            }
            return pwman::cmd_gen(length);
        } else if(command == "totp") {
            if(cmd_args.empty()){
                pwman::print_error("Usage: " + program + " totp [Optional]<add|del> <entry_name>");
                return 1;
            }
            if (cmd_args[0] == "add"){
                return pwman::cmd_totp_add(db_path, cmd_args[1]);
            } else if (cmd_args[0] == "del"){
                return pwman::cmd_totp_del(db_path, cmd_args[1]);
            } 
            
            return pwman::cmd_totp(db_path, cmd_args[0]); 
        }else if (command == "export"){
            std::string format = "csv";
            std::string out_path;
            for (const auto& a : cmd_args) {
                if (a == "xml" || a == "--xml") format = "xml";
                else if (a == "csv" || a == "--csv") format = "csv";
                else out_path = a;  // anything else is the output path
            }
            return pwman::cmd_export(db_path, format, out_path);
        }else if (command == "import"){
            if (cmd_args.empty()) {
                pwman::print_error("Usage: " + program + " import <file.csv>");
                return 1;
            }
            return pwman::cmd_import(db_path, cmd_args[0]);
        }else {
            pwman::print_error("Unknown command: " + command);
            pwman::print_usage(program);
            return 1;
        }
    } catch (const pwman::CryptoError& e) {
        pwman::print_error(e.what());
        return 1;
    } catch (const pwman::DatabaseError& e) {
        pwman::print_error(e.what());
        return 1;
    } catch (const pwman::TotpError& e){
        pwman::print_error(e.what());
        return 1; 
    } catch (const std::exception& e) {
        pwman::print_error(std::string("Unexpected error: ") + e.what());
        return 1;
    }
}
