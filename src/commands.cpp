#include "commands.h"
#include "crypto.h"
#include "database.h"
#include "terminal.h"
#include "totp.h"

#include <iostream>
#include <string>

namespace pwman {

namespace {

// Verify the master password against the stored verification token.
// Returns the derived key on success, throws on failure.
DerivedKey unlock(Database& db) {
    auto salt = db.load_salt();
    std::string master = read_password("Master password: ");
    auto dk = derive_key(master, salt);
    secure_zero(master);

    // Verify by decrypting the stored token
    auto enc_verify = db.load_verify_token();
    try {
        auto plain = decrypt(dk.key, enc_verify);
        if (plain != "pwman_verify") {
            throw CryptoError("Verification mismatch");
        }
    } catch (...) {
        secure_zero(dk.key);
        throw CryptoError("Wrong master password");
    }

    return dk;
}

} // namespace

int cmd_init(const std::string& db_path) {
    Database db(db_path);

    if (db.is_initialized()) {
        print_error("Database already initialized at: " + db_path);
        print_info("Use the existing database or delete it to start fresh.");
        return 1;
    }

    print_info("Initializing new password database: " + db_path);

    std::string master = read_password("Choose master password: ");
    if (master.empty()) {
        print_error("Master password cannot be empty.");
        return 1;
    }

    std::string confirm = read_password("Confirm master password: ");
    if (master != confirm) {
        secure_zero(master);
        secure_zero(confirm);
        print_error("Passwords do not match.");
        return 1;
    }
    secure_zero(confirm);

    auto dk = derive_key(master);
    secure_zero(master);

    // Encrypt a known token for verification
    auto enc_verify = encrypt(dk.key, "pwman_verify");
    db.init(dk.salt, enc_verify);

    secure_zero(dk.key);

    print_success("Database initialized successfully.");
    print_info("Remember your master password - it cannot be recovered!");
    return 0;
}

int cmd_add(const std::string& db_path) {
    Database db(db_path);
    if (!db.is_initialized()) {
        print_error("Database not initialized. Run 'pwman init' first.");
        return 1;
    }

    auto dk = unlock(db);

    std::string name, username, password, url, notes;

    std::cout << "Entry name: " << std::flush;
    std::getline(std::cin, name);
    if (name.empty()) {
        secure_zero(dk.key);
        print_error("Entry name cannot be empty.");
        return 1;
    }

    // Check if entry already exists
    if (db.get_entry(name).has_value()) {
        secure_zero(dk.key);
        print_error("Entry '" + name + "' already exists.");
        return 1;
    }

    std::cout << "Username: " << std::flush;
    std::getline(std::cin, username);

    password = read_password("Password (leave empty to generate): ");
    if (password.empty()) {
        password = generate_password(20);
        print_info("Generated password: " + password);
    }

    std::cout << "URL: " << std::flush;
    std::getline(std::cin, url);

    std::cout << "Notes: " << std::flush;
    std::getline(std::cin, notes);

    auto enc_username = encrypt(dk.key, username);
    auto enc_password = encrypt(dk.key, password);
    auto enc_url = encrypt(dk.key, url);
    auto enc_notes = encrypt(dk.key, notes);

    secure_zero(password);
    secure_zero(dk.key);

    db.add_entry(name, enc_username, enc_password, enc_url, enc_notes);

    print_success("Entry '" + name + "' added successfully.");
    return 0;
}

int cmd_get(const std::string& db_path, const std::string& name) {
    Database db(db_path);
    if (!db.is_initialized()) {
        print_error("Database not initialized. Run 'pwman init' first.");
        return 1;
    }

    auto entry = db.get_entry(name);
    if (!entry.has_value()) {
        print_error("Entry '" + name + "' not found.");
        return 1;
    }

    auto dk = unlock(db);

    std::string username = decrypt(dk.key, entry->enc_username);
    std::string password = decrypt(dk.key, entry->enc_password);
    std::string url = decrypt(dk.key, entry->enc_url);
    std::string notes = decrypt(dk.key, entry->enc_notes);

    secure_zero(dk.key);

    print_table(
        {"Field", "Value"},
        {
            {"Name", entry->name},
            {"Username", username},
            {"Password", password},
            {"URL", url},
            {"Notes", notes},
        }
    );

    secure_zero(username);
    secure_zero(password);

    return 0;
}

int cmd_list(const std::string& db_path) {
    Database db(db_path);
    if (!db.is_initialized()) {
        print_error("Database not initialized. Run 'pwman init' first.");
        return 1;
    }

    auto items = db.list_entries();

    if (items.empty()) {
        print_info("No entries found.");
        return 0;
    }

    std::vector<std::vector<std::string>> rows;
    rows.reserve(items.size());
    for (const auto& item : items) {
        rows.push_back({std::to_string(item.id), item.name});
    }

    print_table({"ID", "Name"}, rows);
    print_info(std::to_string(items.size()) + " entries total.");
    return 0;
}

int cmd_del(const std::string& db_path, const std::string& name) {
    Database db(db_path);
    if (!db.is_initialized()) {
        print_error("Database not initialized. Run 'pwman init' first.");
        return 1;
    }

    if (!db.get_entry(name).has_value()) {
        print_error("Entry '" + name + "' not found.");
        return 1;
    }

    auto dk = unlock(db);
    secure_zero(dk.key);

    std::cout << "Are you sure you want to delete '" << name << "'? [y/N]: " << std::flush;
    std::string answer;
    std::getline(std::cin, answer);

    if (answer != "y" && answer != "Y") {
        print_info("Aborted.");
        return 0;
    }

    if (db.delete_entry(name)) {
        print_success("Entry '" + name + "' deleted.");
    } else {
        print_error("Failed to delete entry.");
        return 1;
    }

    return 0;
}

int cmd_gen(size_t length) {
    std::string pw = generate_password(length);
    std::cout << pw << "\n";
    secure_zero(pw);
    return 0;
}

void print_usage(const std::string& program) {
    std::cout << "pwman - Command Line Password Manager\n\n"
              << "Usage:\n"
              << "  " << program << " init                  Initialize a new database\n"
              << "  " << program << " add                   Add a new entry\n"
              << "  " << program << " get <name>            Retrieve an entry\n"
              << "  " << program << " list                  List all entries\n"
              << "  " << program << " del <name>            Delete an entry\n"
              << "  " << program << " totp [add|del] <name> Manage TOTP for an entry\n"
              << "  " << program << " gen [length]          Generate a random password\n"
              << "\nOptions:\n"
              << "  --db <path>          Use a custom database path\n"
              << "  --help, -h           Show this help message\n";
}


// --- TOTP Commands ---

int cmd_totp_add(const std::string& db_path, const std::string& entry_name){
    Database db(db_path);
    if (!db.is_initialized()) {
        print_error("Database not initialized. Run 'pwman init' first.");
        return 1;
    }

    auto entry = db.get_entry(entry_name);
    if (!entry.has_value()) {
        print_error("Entry '" + entry_name + "' not found. Add it first with 'pwman add'.");
        return 1;
    }

    if (db.has_totp(entry_name)) {
        print_error("Entry '" + entry_name + "' already has TOTP configured.");
        print_info("Delete it first with 'pwman totp del " + entry_name + "'.");
        return 1;
    }

    auto dk = unlock(db);

    std::string input;
    std::cout << "OTP secret or otpauth:// URI: " << std::flush;
    std::getline(std::cin, input);

    if (input.empty()) {
        secure_zero(dk.key);
        print_error("No secret provided.");
        return 1;
    }

    std::string secret_base32;
    std::string algorithm = "SHA1";
    int digits = 6;
    int period = 30;

    if (input.rfind("otpauth://", 0) == 0) {
        // Parse otpauth:// URI

        std::cout << "Oauth URI currently not supported" << std::endl;
        /*
        try {
            auto config = parse_otpauth_uri(input);
            secret_base32 = config.secret_base32;
            algorithm = algorithm_to_string(config.algorithm);
            digits = config.digits;
            period = config.period;
        } catch (const std::exception& e) {
            secure_zero(dk.key);
            secure_zero(input);
            print_error(std::string("Invalid URI: ") + e.what());
            return 1;
        }*/
    } else {
        // Raw Base32 secret
        secret_base32 = base32_normalize(input);
        if (!base32_validate(secret_base32)) {
            secure_zero(dk.key);
            secure_zero(input);
            print_error("Invalid Base32 secret.");
            return 1;
        }
    }

    secure_zero(input);

    // Encrypt the base32 secret and store it
    auto enc_secret = encrypt(dk.key, secret_base32);

    // Verify: generate a code to confirm it works
    auto raw_secret = base32_decode(secret_base32);
    auto algo = string_to_algorithm(algorithm);
    auto code = totp_generate(raw_secret, algo, digits, period);
    int remaining = totp_remaining_seconds(period);

    secure_zero(secret_base32);
    secure_zero(raw_secret);

    db.set_totp(entry->id, enc_secret, algorithm, digits, period);
    secure_zero(dk.key);

    print_success("TOTP configured for '" + entry_name + "'.");
    print_totp_code(entry_name, code, remaining, period);

    return 0;
}

int cmd_totp_del(const std::string& db_path, const std::string& entry_name){
    Database db(db_path);
    if (!db.is_initialized()) {
        print_error("Database not initialized. Run 'pwman init' first.");
        return 1;
    }

    if (!db.has_totp(entry_name)) {
        print_error("No TOTP configured for '" + entry_name + "'.");
        return 1;
    }

    auto dk = unlock(db);
    secure_zero(dk.key);

    std::cout << "Remove TOTP from '" << entry_name << "'? [y/N]: " << std::flush;
    std::string answer;
    std::getline(std::cin, answer);

    if (answer != "y" && answer != "Y") {
        print_info("Aborted.");
        return 0;
    }

    if (db.delete_totp(entry_name)) {
        print_success("TOTP removed from '" + entry_name + "'.");
    } else {
        print_error("Failed to remove TOTP.");
        return 1;
    }

    return 0;
}

int cmd_totp(const std::string& db_path, const std::string& entry_name) {
    Database db(db_path);
    if (!db.is_initialized()) {
        print_error("Database not initialized. Run 'pwman init' first.");
        return 1;
    }

    auto totp_data = db.get_totp(entry_name);
    if (!totp_data.has_value()) {
        print_error("No TOTP configured for '" + entry_name + "'.");
        print_info("Add one with 'pwman totp add " + entry_name + "'.");
        return 1;
    }

    auto dk = unlock(db);

    // Decrypt the base32 secret
    std::string secret_base32 = decrypt(dk.key, totp_data->enc_secret);
    secure_zero(dk.key);

    // Decode and generate
    auto raw_secret = base32_decode(secret_base32);
    secure_zero(secret_base32);

    auto algo = string_to_algorithm(totp_data->algorithm);
    auto code = pwman::totp_generate(raw_secret, algo, totp_data->digits, totp_data->period);
    int remaining = pwman::totp_remaining_seconds(totp_data->period);

    secure_zero(raw_secret);

    print_totp_code(entry_name, code, remaining, totp_data->period);

    return 0;
}

} // namespace pwman
