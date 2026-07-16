#include "commands.h"
#include "crypto.h"
#include "database.h"
#include "terminal.h"
#include "totp.h"

#include <sodium.h>

#include <chrono>
#include <csignal>
#include <cstdio>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>

#ifdef _WIN32
#include <conio.h>
#include <windows.h>
#else
#include <sys/select.h>
#include <termios.h>
#include <unistd.h>
#endif

namespace pwman {

namespace {

const char* password_strength_label(PasswordStrength s) {
    switch (s) {
        case WEAK:   return "weak";
        case MEDIUM: return "medium";
        case STRONG: return "strong";
    }
    return "unknown";
}

// Derive and verify the Argon2id field-encryption key from the master
// password. The whole-database SQLCipher layer is already unlocked by the time
// this runs (see open_vault); this second, independent key protects the
// individual field values as defence in depth. Throws on mismatch.
DerivedKey derive_field_key(const Database& db, const std::string& master) {
    auto salt = db.load_salt();
    auto dk = derive_key(master, salt);

    // Verify by decrypting the stored token. The AEAD decrypt is constant-time
    // and authenticates the ciphertext; compare the plaintext in constant time
    // as defence-in-depth to avoid leaking any byte-level mismatch via timing.
    auto enc_verify = db.load_verify_token();
    try {
        auto plain = decrypt(dk.key, enc_verify);
        static const std::string expected = "pwman_verify";
        bool ok = (plain.size() == expected.size()) &&
                  (sodium_memcmp(plain.data(), expected.data(), expected.size()) == 0);
        secure_zero(plain);
        if (!ok) {
            throw CryptoError("Verification mismatch");
        }
    } catch (...) {
        secure_zero(dk.key);
        throw CryptoError("Wrong master password");
    }

    return dk;
}

// Prompt for the master password and open the encrypted vault with it. The
// SQLCipher passphrase and the field key are one and the same secret, so the
// caller receives the password back (in master) to derive the field key when
// needed. Throws DatabaseError on a wrong password or an unrecognised file.
std::unique_ptr<Database> open_vault(const std::string& db_path, std::string& master) {
    master = read_password("Master password: ");
    try {
        auto db = std::make_unique<Database>(db_path, master, /*create=*/false);
        if (!db->is_initialized()) {
            secure_zero(master);
            throw DatabaseError("Database not initialized. Run 'pwman init' first.");
        }
        return db;
    } catch (...) {
        secure_zero(master);
        throw;
    }
}

void copy_to_clipboard(const std::string& text) {
#ifdef __APPLE__
    FILE* p = popen("pbcopy", "w");
#elif defined(_WIN32)
    FILE* p = _popen("clip", "w");
#else
    FILE* p = popen(
        "command -v wl-copy >/dev/null 2>&1 && wl-copy"
        " || xclip -selection clipboard 2>/dev/null"
        " || xsel --clipboard --input 2>/dev/null", "w");
#endif
    if (!p) return;
    std::fwrite(text.data(), 1, text.size(), p);
#ifdef _WIN32
    _pclose(p);
#else
    pclose(p);
#endif
}

volatile std::sig_atomic_t g_totp_interrupt = 0;
void totp_on_sigint(int) { g_totp_interrupt = 1; }

// Number of newlines emitted by print_totp_code. Used by the live display to
// move the cursor back to the top of the box before redrawing.
constexpr int kTotpBoxLines = 11;

#ifndef _WIN32
struct RawModeGuard {
    termios old_term{};
    bool active = false;
    RawModeGuard() {
        if (isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &old_term) == 0) {
            termios new_term = old_term;
            new_term.c_lflag &= ~(static_cast<tcflag_t>(ICANON) | static_cast<tcflag_t>(ECHO));
            new_term.c_cc[VMIN] = 0;
            new_term.c_cc[VTIME] = 0;
            active = (tcsetattr(STDIN_FILENO, TCSANOW, &new_term) == 0);
        }
    }
    ~RawModeGuard() { if (active) tcsetattr(STDIN_FILENO, TCSANOW, &old_term); }
};

struct SigintGuard {
    using handler_t = void(*)(int);
    handler_t prev;
    explicit SigintGuard(handler_t h) : prev(std::signal(SIGINT, h)) {}
    ~SigintGuard() { std::signal(SIGINT, prev); }
};
#endif

void live_totp_display(const std::string& name,
                       const std::vector<uint8_t>& raw_secret,
                       HashAlgorithm algo,
                       int digits,
                       int period) {
#ifndef _WIN32
    RawModeGuard raw_guard;
    SigintGuard sig_guard(totp_on_sigint);
#endif

    auto step_of = [period]() -> uint64_t {
        auto now = std::chrono::system_clock::now();
        auto secs = std::chrono::duration_cast<std::chrono::seconds>(
            now.time_since_epoch()).count();
        return static_cast<uint64_t>(secs) / static_cast<uint64_t>(period);
    };

    uint64_t current_step = step_of();
    std::string code = totp_generate(raw_secret, algo, digits, period);
    copy_to_clipboard(code);

    print_info("Code copied to clipboard. Press 'q' to quit.");

    bool first_draw = true;
    g_totp_interrupt = 0;
    while (!g_totp_interrupt) {
        uint64_t step_now = step_of();
        if (step_now != current_step) {
            current_step = step_now;
            secure_zero(code);
            code = totp_generate(raw_secret, algo, digits, period);
            copy_to_clipboard(code);
        }
        int remaining = totp_remaining_seconds(period);

        if (!first_draw) {
            std::cout << "\033[" << kTotpBoxLines << "F" << "\033[J";
        }
        first_draw = false;
        print_totp_code(name, code, remaining, period);
        std::cout.flush();

#ifdef _WIN32
        Sleep(200);
        while (_kbhit()) {
            int c = _getch();
            if (c == 'q' || c == 'Q' || c == 27) { g_totp_interrupt = 1; break; }
        }
#else
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);
        timeval tv{0, 200000};
        int r = select(STDIN_FILENO + 1, &fds, nullptr, nullptr, &tv);
        if (r > 0 && FD_ISSET(STDIN_FILENO, &fds)) {
            char c;
            ssize_t n = read(STDIN_FILENO, &c, 1);
            if (n == 1 && (c == 'q' || c == 'Q' || c == 27)) break;
        }
#endif
    }

    // Clear the clipboard so the TOTP code doesn't linger after exit.
    copy_to_clipboard("");
    secure_zero(code);
}

} // namespace

int cmd_init(const std::string& db_path) {
    namespace fs = std::filesystem;
    if (fs::exists(db_path) && fs::file_size(db_path) > 0) {
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

    if (evaluate_password_strength(master) == WEAK) {
        print_info("Warning: master password strength is weak. "
                   "Consider using a longer or more varied passphrase.");
    }

    // Provision a fresh SQLCipher database encrypted with the master password.
    Database db(db_path, master, /*create=*/true);

    // Independent Argon2id key (fresh random salt) for field-level encryption.
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
    std::string master;
    auto db = open_vault(db_path, master);
    auto dk = derive_field_key(*db, master);
    secure_zero(master);

    std::string name, username, password, url, notes;

    std::cout << "Entry name: " << std::flush;
    std::getline(std::cin, name);
    if (name.empty()) {
        secure_zero(dk.key);
        print_error("Entry name cannot be empty.");
        return 1;
    }

    // Check if entry already exists
    if (db->get_entry(name).has_value()) {
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
        print_info(std::string("Strength: ") +
                   password_strength_label(evaluate_password_strength(password)));
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
    secure_zero(username);
    secure_zero(url);
    secure_zero(notes);
    secure_zero(dk.key);

    db->add_entry(name, enc_username, enc_password, enc_url, enc_notes);

    print_success("Entry '" + name + "' added successfully.");
    return 0;
}

int cmd_get(const std::string& db_path, const std::string& name) {
    std::string master;
    auto db = open_vault(db_path, master);
    auto dk = derive_field_key(*db, master);
    secure_zero(master);

    auto entry = db->get_entry(name);
    if (!entry.has_value()) {
        secure_zero(dk.key);
        print_error("Entry '" + name + "' not found.");
        return 1;
    }

    std::string username = decrypt(dk.key, entry->enc_username);
    std::string password = decrypt(dk.key, entry->enc_password);
    std::string url = decrypt(dk.key, entry->enc_url);
    std::string notes = decrypt(dk.key, entry->enc_notes);

    secure_zero(dk.key);

    {
        std::vector<std::vector<std::string>> rows = {
            {"Name", entry->name},
            {"Username", username},
            {"Password", password},
            {"URL", url},
            {"Notes", notes},
        };
        print_table({"Field", "Value"}, rows);
        for (auto& row : rows) {
            for (auto& cell : row) {
                secure_zero(cell);
            }
        }
    }

    secure_zero(username);
    secure_zero(password);
    secure_zero(url);
    secure_zero(notes);

    return 0;
}

int cmd_list(const std::string& db_path) {
    std::string master;
    auto db = open_vault(db_path, master);
    secure_zero(master);

    auto items = db->list_entries();

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
    std::string master;
    auto db = open_vault(db_path, master);
    secure_zero(master);

    if (!db->get_entry(name).has_value()) {
        print_error("Entry '" + name + "' not found.");
        return 1;
    }

    std::cout << "Are you sure you want to delete '" << name << "'? [y/N]: " << std::flush;
    std::string answer;
    std::getline(std::cin, answer);

    if (answer != "y" && answer != "Y") {
        print_info("Aborted.");
        return 0;
    }

    if (db->delete_entry(name)) {
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
    print_info(std::string("Strength: ") +
               password_strength_label(evaluate_password_strength(pw)));
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
    std::string master;
    auto db = open_vault(db_path, master);
    auto dk = derive_field_key(*db, master);
    secure_zero(master);

    auto entry = db->get_entry(entry_name);
    if (!entry.has_value()) {
        secure_zero(dk.key);
        print_error("Entry '" + entry_name + "' not found. Add it first with 'pwman add'.");
        return 1;
    }

    if (db->has_totp(entry_name)) {
        secure_zero(dk.key);
        print_error("Entry '" + entry_name + "' already has TOTP configured.");
        print_info("Delete it first with 'pwman totp del " + entry_name + "'.");
        return 1;
    }

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
        // Parse otpauth:// URI — not implemented yet. Zero secrets and bail
        // instead of falling through with an empty secret_base32.
        secure_zero(dk.key);
        secure_zero(input);
        print_error("otpauth:// URIs are not yet supported. Provide the raw Base32 secret instead.");
        return 1;
    }

    // Raw Base32 secret
    secret_base32 = base32_normalize(input);
    if (!base32_validate(secret_base32)) {
        secure_zero(dk.key);
        secure_zero(secret_base32);
        secure_zero(input);
        print_error("Invalid Base32 secret.");
        return 1;
    }

    secure_zero(input);

    // Encrypt the base32 secret and store it
    auto enc_secret = encrypt(dk.key, secret_base32);

    // Decode for live display; validates the secret too
    auto raw_secret = base32_decode(secret_base32);
    auto algo = string_to_algorithm(algorithm);

    secure_zero(secret_base32);

    db->set_totp(entry->id, enc_secret, algorithm, digits, period);
    secure_zero(dk.key);

    print_success("TOTP configured for '" + entry_name + "'.");
    live_totp_display(entry_name, raw_secret, algo, digits, period);

    secure_zero(raw_secret);

    return 0;
}

int cmd_totp_del(const std::string& db_path, const std::string& entry_name){
    std::string master;
    auto db = open_vault(db_path, master);
    secure_zero(master);

    if (!db->has_totp(entry_name)) {
        print_error("No TOTP configured for '" + entry_name + "'.");
        return 1;
    }

    std::cout << "Remove TOTP from '" << entry_name << "'? [y/N]: " << std::flush;
    std::string answer;
    std::getline(std::cin, answer);

    if (answer != "y" && answer != "Y") {
        print_info("Aborted.");
        return 0;
    }

    if (db->delete_totp(entry_name)) {
        print_success("TOTP removed from '" + entry_name + "'.");
    } else {
        print_error("Failed to remove TOTP.");
        return 1;
    }

    return 0;
}

int cmd_totp(const std::string& db_path, const std::string& entry_name) {
    std::string master;
    auto db = open_vault(db_path, master);
    auto dk = derive_field_key(*db, master);
    secure_zero(master);

    auto totp_data = db->get_totp(entry_name);
    if (!totp_data.has_value()) {
        secure_zero(dk.key);
        print_error("No TOTP configured for '" + entry_name + "'.");
        print_info("Add one with 'pwman totp add " + entry_name + "'.");
        return 1;
    }

    // Decrypt the base32 secret
    std::string secret_base32 = decrypt(dk.key, totp_data->enc_secret);
    secure_zero(dk.key);

    // Decode and generate
    auto raw_secret = base32_decode(secret_base32);
    secure_zero(secret_base32);

    auto algo = string_to_algorithm(totp_data->algorithm);

    live_totp_display(entry_name, raw_secret, algo, totp_data->digits, totp_data->period);

    secure_zero(raw_secret);

    return 0;
}

} // namespace pwman
