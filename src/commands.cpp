#include "commands.h"
#include "crypto.h"
#include "database.h"
#include "list_ui.h"
#include "terminal.h"
#include "totp.h"

#include <sodium.h>

#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#ifdef _WIN32
#include <conio.h>
#include <windows.h>
#else
#include <sys/select.h>
#include <sys/stat.h>
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
    // Non-interactive stdin (piped/scripted input): print a single code and
    // return rather than entering the live loop, which reads stdin in raw mode
    // and would otherwise spin forever once the pipe reaches EOF.
    if (!isatty(STDIN_FILENO)) {
        std::string code = totp_generate(raw_secret, algo, digits, period);
        print_totp_code(name, code, totp_remaining_seconds(period), period);
        secure_zero(code);
        return;
    }

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
    auto dk = derive_field_key(*db, master);
    secure_zero(master);

    auto items = db->list_entries();
    if (items.empty()) {
        secure_zero(dk.key);
        print_info("No entries found.");
        return 0;
    }

    // Decrypt each entry (and its TOTP secret, if any) so the UI can show the
    // masked password and a live TOTP code. Secrets are wiped after the UI.
    std::vector<VaultRow> rows;
    rows.reserve(items.size());
    for (const auto& item : items) {
        auto entry = db->get_entry(item.name);
        if (!entry.has_value()) continue;

        VaultRow row;
        row.name = item.name;
        row.username = decrypt(dk.key, entry->enc_username);
        row.password = decrypt(dk.key, entry->enc_password);

        auto totp = db->get_totp(item.name);
        if (totp.has_value()) {
            std::string secret_b32 = decrypt(dk.key, totp->enc_secret);
            row.totp_secret = base32_decode(secret_b32);
            secure_zero(secret_b32);
            row.totp_algo = string_to_algorithm(totp->algorithm);
            row.totp_digits = totp->digits;
            row.totp_period = totp->period;
            row.has_totp = true;
        }
        rows.push_back(std::move(row));
    }
    secure_zero(dk.key);

    run_list_ui(rows);

    for (auto& r : rows) {
        secure_zero(r.username);
        secure_zero(r.password);
        secure_zero(r.totp_secret);
    }
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
              << "  " << program << " export [xml] [path]   Export all entries to a CSV (or XML) file\n"
              << "  " << program << " import <file.csv>     Import entries from a CSV file\n"
              << "  " << program << " config [db <path>]    Show or set the default database path\n"
              << "\nOptions:\n"
              << "  --db <path>          Use a custom database path (overrides the configured default)\n"
              << "  --version, -v        Show the version\n"
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

namespace {

// One fully-decrypted entry, used only while building an export.
struct ExportRow {
    std::string name, username, password, url, notes;
    bool has_totp = false;
    std::string totp_secret;      // Base32
    std::string totp_algorithm;
    int totp_digits = 0;
    int totp_period = 0;
};

// RFC 4180 CSV field: quote it when it contains a comma, quote or newline, and
// double any embedded quotes.
std::string csv_escape(const std::string& s) {
    if (s.find_first_of(",\"\n\r") == std::string::npos) return s;
    std::string out = "\"";
    for (char c : s) {
        if (c == '"') out += "\"\"";
        else out += c;
    }
    out += "\"";
    return out;
}

std::string xml_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '&':  out += "&amp;";  break;
            case '<':  out += "&lt;";   break;
            case '>':  out += "&gt;";   break;
            case '"':  out += "&quot;"; break;
            case '\'': out += "&apos;"; break;
            default:   out += c;
        }
    }
    return out;
}

std::string build_csv(const std::vector<ExportRow>& rows) {
    std::string out =
        "name,username,password,url,notes,totp_secret,totp_algorithm,totp_digits,totp_period\n";
    for (const auto& r : rows) {
        out += csv_escape(r.name)     + ",";
        out += csv_escape(r.username) + ",";
        out += csv_escape(r.password) + ",";
        out += csv_escape(r.url)      + ",";
        out += csv_escape(r.notes)    + ",";
        if (r.has_totp) {
            out += csv_escape(r.totp_secret)    + ",";
            out += csv_escape(r.totp_algorithm) + ",";
            out += std::to_string(r.totp_digits) + ",";
            out += std::to_string(r.totp_period);
        } else {
            out += ",,,";
        }
        out += "\n";
    }
    return out;
}

std::string build_xml(const std::vector<ExportRow>& rows) {
    std::string out = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<pwman-export>\n";
    for (const auto& r : rows) {
        out += "  <entry>\n";
        out += "    <name>" + xml_escape(r.name) + "</name>\n";
        out += "    <username>" + xml_escape(r.username) + "</username>\n";
        out += "    <password>" + xml_escape(r.password) + "</password>\n";
        out += "    <url>" + xml_escape(r.url) + "</url>\n";
        out += "    <notes>" + xml_escape(r.notes) + "</notes>\n";
        if (r.has_totp) {
            out += "    <totp secret=\"" + xml_escape(r.totp_secret) +
                   "\" algorithm=\"" + xml_escape(r.totp_algorithm) +
                   "\" digits=\"" + std::to_string(r.totp_digits) +
                   "\" period=\"" + std::to_string(r.totp_period) + "\"/>\n";
        }
        out += "  </entry>\n";
    }
    out += "</pwman-export>\n";
    return out;
}

} // namespace

int cmd_export(const std::string& db_path, const std::string& format,
               const std::string& out_path_arg) {
    const bool xml = (format == "xml");

    std::string master;
    auto db = open_vault(db_path, master);
    auto dk = derive_field_key(*db, master);
    secure_zero(master);

    auto items = db->list_entries();
    if (items.empty()) {
        secure_zero(dk.key);
        print_info("No entries found; nothing to export.");
        return 0;
    }

    // Decrypt every entry (and its TOTP config, if any) into export rows.
    std::vector<ExportRow> rows;
    rows.reserve(items.size());
    for (const auto& item : items) {
        auto entry = db->get_entry(item.name);
        if (!entry.has_value()) continue;

        ExportRow r;
        r.name = item.name;
        r.username = decrypt(dk.key, entry->enc_username);
        r.password = decrypt(dk.key, entry->enc_password);
        r.url = decrypt(dk.key, entry->enc_url);
        r.notes = decrypt(dk.key, entry->enc_notes);

        auto totp = db->get_totp(item.name);
        if (totp.has_value()) {
            r.totp_secret = decrypt(dk.key, totp->enc_secret);
            r.totp_algorithm = totp->algorithm;
            r.totp_digits = totp->digits;
            r.totp_period = totp->period;
            r.has_totp = true;
        }
        rows.push_back(std::move(r));
    }
    secure_zero(dk.key);

    std::string out_path = out_path_arg;
    if (out_path.empty()) {
        out_path = std::string("pwman-export.") + (xml ? "xml" : "csv");
    }

    std::string content = xml ? build_xml(rows) : build_csv(rows);

    // Wipe the decrypted secrets we no longer need (the file itself will hold
    // them in plaintext — that is the nature of an export).
    for (auto& r : rows) {
        secure_zero(r.username);
        secure_zero(r.password);
        secure_zero(r.url);
        secure_zero(r.notes);
        secure_zero(r.totp_secret);
    }

    // Create the file and lock its permissions down *before* writing secrets.
    { std::ofstream create(out_path, std::ios::binary | std::ios::trunc); }
#ifndef _WIN32
    ::chmod(out_path.c_str(), S_IRUSR | S_IWUSR);
#endif
    std::ofstream ofs(out_path, std::ios::binary | std::ios::trunc);
    if (!ofs) {
        secure_zero(content);
        print_error("Cannot open output file: " + out_path);
        return 1;
    }
    ofs.write(content.data(), static_cast<std::streamsize>(content.size()));
    ofs.close();
    secure_zero(content);

    print_success("Exported " + std::to_string(rows.size()) + " entries to " +
                  out_path + " (" + (xml ? "XML" : "CSV") + ").");
    print_info("Warning: this file contains your passwords in PLAINTEXT. "
               "Store it securely or delete it after use.");
    return 0;
}

namespace {

// Parse RFC 4180 CSV text into rows of fields. Handles quoted fields, escaped
// quotes ("") and commas/newlines inside quotes; accepts LF and CRLF line ends.
std::vector<std::vector<std::string>> parse_csv(const std::string& text) {
    std::vector<std::vector<std::string>> rows;
    std::vector<std::string> row;
    std::string field;
    bool in_quotes = false;
    bool row_started = false;  // did we see any field content/separator on this line?

    auto end_field = [&]() { row.push_back(std::move(field)); field.clear(); };
    auto end_row = [&]() {
        end_field();
        rows.push_back(std::move(row));
        row.clear();
        row_started = false;
    };

    for (size_t i = 0; i < text.size(); ++i) {
        char c = text[i];
        if (in_quotes) {
            if (c == '"') {
                if (i + 1 < text.size() && text[i + 1] == '"') { field += '"'; ++i; }
                else in_quotes = false;
            } else {
                field += c;
            }
            continue;
        }
        switch (c) {
            case '"':  in_quotes = true; row_started = true; break;
            case ',':  end_field(); row_started = true; break;
            case '\r': break;  // swallow CR (CRLF handled by the LF)
            case '\n': end_row(); break;
            default:   field += c; row_started = true; break;
        }
    }
    // Flush a final row that wasn't newline-terminated.
    if (row_started || !field.empty() || !row.empty()) end_row();
    return rows;
}

std::string to_lower_copy(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}
std::string to_upper_copy(std::string s) {
    for (char& c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return s;
}
std::string trim_copy(const std::string& s) {
    size_t a = s.find_first_not_of(" \t");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t");
    return s.substr(a, b - a + 1);
}
int parse_int_or(const std::string& s, int fallback) {
    try { return std::stoi(s); } catch (...) { return fallback; }
}

// Interpret the value of a TOTP column, which may be a raw Base32 secret or a
// full otpauth:// URI (as exported by KeePassXC and others). Fills secret and,
// for a URI, any algorithm/digits/period query parameters it carries. Returns
// false when no secret can be found.
bool parse_totp_field(const std::string& value, std::string& secret,
                      std::string& algorithm, int& digits, int& period) {
    if (value.rfind("otpauth://", 0) != 0) {
        secret = value;
        return !secret.empty();
    }

    auto qpos = value.find('?');
    if (qpos == std::string::npos) return false;
    std::string query = value.substr(qpos + 1);
    for (size_t i = 0; i < query.size();) {
        size_t amp = query.find('&', i);
        std::string pair = query.substr(i, amp == std::string::npos ? amp : amp - i);
        auto eq = pair.find('=');
        if (eq != std::string::npos) {
            std::string key = to_lower_copy(pair.substr(0, eq));
            std::string val = pair.substr(eq + 1);
            if (key == "secret") secret = val;
            else if (key == "algorithm") algorithm = to_upper_copy(val);
            else if (key == "digits") digits = parse_int_or(val, digits);
            else if (key == "period") period = parse_int_or(val, period);
        }
        if (amp == std::string::npos) break;
        i = amp + 1;
    }
    return !secret.empty();
}

} // namespace

int cmd_import(const std::string& db_path, const std::string& in_path) {
    namespace fs = std::filesystem;
    if (!fs::exists(in_path)) {
        print_error("File not found: " + in_path);
        return 1;
    }

    std::ifstream ifs(in_path, std::ios::binary);
    if (!ifs) {
        print_error("Cannot open file: " + in_path);
        return 1;
    }
    std::string content((std::istreambuf_iterator<char>(ifs)),
                        std::istreambuf_iterator<char>());
    ifs.close();

    auto rows = parse_csv(content);
    secure_zero(content);
    if (rows.empty()) {
        print_info("No rows found in " + in_path);
        return 0;
    }

    // Column titles recognised in a header row. Covers the common layout used by
    // KeePassXC and most password managers (Title, Username, Password, URL,
    // Notes, TOTP) as well as pwman's own export columns.
    static const std::set<std::string> known_columns = {
        "title", "name", "username", "password", "url", "notes", "totp",
        "totp_secret", "totp_algorithm", "totp_digits", "totp_period"};

    std::map<std::string, int> col;
    size_t data_start = 0;
    {
        const auto& first = rows[0];
        bool has_header = false;
        for (const auto& c : first) {
            if (known_columns.count(to_lower_copy(trim_copy(c)))) has_header = true;
        }
        if (has_header) {
            for (int i = 0; i < static_cast<int>(first.size()); ++i) {
                col[to_lower_copy(trim_copy(first[i]))] = i;
            }
            data_start = 1;
        } else {
            // Headerless files are read in pwman's own export column order.
            const char* order[] = {"name", "username", "password", "url", "notes",
                                    "totp_secret", "totp_algorithm", "totp_digits",
                                    "totp_period"};
            for (int i = 0; i < 9; ++i) col[order[i]] = i;
        }
    }
    auto field = [&](const std::vector<std::string>& r, const char* key) -> std::string {
        auto it = col.find(key);
        if (it == col.end() || it->second < 0 ||
            it->second >= static_cast<int>(r.size())) {
            return "";
        }
        return r[it->second];
    };
    // First non-empty value among several accepted column names (aliases).
    auto field_alias = [&](const std::vector<std::string>& r,
                           std::initializer_list<const char*> keys) -> std::string {
        for (const char* k : keys) {
            std::string v = field(r, k);
            if (!v.empty()) return v;
        }
        return "";
    };

    if (col.find("title") == col.end() && col.find("name") == col.end()) {
        print_error("CSV has no 'Title'/'name' column; cannot import.");
        return 1;
    }

    std::string master;
    auto db = open_vault(db_path, master);
    auto dk = derive_field_key(*db, master);
    secure_zero(master);

    int imported = 0, skipped = 0, failed = 0, totp_added = 0;
    for (size_t r = data_start; r < rows.size(); ++r) {
        std::string name = field_alias(rows[r], {"title", "name"});
        if (name.empty()) {
            // Ignore fully blank lines silently; count other nameless rows.
            if (!(rows[r].size() == 1 && rows[r][0].empty())) ++failed;
            continue;
        }
        if (db->get_entry(name).has_value()) {
            ++skipped;
            continue;
        }

        std::string username = field(rows[r], "username");
        std::string password = field(rows[r], "password");
        std::string url = field(rows[r], "url");
        std::string notes = field(rows[r], "notes");

        int64_t id = 0;
        try {
            id = db->add_entry(name,
                               encrypt(dk.key, username),
                               encrypt(dk.key, password),
                               encrypt(dk.key, url),
                               encrypt(dk.key, notes));
            ++imported;
        } catch (const DatabaseError& e) {
            ++failed;
            print_error("Skipping '" + name + "': " + e.what());
        }

        std::string totp_value = field_alias(rows[r], {"totp", "totp_secret"});
        if (id != 0 && !totp_value.empty()) {
            std::string secret;
            std::string algo = to_upper_copy(field(rows[r], "totp_algorithm"));
            int digits = parse_int_or(field(rows[r], "totp_digits"), 6);
            int period = parse_int_or(field(rows[r], "totp_period"), 30);

            parse_totp_field(totp_value, secret, algo, digits, period);
            std::string norm = base32_normalize(secret);
            if (base32_validate(norm)) {
                if (algo.empty()) algo = "SHA1";
                try {
                    db->set_totp(id, encrypt(dk.key, norm), algo, digits, period);
                    ++totp_added;
                } catch (const std::exception& e) {
                    print_error("TOTP for '" + name + "' skipped: " + e.what());
                }
            } else {
                print_error("TOTP for '" + name + "' skipped: invalid secret.");
            }
            secure_zero(secret);
            secure_zero(norm);
            secure_zero(totp_value);
        }

        secure_zero(username);
        secure_zero(password);
        secure_zero(url);
        secure_zero(notes);
    }

    secure_zero(dk.key);
    for (auto& row : rows) {
        for (auto& c : row) secure_zero(c);
    }

    print_success("Imported " + std::to_string(imported) + " entries (" +
                  std::to_string(totp_added) + " with TOTP).");
    if (skipped > 0) {
        print_info(std::to_string(skipped) +
                   " skipped (an entry with that name already exists).");
    }
    if (failed > 0) {
        print_info(std::to_string(failed) + " rows could not be imported.");
    }
    return 0;
}

int cmd_config(const std::vector<std::string>& args) {
    namespace fs = std::filesystem;

    // `config` / `config show`: report the effective configuration.
    if (args.empty() || args[0] == "show" || args[0] == "get") {
        print_info("Config file:   " + config_file_path());

        auto stored = stored_db_path();
        std::cout << "Stored db:     "
                  << (stored ? *stored : std::string("(none)")) << "\n";

        const char* env = std::getenv("PWMAN_DB");
        std::cout << "PWMAN_DB env:  "
                  << (env && env[0] ? env : "(unset)") << "\n";

        std::cout << "Effective db:  " << configured_db_path() << "\n";
        print_info("Override for a single command with '--db <path>'. "
                   "Priority: --db > PWMAN_DB > config file > default.");
        return 0;
    }

    // `config db <path>` / `config set-db <path>`: persist the default.
    if (args[0] == "db" || args[0] == "set-db" || args[0] == "set") {
        if (args.size() < 2) {
            print_error("Usage: pwman config db <path-to-vault" +
                        std::string(kVaultExtension) + ">");
            return 1;
        }
        const std::string& path = args[1];
        if (!has_vault_extension(path)) {
            print_error("Database file must use the '" +
                        std::string(kVaultExtension) + "' extension: " + path);
            return 1;
        }
        set_stored_db_path(path);
        print_success("Default database set to: " + configured_db_path());
        if (std::getenv("PWMAN_DB")) {
            print_info("Note: PWMAN_DB is set and overrides the config file.");
        }
        if (!fs::exists(path)) {
            print_info("That file does not exist yet — run 'pwman init' to create it.");
        }
        return 0;
    }

    // `config clear` / `config unset`: forget the stored default.
    if (args[0] == "clear" || args[0] == "unset") {
        std::error_code ec;
        fs::remove(config_file_path(), ec);
        print_success("Cleared stored default database path.");
        return 0;
    }

    print_error("Unknown config subcommand: " + args[0]);
    print_info("Usage: pwman config [show | db <path> | clear]");
    return 1;
}

} // namespace pwman
