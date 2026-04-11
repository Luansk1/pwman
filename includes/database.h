#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <optional>
#include <memory>
#include <stdexcept>

struct sqlite3;

namespace pwman {

class DatabaseError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

struct Entry {
    int64_t id;
    std::string name;
    std::string username;
    std::string password;   // decrypted
    std::string url;
    std::string notes;
};

class Database {
public:
    // Opens or creates the database file.
    explicit Database(const std::string& path);
    ~Database();

    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;

    // Initialize the schema and store master key salt + verification token.
    void init(const std::vector<uint8_t>& salt, const std::vector<uint8_t>& encrypted_verify);

    // Returns true if the database has been initialized.
    bool is_initialized() const;

    // Load the stored salt.
    std::vector<uint8_t> load_salt() const;

    // Load the encrypted verification token.
    std::vector<uint8_t> load_verify_token() const;

    // Add an encrypted entry. Returns the new row id.
    int64_t add_entry(const std::string& name,
                      const std::vector<uint8_t>& enc_username,
                      const std::vector<uint8_t>& enc_password,
                      const std::vector<uint8_t>& enc_url,
                      const std::vector<uint8_t>& enc_notes);

    // Get all entry names and ids (no decryption needed for the name column).
    struct ListItem {
        int64_t id;
        std::string name;
    };
    std::vector<ListItem> list_entries() const;

    // Get a single encrypted entry by name.
    struct EncryptedEntry {
        int64_t id;
        std::string name;
        std::vector<uint8_t> enc_username;
        std::vector<uint8_t> enc_password;
        std::vector<uint8_t> enc_url;
        std::vector<uint8_t> enc_notes;
    };
    std::optional<EncryptedEntry> get_entry(const std::string& name) const;

    // Delete entry by name. Returns true if a row was deleted.
    bool delete_entry(const std::string& name);

    // ── TOTP ──────────────────────────────────────────────

    struct TOTPEntry {
        int64_t id;
        int64_t entry_id;
        std::vector<uint8_t> enc_secret;
        std::string algorithm;   // "SHA1", "SHA256", "SHA512"
        int digits;              // 6 or 8
        int period;              // usually 30
    };

    // Add a TOTP secret linked to an existing entry.
    // Replaces any existing TOTP for that entry.
    void set_totp(int64_t entry_id,
                  const std::vector<uint8_t>& enc_secret,
                  const std::string& algorithm = "SHA1",
                  int digits = 6,
                  int period = 30);

    // Get TOTP data for an entry (by entry name).
    std::optional<TOTPEntry> get_totp(const std::string& entry_name) const;

    // Remove TOTP from an entry. Returns true if removed.
    bool delete_totp(const std::string& entry_name);

    // Check if an entry has TOTP configured.
    bool has_totp(const std::string& entry_name) const;

    // ── Schema versioning ─────────────────────────────────

    // Returns the current schema version (0 if not set).
    int schema_version() const;

    // Get the database file path.
    const std::string& path() const { return path_; }

private:
    void exec(const std::string& sql);
    void migrate();  // Run pending schema migrations
    void set_schema_version(int version);
    std::string path_;
    sqlite3* db_ = nullptr;
};

// Returns the default database path (~/.pwman/pwman.db).
std::string default_db_path();

} // namespace pwman
