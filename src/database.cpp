#include "database.h"
#include <sqlite3.h>
#include <cstdlib>
#include <filesystem>
#include <fstream>

#ifdef _WIN32
#include <shlobj.h>
#else
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace pwman {

namespace {

std::string get_home_dir() {
#ifdef _WIN32
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_PROFILE, nullptr, 0, path))) {
        return path;
    }
    const char* home = std::getenv("USERPROFILE");
    return home ? home : ".";
#else
    const char* home = std::getenv("HOME");
    if (home) return home;
    struct passwd* pw = getpwuid(getuid());
    return pw ? pw->pw_dir : ".";
#endif
}

// Helper to convert a blob column to vector<uint8_t>.
std::vector<uint8_t> blob_to_vec(sqlite3_stmt* stmt, int col) {
    const auto* data = static_cast<const uint8_t*>(sqlite3_column_blob(stmt, col));
    int len = sqlite3_column_bytes(stmt, col);
    if (!data || len <= 0) return {};
    return {data, data + len};
}

// Escape a passphrase for use inside a single-quoted SQL string literal so it
// can be passed to `PRAGMA key`. Passwords come from getline() and never carry
// embedded NULs, so doubling single quotes is sufficient.
std::string sql_quote(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 2);
    out.push_back('\'');
    for (char c : s) {
        if (c == '\'') out.push_back('\'');
        out.push_back(c);
    }
    out.push_back('\'');
    return out;
}

} // namespace

bool has_vault_extension(const std::string& path) {
    const std::string ext = kVaultExtension;
    if (path.size() < ext.size()) return false;
    return path.compare(path.size() - ext.size(), ext.size(), ext) == 0;
}

std::string default_db_path() {
    namespace fs = std::filesystem;
    fs::path dir = fs::path(get_home_dir()) / ".pwman";
    if (!fs::exists(dir)) {
        fs::create_directories(dir);
    }
#ifndef _WIN32
    ::chmod(dir.c_str(), S_IRWXU);
#endif
    return (dir / (std::string("pwman") + kVaultExtension)).string();
}

std::string config_file_path() {
    namespace fs = std::filesystem;
    return (fs::path(get_home_dir()) / ".pwman" / "config").string();
}

std::optional<std::string> stored_db_path() {
    std::ifstream in(config_file_path());
    if (!in) return std::nullopt;
    std::string line;
    while (std::getline(in, line)) {
        // Skip blanks and comments; parse `db=<path>`.
        if (line.empty() || line[0] == '#') continue;
        const std::string key = "db=";
        if (line.rfind(key, 0) == 0) {
            std::string value = line.substr(key.size());
            if (!value.empty()) return value;
        }
    }
    return std::nullopt;
}

std::string configured_db_path() {
    if (const char* env = std::getenv("PWMAN_DB")) {
        if (env[0] != '\0') return env;
    }
    if (auto stored = stored_db_path()) {
        return *stored;
    }
    return default_db_path();
}

void set_stored_db_path(const std::string& path) {
    namespace fs = std::filesystem;

    // Expand a leading "~/" to the home directory.
    std::string expanded = path;
    if (expanded.rfind("~/", 0) == 0) {
        expanded = (fs::path(get_home_dir()) / expanded.substr(2)).string();
    }

    fs::path dir = fs::path(get_home_dir()) / ".pwman";
    if (!fs::exists(dir)) {
        fs::create_directories(dir);
    }
#ifndef _WIN32
    ::chmod(dir.c_str(), S_IRWXU);
#endif

    const std::string cfg = config_file_path();
    std::ofstream out(cfg, std::ios::trunc);
    if (!out) {
        throw DatabaseError("Cannot write config file: " + cfg);
    }
    out << "# pwman configuration\n";
    out << "db=" << expanded << "\n";
    out.close();
#ifndef _WIN32
    ::chmod(cfg.c_str(), S_IRUSR | S_IWUSR);
#endif
}

Database::Database(const std::string& path, const std::string& master_password, bool create)
    : path_(path) {
    namespace fs = std::filesystem;

    const bool existing = fs::exists(path) && fs::file_size(path) > 0;
    if (!create && !existing) {
        throw DatabaseError("Database not initialized. Run 'pwman init' first.");
    }

    fs::path parent = fs::path(path).parent_path();
    if (!parent.empty() && !fs::exists(parent)) {
        fs::create_directories(parent);
    }
#ifndef _WIN32
    if (!parent.empty()) {
        ::chmod(parent.c_str(), S_IRWXU);
    }
#endif

    int rc = sqlite3_open(path.c_str(), &db_);
    if (rc != SQLITE_OK) {
        std::string err = sqlite3_errmsg(db_);
        sqlite3_close(db_);
        db_ = nullptr;
        throw DatabaseError("Cannot open database: " + err);
    }

#ifndef _WIN32
    // Restrict permissions on the DB and any SQLite sidecar files (-wal, -shm).
    ::chmod(path.c_str(), S_IRUSR | S_IWUSR);
    for (const char* suffix : {"-wal", "-shm", "-journal"}) {
        std::string side = path + suffix;
        if (fs::exists(side)) {
            ::chmod(side.c_str(), S_IRUSR | S_IWUSR);
        }
    }
#endif

    // Supply the SQLCipher passphrase before any read/write. This must happen
    // before the WAL pragma below, otherwise SQLCipher cannot read the header.
    apply_key(master_password);

    // For an existing file, confirm the passphrase actually decrypts it and
    // that the recognition magic marks it as a pwman vault.
    if (existing) {
        verify_vault();
    }

    // Enable WAL mode and foreign keys
    exec("PRAGMA journal_mode=WAL;");
    exec("PRAGMA foreign_keys=ON;");

#ifndef _WIN32
    // WAL mode creates sidecar files on first write — chmod them too.
    for (const char* suffix : {"-wal", "-shm"}) {
        std::string side = path + suffix;
        if (fs::exists(side)) {
            ::chmod(side.c_str(), S_IRUSR | S_IWUSR);
        }
    }
#endif
}

void Database::apply_key(const std::string& master_password) {
    // SQLCipher derives the file-encryption key from this passphrase via
    // PBKDF2; the KDF salt lives in the (plaintext) first 16 bytes of the file.
    exec("PRAGMA key = " + sql_quote(master_password) + ";");
}

void Database::verify_vault() {
    // The first read after PRAGMA key triggers decryption. A wrong passphrase
    // (or a non-SQLCipher file) surfaces here as SQLITE_NOTADB.
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT count(*) FROM sqlite_master;";
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc == SQLITE_OK) {
        rc = sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);
    if (rc != SQLITE_ROW) {
        throw DatabaseError("Incorrect master password, or not a pwman vault.");
    }

    // Correct passphrase — now make sure this is really our application's file
    // and not some other SQLCipher database that shares the passphrase.
    stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "PRAGMA application_id;", -1, &stmt, nullptr) == SQLITE_OK &&
        sqlite3_step(stmt) == SQLITE_ROW) {
        int app_id = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
        if (app_id != kApplicationId) {
            throw DatabaseError("Not a pwman database (recognition magic mismatch).");
        }
    } else {
        sqlite3_finalize(stmt);
        throw DatabaseError("Failed to read database recognition magic.");
    }
}

Database::~Database() {
    if (db_) {
        sqlite3_close(db_);
    }
}

void Database::exec(const std::string& sql) {
    char* err = nullptr;
    int rc = sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        std::string msg = err ? err : "unknown error";
        sqlite3_free(err);
        throw DatabaseError("SQL error: " + msg);
    }
}

void Database::init(const std::vector<uint8_t>& salt, const std::vector<uint8_t>& encrypted_verify) {
    // Stamp the recognition magic into the (encrypted) SQLite header so a
    // decrypted vault can be positively identified as ours. See kApplicationId.
    exec("PRAGMA application_id = " + std::to_string(kApplicationId) + ";");

    // ── Schema v1: Basis-Tabellen ──
    exec(R"(
        CREATE TABLE IF NOT EXISTS meta (
            key   TEXT PRIMARY KEY,
            value BLOB NOT NULL
        );
    )");
    exec(R"(
        CREATE TABLE IF NOT EXISTS entries (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            name         TEXT NOT NULL UNIQUE,
            enc_username BLOB NOT NULL,
            enc_password BLOB NOT NULL,
            enc_url      BLOB,
            enc_notes    BLOB,
            created_at   TEXT DEFAULT (datetime('now')),
            updated_at   TEXT DEFAULT (datetime('now'))
        );
    )");

    // Setze initiale Schema-Version und führe Migrationen aus
    set_schema_version(1);
    migrate();

    // Store salt and verify token
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?);";

    // Salt
    sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, "salt", -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, salt.data(), static_cast<int>(salt.size()), SQLITE_STATIC);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw DatabaseError("Failed to store salt");
    }
    sqlite3_finalize(stmt);

    // Verify token
    sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, "verify", -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, encrypted_verify.data(),
                      static_cast<int>(encrypted_verify.size()), SQLITE_STATIC);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw DatabaseError("Failed to store verify token");
    }
    sqlite3_finalize(stmt);
}

bool Database::is_initialized() const {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT name FROM sqlite_master WHERE type='table' AND name='meta';";
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    bool found = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);

    // Bestehende DB? Migrationen ausführen (const_cast ist OK,
    // weil migrate() nur Schema ändert, nicht den logischen Zustand)
    if (found) {
        const_cast<Database*>(this)->migrate();
    }

    return found;
}

std::vector<uint8_t> Database::load_salt() const {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT value FROM meta WHERE key='salt';";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw DatabaseError("Failed to query salt");
    }
    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        throw DatabaseError("No salt found in database");
    }
    auto result = blob_to_vec(stmt, 0);
    sqlite3_finalize(stmt);
    return result;
}

std::vector<uint8_t> Database::load_verify_token() const {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT value FROM meta WHERE key='verify';";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw DatabaseError("Failed to query verify token");
    }
    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        throw DatabaseError("No verify token found");
    }
    auto result = blob_to_vec(stmt, 0);
    sqlite3_finalize(stmt);
    return result;
}

int64_t Database::add_entry(const std::string& name,
                            const std::vector<uint8_t>& enc_username,
                            const std::vector<uint8_t>& enc_password,
                            const std::vector<uint8_t>& enc_url,
                            const std::vector<uint8_t>& enc_notes) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = R"(
        INSERT INTO entries (name, enc_username, enc_password, enc_url, enc_notes)
        VALUES (?, ?, ?, ?, ?);
    )";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw DatabaseError(std::string("Prepare failed: ") + sqlite3_errmsg(db_));
    }

    sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, enc_username.data(), static_cast<int>(enc_username.size()), SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 3, enc_password.data(), static_cast<int>(enc_password.size()), SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 4, enc_url.data(), static_cast<int>(enc_url.size()), SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 5, enc_notes.data(), static_cast<int>(enc_notes.size()), SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::string err = sqlite3_errmsg(db_);
        sqlite3_finalize(stmt);
        throw DatabaseError("Failed to add entry: " + err);
    }

    int64_t id = sqlite3_last_insert_rowid(db_);
    sqlite3_finalize(stmt);
    return id;
}

std::vector<Database::ListItem> Database::list_entries() const {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT id, name FROM entries ORDER BY name;";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw DatabaseError("Failed to list entries");
    }

    std::vector<ListItem> items;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ListItem item;
        item.id = sqlite3_column_int64(stmt, 0);
        item.name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        items.push_back(std::move(item));
    }
    sqlite3_finalize(stmt);
    return items;
}

std::optional<Database::EncryptedEntry> Database::get_entry(const std::string& name) const {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = R"(
        SELECT id, name, enc_username, enc_password, enc_url, enc_notes
        FROM entries WHERE name = ?;
    )";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw DatabaseError("Failed to query entry");
    }
    sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return std::nullopt;
    }

    EncryptedEntry entry;
    entry.id = sqlite3_column_int64(stmt, 0);
    entry.name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
    entry.enc_username = blob_to_vec(stmt, 2);
    entry.enc_password = blob_to_vec(stmt, 3);
    entry.enc_url = blob_to_vec(stmt, 4);
    entry.enc_notes = blob_to_vec(stmt, 5);
    sqlite3_finalize(stmt);
    return entry;
}

bool Database::delete_entry(const std::string& name) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "DELETE FROM entries WHERE name = ?;";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw DatabaseError("Failed to delete entry");
    }
    sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw DatabaseError("Delete failed");
    }

    int changes = sqlite3_changes(db_);
    sqlite3_finalize(stmt);
    return changes > 0;
}

// ── Schema Versioning & Migration ─────────────────────────

int Database::schema_version() const {
    // Prüfe ob die meta-Tabelle existiert
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT value FROM meta WHERE key='schema_version';";
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return 0;

    int version = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        // schema_version ist als Text-BLOB gespeichert
        const auto* text = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        if (text) version = std::atoi(text);
    }
    sqlite3_finalize(stmt);
    return version;
}

void Database::set_schema_version(int version) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', ?);";
    sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    std::string ver_str = std::to_string(version);
    sqlite3_bind_text(stmt, 1, ver_str.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw DatabaseError("Failed to set schema version");
    }
    sqlite3_finalize(stmt);
}

void Database::migrate() {
    int current = schema_version();

    // v1 → v2: TOTP-Tabelle hinzufügen
    if (current < 2) {
        exec(R"(
            CREATE TABLE IF NOT EXISTS totp_entries (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                entry_id   INTEGER NOT NULL UNIQUE,
                enc_secret BLOB NOT NULL,
                algorithm  TEXT NOT NULL DEFAULT 'SHA1',
                digits     INTEGER NOT NULL DEFAULT 6,
                period     INTEGER NOT NULL DEFAULT 30,
                created_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (entry_id) REFERENCES entries(id) ON DELETE CASCADE
            );
        )");
        set_schema_version(2);
    }

    // Zukünftige Migrationen:
    // if (current < 3) { ... set_schema_version(3); }
}

// ── TOTP CRUD ─────────────────────────────────────────────

void Database::set_totp(int64_t entry_id,
                        const std::vector<uint8_t>& enc_secret,
                        const std::string& algorithm,
                        int digits,
                        int period) {
    if (algorithm != "SHA1" && algorithm != "SHA256" && algorithm != "SHA512") {
        throw DatabaseError("Invalid TOTP algorithm: " + algorithm);
    }
    if (digits < 6 || digits > 8) {
        throw DatabaseError("Invalid TOTP digits (must be 6, 7, or 8): " +
                            std::to_string(digits));
    }
    if (period <= 0 || period > 600) {
        throw DatabaseError("Invalid TOTP period: " + std::to_string(period));
    }
    if (enc_secret.empty()) {
        throw DatabaseError("Refusing to store empty TOTP secret");
    }

    // INSERT OR REPLACE: Wenn der Entry schon TOTP hat, wird es ersetzt
    sqlite3_stmt* stmt = nullptr;
    const char* sql = R"(
        INSERT OR REPLACE INTO totp_entries (entry_id, enc_secret, algorithm, digits, period)
        VALUES (?, ?, ?, ?, ?);
    )";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw DatabaseError(std::string("Prepare failed: ") + sqlite3_errmsg(db_));
    }

    sqlite3_bind_int64(stmt, 1, entry_id);
    sqlite3_bind_blob(stmt, 2, enc_secret.data(),
                      static_cast<int>(enc_secret.size()), SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, algorithm.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 4, digits);
    sqlite3_bind_int(stmt, 5, period);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::string err = sqlite3_errmsg(db_);
        sqlite3_finalize(stmt);
        throw DatabaseError("Failed to set TOTP: " + err);
    }
    sqlite3_finalize(stmt);
}

std::optional<Database::TOTPEntry> Database::get_totp(const std::string& entry_name) const {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = R"(
        SELECT t.id, t.entry_id, t.enc_secret, t.algorithm, t.digits, t.period
        FROM totp_entries t
        JOIN entries e ON e.id = t.entry_id
        WHERE e.name = ?;
    )";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw DatabaseError("Failed to query TOTP");
    }
    sqlite3_bind_text(stmt, 1, entry_name.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return std::nullopt;
    }

    TOTPEntry totp;
    totp.id = sqlite3_column_int64(stmt, 0);
    totp.entry_id = sqlite3_column_int64(stmt, 1);
    totp.enc_secret = blob_to_vec(stmt, 2);
    const auto* algo = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
    totp.algorithm = algo ? algo : "SHA1";
    totp.digits = sqlite3_column_int(stmt, 4);
    totp.period = sqlite3_column_int(stmt, 5);
    sqlite3_finalize(stmt);
    return totp;
}

bool Database::delete_totp(const std::string& entry_name) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = R"(
        DELETE FROM totp_entries
        WHERE entry_id = (SELECT id FROM entries WHERE name = ?);
    )";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw DatabaseError("Failed to delete TOTP");
    }
    sqlite3_bind_text(stmt, 1, entry_name.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw DatabaseError("TOTP delete failed");
    }

    int changes = sqlite3_changes(db_);
    sqlite3_finalize(stmt);
    return changes > 0;
}

bool Database::has_totp(const std::string& entry_name) const {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = R"(
        SELECT 1 FROM totp_entries t
        JOIN entries e ON e.id = t.entry_id
        WHERE e.name = ?
        LIMIT 1;
    )";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    sqlite3_bind_text(stmt, 1, entry_name.c_str(), -1, SQLITE_STATIC);
    bool found = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return found;
}

} // namespace pwman
