#include <gtest/gtest.h>
#include "database.h"
#include "crypto.h"
#include <filesystem>
#include <cstdio>

class DatabaseTest : public ::testing::Test {
protected:
    std::string db_path;

    void SetUp() override {
        pwman::crypto_init();
        db_path = std::filesystem::temp_directory_path() / ("pwman_test_" + std::to_string(::testing::UnitTest::GetInstance()->random_seed()) + ".db");
        // Ensure clean state
        std::filesystem::remove(db_path);
    }

    void TearDown() override {
        std::filesystem::remove(db_path);
        // Also remove WAL and SHM files
        std::filesystem::remove(db_path + "-wal");
        std::filesystem::remove(db_path + "-shm");
    }

    void init_db(pwman::Database& db) {
        auto dk = pwman::derive_key("testmaster");
        auto enc_verify = pwman::encrypt(dk.key, "pwman_verify");
        db.init(dk.salt, enc_verify);
    }
};

TEST_F(DatabaseTest, CreateAndOpen) {
    pwman::Database db(db_path);
    EXPECT_FALSE(db.is_initialized());
}

TEST_F(DatabaseTest, Initialize) {
    pwman::Database db(db_path);
    init_db(db);
    EXPECT_TRUE(db.is_initialized());
}

TEST_F(DatabaseTest, LoadSaltAfterInit) {
    auto dk = pwman::derive_key("testmaster");
    {
        pwman::Database db(db_path);
        auto enc_verify = pwman::encrypt(dk.key, "pwman_verify");
        db.init(dk.salt, enc_verify);
    }
    // Reopen and check salt
    pwman::Database db2(db_path);
    auto loaded_salt = db2.load_salt();
    EXPECT_EQ(loaded_salt, dk.salt);
}

TEST_F(DatabaseTest, VerifyTokenRoundTrip) {
    auto dk = pwman::derive_key("testmaster");
    auto enc_verify = pwman::encrypt(dk.key, "pwman_verify");

    {
        pwman::Database db(db_path);
        db.init(dk.salt, enc_verify);
    }

    pwman::Database db2(db_path);
    auto loaded_token = db2.load_verify_token();
    auto decrypted = pwman::decrypt(dk.key, loaded_token);
    EXPECT_EQ(decrypted, "pwman_verify");
}

TEST_F(DatabaseTest, AddAndGetEntry) {
    pwman::Database db(db_path);
    init_db(db);

    auto dk = pwman::derive_key("testmaster");
    dk = pwman::derive_key("testmaster", db.load_salt());

    auto enc_user = pwman::encrypt(dk.key, "user@example.com");
    auto enc_pass = pwman::encrypt(dk.key, "secret123");
    auto enc_url = pwman::encrypt(dk.key, "https://example.com");
    auto enc_notes = pwman::encrypt(dk.key, "test notes");

    int64_t id = db.add_entry("test_entry", enc_user, enc_pass, enc_url, enc_notes);
    EXPECT_GT(id, 0);

    auto entry = db.get_entry("test_entry");
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry->name, "test_entry");

    auto dec_user = pwman::decrypt(dk.key, entry->enc_username);
    auto dec_pass = pwman::decrypt(dk.key, entry->enc_password);
    auto dec_url = pwman::decrypt(dk.key, entry->enc_url);
    auto dec_notes = pwman::decrypt(dk.key, entry->enc_notes);

    EXPECT_EQ(dec_user, "user@example.com");
    EXPECT_EQ(dec_pass, "secret123");
    EXPECT_EQ(dec_url, "https://example.com");
    EXPECT_EQ(dec_notes, "test notes");
}

TEST_F(DatabaseTest, GetNonexistentEntry) {
    pwman::Database db(db_path);
    init_db(db);

    auto entry = db.get_entry("doesnt_exist");
    EXPECT_FALSE(entry.has_value());
}

TEST_F(DatabaseTest, DuplicateEntryFails) {
    pwman::Database db(db_path);
    init_db(db);

    auto dk = pwman::derive_key("testmaster");
    dk = pwman::derive_key("testmaster", db.load_salt());

    auto enc = pwman::encrypt(dk.key, "data");
    db.add_entry("dup", enc, enc, enc, enc);
    EXPECT_THROW(db.add_entry("dup", enc, enc, enc, enc), pwman::DatabaseError);
}

TEST_F(DatabaseTest, ListEntries) {
    pwman::Database db(db_path);
    init_db(db);

    auto dk = pwman::derive_key("testmaster");
    dk = pwman::derive_key("testmaster", db.load_salt());
    auto enc = pwman::encrypt(dk.key, "data");

    db.add_entry("beta", enc, enc, enc, enc);
    db.add_entry("alpha", enc, enc, enc, enc);
    db.add_entry("gamma", enc, enc, enc, enc);

    auto items = db.list_entries();
    ASSERT_EQ(items.size(), 3u);
    // Should be ordered alphabetically
    EXPECT_EQ(items[0].name, "alpha");
    EXPECT_EQ(items[1].name, "beta");
    EXPECT_EQ(items[2].name, "gamma");
}

TEST_F(DatabaseTest, DeleteEntry) {
    pwman::Database db(db_path);
    init_db(db);

    auto dk = pwman::derive_key("testmaster");
    dk = pwman::derive_key("testmaster", db.load_salt());
    auto enc = pwman::encrypt(dk.key, "data");

    db.add_entry("to_delete", enc, enc, enc, enc);
    EXPECT_TRUE(db.delete_entry("to_delete"));
    EXPECT_FALSE(db.get_entry("to_delete").has_value());
}

TEST_F(DatabaseTest, DeleteNonexistentEntry) {
    pwman::Database db(db_path);
    init_db(db);

    EXPECT_FALSE(db.delete_entry("nonexistent"));
}

TEST_F(DatabaseTest, ListEmptyDatabase) {
    pwman::Database db(db_path);
    init_db(db);

    auto items = db.list_entries();
    EXPECT_TRUE(items.empty());
}
