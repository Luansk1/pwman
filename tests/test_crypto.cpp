#include <gtest/gtest.h>
#include "crypto.h"
#include <sodium.h>

class CryptoTest : public ::testing::Test {
protected:
    void SetUp() override {
        pwman::crypto_init();
    }
};

TEST_F(CryptoTest, DeriveKeyProducesCorrectSizes) {
    auto dk = pwman::derive_key("testpassword");
    EXPECT_EQ(dk.key.size(), crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    EXPECT_EQ(dk.salt.size(), crypto_pwhash_SALTBYTES);
}

TEST_F(CryptoTest, DeriveKeyWithSameSaltProducesSameKey) {
    auto dk1 = pwman::derive_key("testpassword");
    auto dk2 = pwman::derive_key("testpassword", dk1.salt);
    EXPECT_EQ(dk1.key, dk2.key);
}

TEST_F(CryptoTest, DeriveKeyWithDifferentPasswordProducesDifferentKey) {
    auto dk1 = pwman::derive_key("password1");
    auto dk2 = pwman::derive_key("password2", dk1.salt);
    EXPECT_NE(dk1.key, dk2.key);
}

TEST_F(CryptoTest, EncryptDecryptRoundTrip) {
    auto dk = pwman::derive_key("testpassword");
    std::string plaintext = "Hello, World!";

    auto ciphertext = pwman::encrypt(dk.key, plaintext);
    auto decrypted = pwman::decrypt(dk.key, ciphertext);

    EXPECT_EQ(decrypted, plaintext);
}

TEST_F(CryptoTest, EncryptDecryptEmptyString) {
    auto dk = pwman::derive_key("testpassword");
    std::string plaintext;

    auto ciphertext = pwman::encrypt(dk.key, plaintext);
    auto decrypted = pwman::decrypt(dk.key, ciphertext);

    EXPECT_EQ(decrypted, plaintext);
}

TEST_F(CryptoTest, EncryptDecryptLongString) {
    auto dk = pwman::derive_key("testpassword");
    std::string plaintext(10000, 'A');

    auto ciphertext = pwman::encrypt(dk.key, plaintext);
    auto decrypted = pwman::decrypt(dk.key, ciphertext);

    EXPECT_EQ(decrypted, plaintext);
}

TEST_F(CryptoTest, DecryptWithWrongKeyFails) {
    auto dk1 = pwman::derive_key("password1");
    auto dk2 = pwman::derive_key("password2");

    auto ciphertext = pwman::encrypt(dk1.key, "secret");
    EXPECT_THROW(pwman::decrypt(dk2.key, ciphertext), pwman::CryptoError);
}

TEST_F(CryptoTest, DecryptTruncatedCiphertextFails) {
    auto dk = pwman::derive_key("testpassword");
    auto ciphertext = pwman::encrypt(dk.key, "secret");

    // Truncate
    ciphertext.resize(10);
    EXPECT_THROW(pwman::decrypt(dk.key, ciphertext), pwman::CryptoError);
}

TEST_F(CryptoTest, DecryptCorruptedCiphertextFails) {
    auto dk = pwman::derive_key("testpassword");
    auto ciphertext = pwman::encrypt(dk.key, "secret");

    // Corrupt a byte in the ciphertext portion (after the nonce)
    ciphertext[ciphertext.size() - 1] ^= 0xFF;
    EXPECT_THROW(pwman::decrypt(dk.key, ciphertext), pwman::CryptoError);
}

TEST_F(CryptoTest, EncryptProducesDifferentCiphertextEachTime) {
    auto dk = pwman::derive_key("testpassword");
    auto ct1 = pwman::encrypt(dk.key, "same_plaintext");
    auto ct2 = pwman::encrypt(dk.key, "same_plaintext");

    // Nonces should differ, so ciphertexts should differ
    EXPECT_NE(ct1, ct2);
}

TEST_F(CryptoTest, GeneratePasswordLength) {
    auto pw = pwman::generate_password(30);
    EXPECT_EQ(pw.size(), 30u);
}

TEST_F(CryptoTest, GeneratePasswordDefaultLength) {
    auto pw = pwman::generate_password();
    EXPECT_EQ(pw.size(), 20u);
}

TEST_F(CryptoTest, GeneratePasswordsAreDifferent) {
    auto pw1 = pwman::generate_password(20);
    auto pw2 = pwman::generate_password(20);
    EXPECT_NE(pw1, pw2);
}

TEST_F(CryptoTest, SecureZeroString) {
    std::string s = "sensitive";
    pwman::secure_zero(s);
    EXPECT_TRUE(s.empty());
}

TEST_F(CryptoTest, SecureZeroVector) {
    std::vector<uint8_t> v = {1, 2, 3, 4};
    pwman::secure_zero(v);
    EXPECT_TRUE(v.empty());
}

TEST_F(CryptoTest, InvalidKeySizeEncrypt) {
    std::vector<uint8_t> bad_key = {1, 2, 3};
    EXPECT_THROW(pwman::encrypt(bad_key, "test"), pwman::CryptoError);
}

TEST_F(CryptoTest, InvalidKeySizeDecrypt) {
    std::vector<uint8_t> bad_key = {1, 2, 3};
    std::vector<uint8_t> data(100, 0);
    EXPECT_THROW(pwman::decrypt(bad_key, data), pwman::CryptoError);
}

TEST_F(CryptoTest, InvalidSaltSize) {
    std::vector<uint8_t> bad_salt = {1, 2, 3};
    EXPECT_THROW(pwman::derive_key("password", bad_salt), pwman::CryptoError);
}
