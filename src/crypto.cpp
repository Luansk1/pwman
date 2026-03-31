#include " crypto.h"
#include <sodium.h>
#include <cstring>

namespace pwman {

void crypto_init() {
    if (sodium_init() < 0) {
        throw CryptoError("Failed to initialize libsodium");
    }
}

DerivedKey derive_key(const std::string& password) {
    std::vector<uint8_t> salt(crypto_pwhash_SALTBYTES);
    randombytes_buf(salt.data(), salt.size());
    return derive_key(password, salt);
}

DerivedKey derive_key(const std::string& password, const std::vector<uint8_t>& salt) {
    if (salt.size() != crypto_pwhash_SALTBYTES) {
        throw CryptoError("Invalid salt size");
    }

    DerivedKey dk;
    dk.salt = salt;
    dk.key.resize(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);

    if (crypto_pwhash(dk.key.data(), dk.key.size(),
                      password.c_str(), password.size(),
                      salt.data(),
                      crypto_pwhash_OPSLIMIT_MODERATE,
                      crypto_pwhash_MEMLIMIT_MODERATE,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        throw CryptoError("Key derivation failed (out of memory?)");
    }

    return dk;
}

std::vector<uint8_t> encrypt(const std::vector<uint8_t>& key, const std::string& plaintext) {
    if (key.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
        throw CryptoError("Invalid key size");
    }

    const size_t nonce_len = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    const size_t tag_len = crypto_aead_xchacha20poly1305_ietf_ABYTES;

    std::vector<uint8_t> result(nonce_len + plaintext.size() + tag_len);

    // Generate random nonce
    randombytes_buf(result.data(), nonce_len);

    unsigned long long ciphertext_len;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            result.data() + nonce_len, &ciphertext_len,
            reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size(),
            nullptr, 0,  // no additional data
            nullptr,     // nsec (unused)
            result.data(), // nonce
            key.data()) != 0) {
        throw CryptoError("Encryption failed");
    }

    result.resize(nonce_len + ciphertext_len);
    return result;
}

std::string decrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data) {
    if (key.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
        throw CryptoError("Invalid key size");
    }

    const size_t nonce_len = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    const size_t tag_len = crypto_aead_xchacha20poly1305_ietf_ABYTES;

    if (data.size() < nonce_len + tag_len) {
        throw CryptoError("Ciphertext too short");
    }

    const uint8_t* nonce = data.data();
    const uint8_t* ciphertext = data.data() + nonce_len;
    const size_t ciphertext_len = data.size() - nonce_len;

    std::vector<uint8_t> plaintext(ciphertext_len - tag_len);
    unsigned long long plaintext_len;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.data(), &plaintext_len,
            nullptr,       // nsec (unused)
            ciphertext, ciphertext_len,
            nullptr, 0,    // no additional data
            nonce,
            key.data()) != 0) {
        throw CryptoError("Decryption failed (wrong password or corrupted data)");
    }

    std::string result(reinterpret_cast<const char*>(plaintext.data()), plaintext_len);
    sodium_memzero(plaintext.data(), plaintext.size());
    return result;
}

void secure_zero(void* ptr, size_t len) {
    sodium_memzero(ptr, len);
}

void secure_zero(std::string& s) {
    if (!s.empty()) {
        sodium_memzero(&s[0], s.size());
        s.clear();
    }
}

void secure_zero(std::vector<uint8_t>& v) {
    if (!v.empty()) {
        sodium_memzero(v.data(), v.size());
        v.clear();
    }
}

std::string generate_password(size_t length) {
    const char charset[] =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "!@#$%^&*()-_=+[]{}|;:,.<>?";
    const size_t charset_size = sizeof(charset) - 1;

    std::string password(length, '\0');
    for (size_t i = 0; i < length; ++i) {
        password[i] = charset[randombytes_uniform(static_cast<uint32_t>(charset_size))];
    }
    return password;
}

} // namespace pwman
