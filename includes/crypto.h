#pragma once 

#include <string>
#include <vector>
#include <cstdint>
#include <stdexcept>


namespace pwman{

    class CryptoError : public std::runtime_error {
        public: 
            using std::runtime_error::runtime_error;
    };

    // Derives a 256-bit key from a master password using Argon2id.
    // Returns a 32-byte key. The salt is stored alongside the database.
    struct DerivedKey {
        std::vector<uint8_t> key;   // 32 bytes
        std::vector<uint8_t> salt;  // 16 bytes
    };

    enum PasswordStrength {
        WEAK,
        MEDIUM,
        STRONG
    };


    void crypto_init();

    DerivedKey derive_key(const std::string& password);
    DerivedKey derive_key(const std::string& password, const std::vector<uint8_t>& salt);

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& key, const std::string& plaintext);

    std::string decrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data);

    void secure_zero(void* ptr, size_t len);
    void secure_zero(std::string& s);
    void secure_zero(std::vector<uint8_t>& v);

    std::string generate_password(size_t length = 20);

    PasswordStrength evaluate_password_strength(const std::string& password);
    double calculate_password_entropy(const std::string& password);

    
}