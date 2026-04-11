#pragma once

#include <algorithm>
#include <vector>
#include <string>
#include <cstdint>
#include <stdexcept>

namespace pwman {

    // Supported hash algorithms 
    enum class HashAlgorithm {
        SHA1,
        SHA256,
        SHA512,
    };

    // SHA-1 hash functio (RFC 3174)
    // Input: arbitrary-length message
    // Output: 20-byte (160-bit) digest
    std::vector<uint8_t> sha1(const std::vector<uint8_t>& message);
    
    // HMAC (RFC 2104)
    // Input: key (arbitrary length), message (arbitrary length)
    // Output: MAC of hash-specific length (20/32/64 bytes)
    std::vector<uint8_t> hmac(HashAlgorithm algo, 
                              const std::vector<uint8_t>& key, 
                              const std::vector<uint8_t>& message);

    // HMAC-SHA1 specifically
    // message: time bytes for totp 
    std::vector<uint8_t> hmac_sha1(const std::vector<uint8_t>& key, 
                                   const std::vector<uint8_t>& message);
}