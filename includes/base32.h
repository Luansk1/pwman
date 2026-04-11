#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <stdexcept>

namespace pwman {

    class Base32Error : public std::runtime_error{
        public: 
            using std::runtime_error::runtime_error;
    };

    // validate string if it is a valid base32 string
    bool base32_validate(const std::string& input);

    // Decode base32 string to raw bytes
    std::vector<uint8_t> base32_decode(const std::string& input);

    // Encode raw bytes to base32 string
    std::string base32_encode(const std::vector<uint8_t>& data);

    // Normalize string to base32
    std::string base32_normalize(const std::string& input);

}