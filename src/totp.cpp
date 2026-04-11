#include "totp.h"

namespace pwman {


    std::string algorithm_to_string(HashAlgorithm algo) {
        switch (algo) {
            case HashAlgorithm::SHA1: return "SHA1";
            case HashAlgorithm::SHA256: return "SHA256";
            case HashAlgorithm::SHA512: return "SHA512";
            default: return "SHA1";
        }
    }

    HashAlgorithm string_to_algorithm(const std::string& s){
        if (s == "SHA1") return HashAlgorithm::SHA1;
        if (s == "SHA256") return HashAlgorithm::SHA256;
        if (s == "SHA512") return HashAlgorithm::SHA512;
        throw TotpError("Unsupported algorithm: " + s);
    }

    std::string totp_generate(const std::vector<uint8_t>& secret,
                            HashAlgorithm algo, 
                            int digits, 
                            int period){

        
        const auto now = std::chrono::system_clock::now(); 
        const auto unix_time = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
        
        uint64_t time_step = unix_time / period; 
        std::vector<uint8_t> time_bytes(8);

        for(int i = 7; i >= 0; --i){
            time_bytes[i] = static_cast<uint8_t>(time_step & 0xFF);
            time_step >>= 8; 
        }

        if (algo != HashAlgorithm::SHA1) {
            throw TotpError("Only SHA1 is currently supported");
        }

        std::vector<uint8_t> mac = hmac_sha1(secret, time_bytes);

        int offset = mac.back() & 0x0F;

        uint32_t code = (static_cast<uint32_t>(mac[offset]) << 24) |
                        (static_cast<uint32_t>(mac[offset + 1]) << 16) |
                        (static_cast<uint32_t>(mac[offset + 2]) << 8) |
                        (static_cast<uint32_t>(mac[offset + 3]));

        code &= 0x7FFFFFFF; // Remove the sign bit
        code %= static_cast<uint32_t>(std::pow(10, digits)); // Modulo to get the correct number of digits  

        return std::to_string(code);

    }

    int totp_remaining_seconds(int period){

        const auto now = std::chrono::system_clock::now(); 
        const auto unix_time = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
        
        return period - (unix_time % period);
    }

    TOTPConfig parse_otpauth_uri(const std::string& uri){
        // TODO Implementation for parsing otpauth:// URI
        return TOTPConfig();
    }
}