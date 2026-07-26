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

        if (digits < 6 || digits > 8) {
            throw TotpError("Invalid digits (must be 6, 7, or 8): " +
                            std::to_string(digits));
        }
        if (period <= 0) {
            throw TotpError("Invalid period: " + std::to_string(period));
        }

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

        // Integer power of ten (std::pow uses doubles and can be off by one for
        // large exponents, which would corrupt the modulo).
        uint32_t modulo = 1;
        for (int i = 0; i < digits; ++i) modulo *= 10;
        code %= modulo;

        // Zero-pad on the LEFT to exactly `digits` characters. Without this a
        // code like 048290 would print as "48290" (a lost leading zero) and a
        // code like 123400 must keep its trailing zeros — std::to_string alone
        // drops the leading ones. RFC 6238 requires a fixed-width, padded code.
        std::string out = std::to_string(code);
        if (static_cast<int>(out.size()) < digits) {
            out.insert(out.begin(), digits - out.size(), '0');
        }
        return out;
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