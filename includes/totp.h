
#include <string>
#include <vector>
#include <sodium.h>
#include <map>
#include <chrono>

#include "hmac.h"
#include "base32.h"


namespace pwman {

    class TotpError : public std::runtime_error {
        public: 
            using std::runtime_error::runtime_error;
    };
    
    // TOTP configuration (parsed from otpauth:// URI or manual input)
    struct TOTPConfig {
        std::string secret_base32;  // Raw Base32 secret
        HashAlgorithm algorithm = HashAlgorithm::SHA1;
        int digits = 6; // TOTP length 6 or 8
        int period = 30; // Time step in seconds
        std::string issuer; // e.g. "GitHub"
        std::string account; // e.g. "user@mail.com"
    };

    // Generate a TOTP code for a given time.
    // secret: raw decoded bytes (output of base32_decode)
    // unix_time: current time in seconds since epoch
    // Returns: zero-padded code string, e.g. "048297"
    std::string totp_generate(const std::vector<uint8_t>& secret,
                            HashAlgorithm algo = HashAlgorithm::SHA1, 
                            int digits = 6, 
                            int period = 30);

    
    // Convert HashAlgorithm enum to/from string.
    std::string algorithm_to_string(HashAlgorithm algo);
    HashAlgorithm string_to_algorithm(const std::string& s);
    
    // Parse an otpauth:// URI into a TOTPConfig.
    // Example: otpauth://totp/GitHub:user@mail.com?secret=JBSWY3DP&issuer=GitHub
    TOTPConfig parse_otpauth_uri(const std::string& uri); 

    // Seconds remaining until the current code expires.
    int totp_remaining_seconds(int period = 30); 


}