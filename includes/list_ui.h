#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "hmac.h"  // HashAlgorithm

namespace pwman {

// One row of the interactive list UI. Holds decrypted secrets in memory for the
// lifetime of the UI so passwords can be revealed/copied and TOTP codes can be
// generated live. The caller MUST secure_zero() the sensitive fields (username,
// password, totp_secret) once run_list_ui() returns.
struct VaultRow {
    std::string name;
    std::string username;
    std::string password;                // decrypted

    bool has_totp = false;
    std::vector<uint8_t> totp_secret;    // raw decoded secret bytes
    HashAlgorithm totp_algo = HashAlgorithm::SHA1;
    int totp_digits = 6;
    int totp_period = 30;
};

// Display an interactive FTXUI table of the given rows and block until the user
// quits (q / Esc). Navigate with the arrow keys (or j/k); passwords are shown
// as a fixed-length mask, and the selected one can be revealed (r / Enter) or
// copied to the clipboard (c). TOTP codes refresh live.
void run_list_ui(std::vector<VaultRow>& rows);

} // namespace pwman
