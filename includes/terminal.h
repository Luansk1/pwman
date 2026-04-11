#pragma once

#include <string>
#include <vector>

namespace pwman {

// Read a password from the terminal without echoing characters.
std::string read_password(const std::string& prompt = "Password: ");

// Print a formatted table to stdout.
// headers: column headers
// rows: row data (each row is a vector of strings matching headers length)
void print_table(const std::vector<std::string>& headers,
                 const std::vector<std::vector<std::string>>& rows);

// Print a success message.
void print_success(const std::string& msg);

// Print an error message.
void print_error(const std::string& msg);

// Print an info message.
void print_info(const std::string& msg);

// Print TOTP code with remaining time.
void print_totp_code(const std::string& name,
                     const std::string& code,
                     int remaining_seconds,
                     int period);

} // namespace pwman
