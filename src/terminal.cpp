#include "terminal.h"
#include <iostream>
#include <algorithm>
#include <numeric>

#ifdef _WIN32
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace pwman {

std::string read_password(const std::string& prompt) {
    std::cerr << prompt << std::flush;

    std::string password;

#ifdef _WIN32
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode;
    GetConsoleMode(hStdin, &mode);
    SetConsoleMode(hStdin, mode & ~ENABLE_ECHO_INPUT);

    std::getline(std::cin, password);

    SetConsoleMode(hStdin, mode);
#else
    struct termios old_term, new_term;
    tcgetattr(STDIN_FILENO, &old_term);
    new_term = old_term;
    new_term.c_lflag &= ~static_cast<tcflag_t>(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &new_term);

    std::getline(std::cin, password);

    tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
#endif

    std::cerr << "\n";
    return password;
}

void print_table(const std::vector<std::string>& headers,
                 const std::vector<std::vector<std::string>>& rows) {
    if (headers.empty()) return;

    const size_t cols = headers.size();

    // Calculate column widths
    std::vector<size_t> widths(cols);
    for (size_t i = 0; i < cols; ++i) {
        widths[i] = headers[i].size();
    }
    for (const auto& row : rows) {
        for (size_t i = 0; i < cols && i < row.size(); ++i) {
            widths[i] = std::max(widths[i], row[i].size());
        }
    }

    // Add padding
    for (auto& w : widths) {
        w += 2;
    }

    // Build separator line
    std::string separator = "+";
    for (size_t w : widths) {
        separator += std::string(w, '-') + "+";
    }

    // Print header
    std::cout << separator << "\n";
    std::cout << "|";
    for (size_t i = 0; i < cols; ++i) {
        std::string cell = " " + headers[i];
        cell += std::string(widths[i] - cell.size(), ' ');
        std::cout << cell << "|";
    }
    std::cout << "\n" << separator << "\n";

    // Print rows
    for (const auto& row : rows) {
        std::cout << "|";
        for (size_t i = 0; i < cols; ++i) {
            std::string val = (i < row.size()) ? row[i] : "";
            std::string cell = " " + val;
            cell += std::string(widths[i] - cell.size(), ' ');
            std::cout << cell << "|";
        }
        std::cout << "\n";
    }
    std::cout << separator << "\n";
}

void print_success(const std::string& msg) {
    std::cout << "[+] " << msg << "\n";
}

void print_error(const std::string& msg) {
    std::cerr << "[!] " << msg << "\n";
}

void print_info(const std::string& msg) {
    std::cout << "[*] " << msg << "\n";
}

} // namespace pwman
