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

#ifdef _WIN32
namespace {
struct EchoGuard {
    HANDLE handle;
    DWORD old_mode;
    bool active = false;
    EchoGuard() : handle(GetStdHandle(STD_INPUT_HANDLE)) {
        if (GetConsoleMode(handle, &old_mode)) {
            SetConsoleMode(handle, old_mode & ~ENABLE_ECHO_INPUT);
            active = true;
        }
    }
    ~EchoGuard() { if (active) SetConsoleMode(handle, old_mode); }
};
}
#else
namespace {
struct EchoGuard {
    termios old_term{};
    bool active = false;
    EchoGuard() {
        if (tcgetattr(STDIN_FILENO, &old_term) == 0) {
            termios new_term = old_term;
            new_term.c_lflag &= ~static_cast<tcflag_t>(ECHO);
            active = (tcsetattr(STDIN_FILENO, TCSANOW, &new_term) == 0);
        }
    }
    ~EchoGuard() { if (active) tcsetattr(STDIN_FILENO, TCSANOW, &old_term); }
};
}
#endif

std::string read_password(const std::string& prompt) {
    std::cerr << prompt << std::flush;

    std::string password;
    {
        EchoGuard guard;
        std::getline(std::cin, password);
    }

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

void print_totp_code(const std::string& name,
                     const std::string& code,
                     int remaining_seconds,
                     int period) {

    // "483297" → "483 297",  "94287082" → "9428 7082"
    std::string display_code;
    size_t half = code.size() / 2;
    for (size_t i = 0; i < code.size(); ++i) {
        if (i == half) display_code += ' ';
        display_code += code[i];
    }

    // Calcuclate progress bar 
    const int bar_width = 20;
    int filled = (remaining_seconds * bar_width) / period;
    if (filled < 0) filled = 0;
    if (filled > bar_width) filled = bar_width;

    std::string bar;
    for (int i = 0; i < bar_width; ++i) {
        bar += (i < filled) ? '#' : '-';
    }

    // Countdown-Farbe: unter 5 Sekunden = Warnung
    std::string time_str = std::to_string(remaining_seconds) + "s";

    // Box-Breite berechnen
    std::string title = name + " - TOTP";
    size_t content_width = display_code.size();
    if (content_width < title.size()) content_width = title.size();
    // Bar-Zeile: [bar] XXs / XXs
    std::string bar_line = "[" + bar + "] " + time_str + " / " + std::to_string(period) + "s";
    if (content_width < bar_line.size()) content_width = bar_line.size();
    content_width += 4; // padding

    // Horizontale Linie
    std::string h_line(content_width, '-');

    // Zentrieren
    auto center = [&](const std::string& text) -> std::string {
        if (text.size() >= content_width) return text;
        size_t pad_left = (content_width - text.size()) / 2;
        size_t pad_right = content_width - text.size() - pad_left;
        return std::string(pad_left, ' ') + text + std::string(pad_right, ' ');
    };

    std::cout << "\n";
    std::cout << "+" << h_line << "+" << "\n";
    std::cout << "|" << center(title) << "|" << "\n";
    std::cout << "+" << h_line << "+" << "\n";
    std::cout << "|" << std::string(content_width, ' ') << "|" << "\n";
    std::cout << "|" << center(display_code) << "|" << "\n";
    std::cout << "|" << std::string(content_width, ' ') << "|" << "\n";
    std::cout << "|" << center(bar_line) << "|" << "\n";
    std::cout << "|" << std::string(content_width, ' ') << "|" << "\n";
    std::cout << "+" << h_line << "+" << "\n";
    std::cout << "\n";
    }
} // namespace pwman
