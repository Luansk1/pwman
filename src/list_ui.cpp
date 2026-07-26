#include "list_ui.h"

#include "terminal.h"  // copy_to_clipboard
#include "totp.h"      // totp_generate, totp_remaining_seconds

#include <ftxui/component/component.hpp>
#include <ftxui/component/event.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace pwman {

namespace {

using namespace ftxui;

// Every masked password renders as this many asterisks, regardless of the real
// length, so the display leaks nothing about how long any password is.
constexpr int kMaskWidth = 8;

// Cap the Name/Username columns so a long value can never push the TOTP column
// off the right edge of the screen (that clipping is what made trailing digits
// of a code appear to be "cut off").
constexpr int kNameMax = 20;
constexpr int kUserMax = 20;

const char* kHelp = "↑/↓ move · r reveal · c copy pw · t copy TOTP · / search · q quit";

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return s;
}

// Current TOTP code, zero-padded by totp_generate. `spaced` inserts a readable
// gap for 6-digit codes (used for display, not for the clipboard).
std::string totp_code(const VaultRow& row, bool spaced) {
    std::string code = totp_generate(row.totp_secret, row.totp_algo,
                                     row.totp_digits, row.totp_period);
    if (spaced && code.size() == 6) {
        code = code.substr(0, 3) + " " + code.substr(3);
    }
    return code;
}

} // namespace

void run_list_ui(std::vector<VaultRow>& rows) {
    if (rows.empty()) return;

    auto screen = ScreenInteractive::Fullscreen();

    int selected = 0;          // index into the current filtered view
    bool reveal = false;       // reveal the selected password
    bool searching = false;    // capturing typed characters into `query`
    std::string query;
    std::string status = kHelp;

    // Transient status messages ("Copied …") revert to the help text after a
    // short delay. We store an expiry time instead of sleeping, so the UI
    // thread is never blocked; the repaint ticker makes the revert visible.
    std::chrono::steady_clock::time_point status_expiry{};
    auto flash_status = [&](std::string msg) {
        status = std::move(msg);
        status_expiry = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    };

    // Name/Username column widths: content-sized, floored at the header label
    // and capped so the TOTP column always has room.
    int name_w = 4;  // "Name"
    int user_w = 8;  // "Username"
    for (const auto& r : rows) {
        name_w = std::max(name_w, static_cast<int>(r.name.size()));
        user_w = std::max(user_w, static_cast<int>(r.username.size()));
    }
    name_w = std::min(name_w, kNameMax);
    user_w = std::min(user_w, kUserMax);

    // Row indices matching the current search query (all rows when empty).
    auto filtered = [&]() {
        std::vector<int> view;
        std::string q = to_lower(query);
        for (int i = 0; i < static_cast<int>(rows.size()); ++i) {
            if (q.empty() || to_lower(rows[i].name).find(q) != std::string::npos ||
                to_lower(rows[i].username).find(q) != std::string::npos) {
                view.push_back(i);
            }
        }
        return view;
    };

    // Real row index currently under the cursor, or -1 if the view is empty.
    auto current_row = [&]() -> int {
        auto view = filtered();
        if (view.empty()) return -1;
        selected = std::clamp(selected, 0, static_cast<int>(view.size()) - 1);
        return view[selected];
    };

    auto renderer = Renderer([&] {
        auto view = filtered();
        if (!view.empty()) {
            selected = std::clamp(selected, 0, static_cast<int>(view.size()) - 1);
        }

        Elements lines;
        lines.push_back(hbox({
            text("Name")     | bold | size(WIDTH, EQUAL, name_w),
            separator(),
            text("Username") | bold | size(WIDTH, EQUAL, user_w),
            separator(),
            text("Password") | bold | size(WIDTH, EQUAL, kMaskWidth),
            separator(),
            text("TOTP")     | bold,
        }));
        lines.push_back(separator());

        if (view.empty()) {
            lines.push_back(text("(no matches)") | dim);
        }
        for (int pos = 0; pos < static_cast<int>(view.size()); ++pos) {
            const VaultRow& r = rows[view[pos]];
            const bool sel = (pos == selected);

            std::string pw =
                (sel && reveal) ? r.password : std::string(kMaskWidth, '*');
            Element pw_el = text(pw) | size(WIDTH, EQUAL, kMaskWidth);
            if (sel && reveal) pw_el = pw_el | color(Color::Yellow);

            Element totp_el =
                r.has_totp
                    ? text(totp_code(r, true) + "  (" +
                           std::to_string(totp_remaining_seconds(r.totp_period)) +
                           "s)") | color(Color::Green)
                    : text("—") | dim;

            Element line = hbox({
                text(r.name)     | size(WIDTH, EQUAL, name_w),
                separator(),
                text(r.username) | size(WIDTH, EQUAL, user_w),
                separator(),
                pw_el,
                separator(),
                totp_el,
            });
            if (sel) line = line | inverted | focus;
            lines.push_back(std::move(line));
        }

        // Search bar: active input line, or a hint once a query is set.
        Element search_bar;
        if (searching) {
            search_bar = hbox({text("Search: ") | bold,
                               text(query) | color(Color::Cyan),
                               text("▏")});
        } else if (!query.empty()) {
            search_bar = text("Filter: \"" + query + "\"  (/ to edit, Esc clears)") | dim;
        } else {
            // Let a transient message revert to the help text once it expires.
            if (status_expiry.time_since_epoch().count() != 0 &&
                std::chrono::steady_clock::now() >= status_expiry) {
                status = kHelp;
                status_expiry = {};
            }
            search_bar = text(status) | dim;
        }

        return vbox({
            text(" pwman — vault (" + std::to_string(view.size()) + "/" +
                 std::to_string(rows.size()) + " entries) ") | bold | hcenter,
            separator(),
            vbox(std::move(lines)) | vscroll_indicator | yframe | flex,
            separator(),
            search_bar,
        }) | border;
    });

    auto component = CatchEvent(renderer, [&](Event e) {
        auto view_size = [&]() { return static_cast<int>(filtered().size()); };

        // --- search input mode: typed characters build the query ---
        if (searching) {
            if (e == Event::Escape) {
                searching = false;
                query.clear();
                selected = 0;
                return true;
            }
            if (e == Event::Return) { searching = false; return true; }
            if (e == Event::Backspace) {
                if (!query.empty()) query.pop_back();
                selected = 0;
                return true;
            }
            if (e == Event::ArrowDown) {
                if (selected + 1 < view_size()) { selected++; reveal = false; }
                return true;
            }
            if (e == Event::ArrowUp) {
                if (selected > 0) { selected--; reveal = false; }
                return true;
            }
            if (e.is_character()) {
                const std::string& c = e.character();
                if (!c.empty() && static_cast<unsigned char>(c[0]) >= 0x20) {
                    query += c;
                    selected = 0;
                    return true;
                }
            }
            return false;
        }

        // --- normal navigation mode ---
        if (e == Event::Character('/')) {
            searching = true;
            status = kHelp;
            return true;
        }
        if (e == Event::ArrowDown || e == Event::Character('j')) {
            if (selected + 1 < view_size()) selected++;
            reveal = false;
            status = kHelp;
            status_expiry = {};
            return true;
        }
        if (e == Event::ArrowUp || e == Event::Character('k')) {
            if (selected > 0) selected--;
            reveal = false;
            status = kHelp;
            status_expiry = {};
            return true;
        }
        if (e == Event::Character('r') || e == Event::Return) {
            int idx = current_row();
            if (idx >= 0) {
                reveal = !reveal;
                // Reflects ongoing state, so it persists (no expiry).
                status = reveal ? "Revealing password for '" + rows[idx].name + "'"
                                : std::string(kHelp);
                status_expiry = {};
            }
            return true;
        }
        if (e == Event::Character('c')) {
            int idx = current_row();
            if (idx >= 0) {
                copy_to_clipboard(rows[idx].password);
                flash_status("Copied password for '" + rows[idx].name + "' to clipboard");
            }
            return true;
        }
        if (e == Event::Character('t')) {
            int idx = current_row();
            if (idx >= 0 && rows[idx].has_totp) {
                copy_to_clipboard(totp_code(rows[idx], false));
                flash_status("Copied TOTP code for '" + rows[idx].name + "' to clipboard");
            } else if (idx >= 0) {
                flash_status("'" + rows[idx].name + "' has no TOTP configured");
            }
            return true;
        }
        if (e == Event::Character('q') || e == Event::Escape) {
            screen.Exit();
            return true;
        }
        return false;
    });

    // Repaint a few times a second so the live TOTP codes and countdowns move.
    std::atomic<bool> running{true};
    std::thread ticker([&] {
        while (running.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
            screen.PostEvent(Event::Custom);
        }
    });

    screen.Loop(component);

    running = false;
    ticker.join();
}

} // namespace pwman
