cmake_minimum_required(VERSION 3.16)
project(pwman VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Dependencies via pkg-config
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
# SQLCipher is a drop-in SQLite replacement that transparently encrypts the
# whole database file. Its headers live under include/sqlcipher and expose the
# standard <sqlite3.h> API, so no source changes are needed beyond linking it.
pkg_check_modules(SQLCIPHER REQUIRED IMPORTED_TARGET sqlcipher)

# FTXUI: terminal UI toolkit used by the `list` command's interactive table.
include(FetchContent)
set(FTXUI_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(FTXUI_BUILD_DOCS OFF CACHE BOOL "" FORCE)
set(FTXUI_BUILD_TESTS OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    ftxui
    GIT_REPOSITORY https://github.com/ArthurSonzogni/FTXUI.git
    GIT_TAG v7.0.1
)
FetchContent_MakeAvailable(ftxui)

# Main library (shared between exe and tests)
add_library(pwman_lib STATIC
    src/crypto.cpp
    src/database.cpp
    src/terminal.cpp
    src/commands.cpp
    src/list_ui.cpp
    src/base32.cpp
    src/totp.cpp
    src/hmac.cpp
)
target_include_directories(pwman_lib PUBLIC includes)
target_link_libraries(pwman_lib PUBLIC PkgConfig::SODIUM PkgConfig::SQLCIPHER)
# FTXUI is an implementation detail of list_ui.cpp; keep it private but, since
# pwman_lib is static, CMake still propagates it to the final executable link.
target_link_libraries(pwman_lib PRIVATE ftxui::screen ftxui::dom ftxui::component)

# Executable
add_executable(pwman src/main.cpp)
target_link_libraries(pwman PRIVATE pwman_lib)

# Install rule: `cmake --install build` copies the binary into <prefix>/bin.
# Override the prefix with e.g. `cmake --install build --prefix /opt/homebrew`.
install(TARGETS pwman RUNTIME DESTINATION bin)

# Tests
option(BUILD_TESTS "Build unit tests" ON)
if(BUILD_TESTS)
    enable_testing()

    # Fetch GoogleTest
    include(FetchContent)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.14.0
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    add_executable(pwman_tests
        tests/test_crypto.cpp
        tests/test_database.cpp
        tests/test_terminal.cpp
        tests/test_base32.cpp
        tests/test_hmac.cpp
    )
    target_link_libraries(pwman_tests PRIVATE pwman_lib GTest::gtest_main)
    target_include_directories(pwman_tests PRIVATE includes)

    include(GoogleTest)
    gtest_discover_tests(pwman_tests)
endif()
