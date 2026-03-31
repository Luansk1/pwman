cmake_minimum_required(VERSION 3.16)
project(pwman VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Dependencies via pkg-config
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
pkg_check_modules(SQLITE3 REQUIRED IMPORTED_TARGET sqlite3)

# Main library (shared between exe and tests)
add_library(pwman_lib STATIC
    src/crypto.cpp
    src/database.cpp
    src/terminal.cpp
    src/commands.cpp
)
target_include_directories(pwman_lib PUBLIC include)
target_link_libraries(pwman_lib PUBLIC PkgConfig::SODIUM PkgConfig::SQLITE3)

# Executable
add_executable(pwman src/main.cpp)
target_link_libraries(pwman PRIVATE pwman_lib)

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
    )
    target_link_libraries(pwman_tests PRIVATE pwman_lib GTest::gtest_main)
    target_include_directories(pwman_tests PRIVATE include)

    include(GoogleTest)
    gtest_discover_tests(pwman_tests)
endif()
