cmake_minimum_required(VERSION 3.28)
project(P2P_Secure_File_Sharing)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)   # we don't use C++20 modules; skips a scanner step that Clang+Ninja needs extra tools for

option(P2P_BUILD_TESTS "Build the unit tests" ON)
option(P2P_SANITIZE "Build with AddressSanitizer + UndefinedBehaviorSanitizer (GCC/Clang only)" OFF)

# Sanitizers add extra checks that turn silent memory bugs (buffer overflows, use-after-free,
# signed overflow, ...) into loud crashes. Must be set before the targets are created.
if(P2P_SANITIZE)
    if(MSVC)
        message(FATAL_ERROR "P2P_SANITIZE needs GCC or Clang")
    endif()
    add_compile_options(-fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=address,undefined)
endif()

# Find system OpenSSL and Boost packages
find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED COMPONENTS system)

add_executable(P2P_Secure_File_Sharing main.cpp
        protocol.hpp
        validation.hpp
        disk_budget.hpp
        trust_store.hpp
        identity.hpp
        cli_identity.hpp
        tls_trust.hpp
        file_streaming.hpp
        client_node.hpp
        server_session.hpp
        server_node.hpp
        p2p_node.hpp
)

target_link_libraries(P2P_Secure_File_Sharing PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        Boost::system
)

# ---------------- Fuzzing (Clang only) ----------------
# Fuzzes the header checks and filename sanitizer with libFuzzer. See the README.
option(P2P_BUILD_FUZZERS "Build the libFuzzer fuzz targets (Clang only)" OFF)
if(P2P_BUILD_FUZZERS)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "P2P_BUILD_FUZZERS needs Clang (it uses libFuzzer)")
    endif()
    add_executable(fuzz_validation fuzz/fuzz_validation.cpp)
    target_include_directories(fuzz_validation PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_options(fuzz_validation PRIVATE -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined -O1 -g)
    target_link_options(fuzz_validation PRIVATE -fsanitize=fuzzer,address,undefined)
    target_link_libraries(fuzz_validation PRIVATE Boost::system)
endif()

# ---------------- Unit tests ----------------
if(P2P_BUILD_TESTS)
    enable_testing()

    include(FetchContent)
    FetchContent_Declare(googletest
        URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)   # needed for MSVC
    FetchContent_MakeAvailable(googletest)

    add_executable(unit_tests
        tests/test_protocol.cpp
        tests/test_validation.cpp
        tests/test_disk_budget.cpp
        tests/test_trust_store.cpp
        tests/test_identity.cpp
        tests/test_tls_trust.cpp
        tests/test_hashing.cpp
    )
    target_include_directories(unit_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(unit_tests PRIVATE GTest::gtest_main OpenSSL::Crypto Boost::system)

    include(GoogleTest)
    gtest_discover_tests(unit_tests)

    # Real transfer over TLS on localhost (needs bash, openssl and timeout, so Linux only)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        add_test(NAME end_to_end
                 COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/e2e_test.sh $<TARGET_FILE:P2P_Secure_File_Sharing>)
    endif()
endif()
