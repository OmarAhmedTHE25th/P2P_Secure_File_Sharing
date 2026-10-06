cmake_minimum_required(VERSION 3.28)
project(P2P_Secure_File_Sharing)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)   # we don't use C++20 modules; skips a scanner step that Clang+Ninja needs extra tools for

option(P2P_BUILD_TESTS "Build the unit tests" ON)

# Find system OpenSSL and Boost packages
find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED COMPONENTS system)

add_executable(P2P_Secure_File_Sharing main.cpp
        protocol.hpp
        validation.hpp
        file_streaming.hpp
        client_node.hpp
        server_session.hpp
        server_node.hpp
        p2p_node.hpp
)

# Copy the certificates next to the executable, if they exist.
# (They are not in the repo on purpose: never commit a private key.)
foreach(cert_file server.crt server.key)
    if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${cert_file})
        file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/${cert_file} DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
    else()
        message(WARNING "${cert_file} not found in the project root. Generate it before running the program.")
    endif()
endforeach()

target_link_libraries(P2P_Secure_File_Sharing PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        Boost::system
)

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
