cmake_minimum_required(VERSION 3.28)
project(P2P_Secure_File_Sharing)

set(CMAKE_CXX_STANDARD 20)

# Find system OpenSSL and Boost packages
find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED COMPONENTS system)

add_executable(P2P_Secure_File_Sharing main.cpp
        protocol.hpp
        file_streaming.hpp
        client_node.hpp
        server_session.hpp
        server_node.hpp
        server_node.hpp
)
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/server.crt DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/server.key DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
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
endif()
