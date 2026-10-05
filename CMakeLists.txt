cmake_minimum_required(VERSION 3.28)
project(P2P_Secure_File_Sharing)

set(CMAKE_CXX_STANDARD 20)

# Find system OpenSSL and Boost packages
find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED COMPONENTS system)

add_executable(P2P_Secure_File_Sharing main.cpp)

target_link_libraries(P2P_Secure_File_Sharing PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        Boost::system
)