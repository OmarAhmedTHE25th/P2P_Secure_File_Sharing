//
// Created by DELL on 06/10/2026.
//
#pragma once
#include "iostream"
#include "array"
#include "vector"
#include "memory"
#include "string"
#include "stdexcept"
#include "fstream"
#include "openssl/evp.h"
using std::vector;
using std::size_t;
using std::string;
using std::unique_ptr;
using std::array;
using std::ifstream;
using std::runtime_error;
using std::ios;

class FileStreamer {
public:
    static constexpr size_t CHUNK_SIZE = 64 * 1024;
    using EVP_MD_CTX_ptr = unique_ptr<EVP_MD_CTX,decltype(&EVP_MD_CTX_free)>;
    static array<uint8_t,32> compute_sha256(const string & file_path) {
      ifstream file(file_path,ios::binary);
        if (!file.is_open()) {
            throw runtime_error("File Streamer failed to open -> " + file_path);
        }
        EVP_MD_CTX_ptr md_ctx(EVP_MD_CTX_new(),&EVP_MD_CTX_free);
        if (!md_ctx) {
            throw runtime_error("FileStreamer: Failed to create OpenSSL EVP context");
        }
        if (EVP_DigestInit_ex(md_ctx.get(),EVP_sha256(),nullptr) != 1 ) {
            throw runtime_error("FleStreamer: Failed to initialize SHA256 Digest");
        }
        vector<char> BUFFER(CHUNK_SIZE);
        while (file.read(BUFFER.data(),!BUFFER.empty() || file.gcount() > 0)) {
            if (EVP_DigestUpdate(md_ctx.get(),BUFFER.data(),file.gcount()) != 1) {
                throw runtime_error("FileStreamer: Failed to update SHA256 digest block");
            }
        }
        array<uint8_t,32> raw_hashes{};
        unsigned int hash_len = 0;
        if (EVP_DigestFinal_ex(md_ctx.get(),raw_hashes.data(),&hash_len) != 1) {
            throw runtime_error("FileStreamer: Failed to finalize SHA256 Digest");
        }
    return  raw_hashes;

    }
    static uint64_t get_file_size(const string &file_path) {
        ifstream file(file_path,ios::binary | ios::ate);
        if (!file.is_open()) {
            throw runtime_error("FileStreamer: Unable to open file for size check");
        }
        return file.tellg();
    }
};
#ifndef P2P_SECURE_FILE_SHARING_FILE_STREAMING_HPP
#define P2P_SECURE_FILE_SHARING_FILE_STREAMING_HPP

#endif //P2P_SECURE_FILE_SHARING_FILE_STREAMING_HPP