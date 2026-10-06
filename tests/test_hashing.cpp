#include <gtest/gtest.h>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include "file_streaming.hpp"

namespace {

// A file that deletes itself when the test ends
class TempFile {
public:
    explicit TempFile(const std::string& content) {
        static int counter = 0;
        path_ = (std::filesystem::temp_directory_path() /
                 ("p2p_test_" + std::to_string(counter++) + ".bin")).string();
        std::ofstream file(path_, std::ios::binary);
        file.write(content.data(), static_cast<std::streamsize>(content.size()));
    }
    ~TempFile() { std::error_code ec; std::filesystem::remove(path_, ec); }
    const std::string& path() const { return path_; }
private:
    std::string path_;
};

std::string hex(const std::array<uint8_t, 32>& digest) {
    std::string out;
    char buf[3];
    for (uint8_t byte : digest) {
        std::snprintf(buf, sizeof(buf), "%02x", byte);
        out += buf;
    }
    return out;
}

std::string sha256_of(const std::string& content) {
    TempFile file(content);
    return hex(FileStreamer::compute_sha256(file.path()));
}

} // namespace

TEST(Hashing, EmptyFile) {
    EXPECT_EQ(sha256_of(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(Hashing, ShortKnownString) {
    EXPECT_EQ(sha256_of("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST(Hashing, OneByte) {
    EXPECT_EQ(sha256_of("a"), "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb");
}

// The next four sit right on the 64 KB chunk boundary. They guard the "last partial chunk
// got skipped" bug we fixed: a naive loop gets all of these wrong.
TEST(Hashing, OneByteBelowChunkSize) {
    ASSERT_EQ(FileStreamer::CHUNK_SIZE, 65536u);
    EXPECT_EQ(sha256_of(std::string(65535, 'a')), "6e1bebca6a8229364a162a72ef064826c4cd7457bf54f190ef782bd9deff3e42");
}

TEST(Hashing, ExactlyOneChunk) {
    EXPECT_EQ(sha256_of(std::string(65536, 'a')), "bf718b6f653bebc184e1479f1935b8da974d701b893afcf49e701f3e2f9f9c5a");
}

TEST(Hashing, OneByteOverChunkSize) {
    EXPECT_EQ(sha256_of(std::string(65537, 'a')), "008ffc88d3c96a9f307524eb361e47c5222a887fc45fa0c1fb8d429c5c23b430");
}

TEST(Hashing, ExactlyTwoChunks) {
    EXPECT_EQ(sha256_of(std::string(131072, 'a')), "b44ffb72fcc259676bd80495fef1b44b808ca8f1ffe1b1706a4d7911b0e31f11");
}

TEST(Hashing, SeveralChunksWithAPartialTail) {
    EXPECT_EQ(sha256_of(std::string(200000, 'a')), "2287d207f24a941ff3b56c04c8a25ad56b63e3023207b3bb5b4ac0c9869d74be");
}

TEST(Hashing, MissingFileThrows) {
    EXPECT_THROW(FileStreamer::compute_sha256("this_file_does_not_exist.bin"), std::runtime_error);
}

TEST(FileSize, MatchesContent) {
    EXPECT_EQ(FileStreamer::get_file_size(TempFile("").path()), 0u);
    EXPECT_EQ(FileStreamer::get_file_size(TempFile("hello").path()), 5u);
    EXPECT_EQ(FileStreamer::get_file_size(TempFile(std::string(100000, 'x')).path()), 100000u);
}

TEST(FileSize, MissingFileThrows) {
    EXPECT_THROW(FileStreamer::get_file_size("this_file_does_not_exist.bin"), std::runtime_error);
}
