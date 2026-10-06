#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <vector>
#include "validation.hpp"

namespace {

// Builds a header the way the sender does: every number in big-endian
PacketHeader make_header(MessageType type, uint32_t payload_len, uint64_t file_size, uint16_t filename_len) {
    PacketHeader header{};
    header.msg_type        = static_cast<uint8_t>(type);
    header.payload_len     = boost::endian::native_to_big(payload_len);
    header.total_file_size = boost::endian::native_to_big(file_size);
    header.filename_len    = boost::endian::native_to_big(filename_len);
    return header;
}

PacketHeader good_header() { return make_header(MessageType::METADATA, 9, 1234, 9); }

bool accepted(const std::string& name) {
    std::string clean;
    return validation::sanitize_file_name(name, clean);
}

} // namespace

// ---------------- header checks ----------------

TEST(HeaderCheck, NormalHeaderIsAccepted) {
    EXPECT_EQ(validation::check_metadata_header(good_header()), AckStatus::READY);
}

TEST(HeaderCheck, EmptyFileIsAccepted) {
    EXPECT_EQ(validation::check_metadata_header(make_header(MessageType::METADATA, 5, 0, 5)), AckStatus::READY);
}

TEST(HeaderCheck, WrongMessageTypeIsRefused) {
    for (MessageType type : {MessageType::CHUNK, MessageType::END_OF_FILE, MessageType::ACK}) {
        EXPECT_EQ(validation::check_metadata_header(make_header(type, 9, 1234, 9)), AckStatus::BAD_REQUEST);
    }
    PacketHeader header = good_header();
    header.msg_type = 0xFF;
    EXPECT_EQ(validation::check_metadata_header(header), AckStatus::BAD_REQUEST);
}

TEST(HeaderCheck, ZeroLengthFilenameIsRefused) {
    EXPECT_EQ(validation::check_metadata_header(make_header(MessageType::METADATA, 0, 10, 0)), AckStatus::BAD_REQUEST);
}

TEST(HeaderCheck, FilenameLengthLimitIsExact) {
    const uint16_t max = validation::MAX_FILENAME_LEN;
    EXPECT_EQ(validation::check_metadata_header(make_header(MessageType::METADATA, max, 10, max)), AckStatus::READY);
    EXPECT_EQ(validation::check_metadata_header(make_header(MessageType::METADATA, max + 1, 10, max + 1)), AckStatus::BAD_REQUEST);
}

TEST(HeaderCheck, PayloadLengthMustMatchFilenameLength) {
    EXPECT_EQ(validation::check_metadata_header(make_header(MessageType::METADATA, 100, 10, 9)), AckStatus::BAD_REQUEST);
    EXPECT_EQ(validation::check_metadata_header(make_header(MessageType::METADATA, 9, 10, 100)), AckStatus::BAD_REQUEST);
    EXPECT_EQ(validation::check_metadata_header(make_header(MessageType::METADATA, 0xFFFFFFFF, 10, 9)), AckStatus::BAD_REQUEST);
}

TEST(HeaderCheck, FileSizeLimitIsExact) {
    EXPECT_EQ(validation::check_metadata_header(good_header(), 1000), AckStatus::FILE_TOO_LARGE);   // 1234 > 1000
    EXPECT_EQ(validation::check_metadata_header(make_header(MessageType::METADATA, 9, 1000, 9), 1000), AckStatus::READY);
    EXPECT_EQ(validation::check_metadata_header(make_header(MessageType::METADATA, 9, 1001, 9), 1000), AckStatus::FILE_TOO_LARGE);
}

TEST(HeaderCheck, AbsurdFileSizeClaimIsRefused) {
    EXPECT_EQ(validation::check_metadata_header(make_header(MessageType::METADATA, 9, UINT64_MAX, 9)), AckStatus::FILE_TOO_LARGE);
}

// ---------------- filename sanitizing ----------------

TEST(Sanitize, OrdinaryNamesAreAccepted) {
    for (const char* name : {"photo.jpg", "my file.txt", "report-v2_final.pdf", "archive.tar.gz",
                             "noextension", "CONSOLE.txt", "COM10.txt", "a"}) {
        EXPECT_TRUE(accepted(name)) << name;
    }
}

TEST(Sanitize, NonAsciiNamesAreAccepted) {
    EXPECT_TRUE(accepted("\xD9\x85\xD9\x84\xD9\x81.txt"));   // Arabic "ملف.txt" as UTF-8 bytes
}

TEST(Sanitize, AcceptedNameIsReturnedUnchanged) {
    std::string clean;
    ASSERT_TRUE(validation::sanitize_file_name("my file.txt", clean));
    EXPECT_EQ(clean, "my file.txt");
}

TEST(Sanitize, EmptyAndDotNamesAreRefused) {
    for (const char* name : {"", ".", "..", "...", ".hidden"}) {
        EXPECT_FALSE(accepted(name)) << "[" << name << "]";
    }
}

TEST(Sanitize, PathTraversalIsRefusedOnEveryOS) {
    for (const char* name : {"../secret.txt", "..\\secret.txt", "/etc/passwd", "C:\\Windows\\x.dll",
                             "dir/file.txt", "dir\\file.txt", "./file.txt", "a/../b"}) {
        EXPECT_FALSE(accepted(name)) << name;
    }
}

TEST(Sanitize, NtfsHiddenStreamsAreRefused) {
    EXPECT_FALSE(accepted("file.txt:secret"));
    EXPECT_FALSE(accepted("file.txt:secret:$DATA"));
}

TEST(Sanitize, WindowsReservedNamesAreRefusedInAnyCase) {
    for (const char* name : {"CON", "con", "Con.txt", "NUL.tar.gz", "prn", "AUX.log", "COM1", "com9.txt",
                             "LPT1", "lpt9.txt", "CON .txt"}) {
        EXPECT_FALSE(accepted(name)) << name;
    }
}

TEST(Sanitize, ControlCharactersAreRefused) {
    EXPECT_FALSE(accepted(std::string("a\0b", 3)));    // embedded NUL
    EXPECT_FALSE(accepted("a\tb"));
    EXPECT_FALSE(accepted("a\nb"));
    EXPECT_FALSE(accepted("a\x1b[31mb"));              // terminal escape sequence
    EXPECT_FALSE(accepted("a\x7f""b"));                // DEL
}

TEST(Sanitize, CharactersWindowsForbidsAreRefused) {
    for (const char* name : {"a<b", "a>b", "a\"b", "a|b", "a?b", "a*b"}) {
        EXPECT_FALSE(accepted(name)) << name;
    }
}

TEST(Sanitize, TrailingDotOrSpaceIsRefused) {
    EXPECT_FALSE(accepted("file."));
    EXPECT_FALSE(accepted("file.txt."));
    EXPECT_FALSE(accepted("file.txt "));
}

TEST(Sanitize, LengthLimitIsExact) {
    EXPECT_TRUE(accepted(std::string(validation::MAX_FILENAME_LEN, 'a')));
    EXPECT_FALSE(accepted(std::string(validation::MAX_FILENAME_LEN + 1, 'a')));
}

TEST(Sanitize, RefusedNameLeavesOutputUntouched) {
    std::string clean = "previous";
    EXPECT_FALSE(validation::sanitize_file_name("../x", clean));
    EXPECT_EQ(clean, "previous");
}
