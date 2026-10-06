#include <gtest/gtest.h>
#include <cstddef>
#include "protocol.hpp"

TEST(Protocol, HeaderIsExactly47Bytes) {
    EXPECT_EQ(sizeof(PacketHeader), 47u);
}

TEST(Protocol, FieldsSitAtTheDocumentedOffsets) {
    EXPECT_EQ(offsetof(PacketHeader, msg_type), 0u);
    EXPECT_EQ(offsetof(PacketHeader, payload_len), 1u);
    EXPECT_EQ(offsetof(PacketHeader, total_file_size), 5u);
    EXPECT_EQ(offsetof(PacketHeader, filename_len), 13u);
    EXPECT_EQ(offsetof(PacketHeader, file_hash), 15u);
}

TEST(Protocol, EveryAckStatusHasADescription) {
    const AckStatus all[] = {
        AckStatus::OK, AckStatus::HASH_MISMATCH, AckStatus::SERVER_ERROR,
        AckStatus::READY, AckStatus::BAD_REQUEST, AckStatus::FILE_TOO_LARGE,
        AckStatus::UNSAFE_FILENAME, AckStatus::ALREADY_EXISTS, AckStatus::NO_SPACE
    };
    for (AckStatus status : all) {
        EXPECT_STRNE(describe(status), "unknown reason")
            << "status " << static_cast<int>(status) << " has no description";
    }
}

TEST(Protocol, UnknownStatusFromTheNetworkIsHandledSafely) {
    EXPECT_STREQ(describe(static_cast<AckStatus>(200)), "unknown reason");
}
