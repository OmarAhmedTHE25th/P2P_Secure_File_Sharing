#pragma once

#include <cstdint>
#include <type_traits>

// Message types defining what kind of packet is being sent
enum class MessageType : uint8_t {
    METADATA    = 0x01,  // File name, total size, and full-file SHA-256 hash
    CHUNK       = 0x02,  // A slice of the file binary data
    END_OF_FILE = 0x03,  // Signals transfer complete
    ACK         = 0x04   // Confirmation back to sender
};
// Result codes the receiver sends back inside an ACK

enum class AckStatus : uint8_t {
    OK              = 0,  // final verdict: file verified and saved
    HASH_MISMATCH   = 1,
    SERVER_ERROR    = 2,
    READY           = 3,  // green light: metadata accepted, send the bytes
    BAD_REQUEST     = 4,
    FILE_TOO_LARGE  = 5,
    UNSAFE_FILENAME = 6,
    ALREADY_EXISTS  = 7,
    NO_SPACE        = 8
};

inline const char* describe(AckStatus status) {
    switch (status) {
        case AckStatus::OK:              return "file verified and saved";
        case AckStatus::HASH_MISMATCH:   return "hash did not match, file discarded";
        case AckStatus::SERVER_ERROR:    return "receiver-side error";
        case AckStatus::READY:           return "ready to receive";
        case AckStatus::BAD_REQUEST:     return "malformed request";
        case AckStatus::FILE_TOO_LARGE:  return "file is larger than the receiver allows";
        case AckStatus::UNSAFE_FILENAME: return "filename not allowed";
        case AckStatus::ALREADY_EXISTS:  return "a file with that name already exists";
        case AckStatus::NO_SPACE:        return "not enough disk space on the receiver";
    }
    return "unknown reason";
}
#pragma pack(push, 1)
struct PacketHeader {
    uint8_t  msg_type;         // 1 byte  (MessageType enum)
    uint32_t payload_len;      // 4 bytes (Size of incoming payload following this header)
    uint64_t total_file_size;  // 8 bytes (Total size of file being transferred)
    uint16_t filename_len;     // 2 bytes (Length of filename string)
    uint8_t  file_hash[32];    // 32 bytes (Raw 256-bit SHA-256 hash digest)
};
#pragma pack(pop)

// Enforce layout size at compile-time to guarantee cross-platform alignment
static_assert(sizeof(PacketHeader) == 47, "PacketHeader must be exactly 47 bytes!");