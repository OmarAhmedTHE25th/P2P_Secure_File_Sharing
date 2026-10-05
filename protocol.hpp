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