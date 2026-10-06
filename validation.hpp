#pragma once
// Pure input-validation logic: no sockets, no disk, no globals.
// Keeping it separate from ServerSession is what makes it unit-testable and fuzzable.

#include <array>
#include <cctype>
#include <cstdint>
#include <string>
#include <string_view>
#include <boost/endian/conversion.hpp>
#include "protocol.hpp"

namespace validation {

// 200 (not 255) so that "<name>.part" still fits in the 255-byte limit of most filesystems
inline constexpr uint16_t MAX_FILENAME_LEN = 200;
inline constexpr uint64_t MAX_FILE_SIZE    = 10ULL * 1024 * 1024 * 1024;   // 10 GB

// Judges a METADATA header that arrived from the network (so all numbers are big-endian).
// Returns READY if it is acceptable, otherwise the reason it was refused.
inline AckStatus check_metadata_header(const PacketHeader& header,
                                       uint64_t max_file_size = MAX_FILE_SIZE) {
    if (header.msg_type != static_cast<uint8_t>(MessageType::METADATA)) {
        return AckStatus::BAD_REQUEST;
    }
    const uint32_t payload_len  = boost::endian::big_to_native(header.payload_len);
    const uint16_t filename_len = boost::endian::big_to_native(header.filename_len);
    const uint64_t file_size    = boost::endian::big_to_native(header.total_file_size);

    if (filename_len == 0 || filename_len > MAX_FILENAME_LEN || payload_len != filename_len) {
        return AckStatus::BAD_REQUEST;
    }
    if (file_size > max_file_size) {
        return AckStatus::FILE_TOO_LARGE;
    }
    return AckStatus::READY;
}

// Accepts only a plain, safe filename. The rules are explicit (not "whatever the local OS
// thinks a filename is"), so a Linux receiver and a Windows receiver judge names the same way.
inline bool sanitize_file_name(const std::string& raw, std::string& clean_name) {
    if (raw.empty() || raw.size() > MAX_FILENAME_LEN) return false;

    // No control characters (this includes NUL) and none of the characters Windows forbids.
    // That also rules out every path separator and the ":" used for NTFS hidden streams.
    constexpr std::string_view forbidden = "<>:\"/\\|?*";
    for (unsigned char c : raw) {
        if (c < 0x20 || c == 0x7F) return false;
        if (forbidden.find(static_cast<char>(c)) != std::string_view::npos) return false;
    }

    // No hidden files (this also kills "." and ".."), and no trailing dot or space,
    // because Windows silently strips those and the name would change after we checked it.
    if (raw.front() == '.' || raw.back() == '.' || raw.back() == ' ') return false;

    // Windows reserved device names, with or without an extension ("con", "NUL.txt", ...)
    std::string stem = raw.substr(0, raw.find('.'));
    while (!stem.empty() && stem.back() == ' ') stem.pop_back();
    for (char& c : stem) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));

    static constexpr std::array<std::string_view, 22> reserved = {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    };
    for (std::string_view name : reserved) {
        if (stem == name) return false;
    }

    clean_name = raw;
    return true;
}

} // namespace validation
