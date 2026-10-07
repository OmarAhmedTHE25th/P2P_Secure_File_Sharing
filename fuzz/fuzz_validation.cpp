// libFuzzer harness for the pure validation logic (validation.hpp).
//
// libFuzzer calls LLVMFuzzerTestOneInput over and over with mutated byte strings, steering
// toward inputs that reach new code. We split each input in two:
//   - the first sizeof(PacketHeader) bytes are treated as a header that "arrived from the network"
//   - the rest is treated as a filename that "arrived from the network"
// and then check properties that must hold for EVERY input. If one is violated, we crash on
// purpose so the fuzzer saves the offending input.
//
// Build: cmake -DP2P_BUILD_FUZZERS=ON with Clang.  Run: see the README.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <string>
#include <string_view>
#include <boost/endian/conversion.hpp>
#include "protocol.hpp"
#include "validation.hpp"

namespace {

[[noreturn]] void property_violated(const char* what) {
    std::fputs("PROPERTY VIOLATED: ", stderr);
    std::fputs(what, stderr);
    std::fputc('\n', stderr);
    __builtin_trap();
}

#define CHECK(cond) do { if (!(cond)) property_violated(#cond); } while (0)

void fuzz_header(const uint8_t* data, size_t size) {
    PacketHeader header{};
    std::memcpy(&header, data, std::min(size, sizeof(header)));   // short input = zero padded

    const AckStatus verdict = validation::check_metadata_header(header);

    // The verdict is always one of the three this function is allowed to return
    CHECK(verdict == AckStatus::READY || verdict == AckStatus::BAD_REQUEST ||
          verdict == AckStatus::FILE_TOO_LARGE);

    if (verdict == AckStatus::READY) {
        // Everything the rest of the server relies on after a READY must really be true
        const uint32_t payload_len  = boost::endian::big_to_native(header.payload_len);
        const uint16_t filename_len = boost::endian::big_to_native(header.filename_len);
        const uint64_t file_size    = boost::endian::big_to_native(header.total_file_size);
        CHECK(header.msg_type == static_cast<uint8_t>(MessageType::METADATA));
        CHECK(filename_len >= 1);
        CHECK(filename_len <= validation::MAX_FILENAME_LEN);
        CHECK(payload_len == filename_len);
        CHECK(file_size <= validation::MAX_FILE_SIZE);
    }
}

bool is_reserved_windows_name(std::string stem) {
    while (!stem.empty() && stem.back() == ' ') stem.pop_back();
    for (char& c : stem) {
        if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
    }
    if (stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL") return true;
    return stem.size() == 4 && (stem.compare(0, 3, "COM") == 0 || stem.compare(0, 3, "LPT") == 0) &&
           stem[3] >= '1' && stem[3] <= '9';
}

void fuzz_filename(const uint8_t* data, size_t size) {
    const std::string raw(reinterpret_cast<const char*>(data), size);
    std::string clean = "untouched";

    const bool accepted = validation::sanitize_file_name(raw, clean);

    if (!accepted) {
        CHECK(clean == "untouched");     // a refused name must not leak into the output
        return;
    }

    // Whatever we accept must be safe to use as a file name, on any OS
    CHECK(clean == raw);
    CHECK(!clean.empty());
    CHECK(clean.size() <= validation::MAX_FILENAME_LEN);
    CHECK(clean.front() != '.');
    CHECK(clean.back() != '.' && clean.back() != ' ');

    for (unsigned char c : clean) {
        CHECK(c >= 0x20 && c != 0x7F);                       // no control characters, no NUL
        CHECK(std::string_view("<>:\"/\\|?*").find(static_cast<char>(c)) == std::string_view::npos);
    }

    CHECK(!is_reserved_windows_name(clean.substr(0, clean.find('.'))));

    // And the local filesystem agrees it is a plain name: no folders, not absolute
    const std::filesystem::path path(clean);
    CHECK(path.filename().string() == clean);
    CHECK(!path.has_parent_path());
    CHECK(path.is_relative());
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    fuzz_header(data, size);
    fuzz_filename(data, size);
    if (size > sizeof(PacketHeader)) {          // also try "header, then filename" as the wire does
        fuzz_filename(data + sizeof(PacketHeader), size - sizeof(PacketHeader));
    }
    return 0;
}
