#pragma once
// The list of peers we trust, identified by the SHA-256 fingerprint of their certificate
// (the same idea as SSH's known_hosts). Plain text, one peer per line:
//
//     # comments and blank lines are ignored
//     3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b  alice
//
// No sockets and no OpenSSL in here, so it is easy to unit test.

#include <cctype>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace trust {

struct Entry {
    std::string fingerprint;   // always 64 lowercase hex characters
    std::string name;
};

// Accepts "AB:CD:..." or "abcd..." in any case (colons and spaces are ignored).
// Returns 64 lowercase hex characters, or nothing if the text is not a SHA-256 fingerprint.
inline std::optional<std::string> normalize_fingerprint(std::string_view text) {
    std::string out;
    for (char c : text) {
        const unsigned char uc = static_cast<unsigned char>(c);
        if (c == ':' || c == ' ') continue;
        if (!std::isxdigit(uc)) return std::nullopt;
        out.push_back(static_cast<char>(std::tolower(uc)));
    }
    if (out.size() != 64) return std::nullopt;
    return out;
}

// "3a7b..." -> "3A:7B:..."  (how fingerprints are shown to people)
inline std::string display_fingerprint(const std::string& normalized) {
    std::string out;
    for (std::size_t i = 0; i < normalized.size(); ++i) {
        if (i > 0 && i % 2 == 0) out.push_back(':');
        out.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(normalized[i]))));
    }
    return out;
}

// Names are shown in logs and stored in a text file, so keep them boring
inline bool valid_name(std::string_view name) {
    if (name.empty() || name.size() > 64) return false;
    for (char c : name) {
        const unsigned char uc = static_cast<unsigned char>(c);
        if (!(std::isalnum(uc) || c == '.' || c == '_' || c == '-')) return false;
    }
    return true;
}

namespace detail {
inline std::string trim(std::string_view s) {
    std::size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return std::string(s.substr(b, e - b));
}
} // namespace detail

// Reads the file's text. A line that is not understood grants NO trust; it is skipped, and
// described in `warnings` (when given) so a person can fix it.
inline std::vector<Entry> parse(std::string_view text, std::vector<std::string>* warnings = nullptr) {
    std::vector<Entry> entries;
    std::istringstream in{std::string(text)};
    std::string raw;
    int line_number = 0;
    auto warn = [&](const std::string& message) {
        if (warnings) warnings->push_back("line " + std::to_string(line_number) + ": " + message);
    };
    while (std::getline(in, raw)) {
        ++line_number;
        const std::string line = detail::trim(raw);     // also removes a Windows "\r"
        if (line.empty() || line[0] == '#') continue;

        const std::size_t split = line.find_first_of(" \t");
        if (split == std::string::npos) { warn("expected '<fingerprint> <name>'"); continue; }
        const auto fingerprint = normalize_fingerprint(line.substr(0, split));
        const std::string name = detail::trim(line.substr(split));
        if (!fingerprint) { warn("not a valid SHA-256 fingerprint"); continue; }
        if (!valid_name(name)) { warn("invalid name (use letters, digits, '.', '_' or '-')"); continue; }

        bool duplicate = false;
        for (const Entry& existing : entries) {
            if (existing.fingerprint == *fingerprint) duplicate = true;
        }
        if (duplicate) { warn("this fingerprint is already listed above, ignoring"); continue; }
        entries.push_back({*fingerprint, name});
    }
    return entries;
}

inline std::string serialize(const std::vector<Entry>& entries) {
    std::string out = "# Peers I trust: <SHA-256 fingerprint> <name>\n";
    for (const Entry& e : entries) out += e.fingerprint + "  " + e.name + "\n";
    return out;
}

// The trust list stored in a file. The file is re-read every time it is asked something,
// so adding or removing a peer takes effect immediately, even in a running receiver.
class TrustStore {
public:
    explicit TrustStore(std::filesystem::path file) : file_(std::move(file)) {}

    const std::filesystem::path& path() const { return file_; }

    std::vector<Entry> list(std::vector<std::string>* warnings = nullptr) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return read_unlocked(warnings);
    }

    // The name this fingerprint is trusted under, or nothing if it is not trusted
    std::optional<std::string> find_name(const std::string& normalized_fingerprint) const {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const Entry& e : read_unlocked(nullptr)) {
            if (e.fingerprint == normalized_fingerprint) return e.name;
        }
        return std::nullopt;
    }

    bool is_trusted(const std::string& normalized_fingerprint) const {
        return find_name(normalized_fingerprint).has_value();
    }

    // Each of these returns an error message, or an empty string on success
    std::string add(std::string_view fingerprint_text, std::string_view name) {
        const auto fingerprint = normalize_fingerprint(fingerprint_text);
        if (!fingerprint) return "that is not a SHA-256 fingerprint (expected 64 hex digits)";
        if (!valid_name(name)) return "invalid name (1 to 64 characters: letters, digits, '.', '_' or '-')";

        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<Entry> entries = read_unlocked(nullptr);
        for (const Entry& e : entries) {
            if (e.fingerprint == *fingerprint) return "that fingerprint is already trusted, as '" + e.name + "'";
            if (e.name == name) return "the name '" + e.name + "' is already used by another peer";
        }
        entries.push_back({*fingerprint, std::string(name)});
        return write_unlocked(entries);
    }

    // `who` is a peer's name or its fingerprint
    std::string remove(std::string_view who) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<Entry> entries = read_unlocked(nullptr);
        const auto fingerprint = normalize_fingerprint(who);
        for (auto it = entries.begin(); it != entries.end(); ++it) {
            if (it->name == who || (fingerprint && it->fingerprint == *fingerprint)) {
                entries.erase(it);
                return write_unlocked(entries);
            }
        }
        return "no trusted peer matches '" + std::string(who) + "'";
    }

private:
    std::vector<Entry> read_unlocked(std::vector<std::string>* warnings) const {
        std::ifstream in(file_, std::ios::binary);
        if (!in) return {};                       // no file yet = nobody is trusted
        std::ostringstream text;
        text << in.rdbuf();
        return parse(text.str(), warnings);
    }

    // Write to a temporary file, then swap it in, so a crash can never leave half a list behind
    std::string write_unlocked(const std::vector<Entry>& entries) const {
        std::filesystem::path temp = file_;
        temp += ".tmp";
        {
            std::ofstream out(temp, std::ios::binary | std::ios::trunc);
            if (!out) return "cannot write " + temp.string();
            out << serialize(entries);
            out.flush();
            if (!out) return "cannot write " + temp.string();
        }
        std::error_code ec;
        std::filesystem::rename(temp, file_, ec);
        if (ec) return "cannot update " + file_.string() + ": " + ec.message();
        return "";
    }

    std::filesystem::path file_;
    mutable std::mutex mutex_;
};

} // namespace trust
