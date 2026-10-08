#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include "trust_store.hpp"

namespace {

const std::string FP_A = "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b";
const std::string FP_B = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb";

class TempDir {
public:
    TempDir() {
        std::random_device rd;
        path_ = std::filesystem::temp_directory_path() / ("p2p_trust_" + std::to_string(rd()) + std::to_string(rd()));
        std::filesystem::create_directories(path_);
    }
    ~TempDir() { std::error_code ec; std::filesystem::remove_all(path_, ec); }
    std::filesystem::path file(const std::string& name) const { return path_ / name; }
private:
    std::filesystem::path path_;
};

void write_file(const std::filesystem::path& path, const std::string& text) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << text;
}

std::string read_file(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

} // namespace

// ---------------- fingerprints ----------------

TEST(Fingerprint, PlainLowercaseIsAccepted) {
    EXPECT_EQ(trust::normalize_fingerprint(FP_A), FP_A);
}

TEST(Fingerprint, ColonSeparatedUppercaseIsNormalized) {
    const std::string shown = trust::display_fingerprint(FP_A);
    EXPECT_EQ(shown.size(), 95u);                       // 32 pairs and 31 colons
    EXPECT_EQ(shown.substr(0, 8), "3A:7B:D3");
    EXPECT_EQ(trust::normalize_fingerprint(shown), FP_A);
}

TEST(Fingerprint, SpacesAndMixedCaseAreAccepted) {
    EXPECT_EQ(trust::normalize_fingerprint(" 3A7bD3e2360a3d29eea436fcfb7e44c7 35d117c42d1c1835420b6b9942dd4f1B "), FP_A);
}

TEST(Fingerprint, WrongLengthIsRefused) {
    EXPECT_FALSE(trust::normalize_fingerprint(""));
    EXPECT_FALSE(trust::normalize_fingerprint(FP_A.substr(0, 63)));
    EXPECT_FALSE(trust::normalize_fingerprint(FP_A + "0"));
    EXPECT_FALSE(trust::normalize_fingerprint(FP_A.substr(0, 32)));       // a prefix is not a fingerprint
}

TEST(Fingerprint, NonHexIsRefused) {
    EXPECT_FALSE(trust::normalize_fingerprint(FP_A.substr(0, 63) + "g"));
    EXPECT_FALSE(trust::normalize_fingerprint(FP_A.substr(0, 63) + "-"));
    EXPECT_FALSE(trust::normalize_fingerprint(std::string(64, 'z')));
}

TEST(Names, OnlyBoringNamesAreValid) {
    for (const char* ok : {"alice", "Bob-2", "my.laptop", "a_b", "x"}) EXPECT_TRUE(trust::valid_name(ok)) << ok;
    for (const char* bad : {"", "has space", "semi;colon", "new\nline", "../x", "a/b", "tab\t", "#hash"}) {
        EXPECT_FALSE(trust::valid_name(bad)) << bad;
    }
    EXPECT_TRUE(trust::valid_name(std::string(64, 'a')));
    EXPECT_FALSE(trust::valid_name(std::string(65, 'a')));
}

// ---------------- file format ----------------

TEST(TrustFile, ParsesEntriesAndSkipsCommentsAndBlankLines) {
    const std::string text = "# my friends\n\n" + FP_A + "  alice\n   \n# another\n" + FP_B + "\tbob\n";
    const auto entries = trust::parse(text);
    ASSERT_EQ(entries.size(), 2u);
    EXPECT_EQ(entries[0].fingerprint, FP_A);
    EXPECT_EQ(entries[0].name, "alice");
    EXPECT_EQ(entries[1].fingerprint, FP_B);
    EXPECT_EQ(entries[1].name, "bob");
}

TEST(TrustFile, WindowsLineEndingsAreFine) {
    const auto entries = trust::parse(FP_A + " alice\r\n" + FP_B + " bob\r\n");
    ASSERT_EQ(entries.size(), 2u);
    EXPECT_EQ(entries[0].name, "alice");
    EXPECT_EQ(entries[1].name, "bob");
}

TEST(TrustFile, FingerprintsInColonFormAreAcceptedToo) {
    const auto entries = trust::parse(trust::display_fingerprint(FP_A) + " alice\n");
    ASSERT_EQ(entries.size(), 1u);
    EXPECT_EQ(entries[0].fingerprint, FP_A);
}

TEST(TrustFile, BrokenLinesGrantNoTrustAndAreReported) {
    std::vector<std::string> warnings;
    const std::string text =
        FP_A.substr(0, 40) + " short\n"        // fingerprint too short
        + FP_A + "\n"                          // no name
        + FP_B + " bad name\n"                 // name has a space
        + "justwords here\n";                  // not a fingerprint at all
    const auto entries = trust::parse(text, &warnings);
    EXPECT_TRUE(entries.empty());
    EXPECT_EQ(warnings.size(), 4u);
    EXPECT_NE(warnings[0].find("line 1"), std::string::npos);
}

TEST(TrustFile, DuplicateFingerprintKeepsTheFirstOne) {
    std::vector<std::string> warnings;
    const auto entries = trust::parse(FP_A + " first\n" + FP_A + " second\n", &warnings);
    ASSERT_EQ(entries.size(), 1u);
    EXPECT_EQ(entries[0].name, "first");
    EXPECT_EQ(warnings.size(), 1u);
}

TEST(TrustFile, SerializeThenParseGivesTheSameEntries) {
    const std::vector<trust::Entry> original = {{FP_A, "alice"}, {FP_B, "bob"}};
    const auto back = trust::parse(trust::serialize(original));
    ASSERT_EQ(back.size(), 2u);
    EXPECT_EQ(back[0].fingerprint, FP_A);
    EXPECT_EQ(back[1].name, "bob");
}

// ---------------- the store ----------------

TEST(TrustStore, MissingFileMeansNobodyIsTrusted) {
    TempDir dir;
    trust::TrustStore store(dir.file("trusted_peers.txt"));
    EXPECT_TRUE(store.list().empty());
    EXPECT_FALSE(store.is_trusted(FP_A));
}

TEST(TrustStore, AddedPeerIsTrustedUnderItsName) {
    TempDir dir;
    trust::TrustStore store(dir.file("trusted_peers.txt"));
    EXPECT_EQ(store.add(trust::display_fingerprint(FP_A), "alice"), "");
    EXPECT_TRUE(store.is_trusted(FP_A));
    EXPECT_EQ(store.find_name(FP_A), "alice");
    EXPECT_FALSE(store.is_trusted(FP_B));
}

TEST(TrustStore, TrustMatchesTheWholeFingerprintOnly) {
    TempDir dir;
    trust::TrustStore store(dir.file("trusted_peers.txt"));
    ASSERT_EQ(store.add(FP_A, "alice"), "");
    std::string almost = FP_A;
    almost[63] = (almost[63] == '0') ? '1' : '0';       // differs in the very last digit
    EXPECT_FALSE(store.is_trusted(almost));
    EXPECT_FALSE(store.is_trusted(FP_A.substr(0, 32)));
    EXPECT_FALSE(store.is_trusted(""));
}

TEST(TrustStore, StoredLowercaseNoMatterHowItWasTyped) {
    TempDir dir;
    trust::TrustStore store(dir.file("trusted_peers.txt"));
    ASSERT_EQ(store.add(trust::display_fingerprint(FP_A), "alice"), "");
    EXPECT_NE(read_file(dir.file("trusted_peers.txt")).find(FP_A), std::string::npos);
}

TEST(TrustStore, RejectsBadInputWithoutChangingTheFile) {
    TempDir dir;
    trust::TrustStore store(dir.file("trusted_peers.txt"));
    EXPECT_NE(store.add("not-a-fingerprint", "alice"), "");
    EXPECT_NE(store.add(FP_A, "bad name"), "");
    EXPECT_NE(store.add(FP_A, ""), "");
    EXPECT_TRUE(store.list().empty());
}

TEST(TrustStore, RefusesDuplicates) {
    TempDir dir;
    trust::TrustStore store(dir.file("trusted_peers.txt"));
    ASSERT_EQ(store.add(FP_A, "alice"), "");
    EXPECT_NE(store.add(FP_A, "someone-else").find("already trusted"), std::string::npos);
    EXPECT_NE(store.add(FP_B, "alice").find("already used"), std::string::npos);
    EXPECT_EQ(store.list().size(), 1u);
}

TEST(TrustStore, RemoveByNameAndByFingerprint) {
    TempDir dir;
    trust::TrustStore store(dir.file("trusted_peers.txt"));
    ASSERT_EQ(store.add(FP_A, "alice"), "");
    ASSERT_EQ(store.add(FP_B, "bob"), "");
    EXPECT_EQ(store.remove("alice"), "");
    EXPECT_FALSE(store.is_trusted(FP_A));
    EXPECT_TRUE(store.is_trusted(FP_B));                // removing one peer leaves the others alone
    EXPECT_EQ(store.remove(trust::display_fingerprint(FP_B)), "");
    EXPECT_TRUE(store.list().empty());
}

TEST(TrustStore, RemoveUnknownPeerIsAnError) {
    TempDir dir;
    trust::TrustStore store(dir.file("trusted_peers.txt"));
    ASSERT_EQ(store.add(FP_A, "alice"), "");
    EXPECT_NE(store.remove("nobody"), "");
    EXPECT_NE(store.remove(FP_B), "");
    EXPECT_EQ(store.list().size(), 1u);
}

TEST(TrustStore, EditsToTheFileTakeEffectImmediately) {
    TempDir dir;
    const auto file = dir.file("trusted_peers.txt");
    trust::TrustStore store(file);
    EXPECT_FALSE(store.is_trusted(FP_A));
    write_file(file, FP_A + " alice\n");                 // someone edits the file by hand
    EXPECT_TRUE(store.is_trusted(FP_A));
    write_file(file, "# emptied\n");
    EXPECT_FALSE(store.is_trusted(FP_A));                 // revoked without restarting anything
}

TEST(TrustStore, NoTemporaryFileIsLeftBehind) {
    TempDir dir;
    trust::TrustStore store(dir.file("trusted_peers.txt"));
    ASSERT_EQ(store.add(FP_A, "alice"), "");
    EXPECT_FALSE(std::filesystem::exists(dir.file("trusted_peers.txt.tmp")));
}

TEST(TrustStore, GarbageFileTrustsNobody) {
    TempDir dir;
    const auto file = dir.file("trusted_peers.txt");
    std::string junk;
    junk += '\0';
    junk += "\xff\xfe binary junk ";
    junk += '\0';
    write_file(file, junk + "\n\n####\n");
    trust::TrustStore store(file);
    EXPECT_TRUE(store.list().empty());
    EXPECT_FALSE(store.is_trusted(FP_A));
}
