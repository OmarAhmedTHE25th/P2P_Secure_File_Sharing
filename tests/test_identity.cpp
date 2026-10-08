#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include "identity.hpp"
#include "trust_store.hpp"

namespace {

class TempDir {
public:
    TempDir() {
        std::random_device rd;
        path_ = std::filesystem::temp_directory_path() / ("p2p_ident_" + std::to_string(rd()) + std::to_string(rd()));
        std::filesystem::create_directories(path_);
    }
    ~TempDir() { std::error_code ec; std::filesystem::remove_all(path_, ec); }
    std::filesystem::path file(const std::string& name) const { return path_ / name; }
private:
    std::filesystem::path path_;
};

using CertPtr = std::unique_ptr<X509, decltype(&X509_free)>;
using KeyPtr  = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

CertPtr load_cert(const std::filesystem::path& path) {
    FILE* f = std::fopen(path.string().c_str(), "rb");
    CertPtr cert(f ? PEM_read_X509(f, nullptr, nullptr, nullptr) : nullptr, &X509_free);
    if (f) std::fclose(f);
    return cert;
}

KeyPtr load_key(const std::filesystem::path& path) {
    FILE* f = std::fopen(path.string().c_str(), "rb");
    KeyPtr key(f ? PEM_read_PrivateKey(f, nullptr, nullptr, nullptr) : nullptr, &EVP_PKEY_free);
    if (f) std::fclose(f);
    return key;
}

} // namespace

TEST(Identity, GeneratesKeyAndCertificateFiles) {
    TempDir dir;
    identity::generate(dir.file("id.crt"), dir.file("id.key"), "alice");
    EXPECT_TRUE(std::filesystem::exists(dir.file("id.crt")));
    EXPECT_TRUE(std::filesystem::exists(dir.file("id.key")));
}

TEST(Identity, CertificateIsSelfSignedAndMatchesTheKey) {
    TempDir dir;
    identity::generate(dir.file("id.crt"), dir.file("id.key"), "alice");
    auto cert = load_cert(dir.file("id.crt"));
    auto key = load_key(dir.file("id.key"));
    ASSERT_TRUE(cert);
    ASSERT_TRUE(key);
    EXPECT_EQ(X509_verify(cert.get(), X509_get0_pubkey(cert.get())), 1);     // signed by its own key
    EXPECT_EQ(X509_check_private_key(cert.get(), key.get()), 1);              // key belongs to this cert
    EXPECT_EQ(X509_NAME_cmp(X509_get_subject_name(cert.get()), X509_get_issuer_name(cert.get())), 0);
}

TEST(Identity, CertificateCarriesTheGivenNameAndIsValidNow) {
    TempDir dir;
    identity::generate(dir.file("id.crt"), dir.file("id.key"), "alice-laptop");
    auto cert = load_cert(dir.file("id.crt"));
    ASSERT_TRUE(cert);
    char cn[65] = {};
    X509_NAME_get_text_by_NID(X509_get_subject_name(cert.get()), NID_commonName, cn, sizeof(cn));
    EXPECT_STREQ(cn, "alice-laptop");
    EXPECT_LT(X509_cmp_current_time(X509_get0_notBefore(cert.get())), 0);     // already valid
    EXPECT_GT(X509_cmp_current_time(X509_get0_notAfter(cert.get())), 0);      // not expired
}

TEST(Identity, FingerprintIs64LowercaseHexAndStable) {
    TempDir dir;
    identity::generate(dir.file("id.crt"), dir.file("id.key"), "alice");
    const std::string first = identity::fingerprint_of_file(dir.file("id.crt"));
    EXPECT_EQ(first.size(), 64u);
    EXPECT_EQ(trust::normalize_fingerprint(first), first);                    // already normalized form
    EXPECT_EQ(identity::fingerprint_of_file(dir.file("id.crt")), first);
}

TEST(Identity, TwoIdentitiesNeverShareAFingerprint) {
    TempDir dir;
    identity::generate(dir.file("a.crt"), dir.file("a.key"), "same-name");
    identity::generate(dir.file("b.crt"), dir.file("b.key"), "same-name");
    EXPECT_NE(identity::fingerprint_of_file(dir.file("a.crt")), identity::fingerprint_of_file(dir.file("b.crt")));
}

TEST(Identity, WontOverwriteAnExistingIdentityByAccident) {
    TempDir dir;
    identity::generate(dir.file("id.crt"), dir.file("id.key"), "alice");
    const std::string before = identity::fingerprint_of_file(dir.file("id.crt"));
    EXPECT_THROW(identity::generate(dir.file("id.crt"), dir.file("id.key"), "alice"), std::runtime_error);
    EXPECT_EQ(identity::fingerprint_of_file(dir.file("id.crt")), before);     // untouched
    identity::generate(dir.file("id.crt"), dir.file("id.key"), "alice", /*overwrite=*/true);
    EXPECT_NE(identity::fingerprint_of_file(dir.file("id.crt")), before);     // replaced on request
}

TEST(Identity, RejectsBadNames) {
    TempDir dir;
    EXPECT_THROW(identity::generate(dir.file("id.crt"), dir.file("id.key"), ""), std::runtime_error);
    EXPECT_THROW(identity::generate(dir.file("id.crt"), dir.file("id.key"), std::string(65, 'a')), std::runtime_error);
    EXPECT_FALSE(std::filesystem::exists(dir.file("id.key")));                // nothing half-written
}

#ifndef _WIN32
TEST(Identity, PrivateKeyIsReadableOnlyByItsOwner) {
    TempDir dir;
    identity::generate(dir.file("id.crt"), dir.file("id.key"), "alice");
    const auto perms = std::filesystem::status(dir.file("id.key")).permissions();
    using P = std::filesystem::perms;
    EXPECT_EQ(perms & (P::group_all | P::others_all), P::none);
}

TEST(Identity, KeyStaysPrivateEvenWhenReplacingALooseFile) {
    TempDir dir;
    {   // an old key file that anyone could read
        std::ofstream(dir.file("id.key")) << "old";
        std::filesystem::permissions(dir.file("id.key"), std::filesystem::perms::all);
    }
    identity::generate(dir.file("id.crt"), dir.file("id.key"), "alice", /*overwrite=*/true);
    const auto perms = std::filesystem::status(dir.file("id.key")).permissions();
    using P = std::filesystem::perms;
    EXPECT_EQ(perms & (P::group_all | P::others_all), P::none);
}
#endif

TEST(Identity, FingerprintOfMissingOrBrokenFileFails) {
    TempDir dir;
    EXPECT_THROW(identity::fingerprint_of_file(dir.file("missing.crt")), std::runtime_error);
    std::ofstream(dir.file("junk.crt")) << "this is not a certificate\n";
    EXPECT_THROW(identity::fingerprint_of_file(dir.file("junk.crt")), std::runtime_error);
}
