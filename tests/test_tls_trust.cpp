#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <openssl/x509_vfy.h>
#include "tls_trust.hpp"

namespace {

const std::string FP_ALICE = "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b";
const std::string FP_STRANGER = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb";

class StoreWithAlice {
public:
    StoreWithAlice() {
        std::random_device rd;
        dir_ = std::filesystem::temp_directory_path() / ("p2p_tls_" + std::to_string(rd()) + std::to_string(rd()));
        std::filesystem::create_directories(dir_);
        store = std::make_unique<trust::TrustStore>(dir_ / "trusted_peers.txt");
        EXPECT_EQ(store->add(FP_ALICE, "alice"), "");
    }
    ~StoreWithAlice() { std::error_code ec; std::filesystem::remove_all(dir_, ec); }
    std::unique_ptr<trust::TrustStore> store;
private:
    std::filesystem::path dir_;
};

using tls_trust::judge_peer;
using tls_trust::PeerVerdict;

} // namespace

TEST(JudgePeer, TrustedIdentityIsAccepted) {
    StoreWithAlice s;
    // a self-signed certificate always makes OpenSSL complain with this exact error, and that is expected
    EXPECT_EQ(judge_peer(0, X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT, FP_ALICE, *s.store), PeerVerdict::Trusted);
    EXPECT_EQ(judge_peer(0, X509_V_OK, FP_ALICE, *s.store), PeerVerdict::Trusted);
}

TEST(JudgePeer, StrangerIsRefusedAsUnknown) {
    StoreWithAlice s;
    EXPECT_EQ(judge_peer(0, X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT, FP_STRANGER, *s.store), PeerVerdict::UnknownPeer);
    EXPECT_EQ(judge_peer(0, X509_V_OK, FP_STRANGER, *s.store), PeerVerdict::UnknownPeer);
    EXPECT_EQ(judge_peer(0, X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT, "", *s.store), PeerVerdict::UnknownPeer);
}

TEST(JudgePeer, TrustedButUnusableCertificatesAreRefused) {
    StoreWithAlice s;
    for (int problem : {X509_V_ERR_CERT_HAS_EXPIRED, X509_V_ERR_CERT_NOT_YET_VALID,
                        X509_V_ERR_CERT_REVOKED, X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT,
                        X509_V_ERR_CERT_SIGNATURE_FAILURE, X509_V_ERR_INVALID_PURPOSE}) {
        EXPECT_EQ(judge_peer(0, problem, FP_ALICE, *s.store), PeerVerdict::BadCertificate)
            << X509_verify_cert_error_string(problem);
    }
}

TEST(JudgePeer, OnlyTheCertificateItselfCountsNotOnesAboveIt) {
    StoreWithAlice s;
    EXPECT_EQ(judge_peer(1, X509_V_OK, FP_ALICE, *s.store), PeerVerdict::BadCertificate);
    EXPECT_EQ(judge_peer(2, X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT, FP_ALICE, *s.store), PeerVerdict::BadCertificate);
}

TEST(JudgePeer, RemovingAPeerCutsThemOffImmediately) {
    StoreWithAlice s;
    EXPECT_EQ(judge_peer(0, X509_V_OK, FP_ALICE, *s.store), PeerVerdict::Trusted);
    ASSERT_EQ(s.store->remove("alice"), "");
    EXPECT_EQ(judge_peer(0, X509_V_OK, FP_ALICE, *s.store), PeerVerdict::UnknownPeer);
}

TEST(JudgePeer, EmptyTrustListRefusesEveryone) {
    std::random_device rd;
    const auto dir = std::filesystem::temp_directory_path() / ("p2p_tls_empty_" + std::to_string(rd()));
    trust::TrustStore store(dir / "does_not_exist.txt");
    EXPECT_EQ(judge_peer(0, X509_V_OK, FP_ALICE, store), PeerVerdict::UnknownPeer);
}
