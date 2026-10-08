#pragma once
// Makes the TLS handshake check WHO the other side is, by fingerprint, on both ends.
//
// Every node presents its own self-signed certificate. Nobody vouches for it, so the normal
// "is this signed by a trusted authority?" check always fails with a self-signed error. We
// replace that check with a stricter one: the certificate's fingerprint must be in our own
// trust list (trusted_peers.txt). Anything else is refused, and the refusal prints the
// fingerprint so a person can decide whether to trust it.

#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <boost/asio/ssl.hpp>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include "identity.hpp"
#include "trust_store.hpp"

namespace tls_trust {

enum class PeerVerdict {
    Trusted,
    UnknownPeer,        // a well-formed identity, but not on our trust list
    BadCertificate      // expired, not valid yet, or not a single self-signed certificate
};

// The whole decision, with no OpenSSL objects involved so it is easy to test.
//   depth:          0 is the peer's own certificate; anything higher is a certificate above it
//   openssl_error:  what OpenSSL's normal checks complained about (X509_V_OK if nothing)
inline PeerVerdict judge_peer(int depth, int openssl_error, const std::string& fingerprint,
                              const trust::TrustStore& store) {
    if (depth != 0) return PeerVerdict::BadCertificate;       // we only accept one self-signed identity
    // "self-signed" is the one complaint we expect, since that is what every identity is.
    // Anything else (expired, not valid yet, ...) means the certificate is not usable.
    if (openssl_error != X509_V_OK && openssl_error != X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) {
        return PeerVerdict::BadCertificate;
    }
    return store.is_trusted(fingerprint) ? PeerVerdict::Trusted : PeerVerdict::UnknownPeer;
}

// `log_prefix` is "[SERVER]" or "[CLIENT]"; `peer_word` is how we call the other side in messages
inline std::function<bool(bool, boost::asio::ssl::verify_context&)>
make_verifier(std::shared_ptr<trust::TrustStore> store, std::string log_prefix, std::string peer_word) {
    return [store, log_prefix, peer_word](bool /*openssl's own verdict, replaced by ours*/,
                                          boost::asio::ssl::verify_context& context) -> bool {
        try {
            X509_STORE_CTX* state = context.native_handle();
            const X509* cert = X509_STORE_CTX_get_current_cert(state);
            if (!cert) return false;
            const int depth = X509_STORE_CTX_get_error_depth(state);
            const int error = X509_STORE_CTX_get_error(state);
            const std::string fingerprint = identity::fingerprint_of(cert);

            switch (judge_peer(depth, error, fingerprint, *store)) {
                case PeerVerdict::Trusted:
                    return true;
                case PeerVerdict::UnknownPeer:
                    std::cerr << log_prefix << " Refused the " << peer_word
                              << ": its fingerprint is not in your trust list.\n"
                              << log_prefix << " Fingerprint: " << trust::display_fingerprint(fingerprint) << '\n'
                              << log_prefix << " If you have checked with its owner (a call, or a message you know "
                                               "is really theirs) that this is their fingerprint, trust it with:\n"
                              << log_prefix << "   P2P_Secure_File_Sharing trust add "
                              << trust::display_fingerprint(fingerprint) << " <name>\n";
                    return false;
                case PeerVerdict::BadCertificate:
                    std::cerr << log_prefix << " Refused the " << peer_word << ": its certificate cannot be used ("
                              << X509_verify_cert_error_string(error) << ", depth " << depth << ").\n";
                    return false;
            }
        } catch (...) {
            // never let an exception escape into OpenSSL; when in doubt, refuse
        }
        return false;
    };
}

inline void load_identity(boost::asio::ssl::context& context) {
    context.use_certificate_chain_file(identity::CERT_FILE);
    context.use_private_key_file(identity::KEY_FILE, boost::asio::ssl::context::pem);
}

// For the receiving side: requires the sender to present an identity, and checks it against the list
inline void configure_server(boost::asio::ssl::context& context, std::shared_ptr<trust::TrustStore> store) {
    context.set_options(boost::asio::ssl::context::default_workarounds |
                        boost::asio::ssl::context::no_sslv2 |
                        boost::asio::ssl::context::no_sslv3 |
                        boost::asio::ssl::context::single_dh_use);
    load_identity(context);
    context.set_verify_mode(boost::asio::ssl::verify_peer | boost::asio::ssl::verify_fail_if_no_peer_cert);
    context.set_verify_callback(make_verifier(std::move(store), "[SERVER]", "sender"));
}

// For the sending side: presents our identity, and checks the receiver's against the list
inline void configure_client(boost::asio::ssl::context& context, std::shared_ptr<trust::TrustStore> store) {
    context.set_options(boost::asio::ssl::context::default_workarounds |
                        boost::asio::ssl::context::no_sslv2 |
                        boost::asio::ssl::context::no_sslv3);
    load_identity(context);
    context.set_verify_mode(boost::asio::ssl::verify_peer);
    context.set_verify_callback(make_verifier(std::move(store), "[CLIENT]", "receiver"));
}

} // namespace tls_trust
