#pragma once
// A node's own identity: a private key plus a self-signed certificate made from it.
// Nobody vouches for the certificate. Other peers recognize it by its FINGERPRINT,
// which they get from you through a channel they trust and then write in their trust list.

#include <cstdio>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#if OPENSSL_VERSION_NUMBER < 0x30000000L
#error "OpenSSL 3.0 or newer is required"
#endif

namespace identity {

inline constexpr const char* CERT_FILE  = "identity.crt";
inline constexpr const char* KEY_FILE   = "identity.key";
inline constexpr const char* TRUST_FILE = "trusted_peers.txt";

namespace detail {
using FilePtr = std::unique_ptr<FILE, int (*)(FILE*)>;

// The private key file must never be readable by anyone else, not even for a moment
inline FILE* open_private_file(const std::filesystem::path& path) {
#ifdef _WIN32
    return std::fopen(path.string().c_str(), "wb");
#else
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return nullptr;
    ::fchmod(fd, 0600);
    return ::fdopen(fd, "wb");
#endif
}
} // namespace detail

// SHA-256 of the certificate (its DER encoding), as 64 lowercase hex characters
inline std::string fingerprint_of(const X509* cert) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int length = 0;
    if (!cert || X509_digest(cert, EVP_sha256(), digest, &length) != 1 || length != 32) {
        throw std::runtime_error("could not compute the certificate fingerprint");
    }
    static const char* hex = "0123456789abcdef";
    std::string out;
    for (unsigned int i = 0; i < length; ++i) {
        out.push_back(hex[digest[i] >> 4]);
        out.push_back(hex[digest[i] & 0x0F]);
    }
    return out;
}

inline std::string fingerprint_of_file(const std::filesystem::path& cert_path) {
    detail::FilePtr file(std::fopen(cert_path.string().c_str(), "rb"), &std::fclose);
    if (!file) throw std::runtime_error("cannot open " + cert_path.string());
    std::unique_ptr<X509, decltype(&X509_free)> cert(
        PEM_read_X509(file.get(), nullptr, nullptr, nullptr), &X509_free);
    if (!cert) throw std::runtime_error(cert_path.string() + " is not a valid certificate");
    return fingerprint_of(cert.get());
}

// Creates a new identity: an EC P-256 key and a certificate for it, valid for ten years.
inline void generate(const std::filesystem::path& cert_path, const std::filesystem::path& key_path,
                     const std::string& common_name, bool overwrite = false) {
    namespace fs = std::filesystem;
    if (!overwrite && (fs::exists(cert_path) || fs::exists(key_path))) {
        throw std::runtime_error("identity files already exist (use --force to replace them, "
                                 "but then everyone who trusts your old fingerprint must trust the new one)");
    }
    if (common_name.empty() || common_name.size() > 64) {
        throw std::runtime_error("the name must be 1 to 64 characters long");
    }

    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(EVP_EC_gen("P-256"), &EVP_PKEY_free);
    if (!key) throw std::runtime_error("could not generate a key");

    std::unique_ptr<X509, decltype(&X509_free)> cert(X509_new(), &X509_free);
    if (!cert) throw std::runtime_error("could not create a certificate");
    X509_set_version(cert.get(), 2);   // version 3

    std::unique_ptr<BIGNUM, decltype(&BN_free)> serial(BN_new(), &BN_free);
    if (!serial || BN_rand(serial.get(), 127, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) != 1 ||
        !BN_to_ASN1_INTEGER(serial.get(), X509_get_serialNumber(cert.get()))) {
        throw std::runtime_error("could not create a serial number");
    }

    // Starts a day in the past so a slightly wrong clock does not make it "not valid yet"
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), -24L * 60 * 60);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), 10L * 365 * 24 * 60 * 60);

    X509_NAME* subject = X509_get_subject_name(cert.get());
    if (X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_UTF8,
            reinterpret_cast<const unsigned char*>(common_name.c_str()), -1, -1, 0) != 1 ||
        X509_set_issuer_name(cert.get(), subject) != 1 ||      // self-signed: issuer is itself
        X509_set_pubkey(cert.get(), key.get()) != 1 ||
        X509_sign(cert.get(), key.get(), EVP_sha256()) == 0) {
        throw std::runtime_error("could not build the certificate");
    }

    {
        detail::FilePtr key_file(detail::open_private_file(key_path), &std::fclose);
        if (!key_file) throw std::runtime_error("cannot write " + key_path.string());
        if (PEM_write_PrivateKey(key_file.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1) {
            throw std::runtime_error("could not write the private key");
        }
    }
    {
        detail::FilePtr cert_file(std::fopen(cert_path.string().c_str(), "wb"), &std::fclose);
        if (!cert_file) throw std::runtime_error("cannot write " + cert_path.string());
        if (PEM_write_X509(cert_file.get(), cert.get()) != 1) {
            throw std::runtime_error("could not write the certificate");
        }
    }
}

} // namespace identity
