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
#include <openssl/x509.h>
#include <openssl/err.h>
#include <fstream>
#include <iterator>
#include <openssl/bio.h>
#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
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

        inline FILE* open_private_file(const std::filesystem::path& path) {
#ifdef _WIN32
            return _wfopen(path.wstring().c_str(), L"wb");
#else
            const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
            if (fd < 0) return nullptr;
            ::fchmod(fd, 0600);
            return ::fdopen(fd, "wb");
#endif
        }
        using BioPtr = std::unique_ptr<BIO, int (*)(BIO*)>;

        // Reads a whole file with normal C++ streams (safe for non-ASCII paths on Windows)
        inline std::string read_file(const std::filesystem::path& path) {
            std::ifstream in(path, std::ios::binary);
            if (!in) throw std::runtime_error("cannot open " + path.string());
            return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
        }

        // Writes bytes with OUR C runtime's FILE*, which OpenSSL never touches
        inline void write_private_file(const std::filesystem::path& path, const std::string& bytes) {
            FilePtr file(open_private_file(path), &std::fclose);
            if (!file) throw std::runtime_error("cannot write " + path.string());
            if (!bytes.empty() &&
                std::fwrite(bytes.data(), 1, bytes.size(), file.get()) != bytes.size()) {
                throw std::runtime_error("could not write " + path.string());
                }
            if (std::fflush(file.get()) != 0) throw std::runtime_error("could not flush " + path.string());
            if (std::fclose(file.release()) != 0) throw std::runtime_error("could not close " + path.string());
        }

        inline std::string bio_contents(BIO* bio) {
            char* data = nullptr;
            const long length = BIO_get_mem_data(bio, &data);
            if (length <= 0 || !data) throw std::runtime_error("OpenSSL produced no output");
            return std::string(data, static_cast<std::size_t>(length));
        }
    }
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
        const std::string pem = detail::read_file(cert_path);
        detail::BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), &BIO_free);
        if (!bio) throw std::runtime_error("could not create a memory buffer");
        std::unique_ptr<X509, decltype(&X509_free)> cert(
            PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr), &X509_free);
        if (!cert) throw std::runtime_error(cert_path.string() + " is not a valid certificate");
        return fingerprint_of(cert.get());
    }

    // Can this key file be opened with this passphrase? (empty passphrase = unencrypted key)
    inline bool private_key_loads(const std::filesystem::path& key_path, const std::string& passphrase) {
        try {
            const std::string pem = detail::read_file(key_path);
            detail::BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), &BIO_free);
            if (!bio) return false;
            // Always pass a non-null password pointer, otherwise OpenSSL tries to prompt on a console
            std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(
                PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, const_cast<char*>(passphrase.c_str())),
                &EVP_PKEY_free);
            ERR_clear_error();
            return key != nullptr;
        } catch (...) {
            return false;
        }
    }

        // Creates a new identity: an EC P-256 key and a certificate for it, valid for ten years.
        inline void generate(const std::filesystem::path& cert_path, const std::filesystem::path& key_path,
                             const std::string& common_name, const std::string& passphrase = "",
                             bool overwrite = false) {
            namespace fs = std::filesystem;
            const bool key_existed = fs::exists(key_path);
            const bool cert_existed = fs::exists(cert_path);
            if (!overwrite && (fs::exists(cert_path) || fs::exists(key_path))) {
                throw std::runtime_error("identity files already exist (use --force to replace them, "
                                         "but then everyone who trusts your old fingerprint must trust the new one)");
            }
            if (common_name.empty() || common_name.size() > 64) {
                throw std::runtime_error("the name must be 1 to 64 characters long");
            }
            if (cert_path.has_parent_path()) {
                std::error_code ec;
                fs::create_directories(cert_path.parent_path(), ec);
                if (ec) {
                    throw std::runtime_error("cannot create " + cert_path.parent_path().string() +
                                             ": " + ec.message());
                }
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
            fs::path key_tmp = key_path;
            fs::path cert_tmp = cert_path;
            key_tmp += ".tmp";
            cert_tmp += ".tmp";
        try {
            std::error_code cleanup_ec;
            fs::remove(key_tmp, cleanup_ec);
            fs::remove(cert_tmp, cleanup_ec);

            const EVP_CIPHER* cipher = passphrase.empty() ? nullptr : EVP_aes_256_cbc();
            const unsigned char* pass_data = passphrase.empty()
                ? nullptr
                : reinterpret_cast<const unsigned char*>(passphrase.data());
            const int pass_len = static_cast<int>(passphrase.size());

            detail::BioPtr key_bio(BIO_new(BIO_s_mem()), &BIO_free);
            detail::BioPtr cert_bio(BIO_new(BIO_s_mem()), &BIO_free);
            if (!key_bio || !cert_bio) throw std::runtime_error("could not create a memory buffer");

            if (PEM_write_bio_PrivateKey(key_bio.get(), key.get(), cipher,
                                         pass_data, pass_len, nullptr, nullptr) != 1) {
                throw std::runtime_error("could not encode the private key: " +
                                         std::string(ERR_error_string(ERR_get_error(), nullptr)));
                                         }
            if (PEM_write_bio_X509(cert_bio.get(), cert.get()) != 1) {
                throw std::runtime_error("could not encode the certificate");
            }

            detail::write_private_file(key_tmp, detail::bio_contents(key_bio.get()));
            detail::write_private_file(cert_tmp, detail::bio_contents(cert_bio.get()));

            // these two were the missing part
            if (overwrite) {
                fs::remove(cert_path);
                fs::remove(key_path);
            }
            fs::rename(key_tmp, key_path);
            fs::rename(cert_tmp, cert_path);
        }
        catch (...) {
                std::error_code ec;
                fs::remove(key_tmp, ec);
                fs::remove(cert_tmp, ec);
                if (!key_existed) {
                    fs::remove(key_path, ec);
                }
                if (!cert_existed) {
                    fs::remove(cert_path, ec);
                }
                throw;
            }
        }
}// namespace identity
