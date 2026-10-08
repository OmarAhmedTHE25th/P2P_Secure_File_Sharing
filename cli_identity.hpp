#pragma once
// Command line for managing your identity and who you trust:
//   init [--force] [name]          create identity.key and identity.crt
//   fingerprint                    show your fingerprint
//   trust add <fingerprint> <name> trust a peer
//   trust list                     show who you trust
//   trust remove <name|fingerprint>

#include <filesystem>
#include <iostream>
#include <string>
#include <vector>
#include <boost/asio/ip/host_name.hpp>
#include "identity.hpp"
#include "trust_store.hpp"

namespace cli {

inline void print_identity_usage(const std::string& program) {
    std::cerr << "Identity and trust:\n"
              << "  " << program << " init [--force] [name]\n"
              << "  " << program << " fingerprint\n"
              << "  " << program << " trust add <fingerprint> <name>\n"
              << "  " << program << " trust list\n"
              << "  " << program << " trust remove <name|fingerprint>\n";
}

namespace detail {

inline std::string default_name() {
    try {
        std::string name = boost::asio::ip::host_name();
        std::string cleaned;
        for (char c : name) {
            if (trust::valid_name(std::string(1, c))) cleaned.push_back(c);
        }
        if (!cleaned.empty()) return cleaned.substr(0, 64);
    } catch (...) {}
    return "p2p-node";
}

inline int init(const std::vector<std::string>& args, const std::string& program) {
    bool force = false;
    std::string name;
    for (std::size_t i = 1; i < args.size(); ++i) {
        if (args[i] == "--force") force = true;
        else if (name.empty()) name = args[i];
        else { print_identity_usage(program); return 1; }
    }
    if (name.empty()) name = default_name();
    try {
        identity::generate(identity::CERT_FILE, identity::KEY_FILE, name, force);
        const std::string fingerprint = identity::fingerprint_of_file(identity::CERT_FILE);
        std::cout << "Created " << identity::KEY_FILE << " (keep it secret!) and "
                  << identity::CERT_FILE << " for '" << name << "'.\n"
                  << "Your fingerprint: " << trust::display_fingerprint(fingerprint) << "\n\n"
                  << "Give this fingerprint to the people you want to exchange files with, through a\n"
                  << "channel you trust (a call, or a message from them you know is really theirs).\n"
                  << "Add theirs with:  " << program << " trust add <their-fingerprint> <their-name>\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << '\n';
        return 1;
    }
}

inline int fingerprint(const std::string& program) {
    try {
        std::cout << "Your fingerprint: "
                  << trust::display_fingerprint(identity::fingerprint_of_file(identity::CERT_FILE)) << '\n';
        return 0;
    } catch (const std::exception&) {
        std::cerr << "[ERROR] No identity found here. Create one with: " << program << " init\n";
        return 1;
    }
}

inline int trust_command(const std::vector<std::string>& args, const std::string& program) {
    trust::TrustStore store(identity::TRUST_FILE);
    if (args.size() == 4 && args[1] == "add") {
        const std::string error = store.add(args[2], args[3]);
        if (!error.empty()) { std::cerr << "[ERROR] " << error << '\n'; return 1; }
        std::cout << "Now trusting '" << args[3] << "' ("
                  << trust::display_fingerprint(*trust::normalize_fingerprint(args[2])) << ").\n";
        return 0;
    }
    if (args.size() == 2 && args[1] == "list") {
        std::vector<std::string> warnings;
        const auto entries = store.list(&warnings);
        for (const std::string& w : warnings) {
            std::cerr << "[WARNING] " << identity::TRUST_FILE << ", " << w << '\n';
        }
        if (entries.empty()) { std::cout << "Nobody is trusted yet.\n"; return 0; }
        for (const auto& e : entries) {
            std::cout << e.name << "  " << trust::display_fingerprint(e.fingerprint) << '\n';
        }
        return 0;
    }
    if (args.size() == 3 && args[1] == "remove") {
        const std::string error = store.remove(args[2]);
        if (!error.empty()) { std::cerr << "[ERROR] " << error << '\n'; return 1; }
        std::cout << "No longer trusting '" << args[2] << "'.\n";
        return 0;
    }
    print_identity_usage(program);
    return 1;
}

} // namespace detail

// Returns the exit code if `args` is an identity command, or -1 if it is something else
inline int handle_identity_command(const std::vector<std::string>& args, const std::string& program) {
    if (args.empty()) return -1;
    if (args[0] == "init") return detail::init(args, program);
    if (args[0] == "fingerprint") return detail::fingerprint(program);
    if (args[0] == "trust") return detail::trust_command(args, program);
    return -1;
}

} // namespace cli
