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
#include "identity.hpp"
#include "trust_store.hpp"
#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace cli {
namespace detail {

inline std::string read_password(const std::string& prompt) {
    std::cout << prompt << std::flush;
    std::string pass;
#ifdef _WIN32
    char ch;
    while ((ch = (char)_getch()) != '\r' && ch != '\n') {
        if (ch == '\b') {
            if (!pass.empty()) {
                pass.pop_back();
                std::cout << "\b \b" << std::flush;
            }
        } else {
            pass.push_back(ch);
        }
    }
    std::cout << '\n';
#else
    termios old_t{}, new_t{};
    tcgetattr(STDIN_FILENO, &old_t);
    new_t = old_t;
    new_t.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new_t);

    std::getline(std::cin, pass);
    tcsetattr(STDIN_FILENO, TCSANOW, &old_t);
    std::cout << '\n';
#endif
    return pass;
}

inline std::string default_name() {
#ifdef _WIN32
    const char* user = std::getenv("USERNAME");
#else
    const char* user = std::getenv("USER");
#endif
    return user ? std::string(user) : "a-node";
}

inline void print_identity_usage(const std::string& program) {
    std::cerr << "Identity management:\n"
              << "  " << program << " init [--force] [name]          create identity.key and identity.crt\n"
              << "  " << program << " fingerprint                    show your fingerprint\n"
              << "  " << program << " trust add <fingerprint> <name> trust a peer\n"
              << "  " << program << " trust list                     show who you trust\n"
              << "  " << program << " trust remove <name|fingerprint>\n";
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

    std::string pass1 = read_password("Enter passphrase for private key (press Enter for none): ");
    if (!pass1.empty()) {
        std::string pass2 = read_password("Confirm passphrase: ");
        if (pass1 != pass2) {
            std::cerr << "[ERROR] Passphrases do not match.\n";
            return 1;
        }
    }

    try {
        identity::generate(identity::CERT_FILE, identity::KEY_FILE, name, pass1, force);
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

inline int fingerprint() {
    try {
        const std::string fp = identity::fingerprint_of_file(identity::CERT_FILE);
        std::cout << "Your fingerprint: " << trust::display_fingerprint(fp) << "\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << "\n(Did you run 'init' yet?)\n";
        return 1;
    }
}

inline int trust(const std::vector<std::string>& args, const std::string& program) {
    if (args.size() < 2) { print_identity_usage(program); return 1; }
    const std::string& cmd = args[1];
    trust::TrustStore store(identity::TRUST_FILE);

    if (cmd == "add" && args.size() == 4) {
        const std::string err = store.add(args[2], args[3]);
        if (!err.empty()) { std::cerr << "[ERROR] " << err << "\n"; return 1; }
        std::cout << "Peer '" << args[3] << "' is now trusted.\n";
        return 0;
    } else if (cmd == "list" && args.size() == 2) {
        std::vector<std::string> warnings;
        const auto entries = store.list(&warnings);
        for (const auto& w : warnings) std::cerr << "[WARNING] " << w << "\n";
        if (entries.empty()) {
            std::cout << "Your trust list is empty.\n";
        } else {
            std::cout << "Trusted peers:\n";
            for (const auto& e : entries) {
                std::cout << "  " << trust::display_fingerprint(e.fingerprint) << "  " << e.name << "\n";
            }
        }
        return 0;
    } else if (cmd == "remove" && args.size() == 3) {
        const std::string err = store.remove(args[2]);
        if (!err.empty()) { std::cerr << "[ERROR] " << err << "\n"; return 1; }
        std::cout << "Removed '" << args[2] << "' from trust list.\n";
        return 0;
    } else {
        print_identity_usage(program);
        return 1;
    }
}

} // namespace detail

inline void print_identity_usage(const std::string& program) {
    detail::print_identity_usage(program);
}

inline int handle_identity_command(const std::vector<std::string>& args, const std::string& program) {
    if (args.empty()) return -1;
    const std::string& cmd = args[0];
    if (cmd == "init") return detail::init(args, program);
    if (cmd == "fingerprint") return detail::fingerprint();
    if (cmd == "trust") return detail::trust(args, program);
    return -1;
}

} // namespace cli